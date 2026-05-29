"""
File upload security testing.

Tests file upload endpoints for:
1. Dangerous file type acceptance (PHP, JSP, ASPX, SVG-with-JS, HTML)
2. Missing content-type validation (MIME confusion)
3. Path traversal via filename (../../../evil.php)
4. Polyglot files (JPEG magic bytes + PHP payload)

Does NOT actually execute uploaded files — only checks server acceptance.
"""
import io
import re
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

_UPLOAD_INPUT_TYPES = ("file",)

# Dangerous extensions to attempt
_DANGEROUS_FILES = [
    ("php_webshell",  "evil.php",    b"<?php echo 'KAGESEC_PROBE'; ?>",   "text/plain",       Severity.CRITICAL, "CWE-434"),
    ("php5",          "evil.php5",   b"<?php echo 'KAGESEC_PROBE'; ?>",   "image/jpeg",       Severity.CRITICAL, "CWE-434"),
    ("phtml",         "evil.phtml",  b"<?php echo 'KAGESEC_PROBE'; ?>",   "image/png",        Severity.CRITICAL, "CWE-434"),
    ("jsp",           "evil.jsp",    b"<% out.print('KAGESEC'); %>",       "text/plain",       Severity.CRITICAL, "CWE-434"),
    ("aspx",          "evil.aspx",   b"<% Response.Write('KAGESEC'); %>", "text/plain",       Severity.CRITICAL, "CWE-434"),
    ("svg_xss",       "evil.svg",    b'<svg><script>alert(1)</script></svg>', "image/svg+xml", Severity.HIGH,     "CWE-434"),
    ("html_xss",      "evil.html",   b"<script>alert(1)</script>",         "text/html",        Severity.HIGH,     "CWE-434"),
    ("xml",           "evil.xml",    b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>', "text/xml", Severity.HIGH, "CWE-434"),
    ("path_traversal","../evil.txt", b"KAGESEC_PATH_TRAVERSAL",           "text/plain",       Severity.HIGH,     "CWE-22"),
    ("polyglot_php",  "image.jpg",   b"\xff\xd8\xff<?php echo 'KAGESEC'; ?>", "image/jpeg",  Severity.HIGH,     "CWE-434"),
]

# Responses that confirm the file was accepted
_ACCEPT_SIGNALS = [
    re.compile(r'"(success|uploaded|saved|ok|created)"\s*:\s*true', re.IGNORECASE),
    re.compile(r'(file|upload).{0,30}(success|complete|done|uploaded)', re.IGNORECASE),
    re.compile(r'(url|path|location|href)["\s:]+["\']/.{3,80}\.(php|jsp|aspx|svg|html|xml|jpg)', re.IGNORECASE),
]

_REJECT_SIGNALS = re.compile(
    r"(invalid|not allowed|rejected|unsupported|forbidden|blocked|denied).{0,50}(file|type|extension|format)",
    re.IGNORECASE,
)


def test(page: CrawlResult, client) -> List[Finding]:
    findings = []

    for form in page.forms:
        inputs = form.get("inputs", [])
        has_file_input = any(i.get("type", "").lower() == "file" for i in inputs)
        if not has_file_input:
            continue

        action = form.get("action", page.url)
        method = form.get("method", "post").lower()
        if method != "post":
            continue

        findings.extend(_probe_upload(action, inputs, client, page.url))

    return findings


def _probe_upload(action: str, inputs: list, client, referer: str) -> List[Finding]:
    # Build base form fields (non-file inputs)
    base_data = {}
    file_field_name = None

    for inp in inputs:
        name = inp.get("name", "")
        if not name:
            continue
        itype = inp.get("type", "text").lower()
        if itype == "file":
            file_field_name = name
        elif itype not in ("submit", "button", "image", "reset"):
            base_data[name] = inp.get("value", "") or _placeholder(itype)

    if not file_field_name:
        return []

    findings = []
    for probe_name, filename, content, content_type, severity, cwe in _DANGEROUS_FILES:
        file_obj = io.BytesIO(content)
        files = {file_field_name: (filename, file_obj, content_type)}

        try:
            resp = client.post(
                action,
                data=base_data,
                files=files,
                headers={"Referer": referer},
            )
        except Exception:
            continue

        status = resp.status_code
        body = resp.text if hasattr(resp, "text") else ""

        # Skip if clearly rejected
        if status in (400, 415, 422) or _REJECT_SIGNALS.search(body):
            continue

        # Skip if redirected to login
        if status in (301, 302, 303) and any(kw in resp.headers.get("location", "").lower() for kw in ("login", "auth")):
            continue

        # Check if accepted
        accepted = status in (200, 201, 202, 204)
        for sig in _ACCEPT_SIGNALS:
            if sig.search(body):
                accepted = True
                break

        if accepted:
            findings.append(Finding(
                title=f"Dangerous File Type Accepted: {filename}",
                severity=severity,
                url=action,
                parameter=file_field_name,
                payload=filename,
                evidence=f"HTTP {status} response accepted upload of '{filename}' ({content_type}). Body snippet: {body[:200]}",
                description=(
                    f"The file upload endpoint at {action} accepted a file named '{filename}' "
                    f"with content type '{content_type}'. If the server executes or serves this file "
                    "without sanitisation, an attacker can achieve Remote Code Execution, "
                    "stored XSS, or XXE by uploading and then requesting the file."
                ),
                remediation=(
                    "1. Whitelist allowed MIME types server-side (do not trust client-provided Content-Type). "
                    "2. Validate file extension against a strict allowlist. "
                    "3. Re-encode or strip metadata from uploaded images using a library like Pillow/ImageMagick. "
                    "4. Store uploads outside the web root or in object storage (S3, GCS). "
                    "5. Serve uploads with Content-Disposition: attachment and X-Content-Type-Options: nosniff. "
                    "6. Scan uploads with a malware scanner."
                ),
                owasp_category="A03:2021 Injection",
                cwe=cwe,
                cvss=_cvss(severity),
                confidence=0.80,
                standards={"OWASP": "A03:2021", "CWE": cwe},
            ))

    return findings


def _cvss(severity: Severity) -> float:
    return {Severity.CRITICAL: 9.8, Severity.HIGH: 7.5, Severity.MEDIUM: 5.4, Severity.LOW: 3.1}.get(severity, 0.0)


def _placeholder(itype: str) -> str:
    return {"email": "test@example.com", "password": "Test1234!", "number": "1", "checkbox": "on"}.get(itype, "test")
