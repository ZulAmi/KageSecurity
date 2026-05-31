import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    raw_cookies = page.headers.get("set-cookie", "")
    if not raw_cookies:
        return findings

    # httpx may fold multiple Set-Cookie into one header; handle both
    cookie_lines = [raw_cookies] if "\n" not in raw_cookies else raw_cookies.splitlines()

    for cookie_line in cookie_lines:
        if not cookie_line.strip():
            continue

        name = cookie_line.split("=")[0].strip()
        parts_lower = cookie_line.lower()

        if "httponly" not in parts_lower:
            findings.append(Finding(
                title="Cookie Missing HttpOnly Flag",
                severity=Severity.MEDIUM,
                url=page.url,
                parameter=name,
                payload=None,
                evidence=f"Set-Cookie: {cookie_line[:100]} — HttpOnly not set",
                description="Cookies without HttpOnly can be read by JavaScript, enabling session theft via XSS.",
                remediation="Add the HttpOnly flag to all session and authentication cookies.",
                cwe="CWE-1004",
                cvss=4.3,
                owasp_category="A07:2021 Identification and Authentication Failures",
                standards=["ISO27001-8.8", "HIPAA-164.312a", "GDPR-Art32"],
                confidence=1.0,
            ))

        if "secure" not in parts_lower:
            findings.append(Finding(
                title="Cookie Missing Secure Flag",
                severity=Severity.MEDIUM,
                url=page.url,
                parameter=name,
                payload=None,
                evidence=f"Set-Cookie: {cookie_line[:100]} — Secure not set",
                description="Cookies without the Secure flag can be transmitted over HTTP, exposing them to interception.",
                remediation="Add the Secure flag to all cookies, especially session tokens.",
                cwe="CWE-614",
                cvss=4.3,
                owasp_category="A02:2021 Cryptographic Failures",
                standards=["ISO27001-8.24", "HIPAA-164.312c", "GDPR-Art32"],
                confidence=1.0,
            ))

        if "samesite" not in parts_lower:
            findings.append(Finding(
                title="Cookie Missing SameSite Attribute",
                severity=Severity.LOW,
                url=page.url,
                parameter=name,
                payload=None,
                evidence=f"Set-Cookie: {cookie_line[:100]} — SameSite not set",
                description="Without SameSite, cookies are sent on cross-site requests, enabling CSRF attacks.",
                remediation="Add `SameSite=Lax` (minimum) or `SameSite=Strict` to session cookies.",
                cwe="CWE-352",
                cvss=3.1,
                owasp_category="A01:2021 Broken Access Control",
                standards=["ISO27001-8.8", "GDPR-Art32"],
                confidence=1.0,
            ))

    return findings
