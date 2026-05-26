import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

HEADERS = [
    {
        "header": "Content-Security-Policy",
        "title": "Missing Content-Security-Policy Header",
        "severity": Severity.MEDIUM,
        "cvss": 4.3,
        "cwe": "CWE-693",
        "description": "CSP prevents XSS and data injection attacks by controlling which resources the browser is allowed to load.",
        "remediation": "Add a Content-Security-Policy header. Minimum: `default-src 'self'`.",
    },
    {
        "header": "Strict-Transport-Security",
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "severity": Severity.MEDIUM,
        "cvss": 4.3,
        "cwe": "CWE-319",
        "description": "Without HSTS, browsers may connect over plain HTTP, exposing users to downgrade attacks.",
        "remediation": "Add: `Strict-Transport-Security: max-age=31536000; includeSubDomains`",
    },
    {
        "header": "X-Frame-Options",
        "title": "Missing X-Frame-Options Header (Clickjacking)",
        "severity": Severity.MEDIUM,
        "cvss": 4.3,
        "cwe": "CWE-1021",
        "description": "Without X-Frame-Options, pages can be embedded in iframes and used for clickjacking attacks.",
        "remediation": "Add: `X-Frame-Options: DENY` or use CSP `frame-ancestors 'none'`.",
    },
    {
        "header": "X-Content-Type-Options",
        "title": "Missing X-Content-Type-Options Header",
        "severity": Severity.LOW,
        "cvss": 3.1,
        "cwe": "CWE-693",
        "description": "Without this header browsers may MIME-sniff responses, enabling attacks where uploaded files are executed as scripts.",
        "remediation": "Add: `X-Content-Type-Options: nosniff`",
    },
    {
        "header": "Referrer-Policy",
        "title": "Missing Referrer-Policy Header",
        "severity": Severity.LOW,
        "cvss": 3.1,
        "cwe": "CWE-200",
        "description": "Without a Referrer-Policy, sensitive URL parameters may be leaked via the Referer header to third parties.",
        "remediation": "Add: `Referrer-Policy: strict-origin-when-cross-origin`",
    },
    {
        "header": "Permissions-Policy",
        "title": "Missing Permissions-Policy Header",
        "severity": Severity.LOW,
        "cvss": 2.6,
        "cwe": "CWE-693",
        "description": "Without Permissions-Policy, the page grants unnecessary access to browser features (camera, microphone, geolocation).",
        "remediation": "Add: `Permissions-Policy: camera=(), microphone=(), geolocation=()`",
    },
]


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    headers_lower = {k.lower(): v for k, v in page.headers.items()}

    for h in HEADERS:
        if h["header"].lower() not in headers_lower:
            findings.append(Finding(
                title=h["title"],
                severity=h["severity"],
                url=page.url,
                parameter=None,
                payload=None,
                evidence=f"Response missing '{h['header']}' header",
                description=h["description"],
                remediation=h["remediation"],
                cwe=h["cwe"],
                cvss=h["cvss"],
                owasp_category="A05:2021 Security Misconfiguration",
                standards=["ISO27001-8.24", "HIPAA-164.312c"],
                confidence=1.0,
            ))

    # Check for CSP 'unsafe-inline' even if header is present
    csp = headers_lower.get("content-security-policy", "")
    if csp and "unsafe-inline" in csp:
        findings.append(Finding(
            title="Weak Content-Security-Policy (unsafe-inline)",
            severity=Severity.MEDIUM,
            url=page.url,
            parameter=None,
            payload=None,
            evidence=f"CSP contains 'unsafe-inline': {csp[:120]}",
            description="'unsafe-inline' in CSP negates most XSS protection the policy provides.",
            remediation="Remove 'unsafe-inline'. Use nonces or hashes for inline scripts instead.",
            cwe="CWE-693",
            cvss=4.3,
            owasp_category="A05:2021 Security Misconfiguration",
            standards=["ISO27001-8.24"],
            confidence=1.0,
        ))

    return findings
