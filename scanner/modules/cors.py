import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

EVIL_ORIGIN = "https://evil.kagesec.io"
NULL_ORIGIN = "null"


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []

    for origin, label in [(EVIL_ORIGIN, "arbitrary origin"), (NULL_ORIGIN, "null origin")]:
        try:
            resp = client.get(page.url, headers={"Origin": origin})
        except Exception:
            continue

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()

        if acao == "*":
            findings.append(Finding(
                title="CORS Wildcard — Access-Control-Allow-Origin: *",
                severity=Severity.MEDIUM,
                url=page.url,
                parameter=None,
                payload=f"Origin: {origin}",
                evidence=f"Access-Control-Allow-Origin: * (reflects wildcard for {label})",
                description=(
                    "A wildcard CORS policy allows any website to make cross-origin requests "
                    "and read the response. This exposes API data to malicious third-party pages."
                ),
                remediation="Restrict CORS to specific trusted origins. Never use * with credentials.",
                cwe="CWE-942",
                cvss=4.3,
                owasp_category="A05:2021 Security Misconfiguration",
                standards=["ISO27001-8.23", "GDPR-Art32"],
                confidence=1.0,
            ))
            break

        if (acao == origin or acao == EVIL_ORIGIN) and acac == "true":
            findings.append(Finding(
                title="CORS Misconfiguration — Arbitrary Origin with Credentials",
                severity=Severity.HIGH,
                url=page.url,
                parameter=None,
                payload=f"Origin: {origin}",
                evidence=(
                    f"Access-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Credentials: true\n"
                    f"Server reflected {label} with credentials allowed"
                ),
                description=(
                    "The server reflects arbitrary origins and allows credentials (cookies/auth headers). "
                    "An attacker can host a malicious page that makes authenticated requests on behalf of the victim."
                ),
                remediation=(
                    "Validate the Origin header against an explicit allowlist. "
                    "Never combine `Access-Control-Allow-Credentials: true` with a dynamically reflected origin."
                ),
                cwe="CWE-942",
                cvss=7.5,
                owasp_category="A05:2021 Security Misconfiguration",
                standards=["ISO27001-8.23", "GDPR-Art32"],
                confidence=1.0,
            ))
            break

        if acao == origin and acac != "true":
            findings.append(Finding(
                title="CORS Misconfiguration — Arbitrary Origin Reflected (No Credentials)",
                severity=Severity.MEDIUM,
                url=page.url,
                parameter=None,
                payload=f"Origin: {origin}",
                evidence=f"Access-Control-Allow-Origin: {acao} (reflected {label})",
                description=(
                    "The server reflects arbitrary origins without credentials. "
                    "Unauthenticated API responses can be read by any third-party page."
                ),
                remediation="Restrict CORS to an explicit allowlist of trusted origins.",
                cwe="CWE-942",
                cvss=4.3,
                owasp_category="A05:2021 Security Misconfiguration",
                standards=["ISO27001-8.23"],
                confidence=0.9,
            ))
            break

    return findings
