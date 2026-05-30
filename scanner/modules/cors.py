import threading
import uuid
import httpx
from typing import List
from urllib.parse import urlparse
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

NULL_ORIGIN = "null"

_seen: set = set()
_seen_lock = threading.Lock()


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    host = urlparse(page.url).netloc
    with _seen_lock:
        if host in _seen:
            return []
        _seen.add(host)
    findings = []

    # Use a randomised subdomain so no production allowlist could legitimately contain it.
    # If the server reflects this back, the CORS policy is doing dynamic origin reflection,
    # not a static allowlist match.
    probe_id = uuid.uuid4().hex[:8]
    evil_origin = f"https://kagesec-probe-{probe_id}.evil.invalid"

    for origin, label in [(evil_origin, "arbitrary origin"), (NULL_ORIGIN, "null origin")]:
        try:
            resp = client.get(page.url, headers={"Origin": origin})
        except Exception:
            continue

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()

        if acao == "*":
            # Wildcard + credentials is a real misconfiguration; wildcard alone is advisory
            findings.append(Finding(
                title="CORS Wildcard — Access-Control-Allow-Origin: *",
                severity=Severity.MEDIUM,
                url=page.url,
                parameter=None,
                payload=f"Origin: {origin}",
                evidence="Access-Control-Allow-Origin: * (wildcard CORS policy active)",
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

        # Confirmed reflection: server echoed back the randomised origin we invented —
        # no legitimate allowlist would contain this value.
        if acao == origin and acac == "true":
            findings.append(Finding(
                title="CORS Misconfiguration — Origin Reflection with Credentials",
                severity=Severity.HIGH,
                url=page.url,
                parameter=None,
                payload=f"Origin: {origin}",
                evidence=(
                    f"Access-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Credentials: true\n"
                    f"Server dynamically reflected {label} '{origin}' with credentials allowed"
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
                evidence=f"Access-Control-Allow-Origin: {acao} (dynamically reflected {label})",
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
