import ssl
import socket
import httpx
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    parsed = urlparse(page.url)

    # Only run TLS checks once (from root) and only for HTTPS targets
    if parsed.path not in ("", "/"):
        return []

    if parsed.scheme == "http":
        findings.append(Finding(
            title="Application Accessible Over Unencrypted HTTP",
            severity=Severity.HIGH,
            url=page.url,
            parameter=None,
            payload=None,
            evidence=f"Target is served over HTTP: {page.url}",
            description="Data transmitted over HTTP is unencrypted and can be intercepted by network attackers.",
            remediation="Redirect all HTTP traffic to HTTPS. Obtain and configure a TLS certificate.",
            cwe="CWE-319",
            cvss=7.5,
            owasp_category="A02:2021 Cryptographic Failures",
            standards=["ISO27001-8.24", "HIPAA-164.312c", "GDPR-Art32", "APPI-Art20"],
            confidence=1.0,
        ))
        return findings

    hostname = parsed.hostname
    port = parsed.port or 443

    # Check for HTTP redirect (is HTTPS enforced?)
    http_url = page.url.replace("https://", "http://", 1)
    try:
        http_resp = client.get(http_url, follow_redirects=False, timeout=5)
        location = http_resp.headers.get("location", "")
        if http_resp.status_code in (200, 206) or "https://" not in location:
            findings.append(Finding(
                title="HTTPS Not Enforced — HTTP Accessible Without Redirect",
                severity=Severity.MEDIUM,
                url=http_url,
                parameter=None,
                payload=None,
                evidence=f"HTTP returned status {http_resp.status_code} without redirecting to HTTPS",
                description="The application does not redirect HTTP requests to HTTPS, leaving users vulnerable to interception.",
                remediation="Configure a 301 redirect from HTTP to HTTPS for all requests.",
                cwe="CWE-319",
                cvss=5.9,
                owasp_category="A02:2021 Cryptographic Failures",
                standards=["ISO27001-8.24", "HIPAA-164.312c", "GDPR-Art32"],
                confidence=0.9,
            ))
    except Exception:
        pass

    # Inspect TLS certificate
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

        # Certificate expiry check
        not_after = cert.get("notAfter", "")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(Finding(
                    title="TLS Certificate Expired",
                    severity=Severity.CRITICAL,
                    url=page.url,
                    parameter=None,
                    payload=None,
                    evidence=f"Certificate expired on {not_after}",
                    description="An expired TLS certificate causes browser warnings and may be rejected by clients.",
                    remediation="Renew the TLS certificate immediately. Consider automated renewal via Let's Encrypt.",
                    cwe="CWE-298",
                    cvss=7.5,
                    owasp_category="A02:2021 Cryptographic Failures",
                    standards=["ISO27001-8.24", "HIPAA-164.312c"],
                    confidence=1.0,
                ))
            elif days_left < 30:
                findings.append(Finding(
                    title=f"TLS Certificate Expiring Soon ({days_left} days)",
                    severity=Severity.MEDIUM,
                    url=page.url,
                    parameter=None,
                    payload=None,
                    evidence=f"Certificate expires on {not_after} ({days_left} days remaining)",
                    description="A nearly-expired certificate risks service disruption when it expires.",
                    remediation="Renew the TLS certificate before it expires.",
                    cwe="CWE-298",
                    cvss=4.3,
                    owasp_category="A02:2021 Cryptographic Failures",
                    standards=["ISO27001-8.24"],
                    confidence=1.0,
                ))

        # Weak cipher or TLS version
        if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            findings.append(Finding(
                title=f"Weak TLS Version Supported: {tls_version}",
                severity=Severity.HIGH,
                url=page.url,
                parameter=None,
                payload=None,
                evidence=f"Server negotiated {tls_version} with cipher {cipher[0] if cipher else 'unknown'}",
                description=f"{tls_version} is deprecated and has known cryptographic weaknesses (POODLE, BEAST, etc.).",
                remediation="Disable TLS 1.0 and 1.1. Require TLS 1.2 minimum, TLS 1.3 preferred.",
                cwe="CWE-326",
                cvss=7.4,
                owasp_category="A02:2021 Cryptographic Failures",
                standards=["ISO27001-8.24", "HIPAA-164.312c", "GDPR-Art32"],
                confidence=1.0,
            ))

    except ssl.SSLCertVerificationError as e:
        findings.append(Finding(
            title="TLS Certificate Validation Failed",
            severity=Severity.HIGH,
            url=page.url,
            parameter=None,
            payload=None,
            evidence=str(e),
            description="The TLS certificate failed validation (self-signed, wrong hostname, or untrusted CA).",
            remediation="Use a certificate from a trusted CA. Ensure the CN/SAN matches the hostname.",
            cwe="CWE-295",
            cvss=7.4,
            owasp_category="A02:2021 Cryptographic Failures",
            standards=["ISO27001-8.24", "HIPAA-164.312c"],
            confidence=1.0,
        ))
    except Exception:
        pass

    return findings
