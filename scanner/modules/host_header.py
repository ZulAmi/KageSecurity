"""
Host Header Injection / Password Reset Poisoning — Gap 4

Tests whether the application reflects a forged Host or X-Forwarded-Host header
in:
  - HTTP Location / redirect responses (cache poisoning vector)
  - Response body (reset link poisoning)
  - OOB callbacks (blind host header injection)

Attack classes:
  1. Host header reflection in Location redirect
  2. Host header reflection in response body (password reset link)
  3. X-Forwarded-Host / X-Forwarded-For reflection
  4. OOB callback via blind host header injection (requires interactsh)
"""
import re
import httpx
from typing import List, Optional
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

_ATTACKER_HOST = "attacker.kagesec-test.invalid"

# Headers that can poison host resolution
_INJECTION_HEADERS = [
    "Host",
    "X-Forwarded-Host",
    "X-Forwarded-For",
    "X-Host",
    "X-Custom-IP-Authorization",
    "Forwarded",
    "X-Rewrite-URL",
    "X-Original-URL",
]

# Patterns that suggest a password reset / account link in the body
_RESET_LINK_RE = re.compile(
    r'(https?://[^\s"\'<>]+(?:reset|confirm|activate|verify|token|link)[^\s"\'<>]{0,200})',
    re.IGNORECASE,
)


def test(page: CrawlResult, client: httpx.Client, oob=None) -> List[Finding]:
    findings: List[Finding] = []
    _test_host_reflection(page, client, findings)
    _test_forwarded_host(page, client, findings)
    if oob:
        _test_oob_host(page, client, oob, findings)
    return findings


def _test_host_reflection(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Send a forged Host header and check if it reflects in Location or body."""
    try:
        resp = client.get(
            page.url,
            headers={"Host": _ATTACKER_HOST},
            follow_redirects=False,
        )
    except Exception:
        return

    # Check Location header
    location = resp.headers.get("location", "")
    if _ATTACKER_HOST in location:
        findings.append(Finding(
            title="Host Header Injection — Redirect Poisoning",
            severity=Severity.HIGH,
            url=page.url,
            parameter="Host",
            payload=f"Host: {_ATTACKER_HOST}",
            evidence=f"Forged Host reflected in Location header: {location[:200]}",
            description=(
                "The application reflects the Host header value in HTTP redirect responses. "
                "An attacker can poison password reset links or cache entries by supplying "
                "a malicious Host header, redirecting victims to an attacker-controlled domain."
            ),
            remediation=(
                "Use the configured application URL (from settings/environment variable) "
                "for redirect and link generation — never derive it from the Host header. "
                "Validate the Host header against an allowlist of known domains."
            ),
            cwe="CWE-601",
            cvss=7.4,
            owasp_category="A05:2021 Security Misconfiguration",
            confidence=0.95,
        ))

    # Check body (password reset link poisoning)
    if _ATTACKER_HOST in resp.text:
        link_match = _RESET_LINK_RE.search(resp.text)
        evidence = (
            f"Forged Host reflected in response body. Poisoned link: {link_match.group(1)[:200]}"
            if link_match else
            f"Forged Host '{_ATTACKER_HOST}' reflected in response body"
        )
        findings.append(Finding(
            title="Host Header Injection — Password Reset Link Poisoning",
            severity=Severity.CRITICAL,
            url=page.url,
            parameter="Host",
            payload=f"Host: {_ATTACKER_HOST}",
            evidence=evidence,
            description=(
                "The application uses the Host header to construct URLs in the response body "
                "(e.g., password reset links). An attacker can send a forged Host header to "
                "cause the application to generate a reset link pointing to the attacker's domain, "
                "allowing account takeover when the victim clicks the link in the email."
            ),
            remediation=(
                "Hard-code the application's base URL in configuration. "
                "Never use request.get_host() / $_SERVER['HTTP_HOST'] for link generation "
                "without validating against an allowlist of trusted domains."
            ),
            cwe="CWE-640",
            cvss=9.1,
            owasp_category="A07:2021 Identification and Authentication Failures",
            confidence=0.90,
        ))


def _test_forwarded_host(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Test X-Forwarded-Host and other proxy headers for reflection."""
    proxy_headers = {
        "X-Forwarded-Host": _ATTACKER_HOST,
        "X-Host": _ATTACKER_HOST,
        "Forwarded": f"host={_ATTACKER_HOST}",
    }
    try:
        resp = client.get(page.url, headers=proxy_headers, follow_redirects=False)
    except Exception:
        return

    for header_val in proxy_headers.values():
        host = header_val.split("=")[-1]
        if host in (resp.headers.get("location", "") + resp.text):
            findings.append(Finding(
                title="Host Header Injection — X-Forwarded-Host Reflection",
                severity=Severity.HIGH,
                url=page.url,
                parameter="X-Forwarded-Host",
                payload=f"X-Forwarded-Host: {_ATTACKER_HOST}",
                evidence=f"X-Forwarded-Host value '{host}' reflected in response",
                description=(
                    "The application trusts and reflects the X-Forwarded-Host header without "
                    "validation, enabling cache poisoning and password reset link manipulation."
                ),
                remediation=(
                    "Only trust proxy headers (X-Forwarded-Host, Forwarded) from known, "
                    "configured reverse proxies. Validate all resulting host values against "
                    "an allowlist. Configure your load balancer to strip these headers from "
                    "untrusted client requests."
                ),
                cwe="CWE-601",
                cvss=6.5,
                owasp_category="A05:2021 Security Misconfiguration",
                confidence=0.85,
            ))
            break


def _test_oob_host(page: CrawlResult, client: httpx.Client, oob, findings: List[Finding]):
    """Inject the OOB canary as the Host header for blind detection."""
    canary = oob.get_canary()
    try:
        client.get(
            page.url,
            headers={"Host": canary, "X-Forwarded-Host": canary},
            follow_redirects=False,
            timeout=10,
        )
    except Exception:
        pass
    # OOB result is polled by the engine after all modules finish
