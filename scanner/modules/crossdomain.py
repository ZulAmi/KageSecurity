"""
Cross-domain policy file checks.

Checks for overly permissive crossdomain.xml (Flash) and
clientaccesspolicy.xml (Silverlight) files. Although Flash and Silverlight
are EOL, these files are still present on many legacy apps and CDNs, and
some modern tools (PDF readers, legacy browser plugins) still honour them.

An allow-access-from domain="*" policy lets any site read authenticated
responses on behalf of a visitor — equivalent to a CORS wildcard but affecting
a broader range of client software.
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity
from scanner.utils.http import fetch

_POLICY_PATHS = [
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/crossdomain/crossdomain.xml",
    "/flash/crossdomain.xml",
    "/api/crossdomain.xml",
]

_WILDCARD_PATTERNS = [
    'domain="*"',
    "domain='*'",
    "<allow-access-from domain=\"*\"",
    "<allow-access-from domain='*'",
    "<allow-http-request-headers-from domain=\"*\"",
]

_PERMISSIVE_PATTERNS = [
    'domain="*.',     # wildcard subdomain
    'secure="false"', # allows HTTP on HTTPS site
]


def test(page: CrawlResult, client) -> List[Finding]:
    parsed = urlparse(page.url)
    if parsed.path not in ("/", "", "/index.html", "/index.php"):
        return []   # only probe from root page to avoid duplicate requests

    base = f"{parsed.scheme}://{parsed.netloc}"
    findings: List[Finding] = []

    for path in _POLICY_PATHS:
        url = base + path
        resp = fetch(client, "get", url)
        if resp is None:
            continue
        status = getattr(resp, "status_code", 0)
        if status != 200:
            continue

        body = (getattr(resp, "text", "") or "").lower()
        if "cross-domain-policy" not in body and "cross-domain-access" not in body:
            continue   # not a policy file

        is_wildcard    = any(p.lower() in body for p in _WILDCARD_PATTERNS)
        is_permissive  = any(p.lower() in body for p in _PERMISSIVE_PATTERNS)

        if is_wildcard:
            findings.append(Finding(
                title="Overly Permissive Cross-Domain Policy (Wildcard)",
                severity=Severity.HIGH,
                url=url,
                parameter=None,
                payload=None,
                evidence=f"Policy file at {url} contains a wildcard domain rule (domain=\"*\").",
                description=(
                    f"The cross-domain policy file at {url} allows any origin to make "
                    "credentialed cross-domain requests to this server. This is the equivalent "
                    "of a CORS wildcard but affects Flash, PDF readers, and legacy plugins. "
                    "An attacker can host a malicious SWF or PDF that reads authenticated "
                    "responses from this server on behalf of a victim user."
                ),
                remediation=(
                    "Replace domain=\"*\" with an explicit whitelist of trusted domains. "
                    "If cross-domain access is not required, remove the policy file entirely. "
                    "Ensure secure=\"true\" is set on all allow-access-from elements."
                ),
                cwe="CWE-942",
                cvss=7.5,
                owasp_category="A05:2021 Security Misconfiguration",
                confidence=0.95,
            ))
        elif is_permissive:
            findings.append(Finding(
                title="Permissive Cross-Domain Policy",
                severity=Severity.MEDIUM,
                url=url,
                parameter=None,
                payload=None,
                evidence=f"Policy file at {url} contains a permissive domain rule or secure=false.",
                description=(
                    f"The cross-domain policy at {url} uses a wildcard subdomain pattern or "
                    "allows access over insecure HTTP (secure=\"false\"). This is weaker than "
                    "a full wildcard but still broadens the attack surface."
                ),
                remediation=(
                    "Replace wildcard subdomain patterns with explicit domains. "
                    "Set secure=\"true\" on all allow-access-from elements."
                ),
                cwe="CWE-942",
                cvss=5.3,
                owasp_category="A05:2021 Security Misconfiguration",
                confidence=0.90,
            ))

    return findings
