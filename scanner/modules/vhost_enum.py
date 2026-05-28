"""
Virtual Host / Subdomain Brute Force — Gap 12

Two detection strategies:

1. DNS-based subdomain enumeration:
   Resolve common subdomain prefixes for the target domain. Any that resolve
   to a live IP are flagged.

2. Virtual host probing via Host header:
   Send requests to the target IP with forged Host headers for each subdomain.
   If the server returns different content (not the default vhost response),
   a hidden virtual host was found.

Only runs once per target domain (not per-page).
"""
import os
import yaml
import socket
import httpx
from typing import List, Optional
from urllib.parse import urlparse
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

_BUILTIN_SUBS = os.path.join(os.path.dirname(__file__), "..", "payloads", "subdomains.yaml")
_probed_domains: set = set()
_MAX_SUBDOMAINS = 100


def reset() -> None:
    _probed_domains.clear()


def test(page: CrawlResult, client: httpx.Client, config=None) -> List[Finding]:
    parsed = urlparse(page.url)
    domain = parsed.hostname or ""
    if not domain or domain in _probed_domains:
        return []
    _probed_domains.add(domain)

    # Only run against actual domain names (not IPs)
    if _is_ip(domain):
        return []

    subdomains = _load_subdomains(config)[:_MAX_SUBDOMAINS]
    if not subdomains:
        return []

    findings: List[Finding] = []
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    _dns_enum(domain, subdomains, parsed.scheme, findings)
    _vhost_enum(base_url, domain, subdomains, client, findings)
    return findings


def _load_subdomains(config) -> List[str]:
    custom = getattr(config, "subdomain_wordlist", None)
    path = custom if (custom and os.path.isfile(custom)) else _BUILTIN_SUBS
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict) and "subdomains" in data:
            return [str(s) for s in data["subdomains"] if s]
        if isinstance(data, list):
            return [str(s) for s in data if s]
    except Exception:
        pass
    return []


def _dns_enum(domain: str, subdomains: List[str], scheme: str, findings: List[Finding]):
    """Resolve each subdomain via DNS."""
    parts = domain.split(".")
    # Use the root domain (last two parts for most TLDs)
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    for sub in subdomains:
        fqdn = f"{sub}.{root}"
        try:
            ip = socket.gethostbyname(fqdn)
        except socket.gaierror:
            continue

        findings.append(Finding(
            title=f"Subdomain Discovered — {fqdn}",
            severity=Severity.INFO,
            url=f"{scheme}://{fqdn}",
            parameter=None,
            payload=fqdn,
            evidence=f"DNS resolution: {fqdn} → {ip}",
            description=(
                f"The subdomain '{fqdn}' resolves to {ip}. "
                "Subdomains with weaker security posture can be an entry point into the "
                "main application's environment (e.g., staging/dev with debug mode enabled, "
                "admin panels, internal APIs)."
            ),
            remediation=(
                "Audit all subdomains for security configuration. "
                "Restrict access to internal/development subdomains by IP allowlist. "
                "Implement consistent security headers and TLS across all subdomains. "
                "Monitor for subdomain takeover (dangling CNAME records)."
            ),
            cwe="CWE-200",
            cvss=3.7,
            owasp_category="A05:2021 Security Misconfiguration",
            confidence=1.0,
        ))


def _vhost_enum(base_url: str, domain: str, subdomains: List[str], client: httpx.Client, findings: List[Finding]):
    """Probe for virtual hosts by varying the Host header."""
    # Get default response fingerprint
    try:
        default_resp = client.get(base_url, timeout=8)
        default_len = len(default_resp.text)
        default_status = default_resp.status_code
    except Exception:
        return

    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain

    for sub in subdomains:
        vhost = f"{sub}.{root}"
        try:
            resp = client.get(base_url, headers={"Host": vhost}, timeout=8)
        except Exception:
            continue

        # Different status or significantly different body = different vhost
        status_diff = resp.status_code != default_status
        len_diff = abs(len(resp.text) - default_len)

        if (status_diff or len_diff > 500) and resp.status_code not in (400, 444, 421):
            findings.append(Finding(
                title=f"Virtual Host Discovered — {vhost}",
                severity=Severity.MEDIUM,
                url=base_url,
                parameter="Host",
                payload=f"Host: {vhost}",
                evidence=(
                    f"Host: {vhost} returned HTTP {resp.status_code} with {len(resp.text)}B "
                    f"(default: {default_status}/{default_len}B, diff: {len_diff}B)"
                ),
                description=(
                    f"A virtual host '{vhost}' was discovered on the same IP. "
                    "Virtual hosts that are not publicly documented may have weaker "
                    "security configurations, older software versions, or exposed admin interfaces."
                ),
                remediation=(
                    "Inventory all virtual hosts and ensure consistent security policies. "
                    "Restrict internal/development vhosts by IP allowlist or separate network. "
                    "Remove unused virtual host configurations."
                ),
                cwe="CWE-200",
                cvss=5.3,
                owasp_category="A05:2021 Security Misconfiguration",
                confidence=0.70,
            ))


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False
