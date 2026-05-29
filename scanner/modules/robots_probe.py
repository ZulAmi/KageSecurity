"""
Robots.txt Disallowed Path Probing — Gap 14

Fetches robots.txt, extracts all Disallow directives, then actively probes
each disallowed path. These paths are often the most sensitive areas of the
application (admin panels, internal APIs, staging endpoints).

Findings:
  - Accessible disallowed path (HTTP 200) — HIGH
  - Authenticated path (HTTP 401) — MEDIUM
  - Forbidden path (HTTP 403) — LOW (exists but blocked)
"""
import httpx
from typing import List
from urllib.parse import urlparse
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

_probed_hosts: set = set()


def reset() -> None:
    _probed_hosts.clear()


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    parsed = urlparse(page.url)
    host_key = f"{parsed.scheme}://{parsed.netloc}"

    if host_key in _probed_hosts:
        return []
    _probed_hosts.add(host_key)

    findings: List[Finding] = []
    disallowed = _fetch_disallowed(host_key, client)
    if not disallowed:
        return findings

    _probe_disallowed(host_key, disallowed, client, findings)
    return findings


def _fetch_disallowed(base_url: str, client: httpx.Client) -> List[str]:
    paths = []
    try:
        resp = client.get(f"{base_url}/robots.txt", timeout=8)
        if resp.status_code != 200 or "text/plain" not in resp.headers.get("content-type", "text/plain"):
            return paths
        for line in resp.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line[len("disallow:"):].strip()
                if path and path != "/":
                    paths.append(path)
    except Exception:
        pass
    return paths[:100]


def _probe_disallowed(base_url: str, paths: List[str], client: httpx.Client, findings: List[Finding]):
    for path in paths:
        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        try:
            resp = client.get(url, follow_redirects=False, timeout=8)
        except Exception:
            continue

        code = resp.status_code

        if code == 200:
            body_preview = resp.text[:200].strip()
            findings.append(Finding(
                title=f"Robots.txt Disallowed Path Accessible — {path}",
                severity=Severity.HIGH,
                url=url,
                parameter=None,
                payload=path,
                evidence=f"GET {url} returned HTTP 200 ({len(resp.text)} bytes). Preview: {body_preview[:100]}",
                description=(
                    f"The path '{path}' is listed as Disallow in robots.txt, suggesting it was "
                    "intended to remain hidden from crawlers. It is publicly accessible without "
                    "authentication. Disallowed paths often contain admin panels, internal APIs, "
                    "or sensitive data."
                ),
                remediation=(
                    "Apply authentication and authorisation to sensitive paths. "
                    "robots.txt is a hint to crawlers, not a security control — do not rely on "
                    "it to protect sensitive paths. "
                    "Move sensitive admin interfaces behind VPN or IP allowlist."
                ),
                cwe="CWE-548",
                cvss=7.5,
                owasp_category="A05:2021 Security Misconfiguration",
                confidence=1.0,
            ))
        elif code == 401:
            findings.append(Finding(
                title=f"Robots.txt Disallowed Path Requires Authentication — {path}",
                severity=Severity.MEDIUM,
                url=url,
                parameter=None,
                payload=path,
                evidence=f"GET {url} returned HTTP 401 — path exists but requires authentication",
                description=(
                    f"The path '{path}' is listed in robots.txt Disallow and returns HTTP 401. "
                    "The endpoint exists and may be vulnerable to authentication bypass, "
                    "credential stuffing, or weak credential attacks."
                ),
                remediation=(
                    "Verify that authentication on this endpoint is properly enforced. "
                    "Use strong authentication (MFA, API keys with rate limiting). "
                    "Consider restricting access by IP allowlist for admin paths."
                ),
                cwe="CWE-306",
                cvss=5.3,
                owasp_category="A07:2021 Identification and Authentication Failures",
                confidence=0.90,
            ))
        elif code == 403:
            findings.append(Finding(
                title=f"Robots.txt Disallowed Path Forbidden — {path}",
                severity=Severity.LOW,
                url=url,
                parameter=None,
                payload=path,
                evidence=f"GET {url} returned HTTP 403 — path exists but access is forbidden",
                description=(
                    f"The path '{path}' from robots.txt Disallow returns HTTP 403 (Forbidden). "
                    "The endpoint exists and may be accessible via authentication bypass techniques "
                    "or path traversal variants."
                ),
                remediation=(
                    "Ensure the 403 response is enforced server-side and not just by a frontend check. "
                    "Test with common authorization bypass techniques."
                ),
                cwe="CWE-284",
                cvss=3.7,
                owasp_category="A01:2021 Broken Access Control",
                confidence=0.75,
            ))
