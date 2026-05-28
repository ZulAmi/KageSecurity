import uuid
import httpx
from urllib.parse import urlparse
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

# Unkeyed headers that CDNs/reverse proxies typically strip from cache keys
UNKEYED_HEADERS = [
    ("X-Forwarded-Host", "evil.kagesec.invalid"),
    ("X-Host", "evil.kagesec.invalid"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Forwarded-Proto", "http"),
    ("X-Original-URL", "/poisoned"),
    ("X-Rewrite-URL", "/poisoned"),
    ("X-Forwarded-Port", "443"),
]

_probed_hosts: set = set()


def reset() -> None:
    _probed_hosts.clear()


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []

    # Only test HTTP/HTTPS pages (not synthetic API pages)
    if not page.url.startswith(("http://", "https://")):
        return findings

    parsed = urlparse(page.url)
    host_key = f"{parsed.scheme}://{parsed.netloc}"
    if host_key in _probed_hosts:
        return findings
    _probed_hosts.add(host_key)

    # Use a cache buster to avoid poisoning the actual cache during testing
    cb = uuid.uuid4().hex[:8]
    cache_buster_url = _add_cache_buster(page.url, cb)

    for header_name, header_value in UNKEYED_HEADERS:
        _test_header(cache_buster_url, header_name, header_value, page.url, client, findings)
        if findings:
            break  # One confirmed finding per page is enough

    return findings


def _test_header(test_url: str, header: str, value: str, original_url: str,
                 client: httpx.Client, findings: List[Finding]):
    try:
        resp = client.get(test_url, headers={header: value}, timeout=8)
    except Exception:
        return

    body = resp.text
    location = resp.headers.get("location", "")

    # Check if the injected value is reflected in the poisoned response
    reflected_in_body = value in body and value not in ("http", "/poisoned")
    reflected_in_redirect = value in location and value not in ("http",)
    host_reflected = header in ("X-Forwarded-Host", "X-Host") and "evil.kagesec.invalid" in body

    if not (reflected_in_body or reflected_in_redirect or host_reflected):
        return

    # Confirm the reflection is served from cache (not just a direct echo) by
    # making a second request WITHOUT the injected header to the same cache-busted URL.
    # If the poisoned value still appears, the CDN/proxy has cached it.
    try:
        verify_resp = client.get(test_url, timeout=8)
        verify_body = verify_resp.text
        verify_loc = verify_resp.headers.get("location", "")
        cached = (
            (reflected_in_body and value in verify_body)
            or (reflected_in_redirect and value in verify_loc)
        )
    except Exception:
        cached = False

    # Downgrade confidence: reflection without cache confirmation is Medium (not High)
    if cached:
        severity = Severity.HIGH
        confidence = 0.9
        cache_note = "Poisoned value confirmed in cache: second request without header still returned injected value."
    else:
        severity = Severity.MEDIUM
        confidence = 0.55
        cache_note = "Value reflected in direct response but NOT confirmed in cache (may be direct echo, not poisoning)."

    findings.append(Finding(
            title=f"Web Cache Poisoning via Unkeyed Header: {header}",
            severity=severity,
            url=original_url,
            parameter=header,
            payload=f"{header}: {value}",
            evidence=(
                f"Header value '{value}' reflected in "
                + ("response body" if reflected_in_body or host_reflected else "Location redirect")
                + f" when {header} was injected. {cache_note}"
            ),
            description=(
                "Web cache poisoning via unkeyed headers allows attackers to inject malicious "
                "content into the cache served to all users. The injected header is not used as "
                "part of the cache key, so the poisoned response is served to all subsequent visitors."
            ),
            remediation=(
                "Configure your CDN/reverse proxy to include all headers that affect the response "
                "as cache key components. "
                "Strip or validate X-Forwarded-Host, X-Host, and similar headers at the edge. "
                "Use a Vary header appropriately."
            ),
            cwe="CWE-444",
            cvss=8.1 if cached else 5.3,
            owasp_category="A05:2021 Security Misconfiguration",
            standards=["ISO27001-8.23", "GDPR-Art32"],
            confidence=confidence,
        ))


def _add_cache_buster(url: str, value: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}cb={value}"
