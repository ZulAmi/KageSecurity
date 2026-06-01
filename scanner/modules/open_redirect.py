import re
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

REDIRECT_PARAMS = [
    "redirect", "next", "url", "return", "returnTo", "redir", "goto",
    "target", "dest", "continue", "forward", "location", "to", "out",
]
CANARY_HOST = "evil.com"
PAYLOADS = [
    f"https://{CANARY_HOST}",
    f"//{CANARY_HOST}",
    f"https://{CANARY_HOST}@trusted.com",  # credential-prefix bypass
    f"\\\\{CANARY_HOST}",                   # backslash bypass
    f"https://{CANARY_HOST}%2F",           # URL-encoded slash
]

# Patterns for JS/meta redirects in response body — HTTP 200 responses that
# perform client-side redirects, invisible to Location-header-only detection.
_JS_REDIRECT_RE = re.compile(
    r'(?:window\.location|location\.href|location\.replace|document\.location)'
    r'\s*(?:=|\()\s*["\']([^"\']{4,300})["\']',
    re.IGNORECASE,
)
_META_REDIRECT_RE = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\'][^>]+url=([^\s"\'>;]{4,300})',
    re.IGNORECASE,
)


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    parsed = urlparse(page.url)
    params = parse_qs(parsed.query)

    # Test known redirect parameter names
    for param_name in list(params.keys()):
        if param_name.lower() not in REDIRECT_PARAMS:
            continue
        _probe_param(page.url, parsed, params, param_name, client, findings)

    # Also test any param whose current value already looks like an external URL —
    # the app is clearly passing it through somewhere
    for param_name, values in params.items():
        if param_name.lower() in REDIRECT_PARAMS:
            continue
        val = values[0] if values else ""
        if val.startswith(("http://", "https://", "//")):
            _probe_param(page.url, parsed, params, param_name, client, findings)

    return findings


def _probe_param(page_url, parsed, params, param_name, client, findings):
    for payload in PAYLOADS:
        new_params = dict(params)
        new_params[param_name] = [payload]
        test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))

        try:
            resp = client.get(test_url, follow_redirects=False)
        except Exception:
            continue

        # Check 1: HTTP Location header (standard server-side redirect)
        location = resp.headers.get("location", "")
        if CANARY_HOST in location:
            findings.append(_finding(
                page_url, param_name, payload,
                evidence=f"HTTP redirect to canary via Location header: {location}",
                title="Open Redirect",
            ))
            return

        # Check 2: JavaScript / meta redirect in response body (HTTP 200 responses).
        # Apps that redirect via window.location or <meta refresh> are missed by
        # Location-header-only detection — common in SPAs and form-POST flows.
        for pattern in (_JS_REDIRECT_RE, _META_REDIRECT_RE):
            m = pattern.search(resp.text)
            if m and CANARY_HOST in m.group(1):
                findings.append(_finding(
                    page_url, param_name, payload,
                    evidence=f"JavaScript/meta redirect to canary: {m.group(1)[:120]}",
                    title="Open Redirect — JavaScript/Meta",
                ))
                return


def _finding(url, param, payload, evidence, title="Open Redirect"):
    return Finding(
        title=title,
        severity=Severity.MEDIUM,
        url=url,
        parameter=param,
        payload=payload,
        evidence=evidence,
        description=(
            "Open redirects allow attackers to craft links that appear legitimate "
            "but redirect users to malicious sites — commonly used in phishing attacks."
        ),
        remediation=(
            "Validate redirect destinations against a whitelist of allowed domains. "
            "Use relative paths instead of absolute URLs for internal redirects."
        ),
        cwe="CWE-601",
        cvss=4.3,
        owasp_category="A01:2021 Broken Access Control",
        confidence=0.95,
    )
