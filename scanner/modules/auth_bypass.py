"""
Authentication bypass detection.

Re-requests pages without auth credentials and compares:
- Status code (200 without auth → bypass)
- Response size (similar body → bypass; empty/redirect → protected)
- Body content (auth-gate keywords vs actual content)

Only runs when auth is configured (bearer, cookie, or login_flow).
If no auth is set, nothing to compare against — skip.
"""
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

# Paths that are almost certainly public — skip false-positive noise
_PUBLIC_PATH_FRAGMENTS = (
    "/static/", "/assets/", "/css/", "/js/", "/fonts/", "/images/",
    "/favicon", "/robots.txt", "/sitemap", ".png", ".jpg", ".svg",
    ".woff", ".ttf", ".ico",
)

# Body patterns that indicate an auth wall (login redirect or error page)
_AUTH_WALL_PATTERNS = (
    "login", "sign in", "sign-in", "unauthorized", "401", "403",
    "access denied", "please log in", "authenticate",
)

_MIN_BODY_SIZE = 200  # ignore stub/empty pages


def test(page: CrawlResult, client) -> List[Finding]:
    # Only meaningful when scan was run with auth credentials
    has_auth = _has_auth(client)
    if not has_auth:
        return []

    url = page.url
    if any(frag in url for frag in _PUBLIC_PATH_FRAGMENTS):
        return []

    if page.status_code not in (200, 201, 202):
        return []

    if not page.body or len(page.body) < _MIN_BODY_SIZE:
        return []

    # Re-request without auth headers / cookies
    try:
        anon_resp = client.get(url, headers=_strip_auth_headers(client), cookies={})
    except Exception:
        return []

    anon_code = anon_resp.status_code
    anon_body = anon_resp.text if hasattr(anon_resp, "text") else ""

    # If anonymous gets a redirect to login or a 401/403 → page is properly protected
    if anon_code in (401, 403):
        return []
    if anon_code in (301, 302, 303, 307, 308):
        location = anon_resp.headers.get("location", "").lower()
        if any(kw in location for kw in ("login", "signin", "auth", "sso")):
            return []

    # If anon body contains auth-wall language → protected
    anon_lower = anon_body.lower()
    if any(kw in anon_lower for kw in _AUTH_WALL_PATTERNS):
        return []

    if anon_code != 200 or len(anon_body) < _MIN_BODY_SIZE:
        return []

    # Compare body sizes — if anon response is substantially similar → bypass
    auth_len = len(page.body)
    anon_len = len(anon_body)
    similarity = min(auth_len, anon_len) / max(auth_len, anon_len) if max(auth_len, anon_len) > 0 else 0

    if similarity < 0.70:
        return []  # Bodies are very different — likely different content, not bypass

    return [Finding(
        title="Potential Authentication Bypass — Authenticated Resource Accessible Without Auth",
        severity=Severity.HIGH,
        url=url,
        parameter=None,
        payload=None,
        evidence=(
            f"Authenticated response: HTTP {page.status_code} ({auth_len} bytes). "
            f"Unauthenticated response: HTTP {anon_code} ({anon_len} bytes). "
            f"Body similarity: {similarity:.0%}."
        ),
        description=(
            f"The resource at {url} returned a substantively similar response "
            "when accessed without authentication credentials. This indicates the endpoint "
            "may lack server-side authorisation enforcement, allowing unauthenticated users "
            "to access privileged data or functionality."
        ),
        remediation=(
            "Ensure all protected endpoints enforce authorisation server-side on every request. "
            "Do not rely solely on client-side routing or session cookies without server validation. "
            "Apply middleware-level auth guards consistently across all API routes and page endpoints."
        ),
        owasp_category="A01:2021 Broken Access Control",
        cwe="CWE-306",
        cvss=8.1,
        confidence=0.70,
        standards={"OWASP": "A01:2021", "CWE": "CWE-306"},
    )]


def _has_auth(client) -> bool:
    """Check if the client has auth headers or cookies configured."""
    # RateLimitedClient wraps httpx.Client
    inner = getattr(client, "_client", client)
    headers = dict(getattr(inner, "headers", {}))
    cookies = dict(getattr(inner, "cookies", {}))
    return bool(
        headers.get("authorization") or headers.get("Authorization") or cookies
    )


def _strip_auth_headers(client) -> dict:
    """Return headers dict with auth stripped for anonymous request."""
    inner = getattr(client, "_client", client)
    headers = {k: v for k, v in dict(getattr(inner, "headers", {})).items()
               if k.lower() not in ("authorization", "cookie")}
    return headers
