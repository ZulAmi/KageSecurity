"""
JavaScript Endpoint Extractor — Gap 13

Parses JavaScript files (inline and external) to extract:
  - fetch() / axios.get/post() / $.ajax() / XMLHttpRequest URLs
  - Hard-coded API paths (/api/v1/..., /v2/...)
  - Router definitions (Express, Vue Router, React Router)
  - Commented-out or string-literal API paths

Extracted endpoints are returned as CrawlResult objects so they are fed
back into the scan engine's page queue and tested by all modules.
"""
import re
import httpx
from typing import List, Optional
from urllib.parse import urlparse, urljoin

# Pattern: fetch('...'), fetch("...")
_FETCH_RE = re.compile(
    r'''(?:fetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*["'`]([^"'`\s]{2,300})["'`]''',
    re.IGNORECASE,
)

# jQuery $.ajax / $.get / $.post
_JQUERY_RE = re.compile(
    r'''\$\.(?:ajax|get|post|getJSON)\s*\(\s*(?:\{[^}]*url\s*:\s*)?["'`]([^"'`\s]{2,300})["'`]''',
    re.IGNORECASE,
)

# XMLHttpRequest .open("METHOD", "URL")
_XHR_RE = re.compile(
    r'''\.open\s*\(\s*["'`][A-Z]+["'`]\s*,\s*["'`]([^"'`\s]{2,300})["'`]''',
    re.IGNORECASE,
)

# String literals that look like API paths
_API_PATH_RE = re.compile(
    r'''["'`](/(?:api|v\d+|rest|graphql|services?|endpoints?)/[^"'`\s<>]{2,200})["'`]''',
    re.IGNORECASE,
)

# Express/Hapi route definitions: app.get('/path', ...), router.post('/path', ...)
_ROUTE_RE = re.compile(
    r'''(?:app|router|server|route)\s*\.\s*(?:get|post|put|patch|delete|all|use)\s*\(\s*["'`]([^"'`]{2,200})["'`]''',
    re.IGNORECASE,
)

# Vue Router / React Router path definitions
_ROUTER_PATH_RE = re.compile(
    r'''path\s*:\s*["'`]([^"'`\s]{2,200})["'`]''',
    re.IGNORECASE,
)

# <script src="...">
_SCRIPT_SRC_RE = re.compile(r'''<script[^>]+src=["']([^"']+\.js[^"']*)["']''', re.IGNORECASE)


def extract_endpoints(js_source: str, base_url: str) -> List[str]:
    """
    Extract URL endpoints from a JavaScript source string.
    Returns a deduplicated list of absolute URLs.
    """
    raw: set = set()
    for pattern in (_FETCH_RE, _JQUERY_RE, _XHR_RE, _API_PATH_RE, _ROUTE_RE, _ROUTER_PATH_RE):
        for m in pattern.finditer(js_source):
            raw.add(m.group(1))

    results: List[str] = []
    for raw_url in raw:
        normalized = _normalize(raw_url, base_url)
        if normalized:
            results.append(normalized)

    return list(dict.fromkeys(results))  # deduplicate, preserve order


def extract_js_files(html: str, base_url: str) -> List[str]:
    """Return absolute URLs of all <script src="..."> JS files in an HTML page."""
    urls = []
    for m in _SCRIPT_SRC_RE.finditer(html):
        src = m.group(1).strip()
        abs_url = _normalize(src, base_url)
        if abs_url:
            urls.append(abs_url)
    return urls


def crawl_js_endpoints(
    html: str,
    base_url: str,
    client: httpx.Client,
    max_files: int = 20,
) -> List[str]:
    """
    Fetch all external JS files linked from the page, then extract endpoint URLs.
    Returns a list of unique endpoint URLs found.
    """
    js_files = extract_js_files(html, base_url)[:max_files]
    all_endpoints: set = set()

    # Also extract from inline scripts in the HTML itself
    inline_js = _extract_inline_scripts(html)
    for js in inline_js:
        for ep in extract_endpoints(js, base_url):
            all_endpoints.add(ep)

    for js_url in js_files:
        try:
            resp = client.get(js_url, timeout=10)
            if resp.status_code == 200 and "javascript" in resp.headers.get("content-type", "text/javascript"):
                for ep in extract_endpoints(resp.text, base_url):
                    all_endpoints.add(ep)
        except Exception:
            continue

    return list(all_endpoints)


def _extract_inline_scripts(html: str) -> List[str]:
    scripts = []
    for m in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE):
        content = m.group(1).strip()
        if content:
            scripts.append(content)
    return scripts


def _normalize(url: str, base_url: str) -> Optional[str]:
    """Convert relative or absolute URL to a fully-qualified URL on the same origin."""
    url = url.strip()
    if not url or url.startswith(("data:", "javascript:", "#", "mailto:", "{", "$")):
        return None
    if url.startswith("//"):
        parsed_base = urlparse(base_url)
        return f"{parsed_base.scheme}:{url}"
    if url.startswith(("http://", "https://")):
        return url
    if url.startswith("/"):
        parsed_base = urlparse(base_url)
        return f"{parsed_base.scheme}://{parsed_base.netloc}{url}"
    # Relative paths
    try:
        return urljoin(base_url, url)
    except Exception:
        return None
