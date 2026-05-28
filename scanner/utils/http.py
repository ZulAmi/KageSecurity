import re
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Markers that indicate a React/Vue/Next.js/Angular SPA is serving its index.html
# as a catch-all for routes that don't exist, producing 200 false positives.
_SPA_MARKERS = [
    '<div id="root">',
    "<div id='root'>",
    '<div id="app">',
    "<div id='app'>",
    "__NEXT_DATA__",
    "__nuxt__",
    "ng-version=",
    '<noscript>You need to enable JavaScript',
    "window.__INITIAL_STATE__",
    "window.__PRELOADED_STATE__",
]
_SPA_CT_RE = re.compile(r"\btext/html\b", re.IGNORECASE)


def inject_url_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def get_url_params(url: str) -> dict:
    return parse_qs(urlparse(url).query, keep_blank_values=True)


def is_spa_catchall(resp: httpx.Response) -> bool:
    """Return True when a 200 response is a SPA index.html catch-all, not the real resource.

    SPAs (React, Next.js, Vue, Angular) serve index.html for every unknown route,
    returning HTTP 200 even when the requested file does not exist. Detection modules
    must call this before reporting a finding on a 200 response for a probed path.
    """
    if resp.status_code != 200:
        return False
    ct = resp.headers.get("content-type", "")
    if not _SPA_CT_RE.search(ct):
        return False
    body = resp.text[:2048]
    return any(marker in body for marker in _SPA_MARKERS)


def fetch(client: httpx.Client, method: str, url: str, params: dict | None = None) -> httpx.Response | None:
    try:
        if method == "post":
            return client.post(url, data=params or {})
        return client.get(url, params=params)
    except Exception:
        return None
