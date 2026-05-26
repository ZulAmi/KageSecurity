import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


def inject_url_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def get_url_params(url: str) -> dict:
    return parse_qs(urlparse(url).query, keep_blank_values=True)


def fetch(client: httpx.Client, method: str, url: str, params: dict | None = None) -> httpx.Response | None:
    try:
        if method == "post":
            return client.post(url, data=params or {})
        return client.get(url, params=params)
    except Exception:
        return None
