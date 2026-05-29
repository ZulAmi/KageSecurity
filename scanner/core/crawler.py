import fnmatch
import httpx
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from typing import Set, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.config import ScanConfig


@dataclass
class CrawlResult:
    url: str
    status_code: int
    headers: dict
    body: str
    forms: List[dict] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    screenshot: Optional[bytes] = None          # PNG screenshot (Playwright only)
    network_requests: List[str] = field(default_factory=list)  # XHR/fetch URLs (Playwright only)
    websocket_connections: List[dict] = field(default_factory=list)  # WS connections (Playwright only)


def _normalise_for_dedup(url: str) -> str:
    parsed = urlparse(url)
    # Sort query params so ?b=1&a=2 and ?a=2&b=1 are the same page
    params = sorted(parse_qs(parsed.query).items())
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True), fragment=""))


class Crawler:
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 100, config: Optional["ScanConfig"] = None):
        self.base_url = base_url
        self.base_domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.config = config
        self.visited: Set[str] = set()
        self._include = list(config.include_patterns) if config and config.include_patterns else []
        self._exclude = list(config.exclude_patterns) if config and config.exclude_patterns else []

        _ua = (getattr(config, "user_agent", None) or "KageSec/0.1 Security Scanner") if config else "KageSec/0.1 Security Scanner"
        headers = {"User-Agent": _ua}
        cookies = {}

        if config:
            if config.headers:
                headers.update(config.headers)
            if config.auth:
                auth_type = config.auth.get("type", "")
                auth_value = config.auth.get("value", "")
                if auth_type == "bearer":
                    headers["Authorization"] = f"Bearer {auth_value}"
                elif auth_type == "basic":
                    headers["Authorization"] = f"Basic {auth_value}"
                elif auth_type == "cookie":
                    cookies = config.auth.get("cookies", {})

        _timeout = (getattr(config, "timeout", 10) or 10) if config else 10
        _retries = getattr(config, "retries", 0) if config else 0
        self.client = httpx.Client(
            follow_redirects=True,
            timeout=_timeout,
            headers=headers,
            cookies=cookies,
            transport=httpx.HTTPTransport(retries=_retries),
        )

        if config and getattr(config, "follow_robots", False):
            self._parse_robots()

    def crawl(self) -> List[CrawlResult]:
        results = []
        # Seed from sitemap if available
        sitemap_urls = self._parse_sitemap()
        for url in sitemap_urls:
            if len(self.visited) < self.max_pages:
                self._crawl_page(url, depth=1, results=results)
        # Always crawl from the base URL
        self._crawl_page(self.base_url, depth=0, results=results)
        return results

    def _crawl_page(self, url: str, depth: int, results: List[CrawlResult]):
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return

        dedup_key = _normalise_for_dedup(url)
        if dedup_key in self.visited:
            return
        self.visited.add(dedup_key)

        try:
            response = self.client.get(url)
        except Exception:
            return

        content_type = response.headers.get("content-type", "")
        body = response.text if "html" in content_type or "json" in content_type else ""

        soup = BeautifulSoup(body, "html.parser") if body else None
        forms = self._extract_forms(soup, url) if soup else []
        links = self._extract_links(soup, url) if soup else []

        # Gap 13: extract endpoints from JS files linked in HTML or from JS responses
        if "html" in content_type and body:
            js_endpoints = self._extract_js_bundle_endpoints(body, url)
            for ep in js_endpoints:
                if ep not in links:
                    links.append(ep)
        elif "javascript" in content_type and body:
            links += self._extract_api_endpoints_from_js(body, url)

        results.append(CrawlResult(
            url=url,
            status_code=response.status_code,
            headers=dict(response.headers),
            body=body,
            forms=forms,
            links=links,
        ))

        for link in links:
            self._crawl_page(link, depth + 1, results)

    def _in_scope(self, url: str) -> bool:
        if self._include and not any(fnmatch.fnmatch(url, p) for p in self._include):
            return False
        if self._exclude and any(fnmatch.fnmatch(url, p) for p in self._exclude):
            return False
        return True

    def _extract_links(self, soup: BeautifulSoup, base: str) -> List[str]:
        links = []
        for tag in soup.find_all("a", href=True):
            href = urljoin(base, tag["href"])
            parsed = urlparse(href)
            # Same domain only; strip fragments
            clean = urlunparse(parsed._replace(fragment=""))
            if (
                parsed.netloc == self.base_domain
                and _normalise_for_dedup(clean) not in self.visited
                and self._in_scope(clean)
            ):
                links.append(clean)
        return links

    def _extract_forms(self, soup: BeautifulSoup, base: str) -> List[dict]:
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(base, form.get("action", base))
            method = form.get("method", "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })
            forms.append({"action": action, "method": method, "inputs": inputs})
        return forms

    def _parse_sitemap(self) -> List[str]:
        urls = []
        for path in ("sitemap.xml", "sitemap_index.xml"):
            try:
                resp = self.client.get(urljoin(self.base_url, path), timeout=5)
                if resp.status_code == 200 and "<loc>" in resp.text:
                    soup = BeautifulSoup(resp.text, "lxml-xml")
                    for loc in soup.find_all("loc"):
                        href = loc.text.strip()
                        if urlparse(href).netloc == self.base_domain:
                            urls.append(href)
            except Exception:
                pass
        return urls[:50]  # cap sitemap seed

    def _extract_js_bundle_endpoints(self, html_body: str, base: str) -> List[str]:
        """Gap 13 — fetch linked JS bundles, extract API endpoint URLs from them."""
        try:
            from scanner.core.js_extractor import crawl_js_endpoints
            endpoints = crawl_js_endpoints(html_body, base, self.client, max_files=3)
            same_origin = []
            for ep in endpoints:
                parsed = urlparse(ep)
                if parsed.netloc == self.base_domain and _normalise_for_dedup(ep) not in self.visited:
                    same_origin.append(ep)
            return same_origin[:30]
        except Exception:
            return []

    def _extract_api_endpoints_from_js(self, js_body: str, base: str) -> List[str]:
        import re
        endpoints = []
        for match in re.finditer(r'["\'](/api/[^"\'?\s]+)', js_body):
            path = match.group(1)
            url = urljoin(base, path)
            if urlparse(url).netloc == self.base_domain:
                endpoints.append(url)
        return endpoints[:20]

    def _parse_robots(self) -> None:
        """Parse robots.txt and add Disallow paths to the exclude list."""
        try:
            resp = self.client.get(urljoin(self.base_url, "/robots.txt"), timeout=5)
            if resp.status_code != 200 or "Disallow" not in resp.text:
                return
            user_agent_section = False
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("user-agent:"):
                    ua = line.split(":", 1)[1].strip()
                    user_agent_section = ua in ("*", "KageSec")
                elif user_agent_section and line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        pattern = self.base_url.rstrip("/") + path.rstrip("/") + "*"
                        if pattern not in self._exclude:
                            self._exclude.append(pattern)
        except Exception:
            pass

    def close(self):
        self.client.close()
