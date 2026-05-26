"""
Playwright-based headless browser crawler.

Drop-in replacement for Crawler — identical interface but uses Chromium to execute
JavaScript, capture network requests, handle SPA navigation, and support multi-step
login flows including TOTP 2FA.
"""
from __future__ import annotations

import re
from typing import List, Optional, Set, TYPE_CHECKING
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode

from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext, Request

from scanner.core.crawler import CrawlResult

if TYPE_CHECKING:
    from scanner.core.config import ScanConfig, LoginFlow


def _normalise_for_dedup(url: str) -> str:
    parsed = urlparse(url)
    params = sorted(parse_qs(parsed.query).items())
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True), fragment=""))


def _same_origin(url: str, base: str) -> bool:
    return urlparse(url).netloc == urlparse(base).netloc


def _is_navigable(url: str) -> bool:
    """Filter out non-HTTP links (mailto:, javascript:, tel:, etc.)."""
    scheme = urlparse(url).scheme
    return scheme in ("http", "https")


class BrowserCrawler:
    """
    Playwright headless Chromium crawler.

    Usage:
        crawler = BrowserCrawler("https://target.com", config=scan_config)
        pages = crawler.crawl()
        crawler.close()
    """

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        config: Optional["ScanConfig"] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.config = config
        self.visited: Set[str] = set()
        self._network_requests: List[str] = []

        self._pw = sync_playwright().start()
        self._browser: Browser = self._pw.chromium.launch(headless=True)
        self._context: BrowserContext = self._browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        )

        # Inject auth headers / cookies
        if config and config.auth:
            auth = config.auth
            if auth.get("type") == "bearer":
                self._context.set_extra_http_headers(
                    {"Authorization": f"Bearer {auth['value']}"}
                )
            elif auth.get("type") == "cookie" and auth.get("cookies"):
                cookies = [
                    {"name": k, "value": v, "url": self.base_url}
                    for k, v in auth["cookies"].items()
                ]
                self._context.add_cookies(cookies)

        if config and config.headers:
            self._context.set_extra_http_headers(config.headers)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self) -> List[CrawlResult]:
        results: List[CrawlResult] = []

        # Optionally authenticate before crawling
        if self.config and self.config.login_flow:
            self._authenticate(self.config.login_flow)

        self._crawl_page(self.base_url, depth=0, results=results)
        return results

    def close(self):
        try:
            self._context.close()
            self._browser.close()
            self._pw.stop()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _authenticate(self, flow: "LoginFlow"):
        """Execute a multi-step login flow and persist the session in the context."""
        page = self._context.new_page()
        try:
            page.goto(flow.url, wait_until="networkidle", timeout=20_000)

            page.fill(flow.username_selector, flow.username)
            page.fill(flow.password_selector, flow.password)
            page.click(flow.submit_selector)

            # Handle TOTP 2FA if a secret is provided
            if flow.totp_secret:
                import pyotp
                totp_code = pyotp.TOTP(flow.totp_secret).now()
                # Common TOTP input selectors — try a few
                for selector in [
                    'input[type="text"][name*="otp"]',
                    'input[type="text"][name*="token"]',
                    'input[type="text"][name*="code"]',
                    'input[autocomplete="one-time-code"]',
                ]:
                    try:
                        page.fill(selector, totp_code, timeout=2_000)
                        page.press(selector, "Enter")
                        break
                    except Exception:
                        continue

            # Wait for success_indicator (URL substring or CSS selector)
            try:
                page.wait_for_url(f"**{flow.success_indicator}**", timeout=10_000)
            except Exception:
                try:
                    page.wait_for_selector(flow.success_indicator, timeout=10_000)
                except Exception:
                    pass  # proceed anyway — session cookies are captured regardless

        finally:
            page.close()

    def _crawl_page(self, url: str, depth: int, results: List[CrawlResult]):
        if depth > self.max_depth or len(results) >= self.max_pages:
            return

        dedup_key = _normalise_for_dedup(url)
        if dedup_key in self.visited:
            return
        self.visited.add(dedup_key)

        page = self._context.new_page()
        network_reqs: List[str] = []
        ws_connections: List[dict] = []

        def _on_request(req: Request):
            # Capture XHR / fetch API calls
            if req.resource_type in ("xhr", "fetch") and _same_origin(req.url, self.base_url):
                network_reqs.append(req.url)

        def _on_websocket(ws):
            ws_info: dict = {"url": ws.url, "messages_sent": [], "messages_received": []}
            ws.on("framesent", lambda data: ws_info["messages_sent"].append(data.body if hasattr(data, "body") else str(data)))
            ws.on("framereceived", lambda data: ws_info["messages_received"].append(data.body if hasattr(data, "body") else str(data)))
            ws_connections.append(ws_info)

        page.on("request", _on_request)
        page.on("websocket", _on_websocket)

        try:
            timeout_ms = (self.config.timeout if self.config else 10) * 1_000
            resp = page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            if resp is None:
                return

            status = resp.status
            headers = dict(resp.headers)
            content_type = headers.get("content-type", "")

            if "html" not in content_type and "json" not in content_type:
                return

            body = page.content()
            screenshot = page.screenshot(type="png")

            forms = self._extract_forms(page, url)
            links = self._extract_links(page, url)

            result = CrawlResult(
                url=url,
                status_code=status,
                headers=headers,
                body=body,
                forms=forms,
                links=links,
                screenshot=screenshot,
                network_requests=list(network_reqs),
                websocket_connections=list(ws_connections),
            )
            results.append(result)

            # Recurse into discovered links
            for link in links:
                self._crawl_page(link, depth + 1, results)

            # Also crawl intercepted API endpoints (not already visited)
            for api_url in network_reqs:
                norm = _normalise_for_dedup(api_url)
                if norm not in self.visited and len(results) < self.max_pages:
                    self._crawl_page(api_url, depth + 1, results)

        except Exception:
            pass
        finally:
            page.close()

    def _extract_links(self, page: Page, base: str) -> List[str]:
        links = []
        try:
            hrefs = page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )
            for href in hrefs:
                try:
                    resolved = urljoin(base, href).split("#")[0]
                    if (
                        _is_navigable(resolved)
                        and _same_origin(resolved, self.base_url)
                        and _normalise_for_dedup(resolved) not in self.visited
                    ):
                        links.append(resolved)
                except Exception:
                    continue
        except Exception:
            pass
        return links

    def _extract_forms(self, page: Page, base: str) -> List[dict]:
        forms = []
        try:
            raw_forms = page.evaluate("""
                () => Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action || '',
                    method: f.method || 'get',
                    inputs: Array.from(f.elements).map(el => ({
                        name: el.name || '',
                        type: el.type || 'text',
                        value: el.value || ''
                    })).filter(i => i.name)
                }))
            """)
            for form in raw_forms:
                action = urljoin(base, form["action"]) if form["action"] else base
                forms.append({
                    "action": action,
                    "method": form["method"].lower(),
                    "inputs": form["inputs"],
                })
        except Exception:
            pass
        return forms
