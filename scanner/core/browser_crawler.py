"""
Playwright-based headless browser crawler.

Drop-in replacement for Crawler — identical interface but uses Chromium to execute
JavaScript, capture network requests, handle SPA navigation, and support multi-step
login flows including TOTP 2FA.

Parallel BFS crawl: each worker thread creates its own sync_playwright() stack
(required — Playwright's sync API ties greenlets to the creating thread). Auth cookies
are shared by exporting storage_state() from the main context after login and importing
them into each worker's context. This matches the architecture of commercial DAST tools.
"""
from __future__ import annotations

import fnmatch
import queue
import subprocess
import sys
import threading
from typing import List, Optional, Set, Tuple, TYPE_CHECKING
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode

from playwright.sync_api import sync_playwright, Page, Browser, BrowserContext, Request
from playwright._impl._errors import Error as PlaywrightError

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

    def _launch_chromium(self, pw) -> Browser:
        try:
            return pw.chromium.launch(headless=True)
        except PlaywrightError as exc:
            if "Executable doesn't exist" not in str(exc):
                raise
            print(
                "[kagesec] Playwright browser binaries not found — installing now (one-time setup)...",
                file=sys.stderr,
            )
            subprocess.run(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                check=True,
            )
            return pw.chromium.launch(headless=True)

    def _make_context(self, browser: Browser) -> BrowserContext:
        """Create one isolated BrowserContext with auth/proxy/headers applied."""
        ctx_kwargs: dict = {
            "ignore_https_errors": True,
            "user_agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        }
        config = self.config
        if config and getattr(config, "proxy", None):
            ctx_kwargs["proxy"] = {"server": config.proxy}

        ctx: BrowserContext = browser.new_context(**ctx_kwargs)

        if config and config.auth:
            auth = config.auth
            if auth.get("type") == "bearer":
                ctx.set_extra_http_headers({"Authorization": f"Bearer {auth['value']}"})
            elif auth.get("type") == "cookie" and auth.get("cookies"):
                cookies = [
                    {"name": k, "value": v, "url": self.base_url}
                    for k, v in auth["cookies"].items()
                ]
                ctx.add_cookies(cookies)

        if config and config.headers:
            ctx.set_extra_http_headers(config.headers)

        return ctx

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        config: Optional["ScanConfig"] = None,
        crawl_workers: int = 3,
    ):
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.config = config
        self.visited: Set[str] = set()
        self._visited_lock = threading.Lock()
        self._crawl_workers = max(1, crawl_workers)
        self._network_requests: List[str] = []
        self._include = list(config.include_patterns) if config and config.include_patterns else []
        self._exclude = list(config.exclude_patterns) if config and config.exclude_patterns else []

        # Main-thread Playwright stack: used for _authenticate() and the _crawl_page() shim.
        # Workers create their own stacks — Playwright's sync API ties greenlets to the
        # creating thread, so contexts cannot be shared across threads.
        self._pw = sync_playwright().start()
        self._browser: Browser = self._launch_chromium(self._pw)
        self._context: BrowserContext = self._make_context(self._browser)
        # Backward-compat alias expected by engine.py re-auth path
        self._contexts = [self._context]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def crawl(self) -> List[CrawlResult]:
        results: List[CrawlResult] = []
        results_lock = threading.Lock()
        stop_event = threading.Event()

        # Auth: run login on the main context, export cookies for worker contexts
        auth_cookies: list = []
        if self.config and self.config.login_flow:
            self._authenticate(self.config.login_flow)
            shared_state = self._context.storage_state()
            auth_cookies = shared_state.get("cookies", [])

        work_queue: queue.Queue = queue.Queue()
        work_queue.put((self.base_url, 0))

        def _worker() -> None:
            # Each worker owns its own Playwright/browser/context — required because
            # Playwright's sync API uses greenlets that cannot switch across threads.
            from playwright.sync_api import sync_playwright as _sync_pw
            pw = _sync_pw().start()
            try:
                browser = pw.chromium.launch(headless=True)
                ctx = self._make_context(browser)
                if auth_cookies:
                    ctx.add_cookies(auth_cookies)
                try:
                    while not stop_event.is_set():
                        try:
                            url, depth = work_queue.get(timeout=0.5)
                        except queue.Empty:
                            continue

                        try:
                            if depth > self.max_depth:
                                continue

                            with self._visited_lock:
                                norm = _normalise_for_dedup(url)
                                if norm in self.visited:
                                    continue
                                self.visited.add(norm)

                            with results_lock:
                                if len(results) >= self.max_pages:
                                    continue

                            result, discovered = self._fetch_page(url, depth, ctx)

                            if result is not None:
                                with results_lock:
                                    if len(results) < self.max_pages:
                                        results.append(result)

                            for child_url, child_depth in discovered:
                                with self._visited_lock:
                                    if _normalise_for_dedup(child_url) not in self.visited:
                                        work_queue.put((child_url, child_depth))

                        finally:
                            work_queue.task_done()
                finally:
                    ctx.close()
                    browser.close()
            finally:
                pw.stop()

        threads = [
            threading.Thread(target=_worker, daemon=True, name=f"crawler-{i}")
            for i in range(self._crawl_workers)
        ]
        for t in threads:
            t.start()

        work_queue.join()
        stop_event.set()

        for t in threads:
            t.join(timeout=10.0)

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

            if flow.totp_secret:
                import pyotp
                totp_code = pyotp.TOTP(flow.totp_secret).now()
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

            try:
                page.wait_for_url(f"**{flow.success_indicator}**", timeout=10_000)
            except Exception:
                try:
                    page.wait_for_selector(flow.success_indicator, timeout=10_000)
                except Exception:
                    pass

        finally:
            page.close()

    def _fetch_page(
        self,
        url: str,
        depth: int,
        ctx: BrowserContext,
    ) -> Tuple[Optional[CrawlResult], List[Tuple[str, int]]]:
        """
        Fetch a single URL within the given context.

        Creates and closes its own Page per call. Returns (CrawlResult | None,
        list of (child_url, child_depth) to enqueue). Dedup and max_pages
        enforcement is the caller's responsibility.
        """
        discovered: List[Tuple[str, int]] = []
        page = ctx.new_page()
        network_reqs: List[str] = []
        spa_routes: List[str] = []
        ws_connections: List[dict] = []

        def _on_request(req: Request):
            if req.resource_type in ("xhr", "fetch") and _same_origin(req.url, self.base_url):
                network_reqs.append(req.url)

        def _on_websocket(ws):
            ws_info: dict = {"url": ws.url, "messages_sent": [], "messages_received": []}
            ws.on("framesent", lambda data: ws_info["messages_sent"].append(
                data.body if hasattr(data, "body") else str(data)))
            ws.on("framereceived", lambda data: ws_info["messages_received"].append(
                data.body if hasattr(data, "body") else str(data)))
            ws_connections.append(ws_info)

        page.on("request", _on_request)
        page.on("websocket", _on_websocket)

        try:
            timeout_ms = (self.config.timeout if self.config else 10) * 1_000
            resp = page.goto(url, wait_until="load", timeout=timeout_ms)
            if resp is None:
                return None, discovered

            try:
                page.wait_for_load_state("domcontentloaded", timeout=3_000)
            except Exception:
                pass

            status = resp.status
            final_url = page.url
            headers = dict(resp.headers)
            content_type = headers.get("content-type", "")

            if "html" not in content_type and "json" not in content_type:
                return None, discovered

            # Hook React Router / history.pushState to capture SPA route changes
            page.evaluate("""
                () => {
                    if (!window.__kagesec_routes) window.__kagesec_routes = [];
                    const origPush = history.pushState.bind(history);
                    history.pushState = function(state, title, url) {
                        if (url) window.__kagesec_routes.push(String(url));
                        return origPush(state, title, url);
                    };
                    const origReplace = history.replaceState.bind(history);
                    history.replaceState = function(state, title, url) {
                        if (url) window.__kagesec_routes.push(String(url));
                        return origReplace(state, title, url);
                    };
                }
            """)

            self._scroll_to_load(page)

            body = page.content()
            _want_screenshots = self.config and getattr(self.config, "screenshots", False)
            screenshot = page.screenshot(type="png") if _want_screenshots else b""

            forms = self._extract_forms(page, final_url)
            links = self._extract_links(page, final_url)

            try:
                pushed = page.evaluate("() => window.__kagesec_routes || []")
                for route in pushed:
                    resolved = urljoin(final_url, route).split("#")[0]
                    if (
                        _is_navigable(resolved)
                        and _same_origin(resolved, self.base_url)
                        and self._in_scope(resolved)
                    ):
                        spa_routes.append(resolved)
            except Exception:
                pass

            result = CrawlResult(
                url=final_url,
                status_code=status,
                headers=headers,
                body=body,
                forms=forms,
                links=links,
                screenshot=screenshot,
                network_requests=list(network_reqs),
                websocket_connections=list(ws_connections),
            )

            all_links = list(dict.fromkeys(links + spa_routes))
            for link in all_links:
                discovered.append((link, depth + 1))

            for api_url in network_reqs:
                discovered.append((api_url, depth + 1))

            return result, discovered

        except Exception:
            return None, discovered
        finally:
            page.close()

    def _crawl_page(self, url: str, depth: int, results: List[CrawlResult]) -> None:
        """Backward-compat shim used by engine.py re-auth path — fetches one URL."""
        with self._visited_lock:
            norm = _normalise_for_dedup(url)
            if norm in self.visited:
                return
            self.visited.add(norm)
        result, _ = self._fetch_page(url, depth, self._context)
        if result is not None:
            results.append(result)

    def _scroll_to_load(self, page: Page, passes: int = 3) -> None:
        """Scroll to bottom repeatedly to trigger infinite scroll / lazy content."""
        for _ in range(passes):
            try:
                prev_height = page.evaluate("() => document.body.scrollHeight")
                page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
                try:
                    page.wait_for_load_state("load", timeout=1_500)
                except Exception:
                    pass
                new_height = page.evaluate("() => document.body.scrollHeight")
                if new_height == prev_height:
                    break
            except Exception:
                break

    def _in_scope(self, url: str) -> bool:
        if self._include and not any(fnmatch.fnmatch(url, p) for p in self._include):
            return False
        if self._exclude and any(fnmatch.fnmatch(url, p) for p in self._exclude):
            return False
        return True

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
                        and self._in_scope(resolved)
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
