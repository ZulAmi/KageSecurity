import hashlib
import os
import json
import re
import time
import uuid
import importlib
import inspect
import pkgutil
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core.crawler import Crawler
from scanner.core.scan_result import ScanResult
from scanner.core.config import ScanConfig
from scanner.core.rate_limiter import RateLimiter, RateLimitedClient
from scanner.compliance.mapper import map_to_standards
from scanner.ai.verifier import verify_findings
from scanner.ai.reporter import generate_report

import tempfile
import scanner.modules as _modules_pkg

_CHECKPOINT_DIR = tempfile.gettempdir()

# ---------------------------------------------------------------------------
# Speed: URL normalisation and content deduplication
# ---------------------------------------------------------------------------

# Query params that carry no semantic value — strip before dedup
_TRACKING_PARAMS = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "_ga", "_gl",
    "ref", "source", "mc_cid", "mc_eid", "si", "yclid",
})


def _normalise_url(url: str) -> str:
    """Return a canonical URL with tracking params stripped and params sorted."""
    try:
        parsed = urlparse(url)
        qs = {k: v for k, v in parse_qs(parsed.query).items()
              if k.lower() not in _TRACKING_PARAMS}
        # Sort params so ?a=1&b=2 == ?b=2&a=1
        sorted_qs = urlencode(sorted(qs.items()), doseq=True)
        normalised = urlunparse(parsed._replace(query=sorted_qs, fragment=""))
        return normalised
    except Exception:
        return url


def _content_hash(page) -> str:
    """SHA-256 of the response body, ignoring CSRF tokens and nonces."""
    body = page.body or ""
    # Strip likely-nonce values: 32+ hex chars in attribute values
    body = re.sub(r'(?:nonce|_token|csrf)["\s]*[:=]["\s]*[0-9a-fA-F+/]{20,}["\s]', "", body)
    return hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()


def _deduplicate_pages(pages: list) -> list:
    """
    Remove duplicate pages using two layers:
      1. Normalised URL deduplication (strips tracking params, sorts query params)
      2. Content-hash deduplication (same body ≈ same page rendered at different URL)

    Content-hash dedup only fires when body > 500 bytes to avoid false dedup
    of legitimately short pages (e.g. redirects, empty 404 pages).
    """
    seen_urls: set[str] = set()
    seen_hashes: set[str] = set()
    unique: list = []

    for page in pages:
        norm = _normalise_url(page.url)
        if norm in seen_urls:
            continue
        seen_urls.add(norm)

        body_len = len(page.body or "")
        if body_len > 500:
            ch = _content_hash(page)
            if ch in seen_hashes:
                continue
            seen_hashes.add(ch)

        unique.append(page)

    return unique


# Lazy import so httpx-only installs don't require playwright
def _get_browser_crawler():
    from scanner.core.browser_crawler import BrowserCrawler
    return BrowserCrawler


def _discover_modules():
    modules = []
    for _, name, _ in pkgutil.iter_modules(_modules_pkg.__path__):
        try:
            mod = importlib.import_module(f"scanner.modules.{name}")
            if hasattr(mod, "test"):
                modules.append(mod)
        except Exception:
            pass
    return modules


ALL_MODULES = _discover_modules()


def _load_plugins() -> list:
    """Gap 24 — auto-discover user plugins from ~/.kagesec/plugins/*.py."""
    import glob
    import importlib.util
    import sys

    plugins = []
    plugin_dir = os.path.expanduser("~/.kagesec/plugins")
    if not os.path.isdir(plugin_dir):
        return plugins

    for path in glob.glob(os.path.join(plugin_dir, "*.py")):
        try:
            module_name = f"kagesec_plugin_{os.path.splitext(os.path.basename(path))[0]}"
            spec = importlib.util.spec_from_file_location(module_name, path)
            if not spec or not spec.loader:
                continue
            mod = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = mod
            spec.loader.exec_module(mod)
            if hasattr(mod, "test"):
                plugins.append(mod)
        except Exception:
            pass

    return plugins


_RANDOM_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "curl/8.7.1",
    "python-httpx/0.27.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
]


class _RandomAgentClient:
    """Wraps an httpx.Client to rotate User-Agent randomly on each request."""

    def __init__(self, inner: httpx.Client):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def _rotated_headers(self, kwargs: dict) -> dict:
        import random
        headers = dict(kwargs.pop("headers", {}) or {})
        headers["User-Agent"] = random.choice(_RANDOM_USER_AGENTS)
        return headers

    def get(self, *args, **kwargs):
        kwargs["headers"] = self._rotated_headers(kwargs)
        return self._inner.get(*args, **kwargs)

    def post(self, *args, **kwargs):
        kwargs["headers"] = self._rotated_headers(kwargs)
        return self._inner.post(*args, **kwargs)

    def request(self, *args, **kwargs):
        kwargs["headers"] = self._rotated_headers(kwargs)
        return self._inner.request(*args, **kwargs)

    def close(self):
        self._inner.close()


def _load_cookie_jar(path: str) -> dict:
    """Parse a Netscape-format cookie jar file into a {name: value} dict."""
    cookies: dict = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 7:
                    name, value = parts[5], parts[6]
                    cookies[name] = value
    except Exception:
        pass
    return cookies


# --- Checkpoint helpers ---

def _checkpoint_path(scan_id: str) -> str:
    return os.path.join(_CHECKPOINT_DIR, f"kagesec_{scan_id}.json")


def _load_checkpoint(scan_id: str) -> set[tuple[str, str]]:
    try:
        with open(_checkpoint_path(scan_id)) as f:
            data = json.load(f)
        return {(pair[0], pair[1]) for pair in data.get("completed", [])}
    except Exception:
        return set()


def _save_checkpoint(scan_id: str, completed: set[tuple[str, str]]) -> None:
    try:
        with open(_checkpoint_path(scan_id), "w") as f:
            json.dump({"completed": list(completed)}, f)
    except Exception:
        pass


# --- Main entry point ---

def run_scan(
    target: str | None = None,
    config: ScanConfig | None = None,
    api_key: str | None = None,
    scan_id: str | None = None,
    finding_callback=None,
    concurrency: int = 8,
    progress_callback=None,
) -> tuple[ScanResult, str | None]:
    if config is None:
        config = ScanConfig(target=target or "")

    if scan_id is None:
        scan_id = str(uuid.uuid4())

    # Resumability — load checkpoint if requested
    resume_id = getattr(config, "resume_scan_id", None)
    effective_id = resume_id or scan_id
    completed_pairs: set[tuple[str, str]] = _load_checkpoint(resume_id) if resume_id else set()

    result = ScanResult(target=config.target)

    # Crawler selection
    if getattr(config, "browser", False):
        BrowserCrawler = _get_browser_crawler()
        crawler = BrowserCrawler(
            config.target,
            max_depth=config.max_depth,
            max_pages=config.max_pages,
            config=config,
            crawl_workers=getattr(config, "crawl_workers", 3),
        )
    else:
        crawler = Crawler(config.target, max_depth=config.max_depth, max_pages=config.max_pages, config=config)

    # HTTP client with auth headers
    _ua = (
        getattr(config, "user_agent", None)
        or "KageSec/0.1 Security Scanner"
    )
    headers = {"User-Agent": _ua}
    if config.headers:
        headers.update(config.headers)
    if config.auth:
        auth_type = config.auth.get("type", "")
        auth_value = config.auth.get("value", "")
        if auth_type == "bearer":
            headers["Authorization"] = f"Bearer {auth_value}"
        elif auth_type == "basic":
            headers["Authorization"] = f"Basic {auth_value}"

    # Cookie jar loading (Netscape format)
    jar_cookies: dict = {}
    cookie_jar_path = getattr(config, "cookie_jar", None)
    if cookie_jar_path:
        jar_cookies = _load_cookie_jar(cookie_jar_path)

    base_cookies = {**(config.auth.get("cookies", {}) if config.auth else {}), **jar_cookies}

    proxy = getattr(config, "proxy", None)
    _retries = getattr(config, "retries", 0)
    raw_client = httpx.Client(
        follow_redirects=True,
        timeout=config.timeout,
        headers=headers,
        cookies=base_cookies,
        transport=httpx.HTTPTransport(retries=_retries),
        limits=httpx.Limits(
            max_connections=max(20, concurrency * 2),
            max_keepalive_connections=max(10, concurrency),
            keepalive_expiry=30,
        ),
        **({"proxies": {"all://": proxy}} if proxy else {}),
    )

    # Random User-Agent rotation: wrap the client to rotate UA per request
    if getattr(config, "random_agent", False):
        raw_client = _RandomAgentClient(raw_client)
    # Auto-scale: when the user hasn't set --rate-limit explicitly (still at default 10),
    # give each worker ~3 RPS of headroom. Explicit --rate-limit values are always honoured.
    # Hard cap at 300 RPS to stay responsible on any target.
    _cfg_rps = getattr(config, "rate_limit_rps", 10)
    _effective_rps = min(_cfg_rps if _cfg_rps != 10 else max(10, concurrency * 3), 300)
    limiter = RateLimiter(rps=_effective_rps)
    client = RateLimitedClient(raw_client, limiter)

    # Gap 23: load suppression rules once
    suppression_rules = []
    try:
        from scanner.core.suppressions import load_suppressions
        suppression_rules = load_suppressions()
    except Exception:
        pass

    # Gap 25: load scan policy
    scan_policy = None
    policy_file = getattr(config, "scan_policy_file", None)
    try:
        from scanner.core.scan_policy import ScanPolicy
        scan_policy = ScanPolicy.load(policy_file)
    except Exception:
        pass

    # Gap 24: load user plugins from ~/.kagesec/plugins/*.py
    plugin_modules = _load_plugins()

    # Module selection
    all_available = ALL_MODULES + plugin_modules
    active_modules = all_available
    if config.modules:
        active_modules = [m for m in all_available if m.__name__.split(".")[-1] in config.modules]

    # Gap 25: filter by scan policy
    if scan_policy:
        active_modules = [
            m for m in active_modules
            if scan_policy.is_enabled(m.__name__.split(".")[-1])
        ]

    # Passive mode — observation only, no injection
    if getattr(config, "passive", False):
        _PASSIVE = {
            "security_headers", "cookie_security", "cors", "tls",
            "version_disclosure", "api_key_leak", "dnssec", "csrf",
            "waf_detect", "breach",
        }
        active_modules = [m for m in active_modules if m.__name__.split(".")[-1] in _PASSIVE]

    # Reset per-scan module state (prevents state leak across sequential scans in API mode)
    for _m in active_modules:
        if hasattr(_m, "reset"):
            _m.reset()

    # OOB server for blind injection detection
    oob = None
    if getattr(config, "use_oob", True):
        try:
            from scanner.core.interactsh import OOBServer
            oob = OOBServer(server=getattr(config, "oob_server", None))
        except Exception:
            pass

    start = time.time()

    try:
        har_file = getattr(config, "har_file", None)
        if har_file:
            from scanner.core.har_importer import import_har
            pages = import_har(har_file)
            print(f"[*] HAR import: {len(pages)} requests loaded from {har_file}")
        else:
            print("[*] Crawling target...", flush=True)
            pages = crawler.crawl()
            print(f"[*] Crawl complete: {len(pages)} pages found", flush=True)

        # Append synthetic pages from OpenAPI/GraphQL specs
        if getattr(config, "openapi_spec", None):
            try:
                from scanner.core.api_scanner import scan_openapi
                api_pages = scan_openapi(config.openapi_spec, config.target, raw_client)
                pages.extend(api_pages)
            except Exception as e:
                result.errors.append(f"OpenAPI scanner: {e}")

        if getattr(config, "graphql_endpoint", None):
            try:
                from scanner.core.api_scanner import scan_graphql
                gql_pages = scan_graphql(config.graphql_endpoint, raw_client)
                pages.extend(gql_pages)
            except Exception as e:
                result.errors.append(f"GraphQL scanner: {e}")

        # Speed: deduplicate pages before scanning (normalised URL + content hash)
        before_dedup = len(pages)
        pages = _deduplicate_pages(pages)
        if len(pages) < before_dedup:
            result.errors.append(
                f"[perf] Deduplicated {before_dedup - len(pages)} duplicate page(s) "
                f"({before_dedup} → {len(pages)})"
            )

        # Gap 28: incremental/delta scanning — skip unchanged pages
        full_scan = getattr(config, "force_full_scan", False)
        if not full_scan:
            try:
                from scanner.core.crawl_state import load_state, filter_changed_pages
                saved_state = load_state(config.target)
                if saved_state:
                    changed_pages, skipped_pages = filter_changed_pages(pages, saved_state)
                    if skipped_pages:
                        result.errors.append(
                            f"[delta] Skipping {len(skipped_pages)} unchanged page(s) "
                            f"(use --full to override)"
                        )
                        pages = changed_pages
            except Exception:
                pass

        result.pages_crawled = len(pages)

        # Session re-auth: filter out expired pages and optionally re-crawl them
        reauth_needed = [p for p in pages if _reauth_if_needed(p, config, crawler, raw_client)]
        if reauth_needed:
            extra_pages = []
            for p in reauth_needed:
                try:
                    if hasattr(crawler, "_crawl_page"):
                        crawler._crawl_page(p.url, depth=0, results=extra_pages)
                except Exception:
                    pass
            pages = [p for p in pages if p not in reauth_needed] + extra_pages
            result.pages_crawled = len(pages)

        _max_minutes = getattr(config, "max_time_minutes", 0)
        _deadline = (start + _max_minutes * 60) if _max_minutes > 0 else None

        # 3 seconds per module per page, minimum 120 s. Prevents a handful of
        # stuck modules from hanging the entire scan.
        # When --nuclei-templates is on, the Go engine runs once and needs extra
        # time beyond what the per-page formula allows. Add 600s (10 min) headroom.
        # --max-time is still honoured as the hard wall-clock cap.
        _base_budget = max(120, len(active_modules) * max(1, len(pages)) * 3)
        _nuclei_extra = 600 if getattr(config, "nuclei_templates", False) else 0
        _module_budget = _base_budget + _nuclei_extra

        # Priority ordering: passive/fast modules first so initial findings appear early.
        # Executor processes futures in submission order up to `concurrency` workers.
        _PASSIVE_FAST = frozenset({
            "security_headers", "cookie_security", "cors", "csrf", "tls",
            "version_disclosure", "debug_mode", "clickjacking",
        })
        _HEAVY = frozenset({"param_discovery", "path_discovery", "path_traversal"})

        def _module_priority(m) -> int:
            name = m.__name__.split(".")[-1]
            if name in _PASSIVE_FAST:
                return 0
            if name in _HEAVY:
                return 2
            return 1

        ordered_modules = sorted(active_modules, key=_module_priority)

        executor = ThreadPoolExecutor(max_workers=max(1, concurrency))
        _timed_out = False
        _session_check_interval = 50   # Poll session check URL every N completed futures
        _session_check_counter  = 0
        _session_check_url = getattr(config, "login_session_check_url", "") or ""
        # Modules that produce host-level results (DNS, TLS, WAF) — same answer
        # regardless of which page is tested. Run them once per host, not once per page,
        # to eliminate redundant network round trips without losing any findings.
        _HOST_ONCE = frozenset({
            "dnssec", "tls", "waf_detect", "breach", "subdomain_enum",
        })
        _host_once_submitted: set = set()   # (netloc, module_name) pairs already queued

        try:
            futures = {}
            for _page in pages:
                from urllib.parse import urlparse as _up
                _page_host = _up(_page.url).netloc
                for _mod in ordered_modules:
                    _mod_name = _mod.__name__.split(".")[-1]
                    if (_page.url, _mod.__name__) in completed_pairs:
                        continue
                    if _mod_name in _HOST_ONCE:
                        _host_key = (_page_host, _mod_name)
                        if _host_key in _host_once_submitted:
                            continue
                        _host_once_submitted.add(_host_key)
                    futures[executor.submit(_run_module, _mod, _page, client, oob, config)] = (_mod, _page)
            _total_work = len(futures)
            _done = 0
            _budget_exceeded = False
            # If --max-time is set, cap the as_completed timeout to the
            # remaining wall-clock time so the scan actually stops on time.
            _effective_budget = _module_budget
            if _deadline:
                _remaining = _deadline - time.time()
                _effective_budget = min(_module_budget, max(1.0, _remaining))
            try:
                for future in as_completed(futures, timeout=_effective_budget):
                    if _budget_exceeded:
                        future.cancel()
                        continue
                    module, page = futures[future]
                    try:
                        findings = future.result(timeout=30)
                        for f in findings:
                            if result.add_finding(f) and finding_callback:
                                finding_callback(f)
                        completed_pairs.add((page.url, module.__name__))
                        _save_checkpoint(effective_id, completed_pairs)
                    except Exception as e:
                        result.errors.append(f"{module.__name__}: {e}")
                    finally:
                        _done += 1
                        if progress_callback:
                            progress_callback(_done, _total_work, len(result.findings))
                        # Periodic session check (StackHawk "test path" strategy):
                        # every 50 completed futures, poll the check URL to verify
                        # the session is still valid; re-auth if logged-out indicator fires.
                        if _session_check_url and getattr(config, "login_flow", None):
                            _session_check_counter += 1
                            if _session_check_counter % _session_check_interval == 0:
                                try:
                                    _sc_resp = raw_client.get(_session_check_url, timeout=8)
                                    _lo_pat = getattr(config, "login_logged_out_indicator", "") or ""
                                    _li_pat = getattr(config, "login_logged_in_indicator", "") or ""
                                    _body = _sc_resp.text or ""
                                    _expired = False
                                    if _lo_pat and re.search(_lo_pat, _body, re.I):
                                        _expired = True
                                    if _li_pat and _body and not re.search(_li_pat, _body, re.I):
                                        _expired = True
                                    if _expired and hasattr(crawler, "_authenticate"):
                                        crawler._authenticate(config.login_flow)
                                except Exception:
                                    pass
                        if _deadline and time.time() > _deadline:
                            _budget_exceeded = True
                            result.errors.append(
                                f"[budget] Scan time budget of {_max_minutes}m exceeded — stopping early"
                            )
            except TimeoutError:
                stuck = {futures[f][0].__name__.split(".")[-1] for f in futures if not f.done()}
                incomplete = len(stuck) if stuck else (_total_work - _done)
                result.errors.append(
                    f"[timeout] Module phase exceeded {_module_budget}s budget — "
                    f"{incomplete} module(s) abandoned: {', '.join(sorted(stuck))}. Use --max-time to extend."
                )
                print(
                    f"[!] Module timeout: {incomplete} slow module(s) abandoned after "
                    f"{_module_budget}s: {', '.join(sorted(stuck))}",
                    flush=True,
                )
                _timed_out = True
        finally:
            # cancel_futures=True drops queued-but-not-started work;
            # wait=False avoids blocking on threads stuck in network I/O after timeout
            executor.shutdown(wait=not _timed_out, cancel_futures=_timed_out)

        # Poll OOB for blind callbacks after all modules finish
        if oob:
            for f in _collect_oob_findings(oob, result.findings):
                result.add_finding(f)

    finally:
        crawler.close()
        client.close()
        if oob:
            oob.close()

    result.scan_duration_seconds = time.time() - start
    result.deduplicate()

    # Gap 23: apply suppression rules
    if suppression_rules:
        try:
            from scanner.core.suppressions import apply_suppressions
            result.findings = apply_suppressions(result.findings, suppression_rules)
        except Exception:
            pass

    # Cross-module suppression: SSI and SSTI are ambiguous on any (endpoint, param) pair
    # already confirmed as CSTI or OS Command Injection. The dominant vuln (CSTI/RCE) proves
    # deeper control — the SSI/SSTI signal is explained by that same execution, not a separate
    # vulnerability. Removing the subordinate finding reduces noise without losing information.
    # Generic: applies to any target where multiple injection classes detect on the same param.
    _cm_dominant_keys: set = set()
    _CM_DOMINANT = ("client-side template injection", "os command injection", "remote code execution")
    for _cm_f in result.findings:
        if any(d in _cm_f.title.lower() for d in _CM_DOMINANT) and _cm_f.parameter is not None:
            from urllib.parse import urlparse as _cm_urlparse
            _cm_p = _cm_urlparse(_cm_f.url)
            _cm_dominant_keys.add((_cm_p.netloc + _cm_p.path, _cm_f.parameter))

    if _cm_dominant_keys:
        from urllib.parse import urlparse as _cm_urlparse
        _CM_SUPPRESSABLE = ("server-side include", "server-side template injection")
        _cm_before = len(result.findings)
        result.findings = [
            f for f in result.findings
            if not (
                any(s in f.title.lower() for s in _CM_SUPPRESSABLE)
                and f.parameter is not None
                and (
                    _cm_urlparse(f.url).netloc + _cm_urlparse(f.url).path,
                    f.parameter,
                ) in _cm_dominant_keys
            )
        ]
        _cm_suppressed = _cm_before - len(result.findings)
        if _cm_suppressed:
            result.errors.append(
                f"[cross-module] Suppressed {_cm_suppressed} SSI/SSTI finding(s) subsumed "
                f"by confirmed CSTI/OS Command Injection on the same parameter(s)."
            )

    # Gap 19 — auto-generate PoC curl commands for all findings
    for f in result.findings:
        if f.poc_curl is None and f.url:
            method = "POST" if f.parameter and f.payload and "form" in (f.title or "").lower() else "GET"
            f.build_poc_curl(method=method)

    if config.compliance:
        result.compliance_reports = map_to_standards(result, config.compliance)

    report_md = None
    from scanner.ai.provider import detect as _detect_provider
    _ai_provider, _ai_key = _detect_provider(
        explicit_provider=getattr(config, "ai_provider", None) if config else None,
        explicit_key=api_key or (getattr(config, "api_key", None) if config else None),
    )
    _ai_model = getattr(config, "ai_model", None) if config else None
    if _ai_provider:
        result = verify_findings(result, _ai_key, provider=_ai_provider, model=_ai_model)
        try:
            report_md = generate_report(result, _ai_key, provider=_ai_provider, model=_ai_model)
        except Exception as e:
            result.errors.append(f"[AI report failed] {e}")
            report_md = None

    # Gap 28: save crawl state for next delta scan
    try:
        from scanner.core.crawl_state import save_state
        save_state(config.target, pages if 'pages' in dir() else [])
    except Exception:
        pass

    # Persist to findings DB and classify finding states (New/Repeated/Regressed/Resolved)
    try:
        from scanner.core.findings_db import record_scan, classify_scan
        classify_scan(scan_id, result, config.target)   # populates result.scan_states + resolved_findings
        record_scan(scan_id, result)
    except Exception:
        pass

    return result, report_md


def _run_module(module, page, client, oob=None, config=None):
    if getattr(config, "verbose", False):
        mod_name = module.__name__.split(".")[-1]
        print(f"[~] {mod_name} @ {page.url}", flush=True)

    sig = inspect.signature(module.test)
    params = list(sig.parameters.keys())

    kwargs = {}
    if "oob" in params and oob is not None:
        kwargs["oob"] = oob
    if "config" in params:
        kwargs["config"] = config

    if kwargs:
        return module.test(page, client, **kwargs)
    return module.test(page, client)


def _reauth_if_needed(page, config, crawler, raw_client) -> bool:
    """Detect session expiry and re-authenticate.

    Detection signals (mirrors StackHawk loggedInIndicator/loggedOutIndicator and ZAP auth strategies):
      1. HTTP 401 status code
      2. Redirect to login URL
      3. Response body matches login_logged_out_indicator regex
      4. Response body does NOT match login_logged_in_indicator regex (when set)

    Returns True if re-auth was performed and the page should be revisited.
    """
    login_flow = getattr(config, "login_flow", None)
    if not login_flow:
        return False

    status = getattr(page, "status_code", 200)
    url    = getattr(page, "url", "")
    body   = getattr(page, "body", "") or ""

    # Compare URL paths rather than using substring match — avoids false positives when
    # the login path (/login) is a substring of unrelated paths (/api/login, /users/login).
    _login_path = urlparse(login_flow.url).path.rstrip("/")
    _page_path  = urlparse(url).path.rstrip("/")

    is_expired = (
        status == 401
        or (status in (301, 302, 303) and _page_path == _login_path)
        or (status == 200 and _page_path == _login_path)
    )

    # Regex-based session verification — StackHawk / ZAP "Check every Response" strategy
    logged_out_pat = getattr(config, "login_logged_out_indicator", "") or ""
    logged_in_pat  = getattr(config, "login_logged_in_indicator",  "") or ""
    if logged_out_pat and re.search(logged_out_pat, body, re.I):
        is_expired = True
    if logged_in_pat and body and not re.search(logged_in_pat, body, re.I):
        is_expired = True

    if not is_expired:
        return False

    # Re-authenticate via browser if BrowserCrawler is available
    try:
        if hasattr(crawler, "_authenticate"):
            crawler._authenticate(login_flow)
            return True
    except Exception:
        pass

    # Fallback: re-fetch OAuth2 token via client_credentials if configured.
    # token_url lives in config.auth (set by --auth-oauth2-token-url CLI flag).
    if config.auth and config.auth.get("type") == "bearer":
        token_url = config.auth.get("token_url")
        if token_url:
            try:
                import httpx as _httpx
                resp = _httpx.post(token_url, data={
                    "grant_type": "client_credentials",
                    "client_id": config.auth.get("client_id", ""),
                    "client_secret": config.auth.get("client_secret", ""),
                }, timeout=15)
                resp.raise_for_status()
                new_token = resp.json().get("access_token")
                if new_token:
                    raw_client.headers["Authorization"] = f"Bearer {new_token}"
                    return True
            except Exception as exc:
                import logging
                logging.getLogger(__name__).debug("OAuth2 token refresh failed: %s", exc)

    return False


def _collect_oob_findings(oob, existing_findings):
    from scanner.core.scan_result import Finding, Severity
    interactions = oob.poll(wait_seconds=15)
    findings = []
    for interaction in interactions:
        findings.append(Finding(
            title=f"Blind {interaction.protocol.upper()} Callback Confirmed (OOB)",
            severity=Severity.HIGH,
            url=interaction.remote_address or "OOB",
            parameter=None,
            payload=oob.get_canary(),
            evidence=(
                f"OOB {interaction.protocol} callback received from {interaction.remote_address}. "
                f"The target made an outbound {interaction.protocol.upper()} request to the canary "
                f"host ({oob.get_canary()}), confirming a blind injection vulnerability."
            ),
            description=(
                "The target application initiated an outbound network request to an attacker-controlled "
                "host, confirming a blind injection vulnerability (SSRF, blind command injection, "
                "XXE, or blind SQLi). This is a high-confidence finding."
            ),
            remediation=(
                "Identify which input triggered the callback by reviewing payloads sent during "
                "the scan. Apply input validation, whitelist-based egress filtering, and disable "
                "outbound network access from application processes where not required."
            ),
            owasp_category="A03:2021 Injection",
            confidence=1.0,
        ))
    return findings
