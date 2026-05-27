import os
import json
import time
import uuid
import importlib
import inspect
import pkgutil
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.core.crawler import Crawler
from scanner.core.scan_result import ScanResult
from scanner.core.config import ScanConfig
from scanner.core.rate_limiter import RateLimiter, RateLimitedClient
from scanner.compliance.mapper import map_to_standards
from scanner.ai.verifier import verify_findings
from scanner.ai.reporter import generate_report

import scanner.modules as _modules_pkg

_CHECKPOINT_DIR = "/tmp"


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
        crawler = BrowserCrawler(config.target, max_depth=config.max_depth, max_pages=config.max_pages, config=config)
    else:
        crawler = Crawler(config.target, max_depth=config.max_depth, max_pages=config.max_pages, config=config)

    # HTTP client with auth headers
    headers = {"User-Agent": "KageSec/0.1 Security Scanner"}
    if config.headers:
        headers.update(config.headers)
    if config.auth:
        auth_type = config.auth.get("type", "")
        auth_value = config.auth.get("value", "")
        if auth_type == "bearer":
            headers["Authorization"] = f"Bearer {auth_value}"
        elif auth_type == "basic":
            headers["Authorization"] = f"Basic {auth_value}"

    proxy = getattr(config, "proxy", None)
    raw_client = httpx.Client(
        follow_redirects=True,
        timeout=config.timeout,
        headers=headers,
        cookies=config.auth.get("cookies", {}) if config.auth else {},
        **({"proxies": {"all://": proxy}} if proxy else {}),
    )
    limiter = RateLimiter(rps=getattr(config, "rate_limit_rps", 10))
    client = RateLimitedClient(raw_client, limiter)

    # Module selection
    active_modules = ALL_MODULES
    if config.modules:
        active_modules = [m for m in ALL_MODULES if m.__name__.split(".")[-1] in config.modules]

    # Passive mode — observation only, no injection
    if getattr(config, "passive", False):
        _PASSIVE = {
            "security_headers", "cookie_security", "cors", "tls",
            "version_disclosure", "api_key_leak", "dnssec", "csrf",
            "waf_detect", "breach",
        }
        active_modules = [m for m in active_modules if m.__name__.split(".")[-1] in _PASSIVE]

    # OOB server for blind injection detection
    oob = None
    if getattr(config, "use_oob", True):
        try:
            from scanner.core.oob import OOBServer
            oob = OOBServer(server=getattr(config, "oob_server", "oast.pro"))
        except Exception:
            pass

    start = time.time()

    try:
        pages = crawler.crawl()

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

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {
                executor.submit(_run_module, module, page, client, oob, config): (module, page)
                for page in pages
                for module in active_modules
                if (page.url, module.__name__) not in completed_pairs
            }
            for future in as_completed(futures):
                module, page = futures[future]
                try:
                    findings = future.result(timeout=30)
                    for f in findings:
                        result.add_finding(f)
                        if finding_callback:
                            finding_callback(f)
                    completed_pairs.add((page.url, module.__name__))
                    _save_checkpoint(effective_id, completed_pairs)
                except Exception as e:
                    result.errors.append(f"{module.__name__}: {e}")

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

    if config.compliance:
        result.compliance_reports = map_to_standards(result, config.compliance)

    report_md = None
    if api_key:
        result = verify_findings(result, api_key)
        report_md = generate_report(result, api_key)

    return result, report_md


def _run_module(module, page, client, oob=None, config=None):
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
    """Detect session expiry (401 or redirect to login) and re-authenticate.

    Returns True if re-auth was performed and the page should be revisited.
    """
    login_flow = getattr(config, "login_flow", None)
    if not login_flow:
        return False

    status = getattr(page, "status_code", 200)
    url = getattr(page, "url", "")

    is_expired = (
        status == 401
        or (status in (301, 302, 303) and login_flow.url in url)
        or (status == 200 and login_flow.url in url)
    )

    if not is_expired:
        return False

    # Re-authenticate via browser if BrowserCrawler is available
    try:
        if hasattr(crawler, "_authenticate"):
            crawler._authenticate(login_flow)
            return True
    except Exception:
        pass

    # Fallback: re-fetch OAuth2 token if auth type is bearer
    if config.auth and config.auth.get("type") == "bearer":
        token_url = getattr(config, "_oauth2_token_url", None)
        if token_url:
            try:
                import httpx as _httpx
                resp = _httpx.post(token_url, data={
                    "grant_type": "client_credentials",
                    "client_id": config.auth.get("client_id", ""),
                    "client_secret": config.auth.get("client_secret", ""),
                }, timeout=15)
                new_token = resp.json().get("access_token")
                if new_token:
                    raw_client.headers["Authorization"] = f"Bearer {new_token}"
                    return True
            except Exception:
                pass

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
