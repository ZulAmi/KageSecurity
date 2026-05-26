import time
import importlib
import pkgutil
import httpx
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.core.crawler import Crawler
from scanner.core.scan_result import ScanResult
from scanner.core.config import ScanConfig
from scanner.compliance.mapper import map_to_standards
from scanner.ai.verifier import verify_findings
from scanner.ai.reporter import generate_report

import scanner.modules as _modules_pkg


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


def run_scan(
    target: str | None = None,
    config: ScanConfig | None = None,
    api_key: str | None = None,
) -> tuple[ScanResult, str | None]:
    if config is None:
        config = ScanConfig(target=target or "")

    result = ScanResult(target=config.target)
    crawler = Crawler(config.target, max_depth=config.max_depth, max_pages=config.max_pages, config=config)

    # Build headers for HTTP client
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

    client = httpx.Client(
        follow_redirects=True,
        timeout=config.timeout,
        headers=headers,
        cookies=config.auth.get("cookies", {}) if config.auth else {},
    )

    # Select modules
    active_modules = ALL_MODULES
    if config.modules:
        active_modules = [m for m in ALL_MODULES if m.__name__.split(".")[-1] in config.modules]

    start = time.time()

    try:
        pages = crawler.crawl()
        result.pages_crawled = len(pages)

        # Run all modules against all pages in parallel
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {
                executor.submit(_run_module, module, page, client): (module, page)
                for page in pages
                for module in active_modules
            }
            for future in as_completed(futures):
                module, page = futures[future]
                try:
                    findings = future.result()
                    for f in findings:
                        result.add_finding(f)
                except Exception as e:
                    result.errors.append(f"{module.__name__}: {e}")

    finally:
        crawler.close()
        client.close()

    result.scan_duration_seconds = time.time() - start
    result.deduplicate()

    # Compliance mapping
    if config.compliance:
        result.compliance_reports = map_to_standards(result, config.compliance)

    # AI verification + report
    report_md = None
    if api_key:
        result = verify_findings(result, api_key)
        report_md = generate_report(result, api_key)

    return result, report_md


def _run_module(module, page, client):
    return module.test(page, client)
