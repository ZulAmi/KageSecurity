"""
Integration tests against OWASP Juice Shop.

Requires: docker compose up -d juice-shop
          pytest tests/integration/test_juice_shop.py -v
"""
import pytest
from scanner.core.config import ScanConfig
from scanner.core.engine import run_scan
from scanner.core.scan_result import Severity

JUICE_SHOP_URL = "http://localhost:3000"


@pytest.fixture(scope="module")
def juice_scan():
    config = ScanConfig(
        target=JUICE_SHOP_URL,
        max_depth=2,
        max_pages=40,
    )
    result, _ = run_scan(config=config)
    return result


def test_pages_crawled(juice_scan):
    assert juice_scan.pages_crawled > 0


def test_security_headers_missing(juice_scan):
    header_findings = [f for f in juice_scan.findings if "header" in f.title.lower()]
    assert len(header_findings) > 0, "Juice Shop should have missing security header findings"


def test_xss_or_sqli_detected(juice_scan):
    injection = [
        f for f in juice_scan.findings
        if any(kw in f.title.lower() for kw in ("xss", "sql", "injection", "script"))
    ]
    assert len(injection) > 0, "At least one injection finding expected on Juice Shop"


def test_no_critical_on_healthy_endpoint(juice_scan):
    # /rest/products/search is a known XSS vector — at least 1 HIGH should appear
    high_plus = [f for f in juice_scan.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(high_plus) > 0
