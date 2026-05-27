"""
False-positive baseline: scan a clean nginx server.

Expects zero CRITICAL/HIGH findings — only possible INFO (server version etc.).
Requires: docker compose up -d clean-nginx
          pytest tests/integration/test_clean_target.py -v
"""
import pytest
from scanner.core.config import ScanConfig
from scanner.core.engine import run_scan
from scanner.core.scan_result import Severity

CLEAN_URL = "http://localhost:8888"


@pytest.fixture(scope="module")
def clean_scan():
    config = ScanConfig(
        target=CLEAN_URL,
        max_depth=1,
        max_pages=10,
    )
    result, _ = run_scan(config=config)
    return result


def test_no_critical_findings(clean_scan):
    crits = [f for f in clean_scan.findings if f.severity == Severity.CRITICAL]
    assert len(crits) == 0, f"False-positive CRITICAL findings on clean nginx: {[f.title for f in crits]}"


def test_no_high_findings(clean_scan):
    highs = [f for f in clean_scan.findings if f.severity == Severity.HIGH]
    assert len(highs) == 0, f"False-positive HIGH findings on clean nginx: {[f.title for f in highs]}"


def test_scan_completes(clean_scan):
    assert clean_scan.pages_crawled >= 1
