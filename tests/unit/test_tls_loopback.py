"""Plain HTTP on a loopback address is informational, not a HIGH finding."""
from __future__ import annotations

import pytest

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Severity
from scanner.modules import tls


def _page(url: str) -> CrawlResult:
    return CrawlResult(url=url, status_code=200, headers={}, body="")


@pytest.mark.parametrize("url", ["http://localhost:8888", "http://127.0.0.1/", "http://[::1]:3000", "http://app.localhost"])
def test_loopback_http_is_info(url):
    findings = tls.test(_page(url), client=None)
    assert [f.severity for f in findings] == [Severity.INFO]
    assert "Loopback" in findings[0].title


@pytest.mark.parametrize("url", ["http://example.com", "http://10.0.0.5/", "http://localhost.example.com"])
def test_network_http_is_high(url):
    findings = tls.test(_page(url), client=None)
    assert [f.severity for f in findings] == [Severity.HIGH]
    assert findings[0].title == "Application Accessible Over Unencrypted HTTP"
