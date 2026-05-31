"""Unit tests for scanner/core/scan_result.py"""
import pytest
from scanner.core.scan_result import Finding, ScanResult, Severity, _normalise_url


def _finding(title="XSS", severity=Severity.HIGH, url="http://example.com/page?q=1",
              parameter="q", payload="<script>", evidence="reflected"):
    return Finding(
        title=title, severity=severity, url=url,
        parameter=parameter, payload=payload, evidence=evidence,
        description="desc", remediation="fix",
    )


class TestSeverityOrdering:
    def test_severity_values(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.LOW == "low"

    def test_severity_enum_members(self):
        members = {s.value for s in Severity}
        assert members == {"critical", "high", "medium", "low", "info"}


class TestNormaliseUrl:
    def test_strips_query(self):
        assert _normalise_url("http://x.com/path?q=1&foo=bar") == "http://x.com/path"

    def test_strips_fragment(self):
        assert _normalise_url("http://x.com/page#section") == "http://x.com/page"

    def test_preserves_path(self):
        assert _normalise_url("http://x.com/api/v1/users") == "http://x.com/api/v1/users"


class TestFindingPocCurl:
    def test_get_injects_param(self):
        f = _finding(url="http://x.com/search?q=hello", parameter="q", payload="<script>alert(1)</script>")
        cmd = f.build_poc_curl(method="GET")
        assert "q=%3Cscript%3E" in cmd or "q=<script>" in cmd
        assert "curl" in cmd

    def test_post_includes_data(self):
        f = _finding(parameter="user", payload="admin' OR 1=1--")
        cmd = f.build_poc_curl(method="POST")
        assert "--data" in cmd
        assert "admin" in cmd

    def test_extra_headers_included(self):
        f = _finding()
        cmd = f.build_poc_curl(method="GET", extra_headers={"X-Custom": "value"})
        assert "-H 'X-Custom: value'" in cmd

    def test_sets_poc_curl_field(self):
        f = _finding()
        f.build_poc_curl()
        assert f.poc_curl is not None
        assert "curl" in f.poc_curl


class TestScanResultDeduplication:
    def test_exact_duplicate_removed(self):
        r = ScanResult(target="http://x.com")
        r.add_finding(_finding(title="XSS", url="http://x.com/page?q=1", parameter="q"))
        r.add_finding(_finding(title="XSS", url="http://x.com/page?q=1", parameter="q"))
        r.deduplicate()
        assert len(r.findings) == 1

    def test_same_location_keeps_higher_severity(self):
        # Dedup key is (title, host, parameter) — same title+location with different
        # severities should collapse to one finding at the higher severity.
        r = ScanResult(target="http://x.com")
        r.add_finding(_finding(title="XSS", severity=Severity.LOW, url="http://x.com/p?q=1", parameter="q"))
        r.add_finding(_finding(title="XSS", severity=Severity.CRITICAL, url="http://x.com/p?q=1", parameter="q"))
        r.deduplicate()
        assert len(r.findings) == 1
        assert r.findings[0].severity == Severity.CRITICAL

    def test_passive_deduplicated_globally(self):
        r = ScanResult(target="http://x.com")
        for url in ["http://x.com/page1", "http://x.com/page2", "http://x.com/page3"]:
            r.add_finding(_finding(title="Missing CSP", severity=Severity.MEDIUM,
                                   url=url, parameter=None))
        r.deduplicate()
        titles = [f.title for f in r.findings]
        assert titles.count("Missing CSP") == 1

    def test_different_params_kept_separate(self):
        r = ScanResult(target="http://x.com")
        r.add_finding(_finding(title="XSS", url="http://x.com/p?q=1", parameter="q"))
        r.add_finding(_finding(title="XSS", url="http://x.com/p?name=x", parameter="name"))
        r.deduplicate()
        assert len(r.findings) == 2


class TestScanResultSummary:
    def test_summary_counts(self):
        r = ScanResult(target="http://x.com")
        r.add_finding(_finding(severity=Severity.CRITICAL))
        r.add_finding(_finding(severity=Severity.HIGH, parameter="other"))
        r.add_finding(_finding(severity=Severity.HIGH, url="http://x.com/p2?q=1"))
        summary = r.summary()
        assert summary["total_findings"] == 3
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["high"] == 2
        assert summary["target"] == "http://x.com"

    def test_empty_scan_summary(self):
        r = ScanResult(target="http://x.com", pages_crawled=5, scan_duration_seconds=10.0)
        s = r.summary()
        assert s["total_findings"] == 0
        assert s["pages_crawled"] == 5
        assert s["duration_seconds"] == 10.0
