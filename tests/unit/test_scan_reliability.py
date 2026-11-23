"""End-to-end regression tests for scan reliability fixes, against a local HTTP server."""
from __future__ import annotations

import json
import sys
from argparse import Namespace

import pytest

from scanner.core.config import ScanConfig
from scanner.core.scan_result import Finding, Severity


def _finding(sev: Severity, title="t", url="https://e.com", suppressed=False) -> Finding:
    return Finding(title=title, severity=sev, url=url, parameter=None, payload=None,
                   evidence="", description="", remediation="", false_positive_suppressed=suppressed)


def _cfg(target: str, **kw) -> ScanConfig:
    defaults = dict(target=target, max_pages=5, max_depth=1, modules=["security_headers"],
                    use_oob=False, browser=False)
    defaults.update(kw)
    return ScanConfig(**defaults)


# ---------------------------------------------------------------------------
# --fail-on
# ---------------------------------------------------------------------------

class TestFailOn:
    def test_info_findings_do_not_crash_and_can_breach(self):
        from cli.main import findings_at_or_above
        findings = [_finding(Severity.INFO)]
        assert findings_at_or_above(findings, "high") == []
        assert len(findings_at_or_above(findings, "info")) == 1

    def test_ai_suppressed_findings_ignored(self):
        from cli.main import findings_at_or_above
        assert findings_at_or_above([_finding(Severity.CRITICAL, suppressed=True)], "low") == []

    def test_threshold_is_inclusive(self):
        from cli.main import findings_at_or_above
        findings = [_finding(Severity.HIGH), _finding(Severity.MEDIUM)]
        assert len(findings_at_or_above(findings, "high")) == 1
        assert len(findings_at_or_above(findings, "medium")) == 2

    def test_single_target_exit_code_propagates(self, monkeypatch):
        from cli import main as cli
        monkeypatch.setattr(cli, "_run_single_target", lambda *a, **k: 1)
        monkeypatch.setattr(sys, "argv", ["kagesec", "scan", "https://e.com", "--fail-on", "high"])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 1

    def test_diff_fail_on_info(self, tmp_path):
        from cli.main import _run_diff
        base, cur = tmp_path / "a.json", tmp_path / "b.json"
        base.write_text(json.dumps({"findings": []}))
        cur.write_text(json.dumps({"findings": [{"title": "x", "url": "u", "severity": "info"}]}))
        _run_diff(Namespace(baseline=str(base), current=str(cur), fail_on="high", output="json"))
        with pytest.raises(SystemExit) as exc:
            _run_diff(Namespace(baseline=str(base), current=str(cur), fail_on="info", output="json"))
        assert exc.value.code == 1


class TestGithubOutputs:
    def test_writes_declared_action_outputs(self, tmp_path, monkeypatch):
        from cli.main import _write_github_outputs
        from scanner.core.scan_result import ScanResult

        out = tmp_path / "gh_output"
        monkeypatch.setenv("GITHUB_OUTPUT", str(out))
        result = ScanResult(target="https://e.com")
        result.findings = [_finding(Severity.HIGH), _finding(Severity.LOW, suppressed=True)]
        _write_github_outputs({"sarif": "reports/kagesec_report.sarif"}, result)
        assert out.read_text() == "report-path=reports/kagesec_report.sarif\nfindings-count=1\n"


# ---------------------------------------------------------------------------
# Engine behaviour against a real (local) target
# ---------------------------------------------------------------------------

class TestEngine:
    def test_ai_disabled_never_calls_provider(self, local_site, monkeypatch):
        from scanner.core import engine

        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

        def boom(*a, **k):
            raise AssertionError("AI provider must not be called when ai_enabled=False")

        monkeypatch.setattr(engine, "verify_findings", boom)
        monkeypatch.setattr(engine, "generate_report", boom)
        result, report_md = engine.run_scan(config=_cfg(local_site, ai_enabled=False))
        assert result.findings, "security_headers should flag the header-less test site"
        assert report_md is None

    def test_ai_enabled_uses_provider(self, local_site, monkeypatch):
        from scanner.core import engine

        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        calls = []
        monkeypatch.setattr(engine, "verify_findings", lambda r, *a, **k: calls.append("verify") or r)
        monkeypatch.setattr(engine, "generate_report", lambda *a, **k: "report")
        engine.run_scan(config=_cfg(local_site))
        assert calls == ["verify"]

    def test_browser_falls_back_without_playwright(self, local_site, monkeypatch):
        from scanner.core import engine

        monkeypatch.setattr(engine, "playwright_available", lambda: False)
        result, _ = engine.run_scan(config=_cfg(local_site, browser=True, ai_enabled=False))
        assert result.pages_crawled >= 1
        assert any(e.startswith("[browser]") for e in result.errors)

    def test_proxy_option_does_not_crash(self, local_site):
        from scanner.core import engine

        # Unreachable proxy: the crawl finds nothing, but building the clients must not
        # raise (httpx 0.28 removed the old `proxies=` argument).
        result, _ = engine.run_scan(config=_cfg(local_site, proxy="http://127.0.0.1:9", ai_enabled=False))
        assert result.pages_crawled == 0

    def test_full_scan_is_default_and_findings_repeat(self, local_site):
        from scanner.core import engine

        first, _ = engine.run_scan(config=_cfg(local_site, ai_enabled=False))
        second, _ = engine.run_scan(config=_cfg(local_site, ai_enabled=False))
        assert len(second.findings) == len(first.findings) > 0
        assert set(second.scan_states.values()) == {"repeated"}
        assert second.resolved_findings == []

    def test_delta_mode_never_reports_skipped_findings_as_resolved(self, local_site):
        from scanner.core import engine

        engine.run_scan(config=_cfg(local_site, ai_enabled=False))
        second, _ = engine.run_scan(config=_cfg(local_site, ai_enabled=False, delta_scan=True))
        assert any(e.startswith("[delta]") for e in second.errors)
        assert second.findings == []
        assert second.resolved_findings == []

    def test_module_import_errors_are_reported(self, local_site, monkeypatch):
        from scanner.core import engine

        monkeypatch.setitem(engine.MODULE_IMPORT_ERRORS, "broken_mod", "SyntaxError: boom")
        result, _ = engine.run_scan(config=_cfg(local_site, ai_enabled=False))
        assert any("broken_mod" in e for e in result.errors)

    def test_rate_limit_is_honoured_exactly(self):
        from scanner.core.engine import MAX_RPS, auto_rate_limit
        assert auto_rate_limit(8) == 24
        assert auto_rate_limit(1) == 10
        assert auto_rate_limit(1000) == MAX_RPS


class TestCrawlerScope:
    def test_exclude_pattern_blocks_link(self, local_site):
        from scanner.core.crawler import Crawler

        crawler = Crawler(local_site, max_depth=2, max_pages=10,
                          config=_cfg(local_site, exclude_patterns=["*/logout*"]))
        try:
            urls = {p.url for p in crawler.crawl()}
        finally:
            crawler.close()
        assert f"{local_site}/about" in urls
        assert not any("logout" in u for u in urls)

    def test_sitemap_and_js_urls_are_scope_checked(self, local_site):
        from scanner.core.crawler import Crawler

        crawler = Crawler(local_site, config=_cfg(local_site, exclude_patterns=["*/logout*"]))
        results = []
        try:
            crawler._crawl_page(f"{local_site}/logout", depth=1, results=results)
            crawler._crawl_page("https://other-host.example/", depth=1, results=results)
        finally:
            crawler.close()
        assert results == []


# ---------------------------------------------------------------------------
# CLI end to end
# ---------------------------------------------------------------------------

def test_cli_scan_end_to_end(local_site, tmp_path, monkeypatch):
    """--no-ai with a key in the env, --report-dir, and --fail-on info → exit 1."""
    from cli import main as cli
    from scanner.core import engine

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setattr(engine, "verify_findings",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("AI called")))
    reports = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", [
        "kagesec", "scan", local_site, "--no-ai", "--no-browser", "--no-oob",
        "--modules", "security_headers", "--max-pages", "3",
        "--report-dir", str(reports), "--fail-on", "info",
    ])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    report = json.loads((reports / "kagesec_report.json").read_text())
    assert report["findings"]
    assert "errors" in report


# ---------------------------------------------------------------------------
# --resume and retest
# ---------------------------------------------------------------------------

class TestResume:
    def test_resume_restores_findings(self, local_site):
        from scanner.core import engine

        first, _ = engine.run_scan(config=_cfg(local_site, ai_enabled=False), scan_id="scan-1")
        assert first.findings
        resumed, _ = engine.run_scan(
            config=_cfg(local_site, ai_enabled=False, resume_scan_id="scan-1"), scan_id="scan-2",
        )
        # Every (page, module) pair was already done, so nothing re-ran — but the
        # findings from before the interruption must still be in the result.
        assert {f.title for f in resumed.findings} == {f.title for f in first.findings}

    def test_checkpoint_is_private(self, local_site):
        import os
        import stat

        from scanner.core import engine

        engine.run_scan(config=_cfg(local_site, ai_enabled=False), scan_id="scan-perm")
        mode = os.stat(engine.checkpoint_path("scan-perm")).st_mode
        assert not mode & (stat.S_IRGRP | stat.S_IROTH)

    def test_findings_record_their_module(self, local_site):
        from scanner.core import engine
        result, _ = engine.run_scan(config=_cfg(local_site, ai_enabled=False))
        assert {f.module for f in result.findings} == {"security_headers"}


class TestRetest:
    def _report(self, tmp_path, findings):
        path = tmp_path / "report.json"
        path.write_text(json.dumps({"findings": findings}))
        return str(path)

    def _retest(self, path, finding_id="0"):
        from cli.main import _run_retest
        with pytest.raises(SystemExit) as exc:
            _run_retest(Namespace(finding_id=finding_id, report=path, api_key=None, no_ai=True))
        return exc.value.code

    def test_still_present_exits_1(self, local_site, tmp_path):
        from cli.main import _findings_dict
        from scanner.core import engine

        result, _ = engine.run_scan(config=_cfg(local_site, ai_enabled=False))
        report = _findings_dict(result)
        for f in report["findings"]:
            f["poc_curl"] = None  # force the module re-run path
        assert self._retest(self._report(tmp_path, report["findings"])) == 1

    def test_module_with_oob_parameter_does_not_crash(self, local_site, tmp_path):
        # ssti.test(page, client, oob=None, config=None): passing config positionally
        # used to land in `oob` and crash with AttributeError.
        path = self._report(tmp_path, [{
            "title": "Server-Side Template Injection", "severity": "high",
            "url": f"{local_site}/about?name=x", "parameter": "name", "module": "ssti",
        }])
        assert self._retest(path) == 0

    def test_injection_titles_map_to_the_right_module(self, local_site, tmp_path, capsys):
        path = self._report(tmp_path, [{
            "title": "OS Command Injection", "severity": "critical",
            "url": f"{local_site}/about?cmd=x", "parameter": "cmd",
        }])
        self._retest(path)
        assert "Running module: cmd_injection" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Option precedence: CLI > profile > config.yaml > defaults
# ---------------------------------------------------------------------------

class TestOptionPrecedence:
    def _capture(self, monkeypatch, argv, config_yaml=None):
        from cli import main as cli
        from scanner.core import policy

        if config_yaml is not None:
            with open(policy._CONFIG_PATH, "w") as f:
                f.write(config_yaml)
        seen = {}

        def fake_run_scan(config, **kw):
            seen["config"] = config
            raise SystemExit(0)

        monkeypatch.setattr(cli, "run_scan", fake_run_scan)
        monkeypatch.setattr(sys, "argv", ["kagesec", "scan", "https://e.com", "--no-ai", *argv])
        with pytest.raises(SystemExit):
            cli.main()
        return seen["config"]

    def test_explicit_flag_equal_to_default_beats_config_file(self, monkeypatch):
        cfg = self._capture(monkeypatch, ["--depth", "3"], "depth: 7\nmax_pages: 42\n")
        assert cfg.max_depth == 3          # typed on CLI, even though 3 is the default
        assert cfg.max_pages == 42         # not typed → config file applies

    def test_config_file_can_disable_browser(self, monkeypatch):
        cfg = self._capture(monkeypatch, [], "browser: false\n")
        assert cfg.browser is False

    def test_profile_beats_config_file_but_not_cli(self, monkeypatch):
        from scanner.core import profiles
        monkeypatch.setitem(profiles.BUILT_IN, "t-prof", {"depth": 5, "max_pages": 9})
        cfg = self._capture(monkeypatch, ["--profile", "t-prof", "--max-pages", "100"], "depth: 7\n")
        assert cfg.max_depth == 5
        assert cfg.max_pages == 100

    def test_explicit_dests_handles_forms(self):
        import argparse

        from cli.main import _explicit_dests
        p = argparse.ArgumentParser(prog="kagesec")
        sub = p.add_subparsers()
        scan = sub.add_parser("scan")
        scan.add_argument("target", nargs="?")
        scan.add_argument("--depth", type=int, default=3)
        scan.add_argument("--max-pages", type=int, default=100)
        scan.add_argument("--browser", action="store_true", default=True)
        scan.add_argument("--no-browser", action="store_false", dest="browser")
        got = _explicit_dests(scan, ["scan", "https://e.com", "--max-pages=5", "--no-browser"])
        assert {"max_pages", "browser"} <= got
        assert "depth" not in got


def test_sarif_reports_scan_errors_and_real_version(tmp_path):
    from scanner import __version__
    from scanner.core.scan_result import ScanResult
    from scanner.reporters.sarif_reporter import generate_sarif

    result = ScanResult(target="https://e.com")
    result.findings = [_finding(Severity.HIGH, title="Reflected XSS")]
    result.errors = ["xss: TimeoutError"]
    sarif = json.loads(open(generate_sarif(result, str(tmp_path / "r.sarif"))).read())
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["version"] == __version__
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert notes == [{"level": "warning", "message": {"text": "xss: TimeoutError"}}]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} <= rule_ids
