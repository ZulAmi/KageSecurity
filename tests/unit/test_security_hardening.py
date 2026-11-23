"""Regression tests for the scanner's own attack surface (API server, MCP server,
template code execution, archive extraction)."""
from __future__ import annotations

import io
import json
import os
import sys
import threading
import urllib.error
import urllib.request
import zipfile

import pytest

from scanner.utils.safe_paths import is_within, safe_join, validate_scan_id


# ---------------------------------------------------------------------------
# safe_paths
# ---------------------------------------------------------------------------

class TestSafePaths:
    def test_safe_join_allows_children(self, tmp_path):
        assert safe_join(str(tmp_path), "a/b.yaml") == os.path.realpath(tmp_path / "a" / "b.yaml")

    @pytest.mark.parametrize("evil", ["../x", "a/../../x", "/etc/passwd"])
    def test_safe_join_rejects_escape(self, tmp_path, evil):
        with pytest.raises(ValueError):
            safe_join(str(tmp_path), evil)

    def test_is_within(self, tmp_path):
        assert is_within(str(tmp_path), str(tmp_path / "r.json"))
        assert not is_within(str(tmp_path), "/etc/passwd")

    @pytest.mark.parametrize("bad", ["../x", "a/b", "", "x" * 65, "a b"])
    def test_validate_scan_id_rejects(self, bad):
        with pytest.raises(ValueError):
            validate_scan_id(bad)

    def test_validate_scan_id_accepts_uuid(self):
        assert validate_scan_id("0b7f6c1e-4f0a-4c1e-9a43-6d1c2b3a4f5e")


# ---------------------------------------------------------------------------
# API server
# ---------------------------------------------------------------------------

@pytest.fixture
def api(monkeypatch):
    from scanner.api import server

    jobs = []
    monkeypatch.setattr(server, "_run_scan_job", lambda scan_id, cfg: jobs.append((scan_id, cfg)))
    httpd, token = server.make_server("127.0.0.1", 0, token="s3cret")
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield base, token, jobs
    finally:
        httpd.shutdown()
        httpd.server_close()


def _req(url, method="GET", body=None, token=None, ctype="application/json"):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if data is not None and ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


class TestApiServer:
    def test_default_bind_is_loopback(self):
        import inspect

        from scanner.api import server
        assert inspect.signature(server.serve).parameters["host"].default == "127.0.0.1"

    def test_health_needs_no_auth(self, api):
        base, _, _ = api
        assert _req(f"{base}/v1/health")[0] == 200

    def test_scan_requires_token(self, api):
        base, _, jobs = api
        status, _ = _req(f"{base}/v1/scan", "POST", {"target": "https://example.com"})
        assert status == 401
        status, _ = _req(f"{base}/v1/scan", "POST", {"target": "https://example.com"}, token="wrong")
        assert status == 401
        assert jobs == []

    def test_status_requires_token(self, api):
        base, _, _ = api
        assert _req(f"{base}/v1/scan/abc")[0] == 401

    def test_rejects_non_json_content_type(self, api):
        base, token, jobs = api
        status, _ = _req(f"{base}/v1/scan", "POST", {"target": "https://example.com"},
                         token=token, ctype="text/plain")
        assert status == 415
        assert jobs == []

    @pytest.mark.parametrize("field,value", [
        ("har_file", "/etc/passwd"),
        ("template_dirs", ["/tmp"]),
        ("cookie_jar", "/home/u/.cookies"),
        ("proxy", "http://attacker:8080"),
        ("allow_code_templates", True),
        ("openapi_spec", "/etc/passwd"),
    ])
    def test_rejects_dangerous_fields(self, api, field, value):
        base, token, jobs = api
        status, body = _req(f"{base}/v1/scan", "POST", {"target": "https://example.com", field: value}, token=token)
        assert status == 400
        assert field in body["error"]
        assert jobs == []

    @pytest.mark.parametrize("target", ["file:///etc/passwd", "ftp://x", "example.com", ""])
    def test_rejects_non_http_targets(self, api, target):
        base, token, _ = api
        assert _req(f"{base}/v1/scan", "POST", {"target": target}, token=token)[0] == 400

    def test_rejects_out_of_range_ints(self, api):
        base, token, _ = api
        status, _ = _req(f"{base}/v1/scan", "POST", {"target": "https://e.com", "max_pages": 10**9}, token=token)
        assert status == 400

    def test_valid_scan_is_queued(self, api):
        base, token, jobs = api
        status, body = _req(f"{base}/v1/scan", "POST",
                            {"target": "https://example.com", "max_pages": 5}, token=token)
        assert status == 202
        assert body["status"] == "queued"
        for _ in range(50):
            if jobs:
                break
            threading.Event().wait(0.02)
        assert jobs and jobs[0][1]["target"] == "https://example.com"


# ---------------------------------------------------------------------------
# Template code execution
# ---------------------------------------------------------------------------

CODE_TEMPLATE = """\
id: host-exec
info: {name: Host exec, severity: high}
code:
  - engine: [python3]
    source: print('pwned')
"""
FLOW_TEMPLATE = """\
id: flow-tpl
info: {name: Flow, severity: low}
flow: http(1)
http:
  - method: GET
    path: ["{{BaseURL}}"]
"""
HTTP_TEMPLATE = """\
id: plain-http
info: {name: Plain, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers:
      - type: status
        status: [200]
"""


class TestCodeTemplates:
    @pytest.fixture
    def tdir(self, tmp_path):
        (tmp_path / "code.yaml").write_text(CODE_TEMPLATE)
        (tmp_path / "flow.yaml").write_text(FLOW_TEMPLATE)
        (tmp_path / "http.yaml").write_text(HTTP_TEMPLATE)
        return str(tmp_path)

    def test_code_and_flow_templates_skipped_by_default(self, tdir):
        from scanner.core.template_runner import load_templates
        assert {t.id for t in load_templates([tdir])} == {"plain-http"}

    def test_code_templates_load_with_opt_in(self, tdir):
        from scanner.core.template_runner import load_templates
        assert {t.id for t in load_templates([tdir], allow_code=True)} == {"plain-http", "host-exec", "flow-tpl"}

    def test_config_defaults_to_no_code(self):
        from scanner.core.config import ScanConfig
        assert ScanConfig(target="https://e.com").allow_code_templates is False

    def test_code_runner_withholds_secrets(self, monkeypatch):
        from scanner.core.code_runner import CodeBlock, run_code_block
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-not-leak")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "also-secret")
        src = "import os, json; print(json.dumps({'matched': True, 'output': ','.join(sorted(os.environ))}))"
        res = run_code_block(CodeBlock(engine="python3", source=src, args=[]), target_url="https://e.com")
        if res.error and "not found in PATH" in res.error:
            pytest.skip("python3 not on PATH")
        assert "ANTHROPIC_API_KEY" not in res.output
        assert "AWS_SECRET_ACCESS_KEY" not in res.output
        assert "TARGET" in res.output

    @pytest.mark.parametrize("content,ok", [
        (HTTP_TEMPLATE, True),
        (CODE_TEMPLATE, False),
        (FLOW_TEMPLATE, False),
        ("- not: a mapping", False),
        ("id: x\ninfo: {name: y}\n", False),
    ])
    def test_ai_generated_templates_validated(self, content, ok):
        from scanner.ai.cve_researcher import _is_safe_template
        assert _is_safe_template(content) is ok

    def test_ai_cache_drops_unsafe_templates(self, tmp_path):
        from scanner.ai.cve_researcher import _write_cache
        _write_cache(str(tmp_path), {"server": "nginx"}, [
            {"filename": "good.yaml", "content": HTTP_TEMPLATE},
            {"filename": "evil.yaml", "content": CODE_TEMPLATE},
        ])
        assert (tmp_path / "good.yaml").exists()
        assert not (tmp_path / "evil.yaml").exists()


# ---------------------------------------------------------------------------
# Template download / archive extraction
# ---------------------------------------------------------------------------

class TestTemplateDownload:
    def _zip(self, members: dict[str, str]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, content in members.items():
                zf.writestr(name, content)
        return buf.getvalue()

    def test_is_compatible_uses_top_level_keys(self):
        from scanner.core.updater import is_compatible
        assert is_compatible(HTTP_TEMPLATE.encode())
        assert not is_compatible(CODE_TEMPLATE.encode())
        assert not is_compatible(FLOW_TEMPLATE.encode())
        # "code:" inside a description is not a code template
        assert is_compatible(b"id: x\ninfo:\n  description: 'error code: 5'\nhttp: []\n")

    def test_download_blocks_traversal_and_code(self, tmp_path, monkeypatch):
        from scanner.core import updater

        archive = self._zip({
            "nuclei-templates-v1/http/ok.yaml": HTTP_TEMPLATE,
            "nuclei-templates-v1/http/../../../escape.yaml": HTTP_TEMPLATE,
            "nuclei-templates-v1/code/rce.yaml": CODE_TEMPLATE,
            "nuclei-templates-v1/http/sneaky-code.yaml": CODE_TEMPLATE,
        })

        class _Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        requested = []

        def fake_urlopen(req, timeout=0):
            requested.append(req.full_url)
            return _Resp(archive)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(updater, "_VERSION_STAMP", str(tmp_path / ".version"))
        monkeypatch.setattr(updater, "_TEMPLATES_DIR", str(tmp_path))
        dest = tmp_path / "templates"
        stats = updater.download_templates(str(dest), version="v1", verbose=False)

        assert requested == [
            "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v1.zip"
        ]
        assert (dest / "http" / "ok.yaml").exists()
        assert not (tmp_path / "escape.yaml").exists()
        assert not (dest / "code").exists()
        assert not (dest / "http" / "sneaky-code.yaml").exists()
        assert stats["saved"] == 1


class TestImportScan:
    def test_import_rejects_path_traversal(self, tmp_path, monkeypatch):
        from cli import main as cli

        zpath = tmp_path / "evil.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("_meta.json", json.dumps({"scan_id": "../../pwn"}))
        workdir = tmp_path / "work"
        workdir.mkdir()
        monkeypatch.chdir(workdir)
        with pytest.raises(SystemExit):
            cli._import_scan(str(zpath))

    def test_import_writes_reports_by_basename_only(self, tmp_path, monkeypatch):
        from cli import main as cli

        zpath = tmp_path / "x.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("_meta.json", json.dumps({"scan_id": "abc-123"}))
            zf.writestr("../../outside.json", "{}")
        workdir = tmp_path / "a" / "b" / "work"
        workdir.mkdir(parents=True)
        monkeypatch.chdir(workdir)
        cli._import_scan(str(zpath))
        assert (workdir / "outside.json").exists()
        assert not (tmp_path / "a" / "outside.json").exists()


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

class TestMcpServer:
    @pytest.fixture
    def mcp_mod(self, tmp_path, monkeypatch):
        pytest.importorskip("mcp")
        from scanner import mcp_server
        monkeypatch.setattr(mcp_server, "REPORTS_ROOT", str(tmp_path / "mcp-reports"))
        return mcp_server

    @pytest.mark.parametrize("url", ["--help", "file:///etc/passwd", "javascript:alert(1)", "example.com"])
    def test_rejects_bad_urls(self, mcp_mod, url):
        with pytest.raises(ValueError):
            mcp_mod.build_scan_command(url, "/tmp/r")

    def test_rejects_flag_injection_via_modules(self, mcp_mod):
        with pytest.raises(ValueError):
            mcp_mod.build_scan_command("https://e.com", "/tmp/r", modules="xss,--notify-webhook=https://evil")

    def test_url_is_after_double_dash(self, mcp_mod):
        cmd = mcp_mod.build_scan_command("https://e.com", "/tmp/r", modules="xss,sqli", max_pages=10_000)
        assert cmd[-2:] == ["--", "https://e.com"]
        assert cmd[cmd.index("--max-pages") + 1] == "200"

    def test_cli_parses_mcp_command(self, mcp_mod, monkeypatch):
        """The argv the MCP server builds must parse to the intended target and modules."""
        from cli import main as cli

        cmd = mcp_mod.build_scan_command("https://e.com/path", "/tmp/r", modules="xss,sqli")
        seen = {}

        def fake_single(target, args, prefix, print_lock=None):
            seen["target"], seen["modules"], seen["report_dir"] = target, args.modules, args.report_dir
            return 0

        monkeypatch.setattr(cli, "_run_single_target", fake_single)
        monkeypatch.setattr(sys, "argv", ["kagesec", *cmd[cmd.index("scan"):]])
        cli.main()
        assert seen == {"target": "https://e.com/path", "modules": ["xss", "sqli"], "report_dir": "/tmp/r"}

    def test_read_report_confined(self, mcp_mod, tmp_path):
        out = json.loads(mcp_mod.kagesec_read_report("/etc/passwd"))
        assert "error" in out
        inside = os.path.join(mcp_mod.REPORTS_ROOT, "scan-x", "kagesec_report.json")
        os.makedirs(os.path.dirname(inside), exist_ok=True)
        with open(inside, "w") as f:
            f.write('{"ok": true}')
        assert json.loads(mcp_mod.kagesec_read_report(inside)) == {"ok": True}

