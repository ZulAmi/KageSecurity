"""
KageSec API server — `kagesec serve`.

Exposes a minimal HTTP API so CI/CD pipelines, dashboards, and external scripts
can orchestrate scans without shelling out to the CLI.

Endpoints:
  GET  /v1/health                    → liveness check
  POST /v1/scan       {body: config} → start scan, returns scan_id
  GET  /v1/scan/{id}                 → status + live counters
  GET  /v1/scan/{id}/report          → full findings JSON (only when complete)
  DELETE /v1/scan/{id}               → remove scan from memory

No external dependencies — uses Python's built-in http.server + threading.
"""
from __future__ import annotations

import json
import threading
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

_VERSION = "0.2.0"

# scan_id → {"status": str, "config_dict": dict, "result": dict|None, "error": str|None}
_scans: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):  # noqa: A002
        pass  # suppress default access log; server prints its own start message

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        if self.path == "/v1/health":
            self._json(200, {"status": "ok", "version": _VERSION, "scans": len(_scans)})

        elif self.path.startswith("/v1/scan/"):
            parts = self.path.split("/")
            # /v1/scan/{id}  or  /v1/scan/{id}/report
            if len(parts) == 4:
                self._get_status(parts[3])
            elif len(parts) == 5 and parts[4] == "report":
                self._get_report(parts[3])
            else:
                self._json(404, {"error": "Not found"})

        else:
            self._json(404, {"error": "Not found"})

    # ------------------------------------------------------------------ POST
    def do_POST(self):
        if self.path == "/v1/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            try:
                cfg = json.loads(body)
            except json.JSONDecodeError as e:
                self._json(400, {"error": f"Invalid JSON: {e}"})
                return

            if not cfg.get("target"):
                self._json(400, {"error": "'target' is required"})
                return

            scan_id = str(uuid.uuid4())
            with _lock:
                _scans[scan_id] = {
                    "status": "queued",
                    "config_dict": cfg,
                    "result": None,
                    "error": None,
                }

            t = threading.Thread(target=_run_scan_thread, args=(scan_id, cfg), daemon=True)
            t.start()
            self._json(202, {"scan_id": scan_id, "status": "queued"})

        else:
            self._json(404, {"error": "Not found"})

    # ------------------------------------------------------------------ DELETE
    def do_DELETE(self):
        if self.path.startswith("/v1/scan/"):
            scan_id = self.path.split("/")[-1]
            with _lock:
                if scan_id not in _scans:
                    self._json(404, {"error": "Scan not found"})
                    return
                state = _scans[scan_id]
                if state["status"] == "running":
                    self._json(409, {"error": "Scan is still running"})
                    return
                del _scans[scan_id]
            self._json(200, {"deleted": scan_id})
        else:
            self._json(404, {"error": "Not found"})

    # ------------------------------------------------------------------ helpers
    def _get_status(self, scan_id: str) -> None:
        with _lock:
            state = _scans.get(scan_id)
        if not state:
            self._json(404, {"error": "Scan not found"})
            return
        result = state.get("result") or {}
        self._json(200, {
            "scan_id": scan_id,
            "status": state["status"],
            "target": state["config_dict"].get("target"),
            "pages_crawled": result.get("pages_crawled", 0),
            "findings_count": result.get("findings_count", 0),
            "duration_seconds": result.get("duration_seconds"),
            "error": state.get("error"),
        })

    def _get_report(self, scan_id: str) -> None:
        with _lock:
            state = _scans.get(scan_id)
        if not state:
            self._json(404, {"error": "Scan not found"})
            return
        if state["status"] != "complete":
            self._json(425, {"error": "Scan not complete yet", "status": state["status"]})
            return
        self._json(200, state["result"].get("report", {}))

    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ---------------------------------------------------------------------------
# Background scan runner
# ---------------------------------------------------------------------------

def _run_scan_thread(scan_id: str, cfg: dict) -> None:
    with _lock:
        _scans[scan_id]["status"] = "running"

    try:
        from scanner.core.config import ScanConfig
        from scanner.core.engine import run_scan

        # Build ScanConfig from the JSON body — unknown keys are silently ignored
        allowed = {f.name for f in ScanConfig.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        clean = {k: v for k, v in cfg.items() if k in allowed}
        config = ScanConfig(**clean)

        api_key = cfg.get("api_key") or None
        result_obj, _ = run_scan(config=config, api_key=api_key, scan_id=scan_id)

        findings = [
            {
                "title": f.title,
                "severity": f.severity.value,
                "url": f.url,
                "parameter": f.parameter,
                "payload": f.payload,
                "evidence": f.evidence,
                "owasp_category": f.owasp_category,
                "cwe": f.cwe,
                "cvss": f.cvss,
                "verified": f.verified,
                "confidence": f.confidence,
                "ai_verdict": f.ai_verdict,
                "ai_analysis": f.ai_analysis,
                "remediation": f.remediation,
            }
            for f in result_obj.findings
            if not f.false_positive_suppressed
        ]

        summary = result_obj.summary()
        with _lock:
            _scans[scan_id]["status"] = "complete"
            _scans[scan_id]["result"] = {
                "pages_crawled": result_obj.pages_crawled,
                "findings_count": len(findings),
                "duration_seconds": result_obj.scan_duration_seconds,
                "report": {
                    "summary": summary,
                    "findings": findings,
                    "compliance": [cr.summary() for cr in result_obj.compliance_reports],
                },
            }

    except Exception:
        with _lock:
            _scans[scan_id]["status"] = "error"
            _scans[scan_id]["error"] = traceback.format_exc()[-500:]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def serve(host: str = "0.0.0.0", port: int = 8080) -> None:
    """Start the blocking HTTP server. Call from CLI."""
    httpd = HTTPServer((host, port), _Handler)
    print(f"[+] KageSec API server listening on http://{host}:{port}")
    print(f"    POST /v1/scan          {{\"target\": \"https://example.com\", ...}}")
    print(f"    GET  /v1/scan/{{id}}    status + live counters")
    print(f"    GET  /v1/scan/{{id}}/report  full findings (when complete)")
    print(f"    GET  /v1/health        liveness check")
    print()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
        httpd.server_close()
