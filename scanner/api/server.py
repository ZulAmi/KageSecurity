"""
KageSec API server — `kagesec serve`.

Exposes a minimal HTTP API so CI/CD pipelines, dashboards, and external scripts
can orchestrate scans without shelling out to the CLI.

Endpoints:
  GET    /v1/health               → liveness check (no auth)
  POST   /v1/scan  {json config}  → queue a scan, returns scan_id
  GET    /v1/scan/{id}            → status + live counters
  GET    /v1/scan/{id}/report     → full findings JSON (only when complete)
  DELETE /v1/scan/{id}            → remove a finished scan from memory

Security model — this server makes the host send attack traffic, so:
  * it binds to 127.0.0.1 unless told otherwise;
  * every endpoint except /v1/health needs ``Authorization: Bearer <token>``;
  * POST bodies must be ``application/json`` (blocks cross-site form posts);
  * only an allowlist of ScanConfig fields is accepted — nothing that reads local
    files (HAR, cookie jars, wordlists, template dirs) or reroutes traffic (proxy);
  * scans run on a bounded worker pool with a bounded queue.

No external dependencies — uses Python's built-in http.server + threading.
"""
from __future__ import annotations

import hmac
import json
import secrets
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from scanner import __version__

MAX_BODY_BYTES = 1_000_000
MAX_PENDING_SCANS = 20       # queued + running
MAX_STORED_SCANS = 200       # finished scans kept in memory before the oldest is evicted

# ScanConfig fields a remote caller may set, with the type each must have.
# Anything not listed here (file paths, proxy, template dirs, code templates,
# login flows, wordlists) is rejected with 400.
_ALLOWED_FIELDS: dict[str, type | tuple[type, ...]] = {
    "target": str,
    "max_depth": int,
    "max_pages": int,
    "modules": list,
    "auth": dict,
    "headers": dict,
    "rate_limit_rps": int,
    "timeout": int,
    "compliance": list,
    "passive": bool,
    "include_patterns": list,
    "exclude_patterns": list,
    "level": int,
    "risk": int,
    "concurrency": int,
    "max_time_minutes": int,
    "use_oob": bool,
    "graphql_endpoint": str,
    "ai_enabled": bool,
    "nuclei_templates": bool,
}
_INT_BOUNDS = {
    "max_depth": (0, 10), "max_pages": (1, 5000), "rate_limit_rps": (1, 300),
    "timeout": (1, 120), "level": (1, 5), "risk": (1, 3), "concurrency": (1, 32),
    "max_time_minutes": (0, 24 * 60),
}


class _State:
    """Server-wide state, created by serve()."""

    def __init__(self, token: str, max_concurrent: int):
        self.token = token
        self.scans: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=max(1, max_concurrent), thread_name_prefix="kagesec-scan")


_state: _State | None = None


def validate_config(body: Any) -> tuple[dict | None, str | None]:
    """Return (clean_config, None) or (None, error_message)."""
    if not isinstance(body, dict):
        return None, "body must be a JSON object"
    unknown = sorted(set(body) - set(_ALLOWED_FIELDS))
    if unknown:
        return None, f"fields not allowed via the API: {', '.join(unknown)}"
    for key, value in body.items():
        expected = _ALLOWED_FIELDS[key]
        # bool is a subclass of int — don't accept True where an int is expected
        if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
            return None, f"'{key}' must be of type {getattr(expected, '__name__', expected)}"
        if key in _INT_BOUNDS:
            lo, hi = _INT_BOUNDS[key]
            if not lo <= value <= hi:
                return None, f"'{key}' must be between {lo} and {hi}"
    target = body.get("target")
    if not target:
        return None, "'target' is required"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None, "'target' must be an http(s) URL"
    return dict(body), None


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    server_version = "KageSec"
    sys_version = ""

    def log_message(self, format, *args):  # noqa: A002
        pass  # suppress default access log; server prints its own start message

    # ------------------------------------------------------------------ auth
    def _authorised(self) -> bool:
        header = self.headers.get("Authorization", "")
        scheme, _, supplied = header.partition(" ")
        if scheme.lower() != "bearer" or not supplied:
            return False
        return hmac.compare_digest(supplied.strip().encode(), _state.token.encode())

    def _require_auth(self) -> bool:
        if self._authorised():
            return True
        self._json(401, {"error": "missing or invalid bearer token"}, extra_headers={"WWW-Authenticate": "Bearer"})
        return False

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        if self.path == "/v1/health":
            self._json(200, {"status": "ok"})
            return
        if not self._require_auth():
            return
        parts = self.path.split("/")
        # /v1/scan/{id}  or  /v1/scan/{id}/report
        if self.path.startswith("/v1/scan/") and len(parts) == 4:
            self._get_status(parts[3])
        elif self.path.startswith("/v1/scan/") and len(parts) == 5 and parts[4] == "report":
            self._get_report(parts[3])
        elif self.path == "/v1/version":
            self._json(200, {"version": __version__})
        else:
            self._json(404, {"error": "Not found"})

    # ------------------------------------------------------------------ POST
    def do_POST(self):
        if self.path != "/v1/scan":
            self._json(404, {"error": "Not found"})
            return
        if not self._require_auth():
            return
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ctype != "application/json":
            self._json(415, {"error": "Content-Type must be application/json"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = -1
        if length <= 0 or length > MAX_BODY_BYTES:
            self._json(413 if length > MAX_BODY_BYTES else 400, {"error": "invalid Content-Length"})
            return
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self._json(400, {"error": f"Invalid JSON: {e}"})
            return

        cfg, err = validate_config(body)
        if err:
            self._json(400, {"error": err})
            return

        with _state.lock:
            active = sum(1 for s in _state.scans.values() if s["status"] in ("queued", "running"))
            if active >= MAX_PENDING_SCANS:
                self._json(429, {"error": "too many scans queued — retry later"}, extra_headers={"Retry-After": "30"})
                return
            _evict_finished_locked()
            scan_id = str(uuid.uuid4())
            _state.scans[scan_id] = {"status": "queued", "config_dict": cfg, "result": None, "error": None}

        _state.pool.submit(_run_scan_job, scan_id, cfg)
        self._json(202, {"scan_id": scan_id, "status": "queued"})

    # ------------------------------------------------------------------ DELETE
    def do_DELETE(self):
        if not self.path.startswith("/v1/scan/"):
            self._json(404, {"error": "Not found"})
            return
        if not self._require_auth():
            return
        scan_id = self.path.split("/")[-1]
        with _state.lock:
            state = _state.scans.get(scan_id)
            if state is None:
                self._json(404, {"error": "Scan not found"})
                return
            if state["status"] in ("queued", "running"):
                self._json(409, {"error": "Scan is still running"})
                return
            del _state.scans[scan_id]
        self._json(200, {"deleted": scan_id})

    # ------------------------------------------------------------------ helpers
    def _get_status(self, scan_id: str) -> None:
        with _state.lock:
            state = _state.scans.get(scan_id)
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
        with _state.lock:
            state = _state.scans.get(scan_id)
        if not state:
            self._json(404, {"error": "Scan not found"})
            return
        if state["status"] != "complete":
            self._json(425, {"error": "Scan not complete yet", "status": state["status"]})
            return
        self._json(200, state["result"].get("report", {}))

    def _json(self, status: int, body: dict, extra_headers: dict | None = None) -> None:
        data = json.dumps(body, indent=2, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


def _evict_finished_locked() -> None:
    """Drop the oldest finished scans once MAX_STORED_SCANS is reached. Caller holds the lock."""
    finished = [sid for sid, s in _state.scans.items() if s["status"] in ("complete", "error")]
    while len(_state.scans) >= MAX_STORED_SCANS and finished:
        del _state.scans[finished.pop(0)]


# ---------------------------------------------------------------------------
# Background scan runner
# ---------------------------------------------------------------------------

def _run_scan_job(scan_id: str, cfg: dict) -> None:
    with _state.lock:
        _state.scans[scan_id]["status"] = "running"

    try:
        from scanner.core.config import ScanConfig
        from scanner.core.engine import run_scan

        config = ScanConfig(**cfg)
        result_obj, _ = run_scan(config=config, scan_id=scan_id, concurrency=config.concurrency)

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

        with _state.lock:
            _state.scans[scan_id]["status"] = "complete"
            _state.scans[scan_id]["result"] = {
                "pages_crawled": result_obj.pages_crawled,
                "findings_count": len(findings),
                "duration_seconds": result_obj.scan_duration_seconds,
                "report": {
                    "summary": result_obj.summary(),
                    "findings": findings,
                    "compliance": [cr.summary() for cr in result_obj.compliance_reports],
                    "errors": [str(e) for e in result_obj.errors],
                },
            }

    except Exception:
        with _state.lock:
            _state.scans[scan_id]["status"] = "error"
            _state.scans[scan_id]["error"] = traceback.format_exc()[-500:]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def make_server(host: str = "127.0.0.1", port: int = 8080, token: str | None = None,
                max_concurrent: int = 1) -> tuple[ThreadingHTTPServer, str]:
    """Create (but do not start) the server. Returns (server, token)."""
    global _state
    token = token or secrets.token_urlsafe(32)
    _state = _State(token=token, max_concurrent=max_concurrent)
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.daemon_threads = True
    return httpd, token


def serve(host: str = "127.0.0.1", port: int = 8080, token: str | None = None,
          max_concurrent: int = 1) -> None:
    """Start the blocking HTTP server. Call from CLI."""
    generated = token is None
    httpd, token = make_server(host, port, token, max_concurrent)
    print(f"[+] KageSec API server listening on http://{host}:{port}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("[!] Listening on a non-loopback address — anyone who can reach this port and")
        print("    holds the token can make this machine send attack traffic.")
    if generated:
        print(f"[+] API token (generated for this session): {token}")
        print("    Set KAGESEC_API_TOKEN or pass --token to choose your own.")
    print('    curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\')
    print(f'         -d \'{{"target": "https://example.com"}}\' http://{host}:{port}/v1/scan')
    print()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
    finally:
        httpd.server_close()
        _state.pool.shutdown(wait=False, cancel_futures=True)
