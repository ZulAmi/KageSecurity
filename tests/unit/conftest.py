"""Shared fixtures for unit tests."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


@pytest.fixture(autouse=True)
def isolated_kagesec_home(tmp_path, monkeypatch):
    """Keep every test away from the developer's real ~/.kagesec state."""
    from scanner.core import crawl_state, engine, findings_db, policy, suppressions

    home = tmp_path / "kagesec-home"
    home.mkdir()
    # Runtime expanduser() calls (plugins dir, profiles, schedules) resolve here too
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(findings_db, "_DB_PATH", str(home / "findings.db"))
    monkeypatch.setattr(crawl_state, "_STATE_DIR", str(home / "crawl_state"))
    monkeypatch.setattr(policy, "_CONFIG_PATH", str(home / "config.yaml"))
    monkeypatch.setattr(suppressions, "_SUPPRESSIONS_FILE", str(home / "suppressions.yaml"))
    monkeypatch.setattr(engine, "_CHECKPOINT_DIR", str(home / "checkpoints"))
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
                "MISTRAL_API_KEY", "GITHUB_OUTPUT", "KAGESEC_NO_AI", "KAGESEC_PASSIVE",
                "KAGESEC_MODULES", "KAGESEC_EXCLUDE", "KAGESEC_AUTH_BEARER",
                "KAGESEC_AUTH_COOKIE", "NVD_API_KEY", "KAGESEC_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    # Never probe for a local Ollama during tests
    monkeypatch.setattr("scanner.ai.provider._ollama_available", lambda *a, **k: False)
    return home


class _SiteHandler(BaseHTTPRequestHandler):
    """A tiny, deliberately header-less site: index links to /about and /logout."""

    pages = {
        "/": b'<html><body><a href="/about">About</a> <a href="/logout">Logout</a></body></html>',
        "/about": b"<html><body>About us</body></html>",
        "/logout": b"<html><body>Bye</body></html>",
    }

    def log_message(self, *args):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        body = self.pages.get(path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def local_site():
    """Serve _SiteHandler on 127.0.0.1:<random port>; yields the base URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SiteHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
