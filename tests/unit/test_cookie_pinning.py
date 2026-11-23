"""User-supplied session cookies must survive server Set-Cookie during fuzzing."""
from __future__ import annotations

import warnings

import httpx
import pytest

from scanner.utils.http import pin_cookies


def _server(log):
    def handler(req):
        cookie = req.headers.get("cookie", "")
        log.append(cookie)
        if "PHPSESSID='" in cookie:  # invalid session id → server starts a new session
            return httpx.Response(200, headers=[
                ("set-cookie", "PHPSESSID=NEWSESSION; path=/"),
                ("set-cookie", "security=impossible; path=/"),
                ("set-cookie", "tracking=abc; path=/"),
            ])
        return httpx.Response(200)
    return handler


@pytest.mark.parametrize("host", ["localhost:4280", "staging.example.com"])
def test_supplied_cookies_stay_authoritative(host):
    log: list[str] = []
    client = httpx.Client(transport=httpx.MockTransport(_server(log)),
                          cookies={"PHPSESSID": "GOOD", "security": "low"})
    pin_cookies(client, ["PHPSESSID", "security"])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # per-request cookies, as modules use
        client.get(f"http://{host}/probe", cookies={"PHPSESSID": "'", "security": "low"})
    client.get(f"http://{host}/after")
    sent = log[-1]
    assert "PHPSESSID=GOOD" in sent and "NEWSESSION" not in sent
    assert "security=low" in sent and "impossible" not in sent
    assert "tracking=abc" in sent  # unrelated server cookies still work


def test_without_pinning_the_jar_is_polluted():
    """Documents the behaviour pin_cookies exists to prevent."""
    log: list[str] = []
    client = httpx.Client(transport=httpx.MockTransport(_server(log)),
                          cookies={"PHPSESSID": "GOOD", "security": "low"})
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        client.get("http://staging.example.com/probe", cookies={"PHPSESSID": "'", "security": "low"})
    client.get("http://staging.example.com/after")
    assert "NEWSESSION" in log[-1] or "impossible" in log[-1]


def test_engine_pins_auth_cookies(local_site, monkeypatch):
    from scanner.core import engine
    from scanner.core.config import ScanConfig

    captured = {}
    real = engine.pin_cookies

    def spy(client, names):
        captured["names"] = set(names)
        return real(client, names)

    monkeypatch.setattr(engine, "pin_cookies", spy)
    engine.run_scan(config=ScanConfig(
        target=local_site, max_pages=1, modules=["security_headers"], use_oob=False,
        ai_enabled=False, auth={"type": "cookie", "cookies": {"sid": "x"}},
    ))
    assert captured["names"] == {"sid"}
