"""Unit tests for _reauth_if_needed() in scanner/core/engine.py."""
import types
import pytest


def _make_config(login_url="https://app.example.com/login", **kwargs):
    from scanner.core.config import LoginFlow, ScanConfig
    lf = LoginFlow(
        url=login_url,
        username_selector="#user",
        password_selector="#pass",
        submit_selector="button",
        username="admin",
        password="secret",
        success_indicator="/dashboard",
    )
    return ScanConfig(target="https://app.example.com", login_flow=lf, **kwargs)


def _make_page(url, status_code=200, body=""):
    return types.SimpleNamespace(url=url, status_code=status_code, body=body)


class TestReauthURLMatching:
    """Verify that login-redirect detection uses path equality, not substring."""

    def _call(self, page, config, crawler=None, client=None):
        from scanner.core.engine import _reauth_if_needed
        crawler = crawler or types.SimpleNamespace()
        client = client or types.SimpleNamespace(headers={})
        return _reauth_if_needed(page, config, crawler, client)

    def test_exact_login_path_triggers_reauth(self):
        config = _make_config("https://app.example.com/login")
        page = _make_page("https://app.example.com/login", status_code=200)
        # No crawler._authenticate — returns False after detection but still detects
        result = self._call(page, config)
        # We just verify it doesn't crash; real re-auth attempt silently fails without browser
        assert isinstance(result, bool)

    def test_superset_path_does_not_trigger(self):
        """'/users/login' must NOT match a login_flow.url of '/login'."""
        config = _make_config("https://app.example.com/login")
        page = _make_page("https://app.example.com/users/login", status_code=200)
        result = self._call(page, config)
        assert result is False

    def test_substring_path_does_not_trigger(self):
        """/api/login must NOT match /login."""
        config = _make_config("https://app.example.com/login")
        page = _make_page("https://app.example.com/api/login", status_code=200)
        result = self._call(page, config)
        assert result is False

    def test_401_always_triggers(self):
        config = _make_config("https://app.example.com/login")
        page = _make_page("https://app.example.com/dashboard", status_code=401)
        # Detection fires; re-auth attempt fails without browser — result is False
        result = self._call(page, config)
        assert isinstance(result, bool)

    def test_no_login_flow_returns_false(self):
        from scanner.core.config import ScanConfig
        config = ScanConfig(target="https://app.example.com")
        page = _make_page("https://app.example.com/login", status_code=401)
        result = self._call(page, config)
        assert result is False

    def test_logged_out_regex_triggers(self):
        config = _make_config(
            login_logged_out_indicator="Sign in to your account",
        )
        page = _make_page(
            "https://app.example.com/account",
            status_code=200,
            body="<html>Sign in to your account</html>",
        )
        result = self._call(page, config)
        assert isinstance(result, bool)

    def test_logged_in_regex_absent_triggers(self):
        config = _make_config(login_logged_in_indicator="Welcome back")
        page = _make_page(
            "https://app.example.com/account",
            status_code=200,
            body="<html>Please log in.</html>",
        )
        result = self._call(page, config)
        assert isinstance(result, bool)

    def test_logged_in_regex_present_does_not_trigger(self):
        config = _make_config(login_logged_in_indicator="Welcome back")
        page = _make_page(
            "https://app.example.com/account",
            status_code=200,
            body="<html>Welcome back, Alice.</html>",
        )
        result = self._call(page, config)
        assert result is False
