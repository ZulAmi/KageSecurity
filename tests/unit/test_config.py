"""Unit tests for scanner/core/config.py"""
import pytest
from scanner.core.config import ScanConfig, LoginFlow


class TestScanConfigDefaults:
    def test_required_target(self):
        c = ScanConfig(target="http://example.com")
        assert c.target == "http://example.com"

    def test_default_depth_and_pages(self):
        c = ScanConfig(target="http://x.com")
        assert c.max_depth == 3
        assert c.max_pages == 100

    def test_default_rate_limit(self):
        c = ScanConfig(target="http://x.com")
        assert c.rate_limit_rps == 10

    def test_default_passive_false(self):
        c = ScanConfig(target="http://x.com")
        assert c.passive is False

    def test_default_browser_false(self):
        c = ScanConfig(target="http://x.com")
        assert c.browser is False

    def test_default_follow_robots_false(self):
        c = ScanConfig(target="http://x.com")
        assert c.follow_robots is False

    def test_default_use_oob_true(self):
        c = ScanConfig(target="http://x.com")
        assert c.use_oob is True

    def test_default_oob_server(self):
        c = ScanConfig(target="http://x.com")
        assert c.oob_server == "oast.pro"

    def test_override_fields(self):
        c = ScanConfig(
            target="http://x.com",
            max_depth=5,
            max_pages=200,
            passive=True,
            browser=True,
            follow_robots=True,
            use_oob=False,
        )
        assert c.max_depth == 5
        assert c.max_pages == 200
        assert c.passive is True
        assert c.browser is True
        assert c.follow_robots is True
        assert c.use_oob is False

    def test_default_compliance_empty(self):
        c = ScanConfig(target="http://x.com")
        assert c.compliance == []

    def test_default_level_and_risk(self):
        c = ScanConfig(target="http://x.com")
        assert c.level == 1
        assert c.risk == 1

    def test_modules_none_means_all(self):
        c = ScanConfig(target="http://x.com")
        assert c.modules is None


class TestLoginFlow:
    def test_login_flow_fields(self):
        flow = LoginFlow(
            url="http://x.com/login",
            username_selector="#user",
            password_selector="#pass",
            submit_selector="button[type=submit]",
            username="admin",
            password="secret",
            success_indicator="/dashboard",
        )
        assert flow.url == "http://x.com/login"
        assert flow.totp_secret is None

    def test_login_flow_with_totp(self):
        flow = LoginFlow(
            url="http://x.com/login",
            username_selector="#user",
            password_selector="#pass",
            submit_selector="button",
            username="admin",
            password="pass",
            success_indicator="/home",
            totp_secret="JBSWY3DPEHPK3PXP",
        )
        assert flow.totp_secret == "JBSWY3DPEHPK3PXP"
