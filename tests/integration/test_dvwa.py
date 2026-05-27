"""
Integration tests against DVWA (Damn Vulnerable Web Application).

Requires: docker compose up -d dvwa dvwa-db
          Wait ~30s for DVWA to initialise its DB, then run:
          pytest tests/integration/test_dvwa.py -v

These tests assert minimum true-positive counts (we MUST find what we claim to find)
and a false-negative ceiling (we must not miss critical classes entirely).
"""
import pytest
from scanner.core.config import ScanConfig
from scanner.core.engine import run_scan
from scanner.core.scan_result import Severity

DVWA_URL = "http://localhost:4280"

# DVWA ships with security level = low, so all categories should fire
EXPECTED_CATEGORIES = {
    "sqli":           {"min_findings": 1, "severity": Severity.CRITICAL},
    "xss":            {"min_findings": 1, "severity": Severity.HIGH},
    "csrf":           {"min_findings": 1, "severity": Severity.MEDIUM},
    "path_traversal": {"min_findings": 1, "severity": Severity.HIGH},
    "cmd_injection":  {"min_findings": 1, "severity": Severity.CRITICAL},
}


@pytest.fixture(scope="module")
def dvwa_scan():
    config = ScanConfig(
        target=DVWA_URL,
        max_depth=2,
        max_pages=30,
        auth={
            "type": "cookie",
            "cookies": {
                "PHPSESSID": _dvwa_session(),
                "security": "low",
            },
        },
    )
    result, _ = run_scan(config=config)
    return result


def _dvwa_session() -> str:
    """Log in to DVWA and return the session cookie."""
    import httpx
    client = httpx.Client(follow_redirects=True)
    login = client.get(f"{DVWA_URL}/login.php")
    token = _extract_csrf(login.text)
    resp = client.post(f"{DVWA_URL}/login.php", data={
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token,
    })
    assert resp.status_code == 200, "DVWA login failed"
    phpsessid = resp.cookies.get("PHPSESSID")
    assert phpsessid, "No PHPSESSID cookie after login"
    return phpsessid


def _extract_csrf(html: str) -> str:
    import re
    m = re.search(r'name=["\']user_token["\'][^>]*value=["\'](.*?)["\']', html)
    return m.group(1) if m else ""


# --- True-positive assertions ---

def test_sqli_detected(dvwa_scan):
    sqli = [f for f in dvwa_scan.findings if "sql" in f.title.lower()]
    assert len(sqli) >= EXPECTED_CATEGORIES["sqli"]["min_findings"], (
        f"Expected at least {EXPECTED_CATEGORIES['sqli']['min_findings']} SQLi finding(s), got {len(sqli)}"
    )


def test_xss_detected(dvwa_scan):
    xss = [f for f in dvwa_scan.findings if "xss" in f.title.lower() or "cross-site" in f.title.lower()]
    assert len(xss) >= EXPECTED_CATEGORIES["xss"]["min_findings"]


def test_csrf_detected(dvwa_scan):
    csrf = [f for f in dvwa_scan.findings if "csrf" in f.title.lower()]
    assert len(csrf) >= EXPECTED_CATEGORIES["csrf"]["min_findings"]


def test_path_traversal_detected(dvwa_scan):
    pt = [f for f in dvwa_scan.findings if "traversal" in f.title.lower() or "path" in f.title.lower()]
    assert len(pt) >= EXPECTED_CATEGORIES["path_traversal"]["min_findings"]


def test_cmd_injection_detected(dvwa_scan):
    cmd = [f for f in dvwa_scan.findings if "command" in f.title.lower() or "injection" in f.title.lower()]
    assert len(cmd) >= EXPECTED_CATEGORIES["cmd_injection"]["min_findings"]


# --- Coverage assertion ---

def test_no_empty_scan(dvwa_scan):
    assert dvwa_scan.pages_crawled > 0, "No pages were crawled"
    assert len(dvwa_scan.findings) > 0, "No findings at all — scanner is broken"


def test_scan_has_critical_or_high(dvwa_scan):
    high_or_crit = [
        f for f in dvwa_scan.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    assert len(high_or_crit) > 0, "DVWA should have at least one CRITICAL or HIGH finding"
