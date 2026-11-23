"""
Integration tests against DVWA (Damn Vulnerable Web Application).

Requires: docker compose -f tests/integration/docker-compose.yml up -d --wait dvwa dvwa-db
          pytest tests/integration/test_dvwa.py -v
The fixture creates DVWA's database and logs in itself.

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


# Pages that would end the session or change the test setup if crawled or fuzzed:
# logout ends the session, setup.php resets the DB, security.php changes the level.
EXCLUDE = ["*logout*", "*setup.php*", "*security.php*"]

# The modules this suite asserts on. The clean-nginx suite runs every module.
MODULES = ["sqli", "xss", "csrf", "path_traversal", "cmd_injection", "security_headers"]


@pytest.fixture(scope="module")
def dvwa_scan():
    config = ScanConfig(
        target=DVWA_URL,
        max_depth=2,
        max_pages=30,
        modules=MODULES,
        exclude_patterns=EXCLUDE,
        use_oob=False,
        rate_limit_rps=50,     # local container
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
    """Create DVWA's database, log in as admin, and return an authenticated PHPSESSID.

    Fails loudly if the session does not reach the logged-in home page — otherwise the
    scan silently crawls nothing but the login form.
    """
    import httpx
    diag: list[str] = []

    def note(label, resp):
        diag.append(
            f"{label}: {resp.status_code} {resp.url} | set-cookie={resp.headers.get_list('set-cookie')}"
            f" | messages={_messages(resp.text)}"
        )

    with httpx.Client(base_url=DVWA_URL, follow_redirects=True, timeout=30) as client:
        setup = client.get("/setup.php")
        note("GET setup.php", setup)
        note("POST setup.php", client.post("/setup.php", data={
            "create_db": "Create / Reset Database",
            "user_token": _extract_csrf(setup.text),
        }))
        login = client.get("/login.php")
        note("GET login.php", login)
        note("POST login.php", client.post("/login.php", data={
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": _extract_csrf(login.text),
        }))
        diag.append(f"cookie jar: {[(c.name, c.domain, c.path) for c in client.cookies.jar]}")
        home = client.get("/index.php")
        assert "login.php" not in str(home.url), (
            f"DVWA login failed — landed on {home.url}\n" + "\n".join(diag)
        )
        # The jar holds every cookie set during the flow (the final response alone may not).
        sessions = [c.value for c in client.cookies.jar if c.name == "PHPSESSID"]
        assert sessions, "No PHPSESSID cookie after login"
        return sessions[-1]


def _messages(html: str) -> list[str]:
    """DVWA's on-page status messages (login failures, setup results)."""
    import re
    found = re.findall(r'<div class=["\']message["\']>(.*?)</div>', html, re.S)
    return [re.sub(r"<[^>]+>", " ", m).strip()[:200] for m in found]


def _extract_csrf(html: str) -> str:
    import re
    m = re.search(r'name=["\']user_token["\'][^>]*value=["\'](.*?)["\']', html)
    return m.group(1) if m else ""


# --- True-positive assertions ---

def _titled(scan, *needles):
    return [f for f in scan.findings if any(n in f.title.lower() for n in needles)]


def test_session_was_authenticated(dvwa_scan):
    urls = {f.url for f in dvwa_scan.findings}
    assert dvwa_scan.pages_crawled > 3, f"Only {dvwa_scan.pages_crawled} page(s) crawled — session not authenticated?"
    assert any("/vulnerabilities/" in u for u in urls), "No findings under /vulnerabilities/ — crawl never got past login"


def test_sqli_detected(dvwa_scan):
    sqli = [f for f in dvwa_scan.findings if f.title.lower().startswith("sql injection")]
    assert len(sqli) >= EXPECTED_CATEGORIES["sqli"]["min_findings"], (
        f"Expected at least {EXPECTED_CATEGORIES['sqli']['min_findings']} SQLi finding(s), got {len(sqli)}"
    )


def test_xss_detected(dvwa_scan):
    xss = _titled(dvwa_scan, "cross-site scripting", "xss")
    assert len(xss) >= EXPECTED_CATEGORIES["xss"]["min_findings"]


def test_csrf_detected(dvwa_scan):
    csrf = _titled(dvwa_scan, "csrf", "cross-site request forgery")
    assert len(csrf) >= EXPECTED_CATEGORIES["csrf"]["min_findings"]


def test_path_traversal_detected(dvwa_scan):
    pt = _titled(dvwa_scan, "path traversal", "directory traversal", "file inclusion")
    assert len(pt) >= EXPECTED_CATEGORIES["path_traversal"]["min_findings"]


def test_cmd_injection_detected(dvwa_scan):
    cmd = _titled(dvwa_scan, "command injection")
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
