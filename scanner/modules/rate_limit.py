import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

LOGIN_PATH_HINTS = {"login", "signin", "authenticate", "auth", "session", "token", "oauth"}
RESET_PATH_HINTS = {"reset", "forgot", "password", "recover"}
BURST_COUNT = 30


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    path_lower = page.url.lower()

    is_login = any(hint in path_lower for hint in LOGIN_PATH_HINTS)
    is_reset = any(hint in path_lower for hint in RESET_PATH_HINTS)

    if not (is_login or is_reset) and not page.forms:
        return []

    # Find a login-like form on this page
    target_form = None
    for form in page.forms:
        input_types = {i.get("type", "").lower() for i in form["inputs"]}
        if "password" in input_types or is_login:
            target_form = form
            break

    if not target_form and not (is_login or is_reset):
        return []

    url = target_form["action"] if target_form else page.url
    method = target_form["method"].upper() if target_form else "POST"
    data = (
        {i["name"]: "wrongpassword" for i in target_form["inputs"] if i["name"]}
        if target_form else {"username": "admin", "password": "wrongpassword"}
    )

    status_codes = []
    for _ in range(BURST_COUNT):
        try:
            resp = client.request(method, url, data=data)
            status_codes.append(resp.status_code)
        except Exception:
            break

    if not status_codes:
        return []

    got_429 = 429 in status_codes
    got_lockout = any(c in status_codes for c in (423, 403))
    all_200 = all(c == 200 for c in status_codes)

    if all_200 and not got_429 and not got_lockout:
        hint = "login" if is_login else "password reset"
        findings.append(Finding(
            title=f"Missing Rate Limiting on {hint.title()} Endpoint",
            severity=Severity.MEDIUM,
            url=url,
            parameter=None,
            payload=None,
            evidence=(
                f"Sent {BURST_COUNT} rapid {method} requests to {url}. "
                f"All returned HTTP 200 — no 429 Too Many Requests or account lockout detected."
            ),
            description=(
                f"The {hint} endpoint does not rate-limit or lock out accounts after repeated failed attempts, "
                "enabling brute-force and credential stuffing attacks."
            ),
            remediation=(
                "Implement rate limiting (e.g., 5 attempts per minute per IP). "
                "Add account lockout after N consecutive failures. "
                "Use CAPTCHA for login forms. "
                "Monitor and alert on high-velocity authentication failures."
            ),
            cwe="CWE-770",
            cvss=5.3,
            owasp_category="A07:2021 Identification and Authentication Failures",
            standards=["ISO27001-8.8", "HIPAA-164.312a", "GDPR-Art32"],
            confidence=0.85,
        ))

    return findings
