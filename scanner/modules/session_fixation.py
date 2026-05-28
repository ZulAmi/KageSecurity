"""
Session Fixation Detection — Gap 9

Tests whether the server preserves a pre-authentication session token after
a successful login, which would allow an attacker to fixate a session and
hijack it once the victim authenticates.

Detection strategy:
  1. Obtain a fresh session cookie by visiting the login page
  2. Record the session token value
  3. Submit valid credentials (if login_flow is configured) or a probe
  4. Check whether the post-login session token is the same as pre-login
  5. Also check: does the server accept a manually supplied session token?

This module is most effective when a login_flow is configured in ScanConfig.
Without credentials, it falls back to detecting whether the server accepts
a client-supplied session token without regenerating it.
"""
import re
import httpx
from typing import List, Optional
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

# Common session cookie names
_SESSION_COOKIE_NAMES = frozenset({
    "sessionid", "session", "sessid", "sid", "phpsessid", "jsessionid",
    "asp.net_sessionid", "connect.sid", "rack.session", "__session",
    "auth", "token", "authtoken", "_session", "user_session",
})

_FIXED_TOKEN = "KageSec_FixedToken_AAAA1234BBBB5678"


def test(page: CrawlResult, client: httpx.Client, config=None) -> List[Finding]:
    findings: List[Finding] = []
    _detect_fixation(page, client, config, findings)
    return findings


def _detect_fixation(page: CrawlResult, client: httpx.Client, config, findings: List[Finding]):
    # Only run on pages that look like login forms
    if not _is_login_page(page):
        return

    login_flow = getattr(config, "login_flow", None)

    # Strategy A: With login_flow credentials — full fixation test
    if login_flow:
        _test_with_credentials(page, client, login_flow, findings)
    else:
        # Strategy B: No credentials — test if server accepts client-supplied token
        _test_token_acceptance(page, client, findings)


def _test_with_credentials(page: CrawlResult, client: httpx.Client, login_flow, findings: List[Finding]):
    """Full session fixation test using configured credentials."""
    login_url = getattr(login_flow, "url", page.url)
    username = getattr(login_flow, "username", "")
    password = getattr(login_flow, "password", "")
    username_field = getattr(login_flow, "username_field", "username")
    password_field = getattr(login_flow, "password_field", "password")

    # Step 1: get pre-login session
    pre_cookies: dict = {}
    try:
        pre_resp = client.get(login_url, timeout=10)
        pre_cookies = dict(pre_resp.cookies)
    except Exception:
        return

    pre_session = _extract_session(pre_cookies)
    if not pre_session:
        return

    pre_token = pre_session[1]

    # Step 2: authenticate
    try:
        post_resp = client.post(login_url, data={
            username_field: username,
            password_field: password,
        }, timeout=10)
    except Exception:
        return

    post_cookies = dict(post_resp.cookies)
    post_session = _extract_session(post_cookies)

    if not post_session:
        # Try following the redirect
        try:
            follow_resp = client.get(post_resp.headers.get("location", login_url), timeout=10)
            post_session = _extract_session(dict(follow_resp.cookies))
        except Exception:
            return

    if not post_session:
        return

    post_token = post_session[1]

    # Step 3: compare tokens
    if pre_token == post_token and len(pre_token) > 4:
        findings.append(Finding(
            title="Session Fixation — Token Not Regenerated After Login",
            severity=Severity.HIGH,
            url=login_url,
            parameter=pre_session[0],
            payload=f"{pre_session[0]}={pre_token}",
            evidence=(
                f"Session cookie '{pre_session[0]}' has the same value before and after login: "
                f"'{pre_token[:20]}...'"
            ),
            description=(
                "The application does not regenerate the session token upon successful "
                "authentication. An attacker who knows the pre-authentication session ID "
                "(obtained by social engineering, XSS, or network sniffing) can fixate a "
                "session and immediately hijack it after the victim logs in."
            ),
            remediation=(
                "Call session regeneration on every successful login: "
                "PHP: session_regenerate_id(true); "
                "Django: request.session.cycle_key(); "
                "Express: req.session.regenerate(); "
                "Invalidate the old session token server-side."
            ),
            cwe="CWE-384",
            cvss=8.1,
            owasp_category="A07:2021 Identification and Authentication Failures",
            standards=["ISO27001-8.5", "HIPAA-164.312a", "GDPR-Art32"],
            confidence=0.95,
        ))


def _test_token_acceptance(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Check if the server accepts a client-supplied session token (no credentials needed)."""
    # Send a request with a known fake session token
    for name in _SESSION_COOKIE_NAMES:
        try:
            resp = client.get(page.url, cookies={name: _FIXED_TOKEN}, timeout=10)
        except Exception:
            continue

        # Check if our supplied token is reflected or accepted (Set-Cookie not overwriting it)
        set_cookie_header = resp.headers.get("set-cookie", "")
        if name in set_cookie_header:
            # Server sent a new Set-Cookie — good, it's regenerating
            new_val = _parse_cookie_value(set_cookie_header, name)
            if new_val and new_val == _FIXED_TOKEN:
                findings.append(Finding(
                    title="Session Fixation — Server Accepts Client-Supplied Session Token",
                    severity=Severity.HIGH,
                    url=page.url,
                    parameter=name,
                    payload=f"{name}={_FIXED_TOKEN}",
                    evidence=(
                        f"Server echoed the client-supplied token '{_FIXED_TOKEN[:20]}...' "
                        f"back in Set-Cookie: {name}"
                    ),
                    description=(
                        "The server accepts and reuses session tokens supplied by the client "
                        "instead of generating its own. An attacker can pre-set a known session "
                        "token and, after the victim authenticates, use that token to hijack the session."
                    ),
                    remediation=(
                        "Always generate session tokens server-side on session creation. "
                        "Ignore any client-supplied session IDs. "
                        "Regenerate the session token on login."
                    ),
                    cwe="CWE-384",
                    cvss=7.5,
                    owasp_category="A07:2021 Identification and Authentication Failures",
                    standards=["ISO27001-8.5", "HIPAA-164.312a"],
                    confidence=0.80,
                ))
                break
        # If no Set-Cookie issued at all, the server silently accepted our token
        elif not set_cookie_header and resp.status_code == 200:
            findings.append(Finding(
                title="Session Fixation — No Session Token Regeneration Detected",
                severity=Severity.MEDIUM,
                url=page.url,
                parameter=name,
                payload=f"{name}={_FIXED_TOKEN}",
                evidence=(
                    f"Request with client-supplied '{name}={_FIXED_TOKEN[:20]}...' returned "
                    f"HTTP {resp.status_code} with no Set-Cookie regeneration"
                ),
                description=(
                    "The server did not issue a new session token after receiving a client-supplied "
                    "session identifier. This may indicate session fixation vulnerability."
                ),
                remediation=(
                    "Generate session tokens server-side. Regenerate on login. "
                    "Validate that session tokens were created by the server, not supplied by clients."
                ),
                cwe="CWE-384",
                cvss=6.5,
                owasp_category="A07:2021 Identification and Authentication Failures",
                standards=["ISO27001-8.5"],
                confidence=0.55,
            ))
            break


def _is_login_page(page: CrawlResult) -> bool:
    """Heuristic: page has a password input field."""
    body_lower = (page.body or "").lower()
    return (
        'type="password"' in body_lower
        or "type='password'" in body_lower
        or "password" in body_lower and ("login" in body_lower or "signin" in body_lower)
    )


def _extract_session(cookies: dict) -> Optional[tuple]:
    """Return (cookie_name, cookie_value) for the first recognised session cookie."""
    for name, value in cookies.items():
        if name.lower() in _SESSION_COOKIE_NAMES:
            return (name, value)
    return None


def _parse_cookie_value(set_cookie_header: str, name: str) -> Optional[str]:
    m = re.search(rf'{re.escape(name)}=([^;,\s]+)', set_cookie_header, re.IGNORECASE)
    return m.group(1) if m else None
