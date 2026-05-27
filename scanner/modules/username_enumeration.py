"""
Username / email enumeration detection.

Two techniques:
1. Response differentiation: compare response body/status for valid vs invalid usernames
2. Timing oracle: measure response time difference for existing vs non-existing accounts

Targets: /login, /forgot-password, /reset-password, /register endpoints.
"""
import re
import time
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

_SENSITIVE_PATH_RE = re.compile(
    r"/(login|signin|sign-in|forgot[_-]?password|reset[_-]?password|password[_-]?reset"
    r"|register|signup|sign-up|check[_-]?email|verify[_-]?email)",
    re.IGNORECASE,
)

_ENUM_SIGNALS = [
    re.compile(r"(user|account|email|username).{0,30}(not found|does not exist|invalid|no account)", re.IGNORECASE),
    re.compile(r"(incorrect password|wrong password|invalid credentials)", re.IGNORECASE),
    re.compile(r"we.{0,10}(sent|emailed|mailed).{0,40}(if|when).{0,30}exist", re.IGNORECASE),
]

_NOISY_USER = "kagesec_noexist_xzq@invalid-domain-93847.com"
_EXISTING_USERS = ["admin", "administrator", "test@example.com", "user@example.com", "info@"]

# Timing threshold: if valid user takes Xms longer, suspect timing oracle
_TIMING_THRESHOLD_MS = 300
_PROBE_REPEATS = 3


def test(page: CrawlResult, client) -> List[Finding]:
    if not _SENSITIVE_PATH_RE.search(page.url):
        return []

    findings = []

    for form in page.forms:
        if form.get("method", "get").lower() != "post":
            continue

        inputs = form.get("inputs", [])
        user_field = _find_field(inputs, ("email", "username", "user", "login", "identifier"))
        pass_field = _find_field(inputs, ("password", "pass", "pwd"))

        if not user_field:
            continue

        action = form.get("action", page.url)

        # Build base payload
        base_data = {}
        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue
            base_data[name] = inp.get("value", "") or _placeholder(inp.get("type", "text"))

        # --- Technique 1: Response Differentiation ---
        finding = _check_response_diff(action, base_data, user_field, pass_field, client)
        if finding:
            findings.append(finding)
            continue

        # --- Technique 2: Timing Oracle ---
        finding = _check_timing(action, base_data, user_field, pass_field, client)
        if finding:
            findings.append(finding)

    return findings


def _check_response_diff(action, base_data, user_field, pass_field, client) -> Finding | None:
    nonexist_data = dict(base_data)
    nonexist_data[user_field] = _NOISY_USER
    if pass_field:
        nonexist_data[pass_field] = "WrongPass123!"

    try:
        resp_nonexist = client.post(action, data=nonexist_data)
    except Exception:
        return None

    body_nonexist = resp_nonexist.text.lower() if hasattr(resp_nonexist, "text") else ""

    # Test with a common username that may exist
    for candidate in _EXISTING_USERS:
        exist_data = dict(base_data)
        exist_data[user_field] = candidate
        if pass_field:
            exist_data[pass_field] = "WrongPass123!"

        try:
            resp_exist = client.post(action, data=exist_data)
        except Exception:
            continue

        body_exist = resp_exist.text.lower() if hasattr(resp_exist, "text") else ""

        # Different status codes
        if resp_nonexist.status_code != resp_exist.status_code:
            return _make_finding(
                action, user_field,
                f"HTTP {resp_exist.status_code} for known username '{candidate}' "
                f"vs HTTP {resp_nonexist.status_code} for non-existent user",
                "Response Status Differentiation", Severity.MEDIUM, 0.85,
            )

        # Different body content signals
        for sig in _ENUM_SIGNALS:
            nonexist_match = bool(sig.search(body_nonexist))
            exist_match = bool(sig.search(body_exist))
            if nonexist_match and not exist_match:
                snippet = sig.search(body_nonexist).group(0)[:80]
                return _make_finding(
                    action, user_field,
                    f"Non-existent user response contains: '{snippet}' — not present for '{candidate}'",
                    "Response Body Differentiation", Severity.MEDIUM, 0.80,
                )

        # Body length difference > 20%
        len_e = len(body_exist)
        len_n = len(body_nonexist)
        if len_e > 0 and len_n > 0:
            ratio = abs(len_e - len_n) / max(len_e, len_n)
            if ratio > 0.20:
                return _make_finding(
                    action, user_field,
                    f"Response size differs by {ratio:.0%} ({len_e} vs {len_n} bytes) between known and unknown users",
                    "Response Size Differentiation", Severity.LOW, 0.65,
                )

    return None


def _check_timing(action, base_data, user_field, pass_field, client) -> Finding | None:
    def avg_time(username):
        data = dict(base_data)
        data[user_field] = username
        if pass_field:
            data[pass_field] = "WrongPass123!"
        times = []
        for _ in range(_PROBE_REPEATS):
            t0 = time.monotonic()
            try:
                client.post(action, data=data)
            except Exception:
                pass
            times.append((time.monotonic() - t0) * 1000)
        return sum(times) / len(times) if times else 0

    t_nonexist = avg_time(_NOISY_USER)

    for candidate in _EXISTING_USERS[:2]:  # limit to avoid slow scans
        t_exist = avg_time(candidate)
        diff = t_exist - t_nonexist

        if diff > _TIMING_THRESHOLD_MS:
            return _make_finding(
                action, user_field,
                f"Average response time for '{candidate}': {t_exist:.0f}ms vs non-existent user: {t_nonexist:.0f}ms "
                f"(Δ {diff:.0f}ms > {_TIMING_THRESHOLD_MS}ms threshold)",
                "Response Timing Differentiation", Severity.MEDIUM, 0.70,
            )

    return None


def _make_finding(url, param, evidence, technique, severity, confidence) -> Finding:
    return Finding(
        title=f"Username Enumeration via {technique}",
        severity=severity,
        url=url,
        parameter=param,
        payload=_NOISY_USER,
        evidence=evidence,
        description=(
            f"The endpoint {url} reveals whether a username or email address exists in the system "
            f"through {technique.lower()}. Attackers can exploit this to build a list of valid "
            "accounts for targeted credential-stuffing or phishing campaigns."
        ),
        remediation=(
            "Return identical responses for both valid and invalid usernames (generic: 'If that email exists, "
            "you will receive a reset link'). Add artificial delay to equalise timing. "
            "Implement rate limiting and account lockout to slow enumeration attempts."
        ),
        owasp_category="A07:2021 Identification and Authentication Failures",
        cwe="CWE-204",
        cvss=5.3,
        confidence=confidence,
        standards={"OWASP": "A07:2021", "CWE": "CWE-204"},
    )


def _find_field(inputs: list, keywords: tuple) -> str | None:
    for inp in inputs:
        name = (inp.get("name") or "").lower()
        itype = (inp.get("type") or "").lower()
        if any(kw in name for kw in keywords) or itype in keywords:
            return inp.get("name", "")
    return None


def _placeholder(itype: str) -> str:
    return {"email": "test@example.com", "password": "Test1234!", "number": "1"}.get(itype, "test")
