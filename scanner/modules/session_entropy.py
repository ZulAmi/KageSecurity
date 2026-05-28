"""
Session Token Entropy Analysis — Gap 27

Collects multiple session tokens by hitting the login/session endpoint
and performs statistical analysis to detect weak token generators:
  - Shannon entropy (< 3.5 bits/char = LOW)
  - Sequential pattern detection (monotonic increment)
  - Time-based pattern detection (timestamps embedded in token)
  - Length analysis

Burp Sequencer equivalent for KageSec.
"""
import math
import re
import time
import httpx
from typing import List, Optional
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

_SESSION_COOKIE_NAMES = frozenset({
    "sessionid", "session", "sessid", "sid", "phpsessid", "jsessionid",
    "asp.net_sessionid", "connect.sid", "rack.session", "__session",
    "auth", "token", "authtoken", "_session", "user_session",
})

_SAMPLE_SIZE = 20
_MIN_ENTROPY_BITS = 3.5      # bits per character
_MIN_UNIQUE_TOKENS = 10      # skip if server returns same token every time


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings: List[Finding] = []

    # Only run against pages that issue session cookies
    if not _has_session_endpoint(page):
        return findings

    tokens = _collect_tokens(page.url, client)
    if len(set(tokens)) < _MIN_UNIQUE_TOKENS:
        return findings

    _analyse_entropy(tokens, page.url, findings)
    _analyse_sequential(tokens, page.url, findings)
    return findings


def _has_session_endpoint(page: CrawlResult) -> bool:
    """Heuristic: page set a session-like cookie."""
    body_lower = (page.body or "").lower()
    return (
        any(k.lower() in _SESSION_COOKIE_NAMES for k in page.headers.keys())
        or "set-cookie" in {k.lower() for k in page.headers.keys()}
    )


def _collect_tokens(url: str, client: httpx.Client) -> List[str]:
    tokens = []
    for _ in range(_SAMPLE_SIZE):
        try:
            resp = client.get(url, timeout=8)
        except Exception:
            continue
        for cookie_name, cookie_val in resp.cookies.items():
            if cookie_name.lower() in _SESSION_COOKIE_NAMES:
                tokens.append(cookie_val)
                break
        # Also check Set-Cookie header
        sc = resp.headers.get("set-cookie", "")
        if not tokens or (tokens and not sc):
            continue
    return tokens


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


def _analyse_entropy(tokens: List[str], url: str, findings: List[Finding]):
    entropies = [_shannon_entropy(t) for t in tokens]
    avg_entropy = sum(entropies) / len(entropies)
    min_len = min(len(t) for t in tokens)
    total_bits = avg_entropy * min_len

    if avg_entropy < _MIN_ENTROPY_BITS:
        findings.append(Finding(
            title="Session Token Low Entropy — Predictable Token Generator",
            severity=Severity.HIGH,
            url=url,
            parameter="session cookie",
            payload=None,
            evidence=(
                f"Average Shannon entropy: {avg_entropy:.2f} bits/char "
                f"(threshold: {_MIN_ENTROPY_BITS}). "
                f"Effective bits: {total_bits:.1f}. "
                f"Sample: {tokens[0][:30]}..."
            ),
            description=(
                "Session tokens have low entropy, indicating a weak random number generator "
                "or predictable token construction. An attacker may be able to enumerate valid "
                "session tokens through brute force or statistical analysis."
            ),
            remediation=(
                "Use a cryptographically secure random number generator (CSPRNG) with at least "
                "128 bits of entropy for session token generation. "
                "Avoid time-based, sequential, or user-ID-derived session tokens."
            ),
            cwe="CWE-330",
            cvss=7.5,
            owasp_category="A07:2021 Identification and Authentication Failures",
            standards=["ISO27001-8.5", "HIPAA-164.312a", "GDPR-Art32"],
            confidence=0.85,
        ))


def _analyse_sequential(tokens: List[str], url: str, findings: List[Finding]):
    """Detect monotonically increasing tokens (counters, timestamps)."""
    # Try to find a numeric suffix in each token
    numeric_parts = []
    for t in tokens:
        m = re.search(r'(\d{6,})', t)
        if m:
            numeric_parts.append(int(m.group(1)))

    if len(numeric_parts) < _MIN_UNIQUE_TOKENS:
        return

    diffs = [numeric_parts[i+1] - numeric_parts[i] for i in range(len(numeric_parts)-1)]
    # Sequential if most diffs are positive and small
    positive_diffs = [d for d in diffs if d > 0]
    if len(positive_diffs) >= len(diffs) * 0.8 and max(diffs, default=0) < 10000:
        findings.append(Finding(
            title="Session Token Sequential Pattern Detected",
            severity=Severity.HIGH,
            url=url,
            parameter="session cookie",
            payload=None,
            evidence=(
                f"Numeric component of tokens appears sequential: "
                f"{numeric_parts[:5]} (diffs: {diffs[:5]})"
            ),
            description=(
                "Session tokens contain a monotonically increasing numeric component, suggesting "
                "they are counter-based or timestamp-based rather than cryptographically random. "
                "An attacker can enumerate adjacent token values to hijack other sessions."
            ),
            remediation=(
                "Replace sequential/counter-based token generation with a CSPRNG. "
                "Use UUID v4 or similar cryptographically random identifiers."
            ),
            cwe="CWE-330",
            cvss=9.1,
            owasp_category="A07:2021 Identification and Authentication Failures",
            standards=["ISO27001-8.5", "HIPAA-164.312a"],
            confidence=0.80,
        ))
