"""
Padding Oracle detection.

A padding oracle vulnerability exists when an application decrypts attacker-
supplied ciphertext (e.g. in a cookie or parameter) and returns a different
response when the padding is invalid versus when the padding is valid but the
plaintext is wrong. An attacker can exploit this to decrypt arbitrary ciphertext
or forge valid ciphertext without knowing the key.

Detection strategy (safe, read-only):
  1. Identify base64-like or hex values in cookies and URL parameters
  2. Flip the last byte of the value (simulating invalid padding)
  3. Compare response status/size/body to the original
  4. If the responses are statistically different, a padding oracle may exist

This is a probabilistic signal — human verification is recommended.
"""
from __future__ import annotations

import base64
import re
from typing import List

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity
from scanner.utils.http import fetch

_B64_RE   = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
_HEX_RE   = re.compile(r'[0-9a-fA-F]{32,}')
_MAX_VALS = 3   # cap candidate values per page


def _flip_last_byte_b64(value: str) -> str | None:
    """Decode, flip the last byte, re-encode."""
    try:
        padded = value + "=" * (-len(value) % 4)
        raw = bytearray(base64.b64decode(padded, validate=False))
        if not raw:
            return None
        raw[-1] ^= 0x01
        return base64.b64encode(bytes(raw)).decode().rstrip("=")
    except Exception:
        return None


def _flip_last_byte_hex(value: str) -> str | None:
    try:
        raw = bytearray(bytes.fromhex(value))
        if not raw:
            return None
        raw[-1] ^= 0x01
        return raw.hex()
    except Exception:
        return None


def _candidate_values(page: CrawlResult) -> list[tuple[str, str, str]]:
    """
    Return (location, name, value) tuples for b64/hex values in cookies and params.
    location: 'cookie' | 'param'
    """
    candidates = []

    # Cookie values
    cookie_hdr = page.headers.get("set-cookie", "")
    for match in _B64_RE.finditer(cookie_hdr):
        candidates.append(("cookie", "set-cookie", match.group()))
        if len(candidates) >= _MAX_VALS:
            return candidates

    # URL query params
    from urllib.parse import urlparse, parse_qs
    qs = parse_qs(urlparse(page.url).query)
    for name, vals in qs.items():
        v = vals[0]
        if _B64_RE.fullmatch(v) or _HEX_RE.fullmatch(v):
            candidates.append(("param", name, v))
            if len(candidates) >= _MAX_VALS:
                return candidates

    return candidates


def test(page: CrawlResult, client) -> List[Finding]:
    if page.status_code not in (200, 302, 400):
        return []

    candidates = _candidate_values(page)
    if not candidates:
        return []

    findings: List[Finding] = []

    for location, name, value in candidates:
        # Try flipping as b64 first, then hex
        flipped = _flip_last_byte_b64(value) or _flip_last_byte_hex(value)
        if not flipped or flipped == value:
            continue

        if location == "param":
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(page.url)
            qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            qs[name] = flipped
            probe_url = urlunparse(parsed._replace(query=urlencode(qs)))
            resp = fetch(client, "get", probe_url)
        else:
            # Cookie — modify the header value in the request
            resp = fetch(client, "get", page.url,
                         headers={"Cookie": f"{name}={flipped}"})

        if resp is None:
            continue

        orig_status = page.status_code
        new_status  = getattr(resp, "status_code", 0)
        orig_len    = len(page.body or "")
        new_len     = len(getattr(resp, "text", "") or "")

        # Heuristic: different status code, OR response length diverges by >20%
        status_diff = orig_status != new_status
        size_diff   = orig_len > 0 and abs(new_len - orig_len) / orig_len > 0.20

        if status_diff or size_diff:
            findings.append(Finding(
                title="Potential Padding Oracle Vulnerability",
                severity=Severity.HIGH,
                url=page.url,
                parameter=name,
                payload=flipped,
                evidence=(
                    f"Modified {location} '{name}' by flipping the last byte of the ciphertext. "
                    f"Original response: HTTP {orig_status}, {orig_len} bytes. "
                    f"Modified response: HTTP {new_status}, {new_len} bytes. "
                    f"Statistically different responses indicate possible padding oracle."
                ),
                description=(
                    "The application appears to distinguish between invalid padding and valid "
                    "padding with wrong plaintext when decrypting ciphertext supplied in a "
                    f"{location}. This is the hallmark of a padding oracle vulnerability (e.g. "
                    "CBC mode without authenticated encryption), which allows an attacker to "
                    "decrypt arbitrary ciphertext or forge valid tokens without knowing the key."
                ),
                remediation=(
                    "Use authenticated encryption (AES-GCM or ChaCha20-Poly1305) instead of "
                    "unauthenticated CBC mode. If using CBC, apply an HMAC over the ciphertext "
                    "BEFORE decrypting (Encrypt-then-MAC). Return identical error responses for "
                    "all decryption failures to prevent oracle behaviour."
                ),
                cwe="CWE-649",
                cvss=7.5,
                owasp_category="A02:2021 Cryptographic Failures",
                confidence=0.65,
            ))
            break   # one finding per page is enough — human review required

    return findings
