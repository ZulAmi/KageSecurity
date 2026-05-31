"""
Parameter Name Discovery — Gap 11

Brute-forces parameter names against each page to discover hidden or undocumented
parameters. Uses a two-tier wordlist and variance-based baseline to match the
detection quality of professional tools (Burp Param Miner, Arjun):

  Tier 1 (security-critical): debug, admin, isAdmin, bypass, callback, redirect,
    file, cmd, token, etc. — full detection: status change, JSONP reflection,
    security content patterns, body length diff above measured baseline variance.

  Tier 2 (medium-confidence): format, version, id, feature flags — conservative:
    status change and JSONP reflection only. Body length diff is intentionally
    ignored because these params legitimately resize responses.

Attack classes found:
  - Debug/trace parameters (debug=1, trace=true)
  - Admin bypass parameters (isAdmin=true, role=admin)
  - JSONP/callback injection (callback=evil)
  - Open redirect / SSRF parameters (next=, redirect=, url=)
  - Command injection vectors (cmd=, exec=, action=)
  - File/path inclusion vectors (file=, include=, load=)
"""
import os
import re
import yaml
import httpx
from typing import List, Tuple
from urllib.parse import urlparse, urlunparse, parse_qs
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

_BUILTIN_PARAMS = os.path.join(os.path.dirname(__file__), "..", "payloads", "params.yaml")

# Probe values chosen to be unlikely in legitimate responses but reveal active params.
# Security-specific values per param — param-specific probes reduce echo-reflection noise.
_PROBE_VALUES: dict = {
    "debug":        ["1", "true"],
    "trace":        ["1", "true"],
    "verbose":      ["1", "true"],
    "log":          ["1", "true"],
    "admin":        ["1", "true"],
    "isAdmin":      ["true", "1"],
    "is_admin":     ["true", "1"],
    "role":         ["admin", "superuser"],
    "superuser":    ["1", "true"],
    "privileged":   ["1", "true"],
    "bypass":       ["1", "true"],
    "override":     ["1", "true"],
    "internal":     ["1", "true"],
    "callback":     ["kagesecjsonp"],
    "jsonp":        ["kagesecjsonp"],
    "format":       ["json", "xml", "debug"],
    "output":       ["json", "debug"],
    "type":         ["admin", "debug", "internal"],
    "env":          ["dev", "staging", "debug"],
    "environment":  ["dev", "staging", "debug"],
    "mode":         ["debug", "dev", "admin"],
    "beta":         ["1", "true"],
    "experimental": ["1", "true"],
    "enable":       ["1", "true", "admin"],
    "feature":      ["admin", "debug"],
    "flag":         ["admin", "debug"],
}
_DEFAULT_PROBE = ["kagesec_probe_1337"]

# Response content patterns that indicate a security-relevant parameter effect.
# These are the "what changed" signals — not just "how much changed".
_SECURITY_CONTENT_PATTERNS: list = [
    re.compile(r'debug\s*[:=]\s*true', re.I),
    re.compile(r'isAdmin\s*[:=]\s*true', re.I),
    re.compile(r'"admin"\s*:\s*true', re.I),
    re.compile(r'"role"\s*:\s*"admin"', re.I),
    re.compile(r'Traceback\s+\(most recent call', re.I),   # Python stack trace
    re.compile(r'\tat\s+\S+\.java:\d+'),                    # Java stack trace
    re.compile(r'(?:Fatal error|Warning|Notice):\s+\S', re.I),  # PHP errors
    re.compile(r'SQL syntax.*?MySQL|mysql_fetch_|ORA-\d{5}', re.I),  # DB errors
    re.compile(r'<b>(?:Warning|Fatal error|Parse error)</b>', re.I),
    re.compile(r'"diagnostic"[:\s]|"telemetry"[:\s]', re.I),
    re.compile(r'X-Debug-Token|X-Symfony-Cache', re.I),    # Symfony debug headers echoed
]

# Minimum absolute diff for Tier 1 length-based detection (fallback floor).
# The dynamic variance threshold takes precedence when the page varies naturally.
_FLOOR_DIFF_BYTES = 500
_FLOOR_DIFF_PCT = 0.25


def test(page: CrawlResult, client: httpx.Client, config=None) -> List[Finding]:
    findings: List[Finding] = []
    tier1, tier2 = _load_params(config)
    if not tier1 and not tier2:
        return findings
    _probe_params(page, client, tier1, tier2, findings)
    return findings


def _load_params(config) -> Tuple[List[str], List[str]]:
    custom = getattr(config, "param_wordlist", None)
    path = custom if (custom and os.path.isfile(custom)) else _BUILTIN_PARAMS
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            if "tier1" in data or "tier2" in data:
                t1 = [str(p) for p in (data.get("tier1") or []) if p]
                t2 = [str(p) for p in (data.get("tier2") or []) if p]
                return t1, t2
            # Backwards-compatible flat format: treat all as tier1
            if "params" in data:
                flat = [str(p) for p in data["params"] if p]
                return flat, []
        if isinstance(data, list):
            return [str(p) for p in data if p], []
    except Exception:
        pass
    return [], []


def _probe_params(
    page: CrawlResult,
    client: httpx.Client,
    tier1: List[str],
    tier2: List[str],
    findings: List[Finding],
):
    # Two baseline requests to measure natural page variance (Arjun / Param Miner pattern).
    # Only flag length diffs that are significantly larger than baseline variance.
    try:
        b1 = client.get(page.url, timeout=8)
        b2 = client.get(page.url, timeout=8)
    except Exception:
        return

    baseline_status = b1.status_code
    if baseline_status >= 500:
        return

    natural_variance = abs(len(b2.text) - len(b1.text))
    baseline_len = (len(b1.text) + len(b2.text)) // 2
    # Dynamic threshold: at least 3x the natural variance, floored at _FLOOR_DIFF_BYTES.
    # This prevents flagging pages whose content legitimately changes between requests
    # (timestamps, nonces, CSRF tokens, session-specific data).
    dynamic_threshold = max(natural_variance * 3, _FLOOR_DIFF_BYTES)

    parsed = urlparse(page.url)
    existing_params = set(parse_qs(parsed.query).keys())
    waf_blocked = False

    all_params = [(p, 1) for p in tier1] + [(p, 2) for p in tier2]

    for param, tier in all_params:
        if param in existing_params:
            continue
        if waf_blocked:
            break

        probe_values = _PROBE_VALUES.get(param, _DEFAULT_PROBE)

        for val in probe_values:
            probe_url = _add_param(page.url, param, val)
            try:
                resp = client.get(probe_url, timeout=8)
            except Exception:
                continue

            status_changed = resp.status_code != baseline_status
            jsonp_reflected = param in ("callback", "jsonp") and val in resp.text

            # WAF/rate-limit guard: if server suddenly blocks us, stop probing.
            if status_changed and resp.status_code in (403, 429, 503):
                try:
                    recheck = client.get(page.url, timeout=8)
                    if recheck.status_code != baseline_status:
                        waf_blocked = True
                        break
                except Exception:
                    pass
            if waf_blocked:
                break

            # Plain echo-reflection: error pages often echo unknown param values back.
            # Exclude this as a signal unless JSONP or security pattern also present.
            probe_reflected = (val in resp.text) and (val not in b1.text)

            # Security content patterns — look at WHAT changed, not just how much.
            security_pattern_hit = any(
                pat.search(resp.text) and not pat.search(b1.text)
                for pat in _SECURITY_CONTENT_PATTERNS
            )

            len_diff = abs(len(resp.text) - baseline_len)
            pct_diff = len_diff / max(baseline_len, 1)
            len_diff_significant = len_diff > dynamic_threshold and pct_diff > _FLOOR_DIFF_PCT

            # Tier 1: full detection
            if tier == 1:
                interesting = (
                    status_changed
                    or jsonp_reflected
                    or security_pattern_hit
                    or (len_diff_significant and not (probe_reflected and not security_pattern_hit))
                )
            else:
                # Tier 2: conservative — status change or JSONP only.
                # Length diff is intentionally excluded: format, version, id etc.
                # legitimately change response size and would cause false positives.
                interesting = status_changed or jsonp_reflected

            if not interesting:
                continue

            # Assign severity
            if jsonp_reflected:
                severity = Severity.HIGH
                cvss = 6.1
                confidence = 0.90
            elif status_changed or security_pattern_hit:
                severity = Severity.MEDIUM
                cvss = 5.3
                confidence = 0.80
            else:
                # Length diff only — lower confidence
                severity = Severity.LOW
                cvss = 3.1
                confidence = 0.55

            evidence_parts = []
            if status_changed:
                evidence_parts.append(f"status: {baseline_status}→{resp.status_code}")
            if len_diff_significant:
                evidence_parts.append(f"body length: ~{baseline_len}→{len(resp.text)} (diff {len_diff}B, variance {natural_variance}B)")
            if jsonp_reflected:
                evidence_parts.append(f"JSONP callback '{val}' reflected in response")
            if security_pattern_hit:
                evidence_parts.append("security content pattern detected in response")

            findings.append(Finding(
                title=f"Hidden Parameter Discovered — {param}",
                severity=severity,
                url=page.url,
                parameter=param,
                payload=val,
                evidence="; ".join(evidence_parts),
                description=(
                    f"The undocumented parameter '{param}' caused a measurably different server "
                    f"response when set to '{val}'. This suggests a hidden debug, admin, or "
                    "feature-flag parameter that was not intended to be publicly accessible."
                ),
                remediation=(
                    "Remove debug and admin parameters from production builds. "
                    "Validate and reject unexpected parameters server-side. "
                    "Do not use query parameters for access control decisions. "
                    "Ensure JSONP callbacks are not callable from untrusted origins."
                ),
                cwe="CWE-200",
                cvss=cvss,
                owasp_category="A05:2021 Security Misconfiguration",
                confidence=confidence,
            ))
            break  # one finding per param name


def _add_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    existing = parsed.query
    new_qs = f"{existing}&{name}={value}" if existing else f"{name}={value}"
    return urlunparse(parsed._replace(query=new_qs))
