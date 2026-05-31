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

Performance: once a param is confirmed on a host it is not re-probed on later
pages — equivalent to Arjun's binary-search isolation avoiding redundant requests.
The central dedup in ScanResult.add_finding() prevents duplicate findings; this
cache prevents duplicate network requests.

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
import threading
import yaml
import httpx
from collections import defaultdict
from typing import List, Tuple
from urllib.parse import urlparse, urlunparse, parse_qs
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

_BUILTIN_PARAMS = os.path.join(os.path.dirname(__file__), "..", "payloads", "params.yaml")

# Per-host cache of confirmed param names — once found, skip re-probing on other pages.
# Equivalent to Arjun's binary-search isolation: no redundant network requests for
# params already confirmed on this host. Resets per process (one scan per invocation).
_confirmed_host_params: dict = defaultdict(set)
_confirmed_lock = threading.Lock()

# Probe values chosen to be unlikely in legitimate responses but reveal active params.
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

# Response content patterns — look at WHAT changed, not just how much (Param Miner approach).
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
            if "params" in data:
                # Backwards-compatible flat format: treat all as tier1
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
    host = urlparse(page.url).netloc

    # Two baseline requests to measure natural page variance — Burp Param Miner uses 4,
    # Arjun uses 2. We use 2: enough to detect dynamic content (timestamps, nonces,
    # CSRF tokens) without excessive overhead.
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
    # Dynamic threshold: 3× natural variance, floored at _FLOOR_DIFF_BYTES.
    # Prevents flagging pages that legitimately vary between requests.
    dynamic_threshold = max(natural_variance * 3, _FLOOR_DIFF_BYTES)

    # Canary: random non-existent parameter used to build a "random param baseline"
    # — the same technique Param Miner and Arjun use to prevent false positives on
    # param-sensitive pages. Neither tool skips the page; instead they disable
    # detection factors that fire for ANY random param (Arjun's factor-nulling),
    # and only flag probes that cause a LARGER change than the canary (Param Miner's
    # "similar to baseline" check).
    canary_param = f"_kgsec_{os.urandom(4).hex()}"
    canary_val = os.urandom(6).hex()
    canary_status_changed = False
    canary_len_diff = 0
    try:
        canary_resp = client.get(_add_param(page.url, canary_param, canary_val), timeout=8)
        canary_status_changed = canary_resp.status_code != baseline_status
        canary_len_diff = abs(len(canary_resp.text) - baseline_len)
    except Exception:
        pass

    # Disable detection factors that the canary already triggers (Arjun's approach):
    # — Status change: if any random param changes status, status detection is noise
    # — Length diff: raise threshold to 2× canary diff so probe must cause MUCH more
    #   change than a random param (Param Miner's "similar to random-param baseline")
    use_status_change = not canary_status_changed
    canary_length_threshold = max(canary_len_diff * 2, dynamic_threshold)

    parsed = urlparse(page.url)
    existing_params = set(parse_qs(parsed.query).keys())
    waf_blocked = False

    all_params = [(p, 1) for p in tier1] + [(p, 2) for p in tier2]

    for param, tier in all_params:
        if param in existing_params:
            continue
        if waf_blocked:
            break

        # Skip params already confirmed on this host — central dedup in add_finding()
        # would reject the finding anyway; this prevents the network request entirely.
        with _confirmed_lock:
            if param in _confirmed_host_params[host]:
                continue

        probe_values = _PROBE_VALUES.get(param, _DEFAULT_PROBE)

        for val in probe_values:
            probe_url = _add_param(page.url, param, val)
            try:
                resp = client.get(probe_url, timeout=8)
            except Exception:
                continue

            # Apply canary-adjusted factors (disabled if canary already triggered them)
            status_changed = use_status_change and (resp.status_code != baseline_status)
            jsonp_reflected = param in ("callback", "jsonp") and val in resp.text

            # WAF/rate-limit guard: re-check clean baseline before flagging a block.
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

            # Plain echo-reflection: error pages often echo unknown param values.
            probe_reflected = (val in resp.text) and (val not in b1.text)

            # Content pattern analysis — look at WHAT changed (Param Miner approach).
            security_pattern_hit = any(
                pat.search(resp.text) and not pat.search(b1.text)
                for pat in _SECURITY_CONTENT_PATTERNS
            )

            len_diff = abs(len(resp.text) - baseline_len)
            pct_diff = len_diff / max(baseline_len, 1)
            # Must exceed canary_length_threshold (2× what a random param caused)
            # so only probes that cause SUBSTANTIALLY more change than noise are flagged
            len_diff_significant = len_diff > canary_length_threshold and pct_diff > _FLOOR_DIFF_PCT

            # Tier 1: full detection — any of: status, JSONP, content pattern, length diff
            # Tier 2: conservative — status or JSONP only (length diff excluded because
            #   format, version, id etc. legitimately alter response size)
            if tier == 1:
                interesting = (
                    status_changed
                    or jsonp_reflected
                    or security_pattern_hit
                    or (len_diff_significant and not (probe_reflected and not security_pattern_hit))
                )
            else:
                interesting = status_changed or jsonp_reflected

            if not interesting:
                continue

            if jsonp_reflected:
                severity = Severity.HIGH
                cvss = 6.1
                confidence = 0.90
            elif status_changed or security_pattern_hit:
                severity = Severity.MEDIUM
                cvss = 5.3
                confidence = 0.80
            else:
                severity = Severity.LOW
                cvss = 3.1
                confidence = 0.55

            evidence_parts = []
            if status_changed:
                evidence_parts.append(f"status: {baseline_status}→{resp.status_code}")
            if len_diff_significant:
                evidence_parts.append(
                    f"body length: ~{baseline_len}→{len(resp.text)} "
                    f"(diff {len_diff}B, page variance {natural_variance}B)"
                )
            if jsonp_reflected:
                evidence_parts.append(f"JSONP callback '{val}' reflected in response")
            if security_pattern_hit:
                evidence_parts.append("security content pattern detected in response")

            with _confirmed_lock:
                _confirmed_host_params[host].add(param)

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
