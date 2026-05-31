"""
Parameter Name Discovery — Gap 11

Brute-forces parameter names against each page to discover hidden or undocumented
parameters. Detection relies on response differentiation — if adding a parameter
causes the response to differ significantly (length, status code, content) from
the baseline, that parameter is considered active.

Attack classes found:
  - Debug/trace parameters (debug=1, trace=true)
  - Admin bypass parameters (isAdmin=true, role=admin)
  - JSONP/callback injection (callback=evil)
  - Hidden redirect parameters (next=, return=, to=)
  - Feature flag parameters (beta=1, experimental=true)
"""
import os
import threading
import yaml
import httpx
from typing import List
from urllib.parse import urlparse, urlunparse, parse_qs
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

# Deduplicate across pages — track (host, param) pairs already reported
_seen: set = set()
_seen_lock = threading.Lock()

_BUILTIN_PARAMS = os.path.join(os.path.dirname(__file__), "..", "payloads", "params.yaml")

# Probe values that are unlikely to be in real responses but reveal active params
_PROBE_VALUES = {
    "debug": ["1", "true", "yes"],
    "admin": ["1", "true"],
    "isAdmin": ["true", "1"],
    "format": ["json", "xml"],
    "callback": ["kagesecjsonp"],
    "default": ["kagesec_param_probe_1337"],
}

_MIN_DIFF_BYTES = 2000   # minimum absolute body length difference to flag
_MIN_DIFF_PCT   = 0.20   # also require ≥20% change — filters dynamic pages with small natural variation
_MIN_DIFF_STATUS = True  # flag if status code changes


def test(page: CrawlResult, client: httpx.Client, config=None) -> List[Finding]:
    findings: List[Finding] = []
    params = _load_params(config)
    if not params:
        return findings
    _probe_params(page, client, params, findings)
    return findings


def _load_params(config) -> List[str]:
    custom = getattr(config, "param_wordlist", None)
    path = custom if (custom and os.path.isfile(custom)) else _BUILTIN_PARAMS
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict) and "params" in data:
            return [str(p) for p in data["params"] if p]
        if isinstance(data, list):
            return [str(p) for p in data if p]
    except Exception:
        pass
    return []


def _probe_params(page: CrawlResult, client: httpx.Client, params: List[str], findings: List[Finding]):
    # Baseline response
    try:
        baseline = client.get(page.url, timeout=8)
    except Exception:
        return

    baseline_status = baseline.status_code
    baseline_len = len(baseline.text)

    parsed = urlparse(page.url)
    existing_params = set(parse_qs(parsed.query).keys())
    _waf_blocked = False

    for param in params:
        if param in existing_params:
            continue
        if _waf_blocked:
            break

        # Choose probe values for this param
        probe_values = _PROBE_VALUES.get(param, _PROBE_VALUES["default"])

        for val in probe_values:
            probe_url = _add_param(page.url, param, val)
            try:
                resp = client.get(probe_url, timeout=8)
            except Exception:
                continue

            status_changed = resp.status_code != baseline_status
            len_diff = abs(len(resp.text) - baseline_len)

            # Interesting if JSONP callback reflected or status changed or body differs
            jsonp_reflected = param == "callback" and val in resp.text

            # Skip plain echo-reflection: probe value appears in response but not in baseline
            # (common for error pages that say "unknown param: <value>" — not a real active param)
            probe_reflected = (val in resp.text) and (val not in baseline.text)
            if probe_reflected and not jsonp_reflected:
                continue

            # WAF/rate-limit guard: if status changed to 4xx, re-check the clean baseline
            # to confirm the server hasn't started blocking all requests from our IP
            if status_changed and resp.status_code in (403, 429, 503):
                try:
                    recheck = client.get(page.url, timeout=8)
                    if recheck.status_code != baseline_status:
                        _waf_blocked = True
                        break
                except Exception:
                    pass

            if _waf_blocked:
                break

            pct_diff = len_diff / max(baseline_len, 1)
            interesting = (
                status_changed
                or (len_diff > _MIN_DIFF_BYTES and pct_diff > _MIN_DIFF_PCT)
                or jsonp_reflected
            )
            if not interesting:
                continue

            severity = Severity.HIGH if jsonp_reflected else (
                Severity.MEDIUM if status_changed else Severity.LOW
            )

            evidence_parts = []
            if status_changed:
                evidence_parts.append(f"status: {baseline_status}→{resp.status_code}")
            if len_diff > _MIN_DIFF_BYTES:
                evidence_parts.append(f"body length: {baseline_len}→{len(resp.text)} (diff {len_diff}B)")
            if jsonp_reflected:
                evidence_parts.append(f"JSONP callback '{val}' reflected in response")

            host = urlparse(page.url).netloc
            dedup_key = (host, param)
            with _seen_lock:
                if dedup_key in _seen:
                    break
                _seen.add(dedup_key)

            findings.append(Finding(
                title=f"Hidden Parameter Discovered — {param}",
                severity=severity,
                url=page.url,
                parameter=param,
                payload=val,
                evidence="; ".join(evidence_parts),
                description=(
                    f"The undocumented parameter '{param}' caused a different server response "
                    f"when set to '{val}'. This may indicate a hidden debug, admin, or feature "
                    "flag parameter that was not intended to be publicly accessible."
                ),
                remediation=(
                    "Remove debug and admin parameters from production. "
                    "Validate and reject unexpected parameters. "
                    "Do not use query parameters for access control decisions. "
                    "Ensure JSONP callbacks are not callable from untrusted origins."
                ),
                cwe="CWE-200",
                cvss=5.3 if not jsonp_reflected else 6.1,
                owasp_category="A05:2021 Security Misconfiguration",
                confidence=0.75,
            ))
            break  # one finding per param name


def _add_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    existing = parsed.query
    new_qs = f"{existing}&{name}={value}" if existing else f"{name}={value}"
    return urlunparse(parsed._replace(query=new_qs))
