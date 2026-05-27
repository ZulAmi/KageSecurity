"""
AI-powered CVE researcher.

Design philosophy:
  KageSec has Claude — it can reason about what to check rather than brute-forcing
  thousands of templates against every page. The workflow is:

  1. Fingerprint the target's tech stack from headers and body across all pages.
  2. Check the local cache (~/.kagesec/cve_cache/) for this exact stack fingerprint.
     Cache hit → skip Claude entirely, reuse the cached CVE list (30-day TTL).
  3. Cache miss → ask Claude for the 10 most relevant CVEs for this specific stack.
     Save the response to cache. Total payload: ~5-10KB per unique stack, not gigabytes.
  4. Run only the targeted verification requests Claude returned.
  5. Report confirmed findings.

  This means:
  - First scan of "WordPress 5.8 + PHP 7.4": one Claude call, ~5KB cached.
  - Every subsequent scan of any WordPress 5.8 site: zero Claude calls, instant.
  - A site with a novel stack: one Claude call, cached for 30 days.
  - No bulk downloads. No YAML sprawl. No firing 500 probes per page.
"""

from __future__ import annotations

import os
import re
import json
import time
import hashlib
from typing import Optional
import anthropic

from scanner.core.scan_result import Finding, Severity

_CACHE_DIR = os.path.expanduser("~/.kagesec/cve_cache")
_CACHE_TTL_SECONDS = 30 * 24 * 60 * 60   # 30 days

_SYSTEM_PROMPT = """You are a CVE research expert and penetration tester.

Given a detected web application technology stack, identify the most critical known CVEs
that apply to the specific versions detected. For each CVE, provide a safe, read-only
HTTP verification request that a scanner can use to confirm the issue.

Respond ONLY with a valid JSON array. No markdown, no prose. Schema:
[
  {
    "cve_id": "CVE-YYYY-NNNNN",
    "name": "Short human-readable name",
    "severity": "critical|high|medium|low",
    "cvss": 9.8,
    "cwe": "CWE-22",
    "owasp": "A06:2021",
    "affected_component": "Software Name and vulnerable version range",
    "description": "One sentence — what the vulnerability is and what an attacker gains.",
    "remediation": "Specific version to upgrade to or configuration change.",
    "verification": {
      "method": "GET|POST",
      "path": "/exact/path",
      "headers": {},
      "body": null,
      "match_in": "body|header",
      "match_pattern": "regex that confirms the vulnerability",
      "confidence": 0.85
    }
  }
]

Rules:
- Only include CVEs where the detected version is within the confirmed vulnerable range.
- Limit to the top 10 most critical/high CVEs.
- Verification must be safe and read-only (path traversal, error disclosure, version
  fingerprint, timing oracle). Never writes, account creation, or DoS.
- If no confident CVEs exist for this stack, return [].
"""

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
}


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _cache_key(fingerprints: dict[str, str]) -> str:
    """Stable hash of the sorted fingerprint dict — same stack = same key."""
    stable = json.dumps(sorted(fingerprints.items()), sort_keys=True)
    return hashlib.sha256(stable.encode()).hexdigest()[:16]


def _cache_path(key: str) -> str:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    return os.path.join(_CACHE_DIR, f"{key}.json")


def _read_cache(fingerprints: dict[str, str]) -> list[dict] | None:
    path = _cache_path(_cache_key(fingerprints))
    try:
        with open(path) as f:
            entry = json.load(f)
        if time.time() - entry.get("ts", 0) < _CACHE_TTL_SECONDS:
            return entry["cves"]
    except Exception:
        pass
    return None


def _write_cache(fingerprints: dict[str, str], cves: list[dict]) -> None:
    path = _cache_path(_cache_key(fingerprints))
    try:
        with open(path, "w") as f:
            json.dump({"ts": time.time(), "stack": fingerprints, "cves": cves}, f, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# AI research
# ---------------------------------------------------------------------------

def research_cves(fingerprints: dict[str, str], api_key: str) -> list[dict]:
    """
    Return CVEs for this tech stack. Checks cache first; only calls Claude on a miss.
    """
    if not fingerprints or not api_key:
        return []

    # Cache hit — skip Claude entirely
    cached = _read_cache(fingerprints)
    if cached is not None:
        return cached

    # Cache miss — ask Claude
    tech_summary = "\n".join(f"  - {k}: {v}" for k, v in fingerprints.items())
    prompt = (
        f"Technology stack detected:\n{tech_summary}\n\n"
        "Return the top CVEs for this exact stack as a JSON array."
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text.strip()
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1].lstrip("json").strip() if len(parts) >= 2 else raw

        cves = json.loads(raw)
        if isinstance(cves, list):
            _write_cache(fingerprints, cves)   # save for next 30 days
            return cves
    except Exception:
        pass

    return []


# ---------------------------------------------------------------------------
# Verification + finding builder
# ---------------------------------------------------------------------------

def verify_and_build_findings(cve_list: list[dict], base_url: str, http_client) -> list[Finding]:
    """Execute only the targeted verification requests Claude identified. No bulk probing."""
    findings = []

    for cve in cve_list:
        verification = cve.get("verification", {})
        if not verification:
            # No verification step — report as informational fingerprint match only
            findings.append(_make_finding(cve, base_url, None, None, confirmed=False))
            continue

        path = verification.get("path", "/")
        url = base_url.rstrip("/") + path
        method = verification.get("method", "GET").upper()
        headers = verification.get("headers", {})
        body = verification.get("body")
        match_in = verification.get("match_in", "body")
        match_pattern = verification.get("match_pattern", "")
        confidence = float(verification.get("confidence", 0.5))

        try:
            resp = _make_request(http_client, method, url, headers, body)
            if resp is None:
                continue

            status, resp_body, resp_headers = resp
            target = (
                resp_body if match_in == "body"
                else " ".join(f"{k}: {v}" for k, v in resp_headers.items())
            )

            confirmed = False
            if match_pattern:
                try:
                    confirmed = bool(re.search(match_pattern, target, re.IGNORECASE | re.DOTALL))
                except re.error:
                    confirmed = match_pattern.lower() in target.lower()
            else:
                confirmed = status < 400

            if confirmed or confidence >= 0.7:
                findings.append(
                    _make_finding(cve, url, resp_body[:300] if confirmed else None, status, confirmed=confirmed)
                )

        except Exception:
            continue

    return findings


def _make_request(client, method: str, url: str, headers: dict, body: Optional[str]):
    try:
        kwargs = {"headers": headers}
        if method == "GET":
            resp = client.get(url, **kwargs)
        elif method == "POST":
            resp = client.post(url, content=body, **kwargs)
        elif method == "PUT":
            resp = client.put(url, content=body, **kwargs)
        elif method == "DELETE":
            resp = client.delete(url, **kwargs)
        else:
            resp = client.get(url, **kwargs)

        return resp.status_code, getattr(resp, "text", ""), dict(getattr(resp, "headers", {}))
    except Exception:
        return None


def _make_finding(cve: dict, url: str, evidence_body: Optional[str], status: Optional[int], confirmed: bool) -> Finding:
    cve_id = cve.get("cve_id", "Unknown CVE")
    severity = _SEVERITY_MAP.get(cve.get("severity", "medium").lower(), Severity.MEDIUM)

    evidence = f"AI CVE: {cve_id} — {cve.get('affected_component', 'unknown component')}"
    if status is not None:
        evidence += f" | HTTP {status}"
    if evidence_body and confirmed:
        evidence += f" | Confirmed: {evidence_body[:200]}"
    else:
        evidence += " (stack fingerprint match — not yet verified)"

    return Finding(
        title=f"{'[Verified] ' if confirmed else ''}CVE: {cve.get('name', cve_id)}",
        severity=severity,
        url=url,
        parameter=None,
        payload=None,
        evidence=evidence,
        description=(
            f"{cve.get('description', '')} "
            f"Affected: {cve.get('affected_component', 'detected component')}."
        ),
        remediation=cve.get("remediation", f"Apply the vendor patch for {cve_id}."),
        cwe=cve.get("cwe"),
        cvss=float(cve.get("cvss", 0.0)),
        owasp_category=cve.get("owasp", "A06:2021"),
        standards={"CVE": cve_id, "OWASP": cve.get("owasp", "A06:2021")},
        confidence=0.85 if confirmed else 0.55,
        verified=confirmed,
    )
