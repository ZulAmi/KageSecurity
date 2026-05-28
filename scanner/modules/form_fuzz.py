"""
Form fuzzing module — FuzzDB-style exhaustive input testing.

For every form discovered on a page, injects each payload from all YAML
payload databases into each field independently (one field fuzzed at a time,
others filled with benign values) and checks the response for:
  - SQL error strings       → SQLi
  - Reflected payload       → XSS
  - Path traversal markers  → LFI
  - Template expression     → SSTI
  - Command output          → RCE
  - SSRF indicators         → SSRF

This is the exhaustive complement to the targeted injection modules — it
ensures every form input is tested even when the URL has no query params.
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlencode

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity
from scanner.utils.http import fetch
from scanner.core.payload_loader import load as _load_payloads

# Fuzz payload sets — small but representative across classes
# Loaded from scanner/payloads/form_fuzz.yaml; hardcoded list is the fallback.
_FUZZ_PAYLOADS_RAW = _load_payloads("form_fuzz") or []

def _build_fuzz_payloads():
    _sev_map = {
        "critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
    }
    result = []
    for row in _FUZZ_PAYLOADS_RAW:
        if isinstance(row, (list, tuple)) and len(row) >= 6:
            payload, cls, detect, sev_s, cwe, owasp = row[:6]
            result.append((str(payload), str(cls), str(detect),
                           _sev_map.get(str(sev_s).lower(), Severity.MEDIUM),
                           str(cwe), str(owasp)))
    return result or _FUZZ_PAYLOADS_FALLBACK

_FUZZ_PAYLOADS_FALLBACK: list[tuple[str, str, str, Severity, str, str]] = [
    # (payload, class_name, detection_string_in_response, severity, cwe, owasp)
    ("'", "SQLi probe", "sql syntax", Severity.CRITICAL, "CWE-89", "A03:2021 Injection"),
    ("' OR '1'='1", "SQLi boolean", "sql syntax", Severity.CRITICAL, "CWE-89", "A03:2021 Injection"),
    ("<script>alert(1)</script>", "XSS reflected", "<script>alert(1)</script>", Severity.HIGH, "CWE-79", "A03:2021 Injection"),
    ("{{7*7}}", "SSTI probe", "49", Severity.HIGH, "CWE-1336", "A03:2021 Injection"),
    ("${7*7}", "SSTI EL probe", "49", Severity.HIGH, "CWE-1336", "A03:2021 Injection"),
    ("../../../../etc/passwd", "Path traversal", "root:x:0:0", Severity.HIGH, "CWE-22", "A01:2021 Broken Access Control"),
    (";id;", "Command injection", "uid=", Severity.CRITICAL, "CWE-78", "A03:2021 Injection"),
    ("| id", "Command injection pipe", "uid=", Severity.CRITICAL, "CWE-78", "A03:2021 Injection"),
    ("http://169.254.169.254/latest/meta-data/", "SSRF AWS", "ami-id", Severity.HIGH, "CWE-918", "A10:2021 SSRF"),
    ("%00", "Null byte", "Warning:", Severity.LOW, "CWE-20", "A03:2021 Injection"),
]

_SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()", "ora-01756", "sqlite_",
]

_MAX_FORMS   = 5    # cap forms per page to avoid explosion
_MAX_INPUTS  = 8    # cap inputs per form
_BENIGN_VAL  = "test"

_FUZZ_PAYLOADS = _build_fuzz_payloads()


def test(page: CrawlResult, client) -> List[Finding]:
    if not page.forms:
        return []

    findings: List[Finding] = []
    seen: set[tuple] = set()

    for form in page.forms[:_MAX_FORMS]:
        action  = form.get("action", page.url)
        method  = form.get("method", "get").lower()
        inputs  = [i for i in form.get("inputs", []) if i.get("name")][:_MAX_INPUTS]

        if not inputs:
            continue

        for target_idx, target_input in enumerate(inputs):
            field_name = target_input["name"]

            for payload, class_name, detection, severity, cwe, owasp in _FUZZ_PAYLOADS:
                dedup = (action, field_name, payload)
                if dedup in seen:
                    continue
                seen.add(dedup)

                # Build form data: fuzz one field, benign values for others
                data = {
                    inp["name"]: (payload if i == target_idx else _BENIGN_VAL)
                    for i, inp in enumerate(inputs)
                }

                resp = _submit_form(client, method, action, data)
                if resp is None:
                    continue

                body = (getattr(resp, "text", "") or "").lower()
                status = getattr(resp, "status_code", 0)

                # Detect SQL errors regardless of the simple detection string
                triggered = detection.lower() in body
                if class_name.startswith("SQLi") and not triggered:
                    triggered = any(err in body for err in _SQL_ERRORS)

                if triggered:
                    findings.append(Finding(
                        title=f"{class_name} via Form Field",
                        severity=severity,
                        url=action,
                        parameter=field_name,
                        payload=payload,
                        evidence=(
                            f"Form field '{field_name}' on {action} responded to "
                            f"{class_name} payload. Detection: '{detection[:80]}' found in response "
                            f"(HTTP {status})."
                        ),
                        description=(
                            f"The form input '{field_name}' did not sanitise the injected payload, "
                            f"indicating a {class_name} vulnerability."
                        ),
                        remediation=(
                            "Validate and sanitise all form inputs server-side. "
                            "Use parameterised queries for database calls, "
                            "output-encode for HTML contexts, and avoid passing "
                            "user input to system commands or template engines."
                        ),
                        cwe=cwe,
                        cvss=_severity_to_cvss(severity),
                        owasp_category=owasp,
                        confidence=0.80,
                    ))
                    break  # one confirmed finding per field per class is enough

    return findings


def _submit_form(client, method: str, action: str, data: dict):
    try:
        if method == "post":
            return fetch(client, "post", action, data=urlencode(data),
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        else:
            from urllib.parse import urlencode as _ue, urlparse, urlunparse, parse_qs
            parsed = urlparse(action)
            qs = _ue({**{k: v[0] for k, v in parse_qs(parsed.query).items()}, **data})
            url = urlunparse(parsed._replace(query=qs))
            return fetch(client, "get", url)
    except Exception:
        return None


def _severity_to_cvss(s: Severity) -> float:
    return {Severity.CRITICAL: 9.8, Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0, Severity.LOW: 3.1}.get(s, 0.0)
