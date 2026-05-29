import json
import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import get_url_params

_CANARY = "kagesec_pp_1"

POLLUTION_PARAMS = [
    "__proto__[polluted]",
    "constructor[prototype][polluted]",
    "__proto__.polluted",
]

# JS patterns that indicate dangerous merge functions in client-side code
_DANGEROUS_MERGE_PATTERNS = [
    "_.merge(",
    "$.extend(true,",
    "deepmerge(",
    "lodash.merge(",
    "Object.assign(",
]


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    _test_url_params(page, client, findings)
    _test_json_body(page, client, findings)
    _check_static_patterns(page, findings)
    return findings


def _test_url_params(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    params = get_url_params(page.url)
    if not params:
        return
    for pollution_key in POLLUTION_PARAMS:
        from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
        parsed = urlparse(page.url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[pollution_key] = [_CANARY]
        test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        try:
            resp = client.get(test_url, timeout=8)
        except Exception:
            continue
        if resp and _CANARY in resp.text:
            findings.append(_finding(page.url, pollution_key, f"{pollution_key}={_CANARY}"))
            return


def _test_json_body(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Try prototype pollution via JSON POST body."""
    content_type = page.headers.get("content-type", "")
    if "json" not in content_type and "javascript" not in content_type:
        return

    for payload_obj in [
        {"__proto__": {"polluted": _CANARY}},
        {"constructor": {"prototype": {"polluted": _CANARY}}},
    ]:
        try:
            resp = client.post(
                page.url,
                content=json.dumps(payload_obj),
                headers={"Content-Type": "application/json"},
                timeout=8,
            )
        except Exception:
            continue
        if resp and _CANARY in resp.text:
            payload_str = json.dumps(payload_obj)
            findings.append(_finding(page.url, "request body", payload_str))
            return


def _check_static_patterns(page: CrawlResult, findings: List[Finding]):
    """Detect dangerous client-side merge patterns in page JS."""
    sources = [page.body] + list(getattr(page, "network_requests", []))
    for source in sources:
        for pattern in _DANGEROUS_MERGE_PATTERNS:
            if pattern in source:
                findings.append(Finding(
                    title="Prototype Pollution — Dangerous Merge Pattern (Client-Side)",
                    severity=Severity.MEDIUM,
                    url=page.url,
                    parameter=None,
                    payload=None,
                    evidence=f"Dangerous merge pattern '{pattern}' found in client-side JavaScript",
                    description=(
                        "Client-side JavaScript uses a merge/extend function that may be vulnerable "
                        "to prototype pollution when applied to user-controlled objects. This can "
                        "lead to property injection on Object.prototype affecting all objects."
                    ),
                    remediation=(
                        "Sanitize object keys: reject '__proto__', 'constructor', 'prototype'. "
                        "Use Object.create(null) for dictionaries. "
                        "Upgrade lodash to >=4.17.21."
                    ),
                    cwe="CWE-1321",
                    cvss=5.6,
                    owasp_category="A08:2021 Software and Data Integrity Failures",
                    standards=["ISO27001-8.23"],
                    confidence=0.5,
                ))
                return


def _finding(url: str, param: str, payload: str) -> Finding:
    return Finding(
        title="Prototype Pollution",
        severity=Severity.HIGH,
        url=url,
        parameter=param,
        payload=payload,
        evidence=f"Canary value '{_CANARY}' appeared in response after prototype pollution payload",
        description=(
            "Prototype pollution allows attackers to inject properties onto JavaScript's "
            "Object.prototype, potentially leading to remote code execution in Node.js, "
            "XSS, or authentication bypass depending on application logic."
        ),
        remediation=(
            "Reject '__proto__', 'constructor', and 'prototype' as object keys at all input boundaries. "
            "Use JSON.parse with a reviver function. "
            "Freeze Object.prototype with Object.freeze(Object.prototype)."
        ),
        cwe="CWE-1321",
        cvss=8.1,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "GDPR-Art32"],
        confidence=0.9,
    )
