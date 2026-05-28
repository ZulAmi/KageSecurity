"""
HTTP Parameter Pollution (HPP) detection.

Sends duplicate query parameters with conflicting values and checks whether
the server (or a downstream component) uses the attacker-supplied value
instead of the legitimate one — a sign of parameter parsing inconsistency
that can be used to bypass WAFs, authentication, or business logic.
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity
from scanner.utils.http import fetch

_CANARY = "kagesec_hpp_test"


def test(page: CrawlResult, client) -> List[Finding]:
    parsed = urlparse(page.url)
    if not parsed.query:
        return []

    params = parse_qs(parsed.query)
    findings: List[Finding] = []

    for param in list(params.keys())[:5]:   # cap to 5 params per page
        legit_val = params[param][0]
        # Append a duplicate param with the canary value AFTER the legitimate one
        polluted_qs = urlencode({**{k: v[0] for k, v in params.items()}, **{}}, doseq=False)
        polluted_qs += f"&{param}={_CANARY}"
        polluted_url = urlunparse(parsed._replace(query=polluted_qs))

        resp = fetch(client, "get", polluted_url)
        if resp is None:
            continue

        body = getattr(resp, "text", "") or ""
        # If the canary is reflected but the legitimate value is NOT, the server
        # is using the last occurrence — a clear HPP signal
        if _CANARY in body and legit_val not in body:
            findings.append(Finding(
                title="HTTP Parameter Pollution (HPP)",
                severity=Severity.MEDIUM,
                url=page.url,
                parameter=param,
                payload=f"{param}={legit_val}&{param}={_CANARY}",
                evidence=(
                    f"Duplicate parameter '{param}' sent with values '{legit_val}' and '{_CANARY}'. "
                    f"Server reflected the attacker-supplied value ('{_CANARY}') and ignored "
                    f"the legitimate value — indicating last-occurrence parsing."
                ),
                description=(
                    "The server processes duplicate query parameters by using the last occurrence "
                    "rather than the first. An attacker can append a duplicate parameter after a "
                    "legitimate one (e.g. in a signed URL) to override its value, potentially "
                    "bypassing WAF rules, authentication checks, or business logic validation."
                ),
                remediation=(
                    "Enforce strict parameter parsing — reject requests with duplicate parameter "
                    "names, or explicitly use only the first occurrence. Validate parameters "
                    "after WAF processing, not before."
                ),
                cwe="CWE-235",
                cvss=5.4,
                owasp_category="A03:2021 Injection",
                confidence=0.85,
            ))

    return findings
