"""
WAF detection module.

Sends a known-malicious probe, then fingerprints the blocker from headers,
status codes, and response body patterns. Surfaces a finding so the user
knows their results may be incomplete, and which WAF to work around.

This module is passive-safe — the probe is a single request, not a scan.
"""
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity
from scanner.utils.http import inject_url_param, fetch

# Probe that no legitimate app would serve but any WAF should catch
_PROBE_PAYLOAD = "'><script>alert(1)</script>/**/UNION/**/SELECT/**/1--"

_WAF_SIGNATURES: list[tuple[str, str, str]] = [
    # (WAF name, detection type, pattern)
    ("Cloudflare",      "header",  "cf-ray"),
    ("Cloudflare",      "body",    "cloudflare"),
    ("Cloudflare",      "body",    "Attention Required! | Cloudflare"),
    ("AWS WAF",         "header",  "x-amzn-requestid"),
    ("AWS WAF",         "body",    "Request blocked"),
    ("Imperva / Incapsula", "header", "x-iinfo"),
    ("Imperva / Incapsula", "body",   "Incapsula incident"),
    ("Imperva / Incapsula", "body",   "Request unsuccessful"),
    ("Akamai",          "header",  "x-check-cacheable"),
    ("Akamai",          "body",    "Reference #"),
    ("Akamai",          "body",    "Access Denied"),
    ("ModSecurity",     "header",  "x-mod-security"),
    ("ModSecurity",     "body",    "ModSecurity Action"),
    ("ModSecurity",     "body",    "Not Acceptable!"),
    ("Sucuri",          "header",  "x-sucuri-id"),
    ("Sucuri",          "body",    "Sucuri WebSite Firewall"),
    ("Barracuda",       "body",    "Barracuda Web Application Firewall"),
    ("F5 BIG-IP ASM",  "body",    "The requested URL was rejected"),
    ("F5 BIG-IP ASM",  "header",  "x-cnection"),
    ("Fortinet",        "body",    "FortiWeb"),
    ("Fortinet",        "header",  "fortiwafsid"),
    ("Nginx (generic)", "body",    "nginx"),
    ("Generic WAF",     "status",  "406"),
    ("Generic WAF",     "status",  "429"),
    ("Generic WAF",     "status",  "503"),
]


def test(page: CrawlResult, client) -> List[Finding]:
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(page.url)

    # Need at least one query param to inject into; fabricate one if none
    if parsed.query:
        probe_url = inject_url_param(page.url, next(iter(parse_qs(parsed.query))), _PROBE_PAYLOAD)
    else:
        probe_url = page.url + ("&" if parsed.query else "?") + "q=" + _PROBE_PAYLOAD

    resp = fetch(client, "get", probe_url)
    if not resp:
        return []

    status = str(resp.status_code) if hasattr(resp, "status_code") else "0"
    body = (getattr(resp, "text", "") or "").lower()
    headers = {k.lower(): v.lower() for k, v in (resp.headers.items() if hasattr(resp, "headers") else [])}

    detected: list[str] = []
    for waf_name, det_type, pattern in _WAF_SIGNATURES:
        if waf_name in detected:
            continue
        if det_type == "header" and pattern.lower() in headers:
            detected.append(waf_name)
        elif det_type == "body" and pattern.lower() in body:
            detected.append(waf_name)
        elif det_type == "status" and status == pattern:
            detected.append(waf_name)

    if not detected:
        return []

    waf_name = detected[0]
    return [Finding(
        title=f"WAF Detected — {waf_name}",
        severity=Severity.INFO,
        url=page.url,
        parameter=None,
        payload=_PROBE_PAYLOAD,
        evidence=f"WAF fingerprint matched for: {', '.join(detected)}. Probe returned HTTP {status}.",
        description=(
            f"A Web Application Firewall ({waf_name}) was detected in front of this target. "
            "The WAF may be silently blocking or altering scan payloads, causing active modules "
            "to under-report vulnerabilities. Findings from this scan may be incomplete."
        ),
        remediation=(
            "This is informational. Review scan results with the understanding that the WAF may "
            "have suppressed some findings. Consider testing with WAF bypass techniques or from "
            "a whitelisted IP to get complete coverage."
        ),
        cwe=None,
        cvss=0.0,
        owasp_category="A05:2021 Security Misconfiguration",
        confidence=0.8,
    )]
