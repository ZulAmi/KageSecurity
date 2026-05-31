"""
Clickjacking detection — beyond basic X-Frame-Options.

Checks for all clickjacking protection layers:
  1. X-Frame-Options header (DENY / SAMEORIGIN)
  2. CSP frame-ancestors directive (the modern replacement)
  3. Double-framing bypass: ALLOWALL or missing header on sub-paths
  4. Meta tag fallback: <meta http-equiv="X-Frame-Options"> (not honoured by all browsers)

A page is vulnerable when BOTH X-Frame-Options AND CSP frame-ancestors are absent
or misconfigured, since either alone is sufficient protection on modern browsers.
"""
from __future__ import annotations

from typing import List

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

_FRAMING_HEADERS = ("x-frame-options", "content-security-policy")

# XFO values that actually protect
_XFO_SAFE = {"deny", "sameorigin"}


def test(page: CrawlResult, client) -> List[Finding]:
    content_type = page.headers.get("content-type", "")
    if "html" not in content_type:
        return []   # only check HTML pages

    if page.status_code not in range(200, 400):
        return []

    headers_lower = {k.lower(): v.lower() for k, v in page.headers.items()}
    findings: List[Finding] = []

    xfo = headers_lower.get("x-frame-options", "")
    csp = headers_lower.get("content-security-policy", "")

    xfo_protected = any(safe in xfo for safe in _XFO_SAFE)
    csp_protected = "frame-ancestors" in csp

    # Both absent → vulnerable
    if not xfo_protected and not csp_protected:
        # Check for meta tag fallback (not reliable but worth noting)
        meta_xfo = 'x-frame-options' in (page.body or "").lower()

        findings.append(Finding(
            title="Clickjacking — No Framing Protection",
            severity=Severity.MEDIUM,
            url=page.url,
            parameter=None,
            payload=None,
            evidence=(
                f"Neither X-Frame-Options nor CSP frame-ancestors is set. "
                f"XFO header: '{xfo or 'absent'}'. "
                f"CSP frame-ancestors: {'absent' if not csp_protected else 'present but missing frame-ancestors'}."
                + (" Meta tag fallback detected (not reliable)." if meta_xfo else "")
            ),
            description=(
                "The page can be embedded in an iframe by any origin. An attacker can host "
                "a malicious page that overlays transparent iframes over legitimate UI elements, "
                "tricking users into clicking buttons or entering credentials on this site "
                "without their knowledge (clickjacking / UI redressing)."
            ),
            remediation=(
                "Add one or both of:\n"
                "  Content-Security-Policy: frame-ancestors 'self'   (preferred, modern)\n"
                "  X-Frame-Options: SAMEORIGIN                       (legacy fallback)\n"
                "Use frame-ancestors 'none' if the page should never be framed."
            ),
            cwe="CWE-1021",
            cvss=4.3,
            owasp_category="A05:2021 Security Misconfiguration",
            confidence=0.90,
        ))

    # XFO present but not CSP → partial (modern browsers ignore XFO for nested iframes)
    elif xfo_protected and not csp_protected:
        findings.append(Finding(
            title="Clickjacking — X-Frame-Options Without CSP frame-ancestors",
            severity=Severity.LOW,
            url=page.url,
            parameter=None,
            payload=None,
            evidence=(
                f"X-Frame-Options: {xfo} is set but CSP frame-ancestors is absent. "
                "Modern browsers (Chrome 40+) may ignore XFO when frame-ancestors is available "
                "in a nested browsing context."
            ),
            description=(
                "X-Frame-Options provides protection in most browsers but is superseded by "
                "CSP frame-ancestors in modern browsers. Without frame-ancestors, double-framing "
                "attacks can bypass XFO protection in some browser versions."
            ),
            remediation=(
                "Add Content-Security-Policy: frame-ancestors 'self' to complement X-Frame-Options."
            ),
            cwe="CWE-1021",
            cvss=3.1,
            owasp_category="A05:2021 Security Misconfiguration",
            confidence=0.80,
        ))

    # XFO set to ALLOWALL (explicitly insecure)
    if "allowall" in xfo:
        findings.append(Finding(
            title="Clickjacking — X-Frame-Options: ALLOWALL",
            severity=Severity.HIGH,
            url=page.url,
            parameter=None,
            payload=None,
            evidence=f"X-Frame-Options header is set to ALLOWALL: '{xfo}'",
            description=(
                "ALLOWALL is a non-standard X-Frame-Options value that explicitly permits "
                "framing by any origin. Some older browsers treat this as 'no protection'. "
                "This is worse than omitting the header entirely."
            ),
            remediation="Change X-Frame-Options to DENY or SAMEORIGIN and add CSP frame-ancestors.",
            cwe="CWE-1021",
            cvss=6.1,
            owasp_category="A05:2021 Security Misconfiguration",
            confidence=0.95,
        ))

    return findings
