"""
Insecure HTTP method detection.

Tests for:
- TRACE: reflects headers back → XST (Cross-Site Tracing)
- OPTIONS with dangerous methods in Allow header
- PUT/DELETE on non-API paths → filesystem or resource manipulation
- CONNECT method allowed (proxy abuse)
"""
from typing import List
from urllib.parse import urlparse
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

_DANGEROUS_METHODS = {"TRACE", "PUT", "DELETE", "CONNECT", "PATCH"}
_ASSET_EXTENSIONS = (".css", ".js", ".png", ".jpg", ".gif", ".svg", ".woff", ".ico", ".ttf", ".map")


def test(page: CrawlResult, client) -> List[Finding]:
    parsed = urlparse(page.url)
    if any(parsed.path.endswith(ext) for ext in _ASSET_EXTENSIONS):
        return []

    findings = []

    # 1. Test TRACE
    findings.extend(_test_trace(page.url, client))

    # 2. Inspect OPTIONS Allow header
    findings.extend(_test_options(page.url, client))

    return findings


def _test_trace(url: str, client) -> List[Finding]:
    try:
        resp = client.request("TRACE", url)
    except Exception:
        return []

    if resp.status_code in (200, 206):
        body = resp.text if hasattr(resp, "text") else ""
        # TRACE echos the request back; if our User-Agent is in body it's truly reflected
        evidence = f"HTTP {resp.status_code} response to TRACE"
        if "KageSec" in body or "kagesec" in body.lower():
            evidence += " — request headers reflected in body (XST confirmed)"
        return [Finding(
            title="HTTP TRACE Method Enabled (Cross-Site Tracing)",
            severity=Severity.MEDIUM,
            url=url,
            parameter=None,
            payload="TRACE",
            evidence=evidence,
            description=(
                "The server accepts HTTP TRACE requests and reflects the request back to the client. "
                "An attacker can leverage this with a browser XSS payload to steal HttpOnly cookies "
                "via the Cross-Site Tracing (XST) technique, bypassing the HttpOnly protection."
            ),
            remediation=(
                "Disable the TRACE method in your web server configuration. "
                "Apache: TraceEnable Off. Nginx: add 'if ($request_method = TRACE) { return 405; }'. "
                "IIS: remove TRACE from allowed verbs."
            ),
            owasp_category="A05:2021 Security Misconfiguration",
            cwe="CWE-16",
            cvss=4.3,
            confidence=0.92,
            standards={"OWASP": "A05:2021", "CWE": "CWE-16"},
        )]
    return []


def _test_options(url: str, client) -> List[Finding]:
    try:
        resp = client.options(url)
    except Exception:
        return []

    if resp.status_code not in (200, 204):
        return []

    allow = resp.headers.get("allow", "") + resp.headers.get("Allow", "")
    if not allow:
        # Some servers put it in public header
        allow = resp.headers.get("public", "")

    allowed_methods = {m.strip().upper() for m in allow.split(",")}
    dangerous = allowed_methods & _DANGEROUS_METHODS

    if not dangerous:
        return []

    parsed = urlparse(url)
    is_api_path = "/api/" in parsed.path or parsed.path.startswith("/api")

    # PUT/DELETE on API endpoints is expected REST behaviour — lower severity
    rest_methods = dangerous - {"TRACE", "CONNECT"}
    trace_connect = dangerous & {"TRACE", "CONNECT"}

    findings = []

    if trace_connect:
        findings.append(Finding(
            title=f"Dangerous HTTP Methods Allowed: {', '.join(sorted(trace_connect))}",
            severity=Severity.MEDIUM,
            url=url,
            parameter=None,
            payload="OPTIONS",
            evidence=f"Allow: {allow}",
            description=(
                f"The server advertises support for {', '.join(sorted(trace_connect))} via the OPTIONS "
                "Allow header. TRACE enables Cross-Site Tracing; CONNECT can be used for proxy tunnelling."
            ),
            remediation="Disable TRACE and CONNECT in your web server or WAF configuration.",
            owasp_category="A05:2021 Security Misconfiguration",
            cwe="CWE-16",
            cvss=4.3,
            confidence=0.85,
            standards={"OWASP": "A05:2021", "CWE": "CWE-16"},
        ))

    if rest_methods and not is_api_path:
        findings.append(Finding(
            title=f"Potentially Dangerous HTTP Methods on Non-API Endpoint: {', '.join(sorted(rest_methods))}",
            severity=Severity.LOW,
            url=url,
            parameter=None,
            payload="OPTIONS",
            evidence=f"Allow: {allow} (path: {parsed.path})",
            description=(
                f"Methods {', '.join(sorted(rest_methods))} are advertised on a non-API path. "
                "If not intentional, these methods may allow resource creation or deletion."
            ),
            remediation="Restrict HTTP methods to only those required. Block unused verbs at the server or WAF level.",
            owasp_category="A05:2021 Security Misconfiguration",
            cwe="CWE-16",
            cvss=3.1,
            confidence=0.70,
            standards={"OWASP": "A05:2021", "CWE": "CWE-16"},
        ))

    return findings
