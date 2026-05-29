"""
Detect debug mode, verbose error pages, and stack trace disclosure.

Triggers:
- Send requests that provoke server errors (malformed params, missing required fields)
- Check static page body for debug indicators
- Check response headers for debug signals
"""
import re
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

# Patterns in body that indicate debug mode or stack trace exposure
_STACK_TRACE_PATTERNS = [
    # Python / Django / Flask
    re.compile(r"Traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"django\.core\.exceptions", re.IGNORECASE),
    re.compile(r"flask\.debugger", re.IGNORECASE),
    re.compile(r"werkzeug\.debug", re.IGNORECASE),
    re.compile(r"<div id=\"debugger\"", re.IGNORECASE),
    # Java / Spring
    re.compile(r"at\s+[\w\.$]+\([\w]+\.java:\d+\)", re.IGNORECASE),
    re.compile(r"org\.springframework\.", re.IGNORECASE),
    re.compile(r"java\.lang\.NullPointerException", re.IGNORECASE),
    re.compile(r"javax\.servlet\.", re.IGNORECASE),
    # PHP
    re.compile(r"<b>Fatal error</b>.*in.*on line", re.IGNORECASE | re.DOTALL),
    re.compile(r"<b>Warning</b>.*in.*on line", re.IGNORECASE | re.DOTALL),
    re.compile(r"xdebug-error", re.IGNORECASE),
    re.compile(r"PHP\s+(Parse|Fatal|Warning|Notice)\s+error", re.IGNORECASE),
    # Ruby on Rails
    re.compile(r"ActionController::RoutingError", re.IGNORECASE),
    re.compile(r"ActionView::Template::Error", re.IGNORECASE),
    # .NET
    re.compile(r"Server Error in '/' Application\.", re.IGNORECASE),
    re.compile(r"System\.Web\.HttpException", re.IGNORECASE),
    re.compile(r"at System\.\w+\.\w+.*\(.*\.cs:\d+\)", re.IGNORECASE),
    # Node.js — match full stack frames, not the generic 404 "Cannot GET /path" message
    # that every Express app returns for unknown routes (that would be a universal FP).
    re.compile(r"at Object\.<anonymous>\s+\(.*\.js:\d+:\d+\)", re.IGNORECASE),
    re.compile(r"UnhandledPromiseRejectionWarning", re.IGNORECASE),
    # Generic SQL
    re.compile(r"(ORA-\d{5}|SQLSTATE\[|MySQL server has gone away|psycopg2\.)", re.IGNORECASE),
    # Debug UI frameworks
    re.compile(r"<title>.*?(debug|debugger|development error).*?</title>", re.IGNORECASE),
]

_DEBUG_HEADERS = {
    "x-debug-token": "Symfony Profiler debug token exposed",
    "x-debug-token-link": "Symfony Profiler debug link exposed",
    "x-powered-by": None,  # handled separately
    "server": None,        # handled separately
}

_VERBOSE_SERVER_RE = re.compile(
    r"(Apache/[\d.]+|nginx/[\d.]+|Microsoft-IIS/[\d.]+|PHP/[\d.]+|Express \d+|Jetty\([\d.]+\))",
    re.IGNORECASE,
)


def test(page: CrawlResult, client) -> List[Finding]:
    findings = []

    # 1. Check response headers for debug signals
    findings.extend(_check_headers(page))

    # 2. Check existing body for stack traces / debug UI
    if page.body:
        findings.extend(_check_body(page.url, page.body, page.status_code))

    # 3. Probe with malformed inputs to trigger errors
    findings.extend(_probe_error_pages(page, client))

    return findings


def _check_headers(page: CrawlResult) -> List[Finding]:
    findings = []
    for header, note in _DEBUG_HEADERS.items():
        value = page.headers.get(header, "")
        if not value:
            continue
        if header == "x-debug-token":
            findings.append(Finding(
                title="Symfony Profiler Debug Token Exposed in Header",
                severity=Severity.MEDIUM,
                url=page.url,
                parameter=None,
                payload=None,
                evidence=f"Header: {header}: {value}",
                description=(
                    "The Symfony Profiler is enabled in production. The X-Debug-Token header "
                    "exposes an internal token that can be used to access detailed profiling "
                    "data including query logs, request/response dumps, and application internals."
                ),
                remediation="Set APP_ENV=prod and APP_DEBUG=false. Disable profiler in config/packages/prod/web_profiler.yaml.",
                owasp_category="A05:2021 Security Misconfiguration",
                cwe="CWE-215",
                cvss=5.3,
                confidence=0.95,
                standards={"OWASP": "A05:2021", "CWE": "CWE-215"},
            ))
        elif header == "server":
            if _VERBOSE_SERVER_RE.search(value):
                findings.append(Finding(
                    title="Verbose Server Version Disclosure in Header",
                    severity=Severity.LOW,
                    url=page.url,
                    parameter=None,
                    payload=None,
                    evidence=f"Server: {value}",
                    description=(
                        f"The Server header discloses the exact software version: '{value}'. "
                        "This assists attackers in identifying vulnerable software versions."
                    ),
                    remediation="Configure your server to omit or genericise the Server header.",
                    owasp_category="A05:2021 Security Misconfiguration",
                    cwe="CWE-200",
                    cvss=2.7,
                    confidence=0.90,
                    standards={"OWASP": "A05:2021", "CWE": "CWE-200"},
                ))
    return findings


def _check_body(url: str, body: str, status_code: int) -> List[Finding]:
    findings = []
    for pattern in _STACK_TRACE_PATTERNS:
        m = pattern.search(body)
        if m:
            snippet = body[max(0, m.start()-50): m.end()+100].strip()[:200]
            findings.append(Finding(
                title="Stack Trace / Debug Information Disclosed in Response",
                severity=Severity.MEDIUM,
                url=url,
                parameter=None,
                payload=None,
                evidence=f"Debug pattern matched: ...{snippet}...",
                description=(
                    "The application discloses a stack trace or verbose debug error in its HTTP "
                    "response. This reveals internal file paths, library names, line numbers, "
                    "and potentially database queries, significantly aiding an attacker in "
                    "understanding the application's internals."
                ),
                remediation=(
                    "Disable debug mode in production. Configure a generic error page for 5xx errors. "
                    "Set DEBUG=False (Django), APP_DEBUG=false (Laravel/Symfony), or equivalent. "
                    "Log errors server-side rather than displaying them to users."
                ),
                owasp_category="A05:2021 Security Misconfiguration",
                cwe="CWE-209",
                cvss=5.3,
                confidence=0.88,
                standards={"OWASP": "A05:2021", "CWE": "CWE-209"},
            ))
            break  # one finding per page for body errors
    return findings


def _probe_error_pages(page: CrawlResult, client) -> List[Finding]:
    """Send a request with junk params to try to trigger a verbose error."""
    findings = []
    from urllib.parse import urlparse, urlunparse

    parsed = urlparse(page.url)
    # Only probe HTML pages, skip assets
    if any(ext in parsed.path for ext in (".css", ".js", ".png", ".jpg", ".svg", ".woff", ".ico")):
        return []

    probe_url = urlunparse(parsed._replace(query="__kagesec_debug_probe=<script>"))
    try:
        resp = client.get(probe_url)
        if resp.status_code >= 500:
            body = resp.text
            for pattern in _STACK_TRACE_PATTERNS:
                m = pattern.search(body)
                if m:
                    snippet = body[max(0, m.start()-50): m.end()+100].strip()[:200]
                    findings.append(Finding(
                        title="Verbose Error Page Triggered by Invalid Input",
                        severity=Severity.MEDIUM,
                        url=probe_url,
                        parameter="__kagesec_debug_probe",
                        payload="<script>",
                        evidence=f"HTTP {resp.status_code} with stack trace: ...{snippet}...",
                        description=(
                            "Sending an unexpected query parameter triggered a verbose server error "
                            "exposing a stack trace. Attackers can use this to map internal application "
                            "structure, identify libraries, and craft targeted exploits."
                        ),
                        remediation=(
                            "Implement global exception handling that returns a generic 500 error page. "
                            "Disable all debug output in production configuration."
                        ),
                        owasp_category="A05:2021 Security Misconfiguration",
                        cwe="CWE-209",
                        cvss=5.3,
                        confidence=0.90,
                        standards={"OWASP": "A05:2021", "CWE": "CWE-209"},
                    ))
                    break
    except Exception:
        pass

    return findings
