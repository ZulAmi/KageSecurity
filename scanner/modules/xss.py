import re
import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import get_url_params, inject_url_param, fetch

PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    # Polyglots — bypass common filters
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert())//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e",
    '"><details/open/ontoggle=alert(1)>',
]

# Patterns that indicate DOM XSS sinks in JS source
DOM_XSS_SINKS = [
    re.compile(r'document\.write\s*\(', re.IGNORECASE),
    re.compile(r'\.innerHTML\s*=', re.IGNORECASE),
    re.compile(r'\.outerHTML\s*=', re.IGNORECASE),
    re.compile(r'eval\s*\(', re.IGNORECASE),
    re.compile(r'location\.hash', re.IGNORECASE),
    re.compile(r'location\.search', re.IGNORECASE),
    re.compile(r'document\.URL', re.IGNORECASE),
]

REFLECTIVE_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For"]


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    _test_forms(page, client, findings)
    _test_url_params(page, client, findings)
    _test_headers(page, client, findings)
    _check_dom_xss(page, findings)
    return findings


def _test_forms(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    for form in page.forms:
        input_names = [inp["name"] for inp in form["inputs"] if inp["name"]]
        if not input_names:
            continue
        for payload in PAYLOADS:
            data = {name: payload for name in input_names}
            resp = fetch(client, form["method"], form["action"], data)
            if resp and payload in resp.text:
                findings.append(_finding(form["action"], input_names[0], payload, "Reflected XSS"))
                break


def _test_url_params(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    params = get_url_params(page.url)
    for param_name in params:
        for payload in PAYLOADS:
            test_url = inject_url_param(page.url, param_name, payload)
            resp = fetch(client, "get", test_url)
            if resp and payload in resp.text:
                findings.append(_finding(page.url, param_name, payload, "Reflected XSS"))
                break


def _test_headers(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    payload = '<script>alert(1)</script>'
    for header in REFLECTIVE_HEADERS:
        try:
            resp = client.get(page.url, headers={header: payload})
        except Exception:
            continue
        if payload in resp.text:
            findings.append(_finding(page.url, header, payload, "Header-Based Reflected XSS"))


def _check_dom_xss(page: CrawlResult, findings: List[Finding]):
    for pattern in DOM_XSS_SINKS:
        if pattern.search(page.body):
            findings.append(Finding(
                title="Potential DOM-Based XSS Sink Detected",
                severity=Severity.MEDIUM,
                url=page.url,
                parameter=None,
                payload=None,
                evidence=f"DOM XSS sink pattern '{pattern.pattern}' found in page JavaScript",
                description=(
                    "DOM-based XSS occurs when JavaScript uses attacker-controlled data "
                    "(e.g., location.hash) as input to dangerous sinks like document.write or innerHTML."
                ),
                remediation=(
                    "Avoid dangerous sinks. Use textContent instead of innerHTML. "
                    "Sanitize DOM inputs with DOMPurify. "
                    "Implement a strict Content-Security-Policy."
                ),
                cwe="CWE-79",
                cvss=5.4,
                owasp_category="A03:2021 Injection",
                standards=["ISO27001-8.23", "GDPR-Art32"],
                confidence=0.6,
            ))
            break  # one DOM XSS indicator per page is enough


def _finding(url: str, param: str, payload: str, label: str) -> Finding:
    return Finding(
        title=f"Cross-Site Scripting (XSS) — {label}",
        severity=Severity.HIGH,
        url=url,
        parameter=param,
        payload=payload,
        evidence="Payload reflected verbatim in response body",
        description=(
            "XSS allows attackers to inject malicious scripts into web pages viewed by other users, "
            "enabling session theft, credential harvesting, and defacement."
        ),
        remediation=(
            "HTML-encode all user-supplied output. "
            "Implement Content-Security-Policy. "
            "Use framework-level output encoding (Django templates, React JSX auto-escaping)."
        ),
        cwe="CWE-79",
        cvss=6.1,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "HIPAA-164.312a", "GDPR-Art32"],
        confidence=1.0,
    )
