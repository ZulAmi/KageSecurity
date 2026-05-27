"""XPath injection — targets XML-backed datastores via boolean and error-based detection."""
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity
from scanner.utils.http import get_url_params, inject_url_param, fetch

_ERROR_PAYLOADS = [
    "'",
    "\"",
    "' or '1'='1",
    '" or "1"="1',
    "' or 1=1 or '1'='2",
    "x' or name()='username' or 'x'='y",
    "' and count(/*)>0 and '1'='1",
    "' and count(/*)=0 and '1'='1",
    "1' or '1'='1",
    "' or position()=1 or '",
]

_ERROR_SIGNATURES = [
    "XPathException",
    "xpath",
    "System.Xml.XPath",
    "org.apache.xpath",
    "XPath",
    "XPathExpression",
    "SimpleXMLElement",
    "libxml",
    "MSXML",
    "unterminated string",
    "Invalid predicate",
    "XPath error",
]

_BOOL_PAIRS = [
    ("' or '1'='1", "' or '1'='2"),
    ("' or 1=1 or '", "' or 1=2 or '"),
]


def test(page: CrawlResult, client) -> List[Finding]:
    findings = []
    params = get_url_params(page.url)
    for param in params:
        # Error-based detection
        for payload in _ERROR_PAYLOADS:
            url = inject_url_param(page.url, param, payload)
            resp = fetch(client, "get", url)
            if not resp:
                continue
            body = getattr(resp, "text", "")
            matched = next((s for s in _ERROR_SIGNATURES if s.lower() in body.lower()), None)
            if matched:
                findings.append(_finding(page.url, param, payload, f"XPath error signature: '{matched}'"))
                break

        if any(f.parameter == param for f in findings):
            continue

        # Boolean-based detection
        baseline = fetch(client, "get", page.url)
        baseline_len = len(getattr(baseline, "text", "")) if baseline else 0
        for true_p, false_p in _BOOL_PAIRS:
            r_true = fetch(client, "get", inject_url_param(page.url, param, true_p))
            r_false = fetch(client, "get", inject_url_param(page.url, param, false_p))
            if not r_true or not r_false:
                continue
            len_true = len(getattr(r_true, "text", ""))
            len_false = len(getattr(r_false, "text", ""))
            if abs(len_true - baseline_len) < 20 and abs(len_true - len_false) > 50:
                findings.append(_finding(page.url, param, true_p, "Boolean response difference detected"))
                break

    return findings


def _finding(url: str, param: str, payload: str, evidence: str) -> Finding:
    return Finding(
        title="XPath Injection",
        severity=Severity.HIGH,
        url=url,
        parameter=param,
        payload=payload,
        evidence=evidence,
        description=(
            "XPath injection allows an attacker to manipulate XML queries, potentially bypassing "
            "authentication, extracting sensitive data from XML datastores, or causing denial of "
            "service through malformed queries."
        ),
        remediation=(
            "Use parameterised XPath queries or a library that separates query logic from data. "
            "Never concatenate user input into an XPath expression. Validate and whitelist input."
        ),
        cwe="CWE-643",
        cvss=7.5,
        owasp_category="A03:2021 Injection",
        confidence=0.85,
    )
