import re
import uuid
import httpx
from typing import List, Tuple
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

# DOM XSS taint sources — attacker-controlled inputs
_DOM_SOURCES = {
    "location.hash": re.compile(r'\blocation\.hash\b'),
    "location.search": re.compile(r'\blocation\.search\b'),
    "location.href": re.compile(r'\blocation\.href\b'),
    "document.URL": re.compile(r'\bdocument\.URL\b'),
    "document.referrer": re.compile(r'\bdocument\.referrer\b'),
    "document.cookie": re.compile(r'\bdocument\.cookie\b'),
    "window.name": re.compile(r'\bwindow\.name\b'),
    "postMessage": re.compile(r'\baddEventListener\s*\(\s*["\']message["\']'),
    "URLSearchParams": re.compile(r'\bnew\s+URLSearchParams\b'),
    "localStorage": re.compile(r'\blocalStorage\.getItem\b'),
    "sessionStorage": re.compile(r'\bsessionStorage\.getItem\b'),
}

# DOM XSS dangerous sinks
_DOM_SINKS = {
    "innerHTML": re.compile(r'\.innerHTML\s*[+]?='),
    "outerHTML": re.compile(r'\.outerHTML\s*[+]?='),
    "document.write": re.compile(r'\bdocument\.write(?:ln)?\s*\('),
    "eval": re.compile(r'\beval\s*\('),
    "setTimeout(string)": re.compile(r'\bsetTimeout\s*\(\s*["\']'),
    "setInterval(string)": re.compile(r'\bsetInterval\s*\(\s*["\']'),
    "Function()": re.compile(r'\bnew\s+Function\s*\('),
    "location.href=": re.compile(r'\blocation(?:\.href)?\s*=\s*(?!.*https?://)'),
    "src=": re.compile(r'\.\s*src\s*=\s*(?!.*https?://)'),
    "insertAdjacentHTML": re.compile(r'\binsertAdjacentHTML\s*\('),
    "jQuery.html()": re.compile(r'\$\([^)]+\)\.html\s*\('),
    "jQuery.append()": re.compile(r'\$\([^)]+\)\.append\s*\('),
}

# Intermediate propagators (variables that carry taint)
_PROPAGATOR_PATTERNS = [
    # var x = location.hash → tracks x
    re.compile(r'\b(?:var|let|const)\s+(\w+)\s*=\s*(?:.*(?:location\.hash|location\.search|document\.URL|document\.referrer|document\.cookie|window\.name))'),
    # x = location.hash.substring(...)
    re.compile(r'\b(\w+)\s*=\s*(?:.*(?:location\.hash|location\.search|document\.URL))'),
]

# Legacy sink patterns kept for fast-path pre-filter
DOM_XSS_SINKS = [
    re.compile(r'document\.write\s*\(', re.IGNORECASE),
    re.compile(r'\.innerHTML\s*=', re.IGNORECASE),
    re.compile(r'\.outerHTML\s*=', re.IGNORECASE),
    re.compile(r'eval\s*\(', re.IGNORECASE),
]


def _trace_dom_xss(js_source: str) -> List[Tuple[str, str, str]]:
    """
    Taint-trace DOM XSS sources → sinks within a JS snippet.

    Returns list of (source_name, sink_name, evidence_snippet).
    Algorithm:
      1. Identify which taint sources appear in the code.
      2. Collect variable names assigned from those sources (propagators).
      3. Check if any tainted variable (or the raw source expression) appears
         near a dangerous sink within the same script block.
    """
    results = []

    # Find active sources
    active_sources = {name for name, pat in _DOM_SOURCES.items() if pat.search(js_source)}
    if not active_sources:
        return results

    # Collect tainted variable names from propagators
    tainted_vars: set = set()
    for pat in _PROPAGATOR_PATTERNS:
        for m in pat.finditer(js_source):
            tainted_vars.add(m.group(1))

    # Check each sink
    for sink_name, sink_pat in _DOM_SINKS.items():
        for sink_match in sink_pat.finditer(js_source):
            sink_pos = sink_match.start()
            # Look at up to 500 chars before sink for tainted var usage
            context_start = max(0, sink_pos - 500)
            context = js_source[context_start:sink_pos + 100]

            # Direct source usage near sink
            for src_name in active_sources:
                src_pat = _DOM_SOURCES[src_name]
                if src_pat.search(context):
                    snippet = js_source[max(0, sink_pos - 80):sink_pos + 80].strip()
                    results.append((src_name, sink_name, snippet))
                    break

            # Tainted variable near sink
            if not results or results[-1][1] != sink_name:
                for var in tainted_vars:
                    if re.search(r'\b' + re.escape(var) + r'\b', context):
                        for src_name in active_sources:
                            if _DOM_SOURCES[src_name].search(js_source[:sink_pos]):
                                snippet = js_source[max(0, sink_pos - 80):sink_pos + 80].strip()
                                results.append((src_name, sink_name, snippet))
                                break
                        break

    return results


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    _test_url_params(page, client, findings)
    _test_forms(page, client, findings)
    _test_headers(page, client, findings)
    _check_dom_xss(page, findings)
    _test_second_order(page, client, findings)
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
            # Stored XSS: the payload was NOT echoed back in the form submission
            # response (so it isn't just a reflected echo). Check if it persists
            # on a fresh GET of the page — genuine storage implies the GET response
            # must differ from a pre-submission baseline that didn't contain it.
            elif resp:
                pre_submit = fetch(client, "get", page.url)
                if pre_submit and payload in pre_submit.text:
                    # Payload was already in the page before we submitted — skip
                    break
                stored_resp = fetch(client, "get", page.url)
                if (
                    stored_resp
                    and payload in stored_resp.text
                    and payload not in (pre_submit.text if pre_submit else "")
                ):
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
    """
    Two-pass DOM XSS check:
    1. Taint-trace sources → sinks (HIGH confidence, reported as HIGH severity).
    2. Sink-only grep for sinks without a visible source (MEDIUM confidence fallback).
    """
    js_sources = [page.body] + list(getattr(page, "network_requests", []))

    reported_pairs: set = set()

    for js in js_sources:
        if not js:
            continue

        # Pass 1: taint tracing
        traces = _trace_dom_xss(js)
        for src_name, sink_name, snippet in traces:
            key = (src_name, sink_name)
            if key in reported_pairs:
                continue
            reported_pairs.add(key)
            findings.append(Finding(
                title="DOM-Based XSS — Confirmed Source→Sink Data Flow",
                severity=Severity.HIGH,
                url=page.url,
                parameter=None,
                payload=None,
                evidence=(
                    f"Taint source `{src_name}` flows into sink `{sink_name}`.\n"
                    f"Context: {snippet[:200]}"
                ),
                description=(
                    f"Attacker-controlled input from `{src_name}` reaches the dangerous "
                    f"sink `{sink_name}` without sanitization. An attacker can craft a URL "
                    "with a malicious fragment or query string to execute arbitrary JS."
                ),
                remediation=(
                    "Replace dangerous sinks: use textContent instead of innerHTML, "
                    "avoid eval(). Sanitize tainted values with DOMPurify before "
                    "assigning to sinks. Enforce a strict Content-Security-Policy."
                ),
                cwe="CWE-79",
                cvss=7.4,
                owasp_category="A03:2021 Injection",
                standards=["ISO27001-8.23", "GDPR-Art32"],
                confidence=0.85,
            ))

    # Pass 2: sink-only fallback (lower confidence) — only if no taint traces found
    if not reported_pairs:
        for js in js_sources:
            if not js:
                continue
            for pattern in DOM_XSS_SINKS:
                if pattern.search(js):
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
                    break
            else:
                continue
            break


_LINK_RE = re.compile(r'''href=["']([^"'#?]+)["']''', re.IGNORECASE)


def _test_second_order(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Gap 2 — inject canary via forms, then probe all linked pages for delayed reflection."""
    if not page.forms:
        return

    from urllib.parse import urlparse
    base = urlparse(page.url)

    for form in page.forms:
        input_names = [inp["name"] for inp in form["inputs"] if inp["name"]]
        if not input_names:
            continue

        canary = f"ksgso{uuid.uuid4().hex[:10]}ksgso"
        data = {name: canary for name in input_names}
        try:
            submit_resp = fetch(client, form["method"], form["action"], data)
        except Exception:
            continue

        if not submit_resp:
            continue

        # Collect candidate pages: links in the submission response + page body
        candidate_urls: set = set()
        for link_match in _LINK_RE.finditer(submit_resp.text + page.body):
            href = link_match.group(1)
            if href.startswith(("http://", "https://")):
                candidate_urls.add(href)
            elif href.startswith("/"):
                candidate_urls.add(f"{base.scheme}://{base.netloc}{href}")

        # Always check the submission target itself
        candidate_urls.add(form["action"])

        for candidate_url in list(candidate_urls)[:15]:
            # Only probe same origin
            parsed = urlparse(candidate_url)
            if parsed.netloc and parsed.netloc != base.netloc:
                continue
            try:
                resp = client.get(candidate_url, timeout=10)
            except Exception:
                continue
            if canary in resp.text:
                findings.append(Finding(
                    title="Cross-Site Scripting (XSS) — Second-Order / Stored",
                    severity=Severity.CRITICAL,
                    url=candidate_url,
                    parameter=input_names[0],
                    payload=canary,
                    evidence=(
                        f"Canary '{canary}' injected via POST to {form['action']} "
                        f"was reflected on a different page: {candidate_url}"
                    ),
                    description=(
                        "Second-order (stored) XSS: the injected payload was stored by the "
                        "application and reflected on a different page. This enables persistent "
                        "script execution for any user who visits the affected page."
                    ),
                    remediation=(
                        "HTML-encode all stored user input at render time, not only at submission. "
                        "Apply output encoding in templates and use a strict Content-Security-Policy."
                    ),
                    cwe="CWE-79",
                    cvss=9.3,
                    owasp_category="A03:2021 Injection",
                    standards=["ISO27001-8.23", "HIPAA-164.312a", "GDPR-Art32"],
                    confidence=1.0,
                ))
                break


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
