"""
Multi-Step Wizard Form Injection — Gap 31

Detects multi-page checkout / registration wizards and follows the form chain,
injecting canary payloads and checking all intermediate responses for reflection.

Detection heuristics for wizard pages:
  - Progress indicators (step 1 of 3, progress bar)
  - "Next" / "Continue" / "Proceed" buttons (not submit)
  - URL patterns: /step/1, /checkout/step1, ?step=1, ?page=2
  - Form action increments (step1 → step2)
"""
import re
import uuid
import httpx
from typing import List, Optional
from urllib.parse import urljoin, urlparse
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import fetch

_STEP_INDICATOR_RE = re.compile(
    r'(?:step\s*\d+\s*of\s*\d+|page\s*\d+\s*of\s*\d+|'
    r'progress[- ]bar|wizard|checkout|registration\s*step)',
    re.IGNORECASE,
)
_NEXT_BUTTON_RE = re.compile(
    r'(?:type=["\']submit["\'][^>]*value=["\'](?:next|continue|proceed)|'
    r'(?:next|continue|proceed)[^>]*type=["\']submit["\'])',
    re.IGNORECASE,
)
_STEP_URL_RE = re.compile(r'(?:step|page|stage)[=/_](\d+)', re.IGNORECASE)
_MAX_STEPS = 6


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings: List[Finding] = []
    if not _is_wizard_page(page):
        return findings
    _follow_wizard(page, client, findings)
    return findings


def _is_wizard_page(page: CrawlResult) -> bool:
    body = page.body or ""
    return bool(_STEP_INDICATOR_RE.search(body) or _STEP_URL_RE.search(page.url))


def _follow_wizard(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Follow the wizard form chain up to _MAX_STEPS, injecting a canary at each step."""
    canary = f"ksgwiz{uuid.uuid4().hex[:10]}ksgwiz"
    current_page = page
    visited_urls = {page.url}
    all_responses = []

    for step in range(_MAX_STEPS):
        forms = current_page.forms
        if not forms:
            break

        # Pick the form most likely to be the wizard step form
        form = _pick_wizard_form(forms, current_page.body or "")
        if not form:
            break

        input_names = [inp["name"] for inp in form["inputs"] if inp["name"]]
        if not input_names:
            break

        # Inject canary into all text inputs
        data = {}
        for inp in form["inputs"]:
            name = inp.get("name", "")
            if not name:
                continue
            itype = inp.get("type", "text").lower()
            if itype in ("text", "email", "tel", "search", "url", "textarea", "hidden"):
                data[name] = canary
            else:
                data[name] = inp.get("value", "")

        try:
            resp = fetch(client, form["method"], form["action"], data)
        except Exception:
            break

        if not resp:
            break

        all_responses.append((form["action"], resp))

        # Check current response for canary reflection
        if canary in resp.text:
            findings.append(_wizard_finding(
                form["action"], input_names[0], canary, step + 1,
                evidence=f"Canary reflected at step {step + 1} URL: {form['action']}"
            ))

        # Navigate to the next step if redirected or new form found
        next_url = resp.headers.get("location", "")
        if next_url and next_url not in visited_urls:
            abs_next = urljoin(form["action"], next_url)
            visited_urls.add(abs_next)
            try:
                next_resp = client.get(abs_next, timeout=8)
                from scanner.core.crawler import CrawlResult
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(next_resp.text, "html.parser")
                current_page = CrawlResult(
                    url=abs_next,
                    status_code=next_resp.status_code,
                    headers=dict(next_resp.headers),
                    body=next_resp.text,
                    forms=_extract_forms(soup, abs_next),
                )
            except Exception:
                break
        else:
            # No redirect — check if response itself has a next form
            if resp.url and str(resp.url) not in visited_urls:
                visited_urls.add(str(resp.url))
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "html.parser")
                current_page = CrawlResult(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.text,
                    forms=_extract_forms(soup, str(resp.url)),
                )
            else:
                break

    # Post-chain: check all collected responses for the canary
    for url, resp in all_responses:
        if canary in resp.text:
            # Already reported above if at submission step
            pass


def _pick_wizard_form(forms: List[dict], body: str) -> Optional[dict]:
    """Return the form most likely to be a wizard step (not login/search)."""
    for form in forms:
        inputs = form.get("inputs", [])
        input_names = [i.get("name", "").lower() for i in inputs if i.get("name")]
        # Skip login forms
        if "password" in input_names:
            continue
        # Skip forms with no real inputs
        if not any(i.get("type", "text").lower() not in ("hidden", "submit", "button") for i in inputs):
            continue
        return form
    return forms[0] if forms else None


def _extract_forms(soup, base_url: str) -> List[dict]:
    forms = []
    for form in soup.find_all("form"):
        action = urljoin(base_url, form.get("action", base_url))
        method = form.get("method", "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            })
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def _wizard_finding(url: str, param: str, canary: str, step: int, evidence: str) -> Finding:
    return Finding(
        title=f"Multi-Step Injection — Stored XSS/Injection at Wizard Step {step}",
        severity=Severity.HIGH,
        url=url,
        parameter=param,
        payload=canary,
        evidence=evidence,
        description=(
            f"An injected canary payload was reflected at step {step} of a multi-step wizard form. "
            "Multi-step forms that store input between steps can be vulnerable to stored XSS or "
            "injection attacks that only manifest on later steps or in other users' views."
        ),
        remediation=(
            "Sanitize and validate all user input at every step of a multi-step form. "
            "Apply output encoding when rendering stored wizard session data. "
            "Do not store unvalidated user input in session between wizard steps."
        ),
        cwe="CWE-79",
        cvss=7.4,
        owasp_category="A03:2021 Injection",
        confidence=0.80,
    )
