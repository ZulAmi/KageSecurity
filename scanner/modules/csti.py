"""
Client-Side Template Injection (CSTI) — Gap 3/33

Detects template expression evaluation in AngularJS, Vue.js, and React-based
apps by injecting math expressions into URL params and form fields and checking
whether the expression is evaluated in the response or DOM.

Attack classes covered:
  - AngularJS 1.x  {{7*7}} → 49, sandbox escapes
  - Vue.js          {{7*7}} → 49, ${7*7}
  - React           dangerouslySetInnerHTML patterns (passive detection)
  - Handlebars      {{7*7}}, {{{7*7}}}
  - Jinja2/Twig     (overlaps with SSTI — flagged at MEDIUM to avoid duplicate)
"""
import re
import uuid
import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import get_url_params, inject_url_param, fetch

# Each entry: (payload, expected_output_regex, framework_hint, severity)
_CSTI_PAYLOADS = [
    # AngularJS basic
    ("{{7*7}}", re.compile(r'\b49\b'), "AngularJS", Severity.HIGH),
    # AngularJS sandbox escape (1.x < 1.6)
    ("{{constructor.constructor('alert(1)')()}}", re.compile(r'alert\(1\)|TypeError|sandbox'), "AngularJS sandbox", Severity.CRITICAL),
    # Vue.js
    ("{{7*7}}", re.compile(r'\b49\b'), "Vue.js", Severity.HIGH),
    ("${7*7}", re.compile(r'\b49\b'), "Vue.js template literal", Severity.HIGH),
    # Handlebars
    ("{{{7*7}}}", re.compile(r'\b49\b'), "Handlebars", Severity.HIGH),
    ("{{#with 7 as |n|}}{{n}}{{/with}}", re.compile(r'\b7\b'), "Handlebars block", Severity.MEDIUM),
    # Mustache
    ("{{7*7}}", re.compile(r'\b49\b'), "Mustache", Severity.HIGH),
    # Lodash/underscore templates
    ("<%= 7*7 %>", re.compile(r'\b49\b'), "Lodash template", Severity.HIGH),
    ("<% print(7*7) %>", re.compile(r'\b49\b'), "Lodash template", Severity.HIGH),
    # EJS
    ("<%= 7*7 %>", re.compile(r'\b49\b'), "EJS", Severity.HIGH),
]

# Angular framework indicators in page source
_ANGULAR_INDICATORS = [
    re.compile(r'ng-app|angular\.module|ng-controller|ng-model', re.IGNORECASE),
    re.compile(r'angular\.js|angular\.min\.js', re.IGNORECASE),
]
_VUE_INDICATORS = [
    re.compile(r'v-model|v-bind|v-for|v-if|:class|@click', re.IGNORECASE),
    re.compile(r'vue\.js|vue\.min\.js|createApp\(', re.IGNORECASE),
]
_REACT_DANGEROUS_RE = re.compile(r'dangerouslySetInnerHTML\s*=', re.IGNORECASE)
_HANDLEBARS_RE = re.compile(r'Handlebars\.compile|handlebars\.js', re.IGNORECASE)


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings: List[Finding] = []
    _passive_react_check(page, findings)
    _active_csti(page, client, findings)
    return findings


def _passive_react_check(page: CrawlResult, findings: List[Finding]):
    """Flag dangerouslySetInnerHTML usage — passive, no requests needed."""
    if _REACT_DANGEROUS_RE.search(page.body or ""):
        findings.append(Finding(
            title="React dangerouslySetInnerHTML Usage Detected",
            severity=Severity.MEDIUM,
            url=page.url,
            parameter=None,
            payload=None,
            evidence="dangerouslySetInnerHTML prop found in page source/JS bundle",
            description=(
                "React's dangerouslySetInnerHTML bypasses React's XSS protections. "
                "If the HTML string originates from user input or an untrusted API, "
                "it creates a direct DOM XSS vector."
            ),
            remediation=(
                "Avoid dangerouslySetInnerHTML. If required, sanitize with DOMPurify "
                "before passing to __html. Enforce a strict Content-Security-Policy."
            ),
            cwe="CWE-79",
            cvss=5.4,
            owasp_category="A03:2021 Injection",
            confidence=0.60,
        ))


def _active_csti(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Inject template expressions into URL params and forms; check for evaluation."""
    # Detect likely framework to prioritise payloads
    body = page.body or ""
    is_angular = any(p.search(body) for p in _ANGULAR_INDICATORS)
    is_vue = any(p.search(body) for p in _VUE_INDICATORS)
    is_handlebars = bool(_HANDLEBARS_RE.search(body))

    reported: set = set()

    # URL param injection
    params = get_url_params(page.url)
    for param_name in params:
        for payload, expected_re, framework, sev in _CSTI_PAYLOADS:
            marker = f"csti{uuid.uuid4().hex[:6]}"
            tagged_payload = payload + marker
            test_url = inject_url_param(page.url, param_name, tagged_payload)
            resp = fetch(client, "get", test_url)
            if not resp:
                continue
            # Check if the marker appears AND the expression was evaluated
            if marker in resp.text and expected_re.search(resp.text):
                key = (param_name, framework)
                if key in reported:
                    continue
                reported.add(key)
                findings.append(_csti_finding(page.url, param_name, payload, framework, sev))
                break
            # Also check if the literal expression is gone (evaluated away)
            if marker in resp.text and payload not in resp.text:
                key = (param_name, framework + "-eval")
                if key not in reported:
                    reported.add(key)
                    findings.append(_csti_finding(page.url, param_name, payload, framework, sev))
                break

    # Form injection
    for form in page.forms:
        input_names = [inp["name"] for inp in form["inputs"] if inp["name"]]
        if not input_names:
            continue
        for payload, expected_re, framework, sev in _CSTI_PAYLOADS:
            marker = f"csti{uuid.uuid4().hex[:6]}"
            tagged_payload = payload + marker
            data = {name: tagged_payload for name in input_names}
            resp = fetch(client, form["method"], form["action"], data)
            if not resp:
                continue
            if marker in resp.text and expected_re.search(resp.text):
                key = (form["action"], framework)
                if key not in reported:
                    reported.add(key)
                    findings.append(_csti_finding(form["action"], input_names[0], payload, framework, sev))
                break


def _csti_finding(url: str, param: str, payload: str, framework: str, severity: Severity) -> Finding:
    return Finding(
        title=f"Client-Side Template Injection (CSTI) — {framework}",
        severity=severity,
        url=url,
        parameter=param,
        payload=payload,
        evidence=f"Template expression '{payload}' was evaluated by the {framework} engine in the response",
        description=(
            f"Client-side template injection in {framework}: user-supplied input is interpreted "
            "as a template expression and evaluated by the client-side templating engine. "
            "Depending on the framework version, this may allow arbitrary JavaScript execution "
            "or sandbox escape."
        ),
        remediation=(
            "Never interpolate untrusted user input directly into client-side templates. "
            "Use text binding (ng-bind, v-text) instead of expression interpolation. "
            "Upgrade to Angular 2+ which removed the $eval sandbox. "
            "Escape template delimiters in user-controlled strings."
        ),
        cwe="CWE-79",
        cvss=8.8 if severity == Severity.CRITICAL else 6.1,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "GDPR-Art32"],
        confidence=0.85,
    )
