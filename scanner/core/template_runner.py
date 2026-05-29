"""
KageSec Template Engine — Nuclei-compatible YAML template runner.

Template format (YAML):
  id: unique-template-id
  info:
    name: Human-readable name
    severity: critical | high | medium | low | info
    description: What this checks for
    cve: CVE-YYYY-NNNNN          # optional
    cvss: 9.8                    # optional
    cwe: CWE-79                  # optional
    owasp: "A03:2021"            # optional
    tags: [apache, rce]          # optional
    remediation: How to fix it   # optional

  requests:
    - method: GET
      path:
        - "{{BaseURL}}/admin"
        - "{{BaseURL}}/{{Path}}/.git/HEAD"
      headers:                   # optional extra headers
        X-Custom: value
      body: "POST body"          # optional
      matchers-condition: and    # and | or  (default: or)
      matchers:
        - type: status
          status: [200, 204]
        - type: word
          part: body             # body | header | status
          words: ["root:x:0:0"]
          condition: or          # and | or within this matcher
          negative: false        # invert matcher
        - type: regex
          part: body
          regex:
            - "(?i)password\\s*="
        - type: header
          header: content-type
          words: ["application/json"]

Variables available in path / headers / body:
  {{BaseURL}}   — scheme + host + port  (https://example.com)
  {{Hostname}}  — just host             (example.com)
  {{Path}}      — URL path of the crawled page
  {{Port}}      — port number
  {{Scheme}}    — http or https
"""

from __future__ import annotations

import itertools
import os
import re
import yaml
import glob
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from scanner.core.scan_result import Finding, Severity

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_DEFAULT_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TemplateMatcher:
    type: str                          # status | word | regex | header
    part: str = "body"                 # body | header | status
    words: list[str] = field(default_factory=list)
    regex: list[str] = field(default_factory=list)
    status: list[int] = field(default_factory=list)
    header: str = ""                   # header name (for type=header)
    condition: str = "or"              # and | or within this matcher's items
    negative: bool = False


@dataclass
class TemplateExtractor:
    name: str                          # variable name to store extracted value
    type: str = "regex"                # regex | kval | json
    part: str = "body"                 # body | header
    regex: list[str] = field(default_factory=list)
    group: int = 0                     # capture group index
    header: str = ""                   # header name for type=kval
    json_path: str = ""                # dot-path for type=json (e.g. "data.token")


@dataclass
class TemplateRequest:
    method: str
    paths: list[str]
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    matchers_condition: str = "or"     # and | or across matchers
    matchers: list[TemplateMatcher] = field(default_factory=list)
    stop_at_first_match: bool = True
    # Nuclei-compatible fuzzing
    payloads: dict[str, list[str]] = field(default_factory=dict)   # {varname: [val1, val2, ...]}
    attack: str = "batteringram"    # batteringram | pitchfork | clusterbomb
    extractors: list[TemplateExtractor] = field(default_factory=list)
    id: Optional[str] = None          # named request block (used by flow:)


@dataclass
class Template:
    id: str
    name: str
    severity: Severity
    description: str
    remediation: str
    requests: list[TemplateRequest]
    cve: Optional[str] = None
    cvss: float = 0.0
    cwe: Optional[str] = None
    owasp: str = "A05:2021"
    tags: list[str] = field(default_factory=list)
    source_file: str = ""
    template_vars: dict[str, str] = field(default_factory=dict)  # Nuclei variables: block
    flow: Optional[str] = None                                    # Nuclei flow: script
    is_headless: bool = False                                     # True for headless: templates
    rate_limit_rps: Optional[float] = None                       # Gap 26 — per-template rate limit


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_templates(dirs: list[str] | None = None) -> list[Template]:
    """Load all YAML templates from one or more directories (recursive)."""
    search_dirs = dirs or [_DEFAULT_TEMPLATES_DIR]
    templates = []
    for d in search_dirs:
        for path in glob.glob(os.path.join(d, "**", "*.yaml"), recursive=True):
            try:
                t = _parse_template(path)
                if t:
                    templates.append(t)
            except Exception:
                pass
    return templates


def _parse_template(path: str) -> Optional[Template]:
    with open(path) as f:
        data = yaml.safe_load(f)
    if not data:
        return None

    info = data.get("info", {})
    severity_str = str(info.get("severity", "info")).lower()
    severity = _SEVERITY_MAP.get(severity_str, Severity.INFO)

    # Headless templates — delegate to headless_runner
    if "headless" in data:
        ht = _parse_headless_template(path, data, info, severity)
        ht._headless_data = data  # type: ignore[attr-defined]
        return ht

    # Gap 15: code: templates — store raw data for code_runner
    if "code" in data:
        t = Template(
            id=data.get("id", os.path.basename(path)),
            name=info.get("name", data.get("id", "")),
            severity=severity,
            description=info.get("description", ""),
            remediation=info.get("remediation", ""),
            cve=info.get("cve") or _extract_cve(info.get("tags", [])),
            cvss=float(info.get("cvss", 0.0)),
            cwe=info.get("cwe"),
            owasp=info.get("owasp", "A05:2021"),
            tags=info.get("tags", []),
            requests=[],
            source_file=path,
        )
        object.__setattr__(t, "_code_data", data)  # type: ignore[call-arg]
        t._code_data = data  # type: ignore[attr-defined]
        return t

    raw_requests = data.get("requests", data.get("http", []))
    if not raw_requests:
        return None

    requests = [_parse_request(r) for r in raw_requests]

    # Nuclei-compatible variables: block — {{varname}} substitution across the template
    template_vars: dict[str, str] = {}
    for k, v in (data.get("variables", {}) or {}).items():
        template_vars[f"{{{{{k}}}}}"] = str(v)

    # Gap 26 — parse rate-limit: field
    rate_limit_rps = None
    raw_rl = data.get("rate-limit") or data.get("rate_limit")
    if raw_rl is not None:
        try:
            rate_limit_rps = float(raw_rl)
        except (TypeError, ValueError):
            pass

    return Template(
        id=data.get("id", os.path.basename(path)),
        name=info.get("name", data.get("id", "")),
        severity=severity,
        description=info.get("description", ""),
        remediation=info.get("remediation", ""),
        cve=info.get("cve") or _extract_cve(info.get("tags", [])),
        cvss=float(info.get("cvss", 0.0)),
        cwe=info.get("cwe"),
        owasp=info.get("owasp", "A05:2021"),
        tags=info.get("tags", []),
        requests=requests,
        source_file=path,
        template_vars=template_vars,
        flow=data.get("flow"),
        rate_limit_rps=rate_limit_rps,
    )


def _parse_request(raw: dict) -> TemplateRequest:
    matchers_raw = raw.get("matchers", [])
    matchers = [_parse_matcher(m) for m in matchers_raw]

    paths = raw.get("path", raw.get("paths", []))
    if isinstance(paths, str):
        paths = [paths]

    # payloads: block — values may be inline lists or file paths (inline only for now)
    raw_payloads = raw.get("payloads", {}) or {}
    payloads: dict[str, list[str]] = {}
    for var, val in raw_payloads.items():
        if isinstance(val, list):
            payloads[var] = [str(v) for v in val]
        else:
            payloads[var] = [str(val)]

    extractors = [_parse_extractor(e) for e in (raw.get("extractors") or [])]

    return TemplateRequest(
        method=raw.get("method", "GET").upper(),
        paths=paths,
        headers=raw.get("headers", {}),
        body=raw.get("body"),
        matchers_condition=raw.get("matchers-condition", raw.get("matchers_condition", "or")).lower(),
        matchers=matchers,
        payloads=payloads,
        attack=raw.get("attack", "batteringram").lower(),
        extractors=extractors,
        id=raw.get("id"),
    )


def _parse_extractor(raw: dict) -> TemplateExtractor:
    return TemplateExtractor(
        name=raw.get("name", "extracted"),
        type=raw.get("type", "regex").lower(),
        part=raw.get("part", "body").lower(),
        regex=raw.get("regex", []),
        group=int(raw.get("group", 0)),
        header=raw.get("header", "").lower(),
        json_path=raw.get("json", ""),
    )


def _parse_matcher(raw: dict) -> TemplateMatcher:
    return TemplateMatcher(
        type=raw.get("type", "word").lower(),
        part=raw.get("part", "body").lower(),
        words=raw.get("words", []),
        regex=raw.get("regex", []),
        status=raw.get("status", []),
        header=raw.get("header", "").lower(),
        condition=raw.get("condition", "or").lower(),
        negative=bool(raw.get("negative", False)),
    )


def _extract_cve(tags: list) -> Optional[str]:
    for tag in tags:
        if re.match(r"CVE-\d{4}-\d+", str(tag), re.IGNORECASE):
            return tag.upper()
    return None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_template(template: Template, page_url: str, client) -> list[Finding]:
    """Run a single template against a URL. Returns findings."""
    parsed = urlparse(page_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    variables = {
        "{{BaseURL}}": base_url,
        "{{Hostname}}": parsed.hostname or "",
        "{{Path}}": parsed.path or "/",
        "{{Port}}": str(parsed.port or (443 if parsed.scheme == "https" else 80)),
        "{{Scheme}}": parsed.scheme,
    }

    # Merge template-level variables (Nuclei variables: block)
    if template.template_vars:
        variables.update(template.template_vars)

    findings = []

    # Headless templates use Playwright instead of httpx
    if template.is_headless:
        return _run_headless_template(template, base_url)

    # Gap 15: code: templates — execute inline Python/shell code blocks
    code_data = getattr(template, "_code_data", None)
    if code_data:
        return _run_code_template(template, page_url, client, base_url)

    # If the template has a flow: script, run it after static requests complete
    if template.flow:
        try:
            from scanner.core.flow_evaluator import run_flow
            flow_results = run_flow(template.flow, template, variables, client)
            for r in flow_results:
                if r.get("status") and r["status"] < 400:
                    findings.append(_make_finding(template, r["url"], r["status"], r.get("body", "")))
        except Exception:
            pass
        return findings

    # Gap 26 — per-template rate limit: sleep between requests
    import time as _time
    _rate_sleep = (1.0 / template.rate_limit_rps) if template.rate_limit_rps else 0.0

    for req in template.requests:
        for path_tpl in req.paths:
            # Expand fuzzing payloads if present
            payload_combos = _expand_payloads(req)
            for combo in payload_combos:
                if _rate_sleep > 0:
                    _time.sleep(_rate_sleep)
                merged = {**variables, **combo}
                url = _substitute(path_tpl, merged)
                result = _execute_request(req, url, merged, client)
                if result is None:
                    continue
                resp_status, resp_body, resp_headers = result

                # Run extractors — extracted values flow into variables for subsequent requests
                if req.extractors:
                    extracted = _run_extractors(req.extractors, resp_status, resp_body, resp_headers)
                    variables.update(extracted)

                if _matches(req, resp_status, resp_body, resp_headers):
                    findings.append(_make_finding(template, url, resp_status, resp_body))
                    if req.stop_at_first_match:
                        return findings
    return findings


def _run_extractors(extractors: list[TemplateExtractor], status: int, body: str, headers: dict) -> dict[str, str]:
    """Run all extractors and return {{{varname}}: value} for substitution."""
    extracted: dict[str, str] = {}
    for ext in extractors:
        value = _extract_one(ext, status, body, headers)
        if value is not None:
            extracted[f"{{{{{ext.name}}}}}"] = value
    return extracted


def _extract_one(ext: TemplateExtractor, status: int, body: str, headers: dict) -> Optional[str]:
    if ext.type == "regex":
        target = _get_part(ext.part, ext.header, status, body, headers)
        for pattern in ext.regex:
            m = re.search(pattern, target, re.IGNORECASE | re.DOTALL)
            if m:
                try:
                    return m.group(ext.group)
                except IndexError:
                    return m.group(0)
        return None

    if ext.type == "kval":
        name = ext.header or ext.name
        return headers.get(name, headers.get(name.lower())) or None

    if ext.type == "json":
        try:
            import json as _json
            data = _json.loads(body)
            for key in ext.json_path.split("."):
                data = data[key]
            return str(data)
        except Exception:
            return None

    return None


def _expand_payloads(req: TemplateRequest) -> list[dict[str, str]]:
    """Return list of variable dicts to substitute per request iteration."""
    if not req.payloads:
        return [{}]  # single pass, no extra vars

    keys = list(req.payloads.keys())
    lists = [req.payloads[k] for k in keys]

    if req.attack == "clusterbomb":
        # cartesian product of all wordlists
        combos = list(itertools.product(*lists))
    elif req.attack == "pitchfork":
        # zip (shortest wins)
        combos = list(zip(*lists))
    else:
        # batteringram — same position across all lists (cycle shorter ones)
        max_len = max(len(lst) for lst in lists)
        combos = [tuple(lst[i % len(lst)] for lst in lists) for i in range(max_len)]

    return [{f"{{{{{k}}}}}": v for k, v in zip(keys, combo)} for combo in combos]


def _execute_request(req: TemplateRequest, url: str, variables: dict, client):
    headers = {k: _substitute(v, variables) for k, v in req.headers.items()}
    body = _substitute(req.body, variables) if req.body else None

    try:
        method = req.method.upper()
        if method == "GET":
            resp = client.get(url, headers=headers)
        elif method == "POST":
            resp = client.post(url, content=body, headers=headers)
        elif method == "PUT":
            resp = client.put(url, content=body, headers=headers)
        elif method == "DELETE":
            resp = client.delete(url, headers=headers)
        elif method == "OPTIONS":
            resp = client.options(url, headers=headers)
        elif method == "HEAD":
            resp = client.head(url, headers=headers)
        elif method == "PATCH":
            resp = client.patch(url, content=body, headers=headers)
        else:
            return None

        resp_body = resp.text if hasattr(resp, "text") else ""
        resp_headers = dict(resp.headers) if hasattr(resp, "headers") else {}
        return resp.status_code, resp_body, resp_headers
    except Exception:
        return None


def _matches(req: TemplateRequest, status: int, body: str, headers: dict) -> bool:
    # Require explicit matchers — a status-only fallback produces SPA catch-all false positives
    if not req.matchers:
        return False

    results = [_eval_matcher(m, status, body, headers) for m in req.matchers]

    if req.matchers_condition == "and":
        return all(results)
    return any(results)


def _eval_matcher(m: TemplateMatcher, status: int, body: str, headers: dict) -> bool:
    result = _eval_matcher_inner(m, status, body, headers)
    return not result if m.negative else result


def _eval_matcher_inner(m: TemplateMatcher, status: int, body: str, headers: dict) -> bool:
    if m.type == "status":
        return status in m.status

    if m.type == "word":
        target = _get_part(m.part, m.header, status, body, headers)
        hits = [w.lower() in target.lower() for w in m.words]
        return all(hits) if m.condition == "and" else any(hits)

    if m.type == "regex":
        target = _get_part(m.part, m.header, status, body, headers)
        hits = [bool(re.search(r, target, re.IGNORECASE | re.DOTALL)) for r in m.regex]
        return all(hits) if m.condition == "and" else any(hits)

    if m.type == "header":
        target = _get_part("header", m.header, status, body, headers)
        hits = [w.lower() in target.lower() for w in m.words]
        return all(hits) if m.condition == "and" else any(hits)

    return False


def _get_part(part: str, header_name: str, status: int, body: str, headers: dict) -> str:
    if part == "body":
        return body
    if part == "status":
        return str(status)
    if part == "header":
        if header_name:
            return headers.get(header_name, headers.get(header_name.lower(), ""))
        return " ".join(f"{k}: {v}" for k, v in headers.items())
    return body


def _substitute(tpl: str, variables: dict) -> str:
    if not tpl:
        return tpl
    for k, v in variables.items():
        tpl = tpl.replace(k, v)
    return tpl


def _parse_headless_template(path: str, data: dict, info: dict, severity: Severity) -> Template:
    """Wrap a headless: YAML template as a Template with is_headless=True."""
    template_vars: dict[str, str] = {}
    for k, v in (data.get("variables", {}) or {}).items():
        template_vars[f"{{{{{k}}}}}"] = str(v)

    return Template(
        id=data.get("id", os.path.basename(path)),
        name=info.get("name", data.get("id", "")),
        severity=severity,
        description=info.get("description", ""),
        remediation=info.get("remediation", ""),
        cve=info.get("cve") or _extract_cve(info.get("tags", [])),
        cvss=float(info.get("cvss", 0.0)),
        cwe=info.get("cwe"),
        owasp=info.get("owasp", "A05:2021"),
        tags=info.get("tags", []),
        requests=[],
        source_file=path,
        template_vars=template_vars,
        flow=None,
        is_headless=True,
        # Stash raw headless data on the template for the runner
        # We use a non-dataclass attribute set after init
    )


def _attach_headless_data(template: Template, data: dict) -> Template:
    """Attach raw headless block to a Template object."""
    object.__setattr__(template, "_headless_data", data)
    return template


def _run_headless_template(template: Template, base_url: str) -> list[Finding]:
    """Execute a headless template using headless_runner."""
    from scanner.core.headless_runner import parse_headless, run_headless

    raw_data = getattr(template, "_headless_data", None)
    if not raw_data:
        return []

    flat_vars = {k.strip("{}"): v for k, v in template.template_vars.items()}
    ht = parse_headless(raw_data, flat_vars)
    if not ht:
        return []

    result = run_headless(ht, base_url)

    if not result.get("matched"):
        return []

    evidence = f"Headless template '{template.id}' matched at {result['url']}"
    if result.get("extracted"):
        evidence += f" | Extracted: {result['extracted']}"
    if result.get("error"):
        evidence += f" | Error: {result['error']}"

    return [Finding(
        title=template.name,
        severity=template.severity,
        url=result["url"],
        parameter=None,
        payload=None,
        evidence=evidence,
        description=template.description,
        remediation=template.remediation,
        cwe=template.cwe,
        cvss=template.cvss,
        owasp_category=template.owasp,
        standards={"CVE": template.cve} if template.cve else {},
        confidence=0.80,
    )]


def _run_code_template(template: Template, page_url: str, client, base_url: str) -> list[Finding]:
    """Gap 15 — execute code: block templates via code_runner subprocess."""
    from scanner.core.code_runner import parse_code_blocks, run_code_block

    code_data = getattr(template, "_code_data", {})
    blocks = parse_code_blocks(code_data)
    if not blocks:
        return []

    # Fetch the page to provide response context
    try:
        resp = client.get(page_url, timeout=10)
        resp_body = resp.text
        resp_status = resp.status_code
        resp_headers = dict(resp.headers)
    except Exception:
        resp_body, resp_status, resp_headers = "", 0, {}

    findings = []
    for block in blocks:
        result = run_code_block(
            block, page_url, resp_body, resp_status, resp_headers
        )
        if result.matched:
            findings.append(Finding(
                title=template.name,
                severity=template.severity,
                url=page_url,
                parameter=None,
                payload=f"code:{block.engine}",
                evidence=(
                    f"Code template '{template.id}' matched. "
                    f"Output: {result.output[:300]}"
                    + (f" | Error: {result.error[:100]}" if result.error else "")
                ),
                description=template.description,
                remediation=template.remediation,
                cwe=template.cwe,
                cvss=template.cvss,
                owasp_category=template.owasp,
                confidence=0.80,
            ))
    return findings


def _make_finding(template: Template, url: str, status: int, body: str) -> Finding:
    evidence = f"Template '{template.id}' matched: HTTP {status}"
    if body:
        evidence += f" | Response snippet: {body[:200]}"
    return Finding(
        title=template.name,
        severity=template.severity,
        url=url,
        parameter=None,
        payload=None,
        evidence=evidence,
        description=template.description,
        remediation=template.remediation,
        cwe=template.cwe,
        cvss=template.cvss,
        owasp_category=template.owasp,
        standards={"CVE": template.cve} if template.cve else {},
        confidence=0.85,
    )
