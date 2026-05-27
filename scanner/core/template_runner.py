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
class TemplateRequest:
    method: str
    paths: list[str]
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    matchers_condition: str = "or"     # and | or across matchers
    matchers: list[TemplateMatcher] = field(default_factory=list)
    stop_at_first_match: bool = True


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

    raw_requests = data.get("requests", data.get("http", []))
    if not raw_requests:
        return None

    requests = [_parse_request(r) for r in raw_requests]

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
    )


def _parse_request(raw: dict) -> TemplateRequest:
    matchers_raw = raw.get("matchers", [])
    matchers = [_parse_matcher(m) for m in matchers_raw]

    paths = raw.get("path", raw.get("paths", []))
    if isinstance(paths, str):
        paths = [paths]

    return TemplateRequest(
        method=raw.get("method", "GET").upper(),
        paths=paths,
        headers=raw.get("headers", {}),
        body=raw.get("body"),
        matchers_condition=raw.get("matchers-condition", raw.get("matchers_condition", "or")).lower(),
        matchers=matchers,
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

    findings = []
    for req in template.requests:
        for path_tpl in req.paths:
            url = _substitute(path_tpl, variables)
            result = _execute_request(req, url, variables, client)
            if result is None:
                continue
            resp_status, resp_body, resp_headers = result
            if _matches(req, resp_status, resp_body, resp_headers):
                findings.append(_make_finding(template, url, resp_status, resp_body))
                if req.stop_at_first_match:
                    return findings
    return findings


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
    if not req.matchers:
        return status < 400

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
