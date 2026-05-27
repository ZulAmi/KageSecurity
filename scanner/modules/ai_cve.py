"""
AI-powered template generation module.

Phase 1 (per-page): Collect technology fingerprints from HTTP headers and body.
Phase 2 (once per target): Ask Claude to generate YAML templates for the detected
stack, then run them through the standard template runner.

Claude generates 20-40 targeted templates (CVEs, misconfigs, exposed panels) for
the exact versions detected — rather than brute-forcing thousands of static templates.
Results are cached in ~/.kagesec/template_cache/ for 30 days per unique stack.

API key is read from config.api_key at scan time — never from the environment at
import time. Global state is keyed by config.target so concurrent scans stay isolated.
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding

_state: dict[str, dict] = {}

_SKIP_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".svg", ".woff", ".ico", ".ttf", ".map",
)

_HEADER_FINGERPRINTS = [
    ("Web Server",         "server"),
    ("Scripting Language", "x-powered-by"),
    ("ASP.NET Version",    "x-aspnet-version"),
    ("ASP.NET MVC",        "x-aspnetmvc-version"),
    ("CDN / Proxy",        "via"),
]

_BODY_FINGERPRINTS = [
    ("WordPress",   re.compile(r'wp-content/(?:themes|plugins)/[^/]+/([0-9.]+)', re.IGNORECASE)),
    ("jQuery",      re.compile(r'jquery[/-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js', re.IGNORECASE)),
    ("React",       re.compile(r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)".*react', re.IGNORECASE)),
    ("Angular",     re.compile(r'angular(?:\.min)?\.js.*?([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Vue.js",      re.compile(r'vue(?:\.min)?\.js.*?([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Bootstrap",   re.compile(r'bootstrap(?:\.min)?\.(?:css|js).*?([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("PHP",         re.compile(r'PHP/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Drupal",      re.compile(r'Drupal\s+([0-9]+)', re.IGNORECASE)),
    ("Django",      re.compile(r'Django/([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Rails",       re.compile(r'Rails\s+([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("OpenSSL",     re.compile(r'OpenSSL/([0-9]+\.[0-9]+\.[0-9]+[a-z]?)', re.IGNORECASE)),
    ("Apache",      re.compile(r'Apache/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("nginx",       re.compile(r'nginx/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Tomcat",      re.compile(r'Apache Tomcat/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Spring Boot", re.compile(r'Spring Boot ([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Express",     re.compile(r'Express/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Next.js",     re.compile(r'Next\.js/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Laravel",     re.compile(r'laravel[/ ]([0-9]+\.[0-9]+)', re.IGNORECASE)),
]


def _get_state(target: str) -> dict:
    if target not in _state:
        _state[target] = {"fingerprints": {}, "queried": False}
    return _state[target]


def test(page: CrawlResult, client, config=None) -> List[Finding]:
    api_key = getattr(config, "api_key", None) if config else None
    if not api_key:
        return []

    target = getattr(config, "target", page.url) if config else page.url
    state = _get_state(target)

    if any(page.url.endswith(ext) for ext in _SKIP_EXTENSIONS):
        return []

    # Phase 1: accumulate fingerprints from every page
    _collect_fingerprints(page, state["fingerprints"])

    # Phase 2: generate templates once — on the root page, after fingerprinting
    if state["queried"]:
        return []

    parsed = urlparse(page.url)
    if parsed.path not in ("", "/", "/index.html", "/index.php"):
        return []

    if not state["fingerprints"]:
        return []

    state["queried"] = True

    try:
        from scanner.ai.cve_researcher import generate_templates
        from scanner.core.template_runner import load_templates, run_template

        base_url = f"{parsed.scheme}://{parsed.netloc}"
        template_dir = generate_templates(dict(state["fingerprints"]), api_key)
        if not template_dir:
            return []

        templates = load_templates([template_dir])
        findings: List[Finding] = []
        for template in templates:
            try:
                results = run_template(template, base_url, client)
                findings.extend(results)
            except Exception:
                pass
        return findings
    except Exception:
        return []


def _collect_fingerprints(page: CrawlResult, fingerprints: dict) -> None:
    for label, header_name in _HEADER_FINGERPRINTS:
        value = page.headers.get(header_name, "")
        if value and label not in fingerprints:
            fingerprints[label] = value

    body = page.body or ""
    for name, pattern in _BODY_FINGERPRINTS:
        if name not in fingerprints:
            m = pattern.search(body)
            if m:
                version = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                fingerprints[name] = f"{name} {version}"
