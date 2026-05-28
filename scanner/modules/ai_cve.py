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

from typing import List
from urllib.parse import urlparse

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding
from scanner.core.fingerprinter import fingerprint_page, _SKIP_EXTENSIONS

_state: dict[str, dict] = {}


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
    fingerprint_page(page, state["fingerprints"])

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


