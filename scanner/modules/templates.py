"""
Template-based scanning module.

Without AI key:  loads all templates, runs every one against every page.
With AI key:     fingerprints the stack across pages, asks Claude which template
                 tags/CVEs are relevant, then runs only the selected subset.

This is the difference between running 10,000+ templates blindly and running
80-200 targeted ones — 50–100× faster with higher signal-to-noise.

Selection is cached per stack fingerprint for 7 days (selector_cache/).
Template loading is cached per directory set for the process lifetime.
"""
from __future__ import annotations

import os
import threading
from typing import List

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding
from scanner.core.template_runner import load_templates, run_template
from scanner.core.fingerprinter import fingerprint_page

# Auto-load nuclei templates if the user has run `kagesec update-templates`
_NUCLEI_TEMPLATES_DIR = os.path.expanduser("~/.kagesec/nuclei-templates")

_template_cache: dict[str, list] = {}          # dir-set → all templates
_state: dict[str, dict] = {}                   # target → per-scan state
_state_lock = threading.Lock()


def _get_all_templates(config=None) -> list:
    extra_dirs = []
    if config:
        extra = getattr(config, "template_dirs", None)
        if extra:
            extra_dirs = list(extra) if isinstance(extra, (list, tuple)) else [extra]

    # Auto-include nuclei templates dir if it exists and not already listed
    if os.path.isdir(_NUCLEI_TEMPLATES_DIR) and _NUCLEI_TEMPLATES_DIR not in extra_dirs:
        extra_dirs.append(_NUCLEI_TEMPLATES_DIR)

    cache_key = str(sorted(extra_dirs))
    if cache_key not in _template_cache:
        _template_cache[cache_key] = load_templates(extra_dirs if extra_dirs else None)
    return _template_cache[cache_key]


def _get_state(target: str) -> dict:
    with _state_lock:
        if target not in _state:
            _state[target] = {
                "fingerprints":  {},
                "selected":      None,   # None = not yet selected
                "selecting":     False,  # selection in progress
                "select_done":   threading.Event(),
            }
        return _state[target]


def test(page: CrawlResult, client, config=None) -> List[Finding]:
    all_templates = _get_all_templates(config)
    if not all_templates:
        return []

    api_key = getattr(config, "api_key", None) if config else None
    target  = getattr(config, "target", page.url) if config else page.url

    if not api_key:
        # No AI — run everything (original behaviour)
        return _run_templates(all_templates, page, client)

    state = _get_state(target)

    # Always accumulate fingerprints from every page
    fingerprint_page(page, state["fingerprints"])

    # If selection already done, just run
    if state["select_done"].is_set():
        return _run_templates(state["selected"] or all_templates, page, client)

    # Race: first thread to reach here triggers selection; others wait
    with _state_lock:
        already_selecting = state["selecting"]
        if not already_selecting:
            state["selecting"] = True

    if already_selecting:
        state["select_done"].wait(timeout=30)
        return _run_templates(state["selected"] or all_templates, page, client)

    # This thread owns the selection
    try:
        from scanner.ai.template_selector import select_templates, summarise_selection
        selected = select_templates(dict(state["fingerprints"]), all_templates, api_key)
        state["selected"] = selected
        summary = summarise_selection(state["fingerprints"], selected, len(all_templates))
        print(f"\n{summary}")
    except Exception:
        state["selected"] = all_templates
    finally:
        state["select_done"].set()

    return _run_templates(state["selected"] or all_templates, page, client)


def _run_templates(templates: list, page: CrawlResult, client) -> List[Finding]:
    findings: List[Finding] = []
    for template in templates:
        try:
            results = run_template(template, page.url, client)
            findings.extend(results)
        except Exception:
            pass
    return findings
