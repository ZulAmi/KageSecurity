"""
Template-based scanning module.

Loads all YAML templates from scanner/templates/ plus any directories passed via
config.template_dirs, then runs them against every crawled page.

config is now properly passed in from the engine, so --templates CLI flag works.
Cache is keyed by the set of directories so it resets if dirs change between scans.
"""
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding
from scanner.core.template_runner import load_templates, run_template

_template_cache: dict[str, list] = {}   # key: frozenset of dirs → template list


def _get_templates(config=None) -> list:
    extra_dirs = []
    if config:
        extra = getattr(config, "template_dirs", None)
        if extra:
            extra_dirs = list(extra) if isinstance(extra, (list, tuple)) else [extra]

    cache_key = str(sorted(extra_dirs))
    if cache_key in _template_cache:
        return _template_cache[cache_key]

    templates = load_templates(extra_dirs if extra_dirs else None)
    _template_cache[cache_key] = templates
    return templates


def test(page: CrawlResult, client, config=None) -> List[Finding]:
    templates = _get_templates(config)
    findings = []
    for template in templates:
        try:
            results = run_template(template, page.url, client)
            findings.extend(results)
        except Exception:
            pass
    return findings
