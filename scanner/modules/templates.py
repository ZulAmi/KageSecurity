"""
Template-based scanning module.

Loads all YAML templates from scanner/templates/ (and any --templates path
passed via config) and runs them against every crawled page.

This makes KageSec extensible in the same way Nuclei is: drop a .yaml file
into scanner/templates/ and it's picked up automatically on the next scan.
"""
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding
from scanner.core.template_runner import load_templates, run_template

_template_cache: list | None = None


def _get_templates(config=None) -> list:
    global _template_cache
    if _template_cache is not None:
        return _template_cache
    extra_dirs = []
    if config:
        extra = getattr(config, "template_dirs", None)
        if extra:
            extra_dirs = extra if isinstance(extra, list) else [extra]
    _template_cache = load_templates(None if not extra_dirs else extra_dirs)
    return _template_cache


def test(page: CrawlResult, client) -> List[Finding]:
    templates = _get_templates()
    findings = []
    for template in templates:
        try:
            results = run_template(template, page.url, client)
            findings.extend(results)
        except Exception:
            pass
    return findings
