"""
AI-powered CVE detection module.

Phase 1 (per-page): Collect technology fingerprints from HTTP headers and body.
Phase 2 (once per unique stack): Ask Claude to identify CVEs, then verify them.

This module is self-throttling: once it has sent the tech stack to Claude for a
given combination of technologies, it won't query again for the same stack.
"""
from __future__ import annotations

import os
import re
from typing import List
from urllib.parse import urlparse

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding

# Module-level state: fingerprints collected across all pages
_fingerprints: dict[str, str] = {}
_queried_stacks: set[str] = set()
_api_key: str | None = os.getenv("ANTHROPIC_API_KEY")

# Version extraction patterns: (friendly_name, header_or_body_pattern, group_index)
_HEADER_FINGERPRINTS = [
    ("Web Server",            "server",                    None),   # raw header value
    ("Scripting Language",    "x-powered-by",              None),
    ("Framework",             "x-aspnet-version",          None),
    ("Framework",             "x-aspnetmvc-version",       None),
    ("CDN / Proxy",           "via",                       None),
    ("Debug Token",           "x-debug-token",             None),
]

_BODY_FINGERPRINTS = [
    ("WordPress",   re.compile(r'wp-content/(?:themes|plugins)/[^/]+/([0-9.]+)', re.IGNORECASE)),
    ("jQuery",      re.compile(r'jquery[/-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js', re.IGNORECASE)),
    ("React",       re.compile(r'react(?:\.development)?\.js.*?([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Angular",     re.compile(r'angular(?:\.min)?\.js.*?([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Vue.js",      re.compile(r'vue(?:\.min)?\.js.*?([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Bootstrap",   re.compile(r'bootstrap(?:\.min)?\.css.*?([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("PHP version", re.compile(r'PHP/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
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
]


def test(page: CrawlResult, client) -> List[Finding]:
    global _api_key

    # Collect fingerprints from this page
    _collect_fingerprints(page)

    # Only trigger AI research once we have meaningful fingerprints
    # and haven't already queried this stack
    if not _fingerprints:
        return []

    stack_key = _stack_key()
    if stack_key in _queried_stacks:
        return []

    # Only query AI on the root domain page to avoid per-page API spam
    parsed = urlparse(page.url)
    if parsed.path not in ("", "/", "/index.html", "/index.php"):
        return []

    if not _api_key:
        return []

    _queried_stacks.add(stack_key)

    try:
        from scanner.ai.cve_researcher import research_cves, verify_and_build_findings
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        cves = research_cves(dict(_fingerprints), _api_key)
        if not cves:
            return []
        return verify_and_build_findings(cves, base_url, client)
    except Exception:
        return []


def _collect_fingerprints(page: CrawlResult) -> None:
    # From response headers
    for label, header_name, _ in _HEADER_FINGERPRINTS:
        value = page.headers.get(header_name, "")
        if value and label not in _fingerprints:
            _fingerprints[label] = value

    # From response body
    search_targets = [page.body]
    if page.headers.get("server"):
        search_targets.append(page.headers["server"])

    for combined in search_targets:
        if not combined:
            continue
        for name, pattern in _BODY_FINGERPRINTS:
            if name not in _fingerprints:
                m = pattern.search(combined)
                if m:
                    version = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                    _fingerprints[name] = f"{name} {version}"


def _stack_key() -> str:
    return "|".join(sorted(_fingerprints.values()))
