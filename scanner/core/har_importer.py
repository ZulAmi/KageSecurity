"""
HAR (HTTP Archive) importer.

Converts a browser-recorded .har file into CrawlResult objects so the full
module pipeline can scan them without crawling a live target.

Usage (CLI):  kagesec scan --har recording.har
Usage (API):  pages = import_har("recording.har")
              result, _ = run_scan(config=config)   # engine receives pre-built pages

HAR spec: http://www.softwareishard.com/blog/har-12-spec/
"""
from __future__ import annotations

import json
import base64
from typing import List
from urllib.parse import urlparse, parse_qs

from scanner.core.crawler import CrawlResult


def import_har(path: str) -> List[CrawlResult]:
    """
    Parse a .har file and return one CrawlResult per HTTP entry.
    Entries with non-HTTP(S) URLs, binary responses, or missing bodies are skipped.
    """
    with open(path, encoding="utf-8", errors="ignore") as f:
        har = json.load(f)

    entries = har.get("log", {}).get("entries", [])
    results: List[CrawlResult] = []
    seen_urls: set[str] = set()

    for entry in entries:
        try:
            result = _entry_to_crawl_result(entry)
            if result is None:
                continue
            dedup = result.url
            if dedup in seen_urls:
                continue
            seen_urls.add(dedup)
            results.append(result)
        except Exception:
            continue

    return results


def _entry_to_crawl_result(entry: dict) -> CrawlResult | None:
    req  = entry.get("request", {})
    resp = entry.get("response", {})

    url = req.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None

    status = resp.get("status", 0)
    if status == 0:
        return None

    # Response headers
    headers: dict[str, str] = {
        h["name"].lower(): h["value"]
        for h in resp.get("headers", [])
    }

    # Response body
    content = resp.get("content", {})
    mime = content.get("mimeType", "")
    body = ""
    if "html" in mime or "json" in mime or "xml" in mime or "text" in mime:
        raw = content.get("text", "")
        if content.get("encoding") == "base64" and raw:
            try:
                raw = base64.b64decode(raw).decode("utf-8", errors="ignore")
            except Exception:
                raw = ""
        body = raw

    # Extract forms from HTML body
    forms = _extract_forms_from_body(body, url)

    # Extract links from HTML body
    links = _extract_links_from_body(body, url)

    # Also capture query params as synthetic form inputs for injection testing
    if parsed.query:
        params = parse_qs(parsed.query)
        synthetic_inputs = [{"name": k, "type": "text", "value": v[0]} for k, v in params.items()]
        if synthetic_inputs:
            forms.append({
                "action": url,
                "method": req.get("method", "GET").lower(),
                "inputs": synthetic_inputs,
            })

    # POST body params
    post_data = req.get("postData", {})
    if post_data:
        post_params = post_data.get("params", [])
        if post_params:
            forms.append({
                "action": url,
                "method": "post",
                "inputs": [{"name": p["name"], "type": "text", "value": p.get("value", "")}
                           for p in post_params],
            })

    return CrawlResult(
        url=url,
        status_code=status,
        headers=headers,
        body=body,
        forms=forms,
        links=links,
    )


def _extract_forms_from_body(body: str, base_url: str) -> list[dict]:
    if not body or "<form" not in body.lower():
        return []
    try:
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin
        soup = BeautifulSoup(body, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action", base_url))
            method = form.get("method", "get").lower()
            inputs = [
                {"name": inp.get("name", ""), "type": inp.get("type", "text"), "value": inp.get("value", "")}
                for inp in form.find_all(["input", "textarea", "select"])
                if inp.get("name")
            ]
            forms.append({"action": action, "method": method, "inputs": inputs})
        return forms
    except Exception:
        return []


def _extract_links_from_body(body: str, base_url: str) -> list[str]:
    if not body:
        return []
    try:
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin, urlparse as _up
        base_domain = _up(base_url).netloc
        soup = BeautifulSoup(body, "html.parser")
        links = []
        for tag in soup.find_all("a", href=True):
            href = urljoin(base_url, tag["href"]).split("#")[0]
            if _up(href).netloc == base_domain:
                links.append(href)
        return links
    except Exception:
        return []
