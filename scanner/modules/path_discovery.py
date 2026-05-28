"""
Wordlist-Based Path / Directory Discovery — Gap 10

Probes known hidden paths (admin panels, config files, backup files, API endpoints)
against the target base URL. Findings are reported when:
  - HTTP 200/201/204/206 (content returned)
  - HTTP 301/302 redirect to a non-login page
  - HTTP 403 Forbidden (path exists but access denied — still valuable intel)
  - HTTP 401 Unauthorized (authentication required — endpoint exists)

Uses the built-in `scanner/payloads/paths.yaml` wordlist. Custom wordlist can be
provided via the `wordlist` config attribute or `--wordlist` CLI flag.

The module runs only against the root page of each host (not every crawled page)
to avoid redundant probes.
"""
import os
import yaml
import httpx
from typing import List, Optional
from urllib.parse import urlparse, urljoin
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import is_spa_catchall

_INTERESTING_CODES = frozenset({200, 201, 204, 206, 301, 302, 307, 308, 401, 403})
_CONTENT_CODES = frozenset({200, 201, 204, 206})

# Severity by HTTP code
_CODE_SEVERITY = {
    200: Severity.HIGH,
    201: Severity.HIGH,
    204: Severity.MEDIUM,
    206: Severity.MEDIUM,
    401: Severity.MEDIUM,
    403: Severity.LOW,
    301: Severity.INFO,
    302: Severity.INFO,
    307: Severity.INFO,
    308: Severity.INFO,
}

# Response body patterns indicating sensitive content
_SENSITIVE_PATTERNS = [
    "password", "secret", "api_key", "apikey", "private_key",
    "BEGIN RSA", "BEGIN EC", "AWS_ACCESS",
    "[mysqld]", "[mysql]", "[database]",
    "<?php", "DB_HOST", "DB_PASSWORD",
]

_BUILTIN_WORDLIST = os.path.join(os.path.dirname(__file__), "..", "payloads", "paths.yaml")

# Track which hosts we've already probed so we don't re-run on every page
_probed_hosts: set = set()


def reset() -> None:
    _probed_hosts.clear()


def test(page: CrawlResult, client: httpx.Client, config=None) -> List[Finding]:
    parsed = urlparse(page.url)
    host_key = f"{parsed.scheme}://{parsed.netloc}"

    # Only probe each host once per scan
    if host_key in _probed_hosts:
        return []
    _probed_hosts.add(host_key)

    paths = _load_paths(config)
    if not paths:
        return []

    # Expand paths with extension variants if --extensions was set
    extensions = getattr(config, "extensions", None)
    if extensions:
        expanded = list(paths)
        for p in paths:
            for ext in extensions:
                if not p.endswith(ext):
                    expanded.append(p.rstrip("/") + ext)
        paths = expanded

    filter_codes = set(getattr(config, "filter_status_codes", None) or [])

    findings: List[Finding] = []
    _probe_paths(host_key, paths, client, findings, filter_codes)
    return findings


def _load_paths(config) -> List[str]:
    custom_wordlist = getattr(config, "path_wordlist", None)
    if custom_wordlist and os.path.isfile(custom_wordlist):
        return _read_wordlist(custom_wordlist)
    return _read_wordlist(_BUILTIN_WORDLIST)


def _read_wordlist(path: str) -> List[str]:
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict) and "paths" in data:
            return [str(p) for p in data["paths"] if p]
        if isinstance(data, list):
            return [str(p) for p in data if p]
    except Exception:
        pass
    return []


def _probe_paths(base_url: str, paths: List[str], client: httpx.Client,
                 findings: List[Finding], filter_codes: set = frozenset()):
    for path in paths:
        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        try:
            resp = client.get(url, follow_redirects=False, timeout=8)
        except Exception:
            continue

        code = resp.status_code
        if code not in _INTERESTING_CODES:
            continue
        if code in filter_codes:
            continue

        # Reject SPA catch-all: React/Next.js returns 200+index.html for every route
        if code in _CONTENT_CODES and is_spa_catchall(resp):
            continue

        # Skip redirects that look like login/error pages
        if code in (301, 302, 307, 308):
            location = resp.headers.get("location", "")
            if any(x in location.lower() for x in (
                "login", "signin", "sign-in", "auth", "authenticate",
                "404", "error", "forbidden", "access-denied", "not-found",
            )):
                continue

        severity = _CODE_SEVERITY.get(code, Severity.INFO)
        is_sensitive = _is_sensitive_content(resp)
        if is_sensitive:
            severity = Severity.CRITICAL

        # Only report 403 when path is security-interesting
        if code == 403 and not _is_interesting_path(path):
            continue

        # Confidence: sensitive content > verified non-HTML 200 > bare 200 > redirect/auth
        if is_sensitive:
            confidence = 0.95
        elif code in _CONTENT_CODES:
            ct = resp.headers.get("content-type", "").lower()
            confidence = 0.85 if "text/html" not in ct else 0.65
        else:
            confidence = 0.85

        findings.append(Finding(
            title=f"Hidden Path Discovered — HTTP {code}",
            severity=severity,
            url=url,
            parameter=None,
            payload=path,
            evidence=(
                f"GET {url} returned HTTP {code}"
                + (f" with {len(resp.text)} bytes" if code in _CONTENT_CODES else "")
                + (" [SENSITIVE CONTENT DETECTED]" if is_sensitive else "")
            ),
            description=(
                f"A hidden or sensitive path was discovered via wordlist probing. "
                f"HTTP {code} indicates the path exists on the server. "
                + ("Sensitive data patterns detected in the response body." if is_sensitive else "")
            ),
            remediation=(
                "Remove or restrict access to sensitive paths. "
                "Apply authentication and authorisation to admin interfaces. "
                "Delete backup files, config files, and development artefacts from production. "
                "Configure your web server to deny access to sensitive file types."
            ),
            cwe="CWE-538" if is_sensitive else "CWE-548",
            cvss=9.1 if is_sensitive else (5.3 if code == 403 else 7.5),
            owasp_category="A05:2021 Security Misconfiguration",
            confidence=confidence,
        ))


def _is_sensitive_content(resp: httpx.Response) -> bool:
    if resp.status_code not in _CONTENT_CODES:
        return False
    body = resp.text[:4096].lower()
    return any(p.lower() in body for p in _SENSITIVE_PATTERNS)


def _is_interesting_path(path: str) -> bool:
    interesting_keywords = (
        "admin", "git", "env", "config", "backup", "api", "actuator",
        "phpmyadmin", "wp-admin", "debug", "secret", "credential",
    )
    return any(k in path.lower() for k in interesting_keywords)
