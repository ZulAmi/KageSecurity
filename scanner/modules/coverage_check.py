"""
Robots.txt + Sitemap.xml Coverage Cross-Reference — Gap 35

After crawling, compares:
  1. URLs listed in robots.txt Disallow directives (should have been probed)
  2. URLs listed in sitemap.xml <loc> entries (should have been crawled)
  3. Crawled pages set

Reports any paths listed in robots/sitemap that were NOT crawled,
representing potential attack surface gaps.
"""
import re
import httpx
from typing import List, Set
from urllib.parse import urlparse
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

_probed_hosts: set = set()


def reset() -> None:
    _probed_hosts.clear()


def test(page: CrawlResult, client: httpx.Client, config=None) -> List[Finding]:
    parsed = urlparse(page.url)
    host_key = f"{parsed.scheme}://{parsed.netloc}"

    if host_key in _probed_hosts:
        return []
    _probed_hosts.add(host_key)

    findings: List[Finding] = []
    crawled_urls = _get_crawled_urls(config)

    robots_paths = _fetch_robots_paths(host_key, client)
    sitemap_urls = _fetch_sitemap_urls(host_key, client)

    _check_coverage(host_key, robots_paths, sitemap_urls, crawled_urls, page.url, findings)
    return findings


def _get_crawled_urls(config) -> Set[str]:
    """Retrieve the set of crawled page URLs from config or scan result context."""
    crawled = getattr(config, "_crawled_urls", set())
    if isinstance(crawled, set):
        return crawled
    return set()


def _fetch_robots_paths(base_url: str, client: httpx.Client) -> List[str]:
    paths = []
    try:
        resp = client.get(f"{base_url}/robots.txt", timeout=8)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        paths.append(path)
    except Exception:
        pass
    return paths[:100]


def _fetch_sitemap_urls(base_url: str, client: httpx.Client) -> List[str]:
    urls = []
    for path in ("sitemap.xml", "sitemap_index.xml"):
        try:
            resp = client.get(f"{base_url}/{path}", timeout=8)
            if resp.status_code == 200 and "<loc>" in resp.text:
                for m in re.finditer(r'<loc>\s*([^<\s]+)\s*</loc>', resp.text):
                    urls.append(m.group(1).strip())
        except Exception:
            pass
    return urls[:200]


def _check_coverage(
    base_url: str,
    robots_paths: List[str],
    sitemap_urls: List[str],
    crawled_urls: Set[str],
    page_url: str,
    findings: List[Finding],
):
    uncovered_sitemap = []
    for url in sitemap_urls:
        if url not in crawled_urls and not _url_matches_crawled(url, crawled_urls):
            uncovered_sitemap.append(url)

    uncovered_robots = []
    for path in robots_paths:
        full_url = base_url.rstrip("/") + "/" + path.lstrip("/")
        if full_url not in crawled_urls and not _url_matches_crawled(full_url, crawled_urls):
            uncovered_robots.append(path)

    if uncovered_sitemap:
        findings.append(Finding(
            title="Coverage Gap — Sitemap URLs Not Crawled",
            severity=Severity.INFO,
            url=page_url,
            parameter=None,
            payload=None,
            evidence=(
                f"{len(uncovered_sitemap)} of {len(sitemap_urls)} sitemap.xml URLs were not crawled. "
                f"Examples: {', '.join(uncovered_sitemap[:5])}"
            ),
            description=(
                "The following URLs are listed in sitemap.xml but were not crawled during this scan. "
                "They represent potential attack surface that was not tested. "
                "This may be due to crawl depth limits, authentication requirements, or JavaScript rendering."
            ),
            remediation=(
                "Increase the crawl depth (--max-depth) or page limit (--max-pages). "
                "Use authenticated scanning (--cookie / --bearer) for authenticated sections. "
                "Use browser-based crawling (--browser) for JavaScript-rendered pages."
            ),
            cwe="CWE-200",
            cvss=0.0,
            owasp_category="A05:2021 Security Misconfiguration",
            confidence=1.0,
        ))

    if uncovered_robots:
        findings.append(Finding(
            title="Coverage Gap — Robots.txt Paths Not Probed",
            severity=Severity.INFO,
            url=page_url,
            parameter=None,
            payload=None,
            evidence=(
                f"{len(uncovered_robots)} of {len(robots_paths)} robots.txt paths were not probed. "
                f"Examples: {', '.join(uncovered_robots[:5])}"
            ),
            description=(
                "The following paths from robots.txt Disallow/Allow were not probed during this scan. "
                "Robots.txt paths are often sensitive areas that were intentionally hidden from crawlers. "
                "They should be actively tested but were missed."
            ),
            remediation=(
                "Enable the robots_probe module (it should run automatically). "
                "Check if the paths require authentication."
            ),
            cwe="CWE-548",
            cvss=0.0,
            owasp_category="A05:2021 Security Misconfiguration",
            confidence=1.0,
        ))


def _url_matches_crawled(url: str, crawled: Set[str]) -> bool:
    """Loose match: ignore trailing slash and query string differences."""
    normalized = url.rstrip("/").split("?")[0]
    return any(c.rstrip("/").split("?")[0] == normalized for c in crawled)
