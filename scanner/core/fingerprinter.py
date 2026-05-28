"""
Tech-stack fingerprinter — shared utility used by template selector and AI CVE researcher.

Extracts web server, language, framework, CMS, library, and CDN signals from
crawled pages via headers, cookies, body patterns, meta tags, and URL patterns.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.crawler import CrawlResult

# ---------------------------------------------------------------------------
# Signal tables
# ---------------------------------------------------------------------------

_HEADER_SIGNALS: list[tuple[str, str]] = [
    ("Web Server",         "server"),
    ("Scripting Language", "x-powered-by"),
    ("ASP.NET Version",    "x-aspnet-version"),
    ("ASP.NET MVC",        "x-aspnetmvc-version"),
    ("CDN / Proxy",        "via"),
    ("X-Runtime",          "x-runtime"),          # Rails response time header
    ("X-Generator",        "x-generator"),
    ("CF-Ray",             "cf-ray"),              # Cloudflare
    ("X-Amz-RequestId",   "x-amz-requestid"),     # AWS
    ("X-Sucuri-ID",        "x-sucuri-id"),         # Sucuri WAF
    ("X-Litespeed-Cache",  "x-litespeed-cache"),   # LiteSpeed
]

# header-name → (tech label, header-value substring)
_COOKIE_SIGNALS: list[tuple[str, str, str]] = [
    ("PHPSESSID",          "PHP",                    ""),
    ("JSESSIONID",         "Java / Tomcat",          ""),
    ("ASP.NET_SessionId",  ".NET / ASP.NET",         ""),
    ("laravel_session",    "Laravel",                ""),
    ("django_session",     "Django",                 ""),
    ("rack.session",       "Ruby / Rack",            ""),
    ("_session_id",        "Ruby on Rails",          ""),
    ("__cfduid",           "Cloudflare",             ""),
    ("__cf_bm",            "Cloudflare Bot Mgmt",    ""),
    ("sid",                "",                       ""),   # generic
]

_BODY_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Versioned fingerprints
    ("WordPress",    re.compile(r'(?:wp-content|wp-includes)/[^"\']*?/([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.IGNORECASE)),
    ("Drupal",       re.compile(r'Drupal\s+([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Joomla",       re.compile(r'Joomla!\s+([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Magento",      re.compile(r'Mage\.VERSION\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Django",       re.compile(r'Django/([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Rails",        re.compile(r'Rails\s+([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Laravel",      re.compile(r'laravel[/ ]([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Spring Boot",  re.compile(r'Spring[\s-]Boot[\s/]([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Express",      re.compile(r'Express/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Next.js",      re.compile(r'Next\.js/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Nuxt",         re.compile(r'nuxt(?:\.min)?\.js.*?([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Apache",       re.compile(r'Apache/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("nginx",        re.compile(r'nginx/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Tomcat",       re.compile(r'Apache Tomcat/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("OpenSSL",      re.compile(r'OpenSSL/([0-9]+\.[0-9]+\.[0-9]+[a-z]?)', re.IGNORECASE)),
    ("PHP",          re.compile(r'PHP/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("jQuery",       re.compile(r'jquery[/-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js', re.IGNORECASE)),
    ("Bootstrap",    re.compile(r'bootstrap(?:\.min)?\.(?:css|js)[^"\']*?([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("React",        re.compile(r'react(?:\.min)?\.js[^"\']*?([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Angular",      re.compile(r'angular(?:\.min)?\.js[^"\']*?([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Vue.js",       re.compile(r'vue(?:\.min)?\.js[^"\']*?([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Elasticsearch",re.compile(r'elasticsearch/([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Struts",       re.compile(r'Apache Struts ([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Symfony",      re.compile(r'Symfony[/ ]([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Yii",          re.compile(r'Yii PHP Framework/([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("CodeIgniter",  re.compile(r'CodeIgniter ([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("CakePHP",      re.compile(r'CakePHP ([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Flask",        re.compile(r'Werkzeug/([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("FastAPI",      re.compile(r'fastapi[/ ]([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Grafana",      re.compile(r'Grafana ([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Jenkins",      re.compile(r'Jenkins ver\. ([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("GitLab",       re.compile(r'GitLab\s+([0-9]+\.[0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Confluence",   re.compile(r'Confluence ([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("JIRA",         re.compile(r'JIRA ([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Kubernetes",   re.compile(r'Kubernetes ([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Moodle",       re.compile(r'Moodle ([0-9]+\.[0-9]+)', re.IGNORECASE)),
    ("Shopify",      re.compile(r'Shopify\.theme\.v([0-9]+\.[0-9]+)', re.IGNORECASE)),
]

# meta name=generator content="..."
_META_GENERATOR = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']',
    re.IGNORECASE,
)

# URL extension → language hint
_PATH_LANG_MAP: dict[str, str] = {
    ".php":  "PHP",
    ".asp":  "ASP",
    ".aspx": "ASP.NET",
    ".jsp":  "Java / JSP",
    ".cfm":  "ColdFusion",
    ".cgi":  "CGI",
    ".rb":   "Ruby",
    ".py":   "Python",
    ".pl":   "Perl",
}

_SKIP_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".svg",
    ".woff", ".woff2", ".ico", ".ttf", ".map", ".gif", ".webp",
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fingerprint_stack(pages: "list[CrawlResult]") -> dict[str, str]:
    """Aggregate tech stack fingerprints from a list of crawled pages."""
    fp: dict[str, str] = {}
    for page in pages:
        _fingerprint_page(page, fp)
    return fp


def fingerprint_page(page: "CrawlResult", existing: dict[str, str]) -> None:
    """Update `existing` dict in-place with signals from a single page."""
    _fingerprint_page(page, existing)


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _fingerprint_page(page: "CrawlResult", fp: dict[str, str]) -> None:
    if any(page.url.endswith(ext) for ext in _SKIP_EXTENSIONS):
        return

    headers_lower = {k.lower(): v for k, v in page.headers.items()}

    # Response headers
    for label, header_name in _HEADER_SIGNALS:
        if label not in fp:
            val = headers_lower.get(header_name, "")
            if val:
                fp[label] = val

    # Set-Cookie signals
    raw_cookie = headers_lower.get("set-cookie", "")
    for cookie_name, tech_label, _ in _COOKIE_SIGNALS:
        if tech_label and tech_label not in fp and cookie_name.lower() in raw_cookie.lower():
            fp[f"Cookie: {cookie_name}"] = tech_label

    # Body patterns
    body = page.body or ""
    for name, pattern in _BODY_PATTERNS:
        if name not in fp:
            m = pattern.search(body)
            if m:
                version = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                fp[name] = f"{name} {version}".strip()

    # Meta generator tag
    if "Meta Generator" not in fp:
        m = _META_GENERATOR.search(body)
        if m:
            fp["Meta Generator"] = m.group(1).strip()

    # URL extension → language hint
    from urllib.parse import urlparse
    path = urlparse(page.url).path
    ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    if ext in _PATH_LANG_MAP and "URL Language Hint" not in fp:
        fp["URL Language Hint"] = _PATH_LANG_MAP[ext]
