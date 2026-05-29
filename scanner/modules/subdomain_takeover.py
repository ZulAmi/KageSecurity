"""
Subdomain takeover detection.

Checks CNAME records for all discovered subdomains. If a CNAME points to a
service that returns a "dangling" response (unclaimed, removed, or available for
registration), the subdomain may be takeable by an attacker.

Runs once per unique domain discovered from page links.
"""
import re
from urllib.parse import urlparse
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

# (service_name, CNAME pattern, fingerprint in HTTP response or NXDOMAIN)
_FINGERPRINTS = [
    ("GitHub Pages",      r"github\.io",            ["There isn't a GitHub Pages site here", "404 There is no GitHub Pages site"]),
    ("Heroku",            r"heroku(app)?\.com",      ["No such app", "herokucdn.com/error-pages/no-such-app"]),
    ("AWS S3",            r"s3\.amazonaws\.com",     ["NoSuchBucket", "The specified bucket does not exist"]),
    ("AWS CloudFront",    r"cloudfront\.net",        ["The request could not be satisfied"]),
    ("Shopify",           r"myshopify\.com",         ["Sorry, this shop is currently unavailable"]),
    ("Fastly",            r"fastly\.net",            ["Fastly error: unknown domain"]),
    ("Ghost",             r"ghost\.io",              ["The thing you were looking for is no longer here"]),
    ("Tumblr",            r"tumblr\.com",            ["There's nothing here"]),
    ("Cargo",             r"cargocollective\.com",   ["404 Not Found"]),
    ("Statuspage",        r"statuspage\.io",         ["page not found"]),
    ("HubSpot",           r"hubspot\.net",           ["Domain not found"]),
    ("Netlify",           r"netlify\.(app|com)",     ["Not Found - Request ID"]),
    ("Zendesk",           r"zendesk\.com",           ["Help Center Closed"]),
    ("Pantheon",          r"pantheonsite\.io",       ["404 error unknown site"]),
    ("Surge.sh",          r"surge\.sh",              ["project not found"]),
    ("Azure Websites",    r"azurewebsites\.net",     ["The web app you have attempted to reach is not available"]),
    ("Azure Cloudapp",    r"cloudapp\.net",          ["404 Web Site not found"]),
    ("ReadMe",            r"readme\.io",             ["Project doesnt exist"]),
    ("Intercom",          r"intercom\.io",           ["Uh oh. That page doesn't exist"]),
    ("WP Engine",         r"wpengine\.com",          ["The site you were looking for couldn't be found"]),
    ("Squarespace",       r"squarespace\.com",       ["No Such Account"]),
    ("Wix",               r"wixsite\.com",           ["Error ConnectYourDomain"]),
    ("Fly.io",            r"fly\.dev",               ["404 - Page Not Found"]),
    ("Render",            r"onrender\.com",          ["Service Not Found"]),
]

_checked_domains: set = set()


def reset() -> None:
    _checked_domains.clear()


def test(page: CrawlResult, client) -> List[Finding]:
    # Collect unique subdomains from links on this page
    domains_to_check = set()
    base_domain = urlparse(page.url).netloc.split(":")[0]

    for link in page.links:
        netloc = urlparse(link).netloc.split(":")[0]
        if netloc and netloc != base_domain and netloc not in _checked_domains:
            domains_to_check.add(netloc)

    # Also check the page's own host if not checked yet
    if base_domain not in _checked_domains:
        domains_to_check.add(base_domain)

    findings = []
    for domain in domains_to_check:
        _checked_domains.add(domain)
        findings.extend(_check_domain(domain, client))

    return findings


def _check_domain(domain: str, client) -> List[Finding]:
    try:
        cname = _resolve_cname(domain)
    except Exception:
        return []

    if not cname:
        return []

    for service, pattern, fingerprints in _FINGERPRINTS:
        if not re.search(pattern, cname, re.IGNORECASE):
            continue

        # CNAME matches — fetch the domain and look for takeover fingerprint
        try:
            resp = client.get(f"https://{domain}", timeout=8)
            body = resp.text if hasattr(resp, "text") else ""
            status = resp.status_code
        except Exception:
            try:
                resp = client.get(f"http://{domain}", timeout=8)
                body = resp.text if hasattr(resp, "text") else ""
                status = resp.status_code
            except Exception:
                # DNS CNAME exists but HTTP connection failed — this is a possible
                # takeover candidate, not a confirmed one. The service endpoint may
                # just be temporarily down. Downgrade to MEDIUM with low confidence
                # so analysts can investigate without treating it as confirmed HIGH.
                return [_make_finding(domain, cname, service,
                                      "CNAME points to unresolvable or unreachable endpoint (potential dangling DNS)",
                                      Severity.MEDIUM, 0.50)]

        for fp in fingerprints:
            if fp.lower() in body.lower():
                return [_make_finding(domain, cname, service,
                                      f"HTTP {status} response body contains fingerprint: '{fp}'",
                                      Severity.HIGH, 0.92)]

    return []


def _resolve_cname(domain: str) -> str | None:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "CNAME")
        return str(answers[0].target).rstrip(".")
    except ImportError:
        pass
    except Exception:
        return None

    # Fallback: socket doesn't expose CNAME, skip
    return None


def _make_finding(domain, cname, service, evidence, severity, confidence) -> Finding:
    return Finding(
        title=f"Subdomain Takeover Risk: {domain} → {service}",
        severity=severity,
        url=f"https://{domain}",
        parameter=None,
        payload=None,
        evidence=f"CNAME: {domain} → {cname} ({service}). {evidence}",
        description=(
            f"The subdomain {domain} has a CNAME record pointing to {cname} ({service}), "
            "but the target service appears unclaimed or unavailable. An attacker can register "
            "the dangling resource on the target platform and serve malicious content under "
            f"your domain ({domain}), enabling phishing, cookie theft, or CSP bypass."
        ),
        remediation=(
            f"1. Remove the CNAME record for {domain} if the service is no longer in use. "
            f"2. If the service is still needed, reclaim the resource on {service}. "
            "3. Audit all DNS records for dangling CNAMEs regularly."
        ),
        owasp_category="A05:2021 Security Misconfiguration",
        cwe="CWE-350",
        cvss=8.1,
        confidence=confidence,
        standards={"OWASP": "A05:2021", "CWE": "CWE-350"},
    )
