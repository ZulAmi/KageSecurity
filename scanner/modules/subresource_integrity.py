import re
import httpx
from urllib.parse import urlparse
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    base_domain = urlparse(page.url).netloc

    # Find all <script src> and <link href> pointing to external origins
    script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
    link_pattern = re.compile(r'<link[^>]+href=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)

    for match in list(script_pattern.finditer(page.body)) + list(link_pattern.finditer(page.body)):
        tag = match.group(0)
        url = match.group(1)

        parsed = urlparse(url)
        if not parsed.netloc or parsed.netloc == base_domain:
            continue  # skip relative or same-origin resources

        if "integrity=" not in tag.lower():
            resource_type = "script" if "<script" in tag.lower() else "stylesheet"
            findings.append(Finding(
                title=f"Missing Subresource Integrity (SRI) on External {resource_type.title()}",
                severity=Severity.MEDIUM,
                url=page.url,
                parameter=None,
                payload=None,
                evidence=f"External {resource_type} without integrity attribute: {url[:100]}",
                description=(
                    "Without SRI, if the CDN or external host is compromised, "
                    "malicious code can be injected into your page without detection."
                ),
                remediation=(
                    f"Generate an SRI hash for the resource and add `integrity` and `crossorigin` attributes. "
                    f"Use: https://www.srihash.org/"
                ),
                cwe="CWE-353",
                cvss=4.3,
                owasp_category="A08:2021 Software and Data Integrity Failures",
                standards=["ISO27001-8.25"],
                confidence=1.0,
            ))

    return findings
