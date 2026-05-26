import re
import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

VERSION_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]

JS_LIB_PATTERNS = [
    (r"jquery[/-](\d+\.\d+\.\d+)", "jQuery"),
    (r"bootstrap[/-](\d+\.\d+\.\d+)", "Bootstrap"),
    (r"react[/-](\d+\.\d+\.\d+)", "React"),
    (r"angular[/-](\d+\.\d+\.\d+)", "Angular"),
    (r"vue[/-](\d+\.\d+\.\d+)", "Vue.js"),
    (r"lodash[/-](\d+\.\d+\.\d+)", "Lodash"),
]

META_PATTERNS = [
    (r'<meta name="generator" content="([^"]+)"', "Generator meta tag"),
    (r'WordPress (\d+\.\d+)', "WordPress version in HTML"),
    (r'Drupal (\d+)', "Drupal version in HTML"),
    (r'Joomla! (\d+\.\d+)', "Joomla version in HTML"),
]


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []

    # Check version-disclosing response headers
    for header in VERSION_HEADERS:
        value = page.headers.get(header, "")
        if value and re.search(r'\d+\.\d+', value):
            findings.append(Finding(
                title=f"Server Version Disclosed via {header.title()} Header",
                severity=Severity.LOW,
                url=page.url,
                parameter=None,
                payload=None,
                evidence=f"{header}: {value}",
                description="Exposing server/framework versions helps attackers find known CVEs for your exact version.",
                remediation=f"Remove or suppress the `{header}` header in your web server configuration.",
                cwe="CWE-200",
                cvss=2.6,
                owasp_category="A06:2021 Vulnerable and Outdated Components",
                standards=["ISO27001-8.25"],
                confidence=1.0,
            ))

    # Check JS library versions in page body
    for pattern, lib_name in JS_LIB_PATTERNS:
        match = re.search(pattern, page.body, re.IGNORECASE)
        if match:
            findings.append(Finding(
                title=f"JavaScript Library Version Disclosed: {lib_name}",
                severity=Severity.LOW,
                url=page.url,
                parameter=None,
                payload=None,
                evidence=f"Found {lib_name} {match.group(1)} referenced in page source",
                description=f"Disclosing {lib_name} version allows attackers to target known vulnerabilities in that version.",
                remediation=f"Keep {lib_name} updated. Remove version numbers from filenames and content.",
                cwe="CWE-200",
                cvss=2.6,
                owasp_category="A06:2021 Vulnerable and Outdated Components",
                standards=["ISO27001-8.25"],
                confidence=0.9,
            ))

    # Check meta generator tags and inline version strings
    for pattern, label in META_PATTERNS:
        match = re.search(pattern, page.body, re.IGNORECASE)
        if match:
            findings.append(Finding(
                title=f"CMS/Framework Version Disclosed ({label})",
                severity=Severity.LOW,
                url=page.url,
                parameter=None,
                payload=None,
                evidence=f"Detected: {match.group(0)[:100]}",
                description="CMS version information helps attackers identify unpatched vulnerabilities.",
                remediation="Remove generator meta tags and version strings from public output.",
                cwe="CWE-200",
                cvss=2.6,
                owasp_category="A06:2021 Vulnerable and Outdated Components",
                standards=["ISO27001-8.25"],
                confidence=0.9,
            ))

    return findings
