import re
import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import get_url_params, inject_url_param

# Patterns that indicate serialised objects in request/response bodies or params
JAVA_SERIAL_MAGIC = b"\xac\xed\x00\x05"
JAVA_SERIAL_B64 = "rO0AB"  # base64 of \xac\xed\x00\x05

PHP_SERIAL_PATTERNS = [
    re.compile(r'O:\d+:"[a-zA-Z_]', re.IGNORECASE),  # PHP object
    re.compile(r'a:\d+:\{'),                           # PHP array
    re.compile(r's:\d+:"'),                            # PHP string
]

PICKLE_HEADER_B64 = ["gASV", "gAR", "KGNv"]  # common base64-encoded Python pickle starts

INDICATORS = [
    ("Java serialized object (base64)", lambda v: JAVA_SERIAL_B64 in v),
    ("PHP serialized object", lambda v: any(p.search(v) for p in PHP_SERIAL_PATTERNS)),
    ("Python pickle (base64)", lambda v: any(v.startswith(h) for h in PICKLE_HEADER_B64)),
]


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []

    # Check URL parameters for serialized object patterns
    params = get_url_params(page.url)
    for param_name, values in params.items():
        value = values[0] if values else ""
        for label, detector in INDICATORS:
            if detector(value):
                findings.append(_indicator_finding(page.url, param_name, value, label))
                break

    # Check cookies for serialized patterns
    cookies_header = page.headers.get("set-cookie", "")
    for label, detector in INDICATORS:
        if detector(cookies_header):
            findings.append(_indicator_finding(page.url, "cookie", cookies_header[:60], label))
            break

    # Check response body for Java serial magic or ViewState
    if JAVA_SERIAL_B64 in page.body:
        findings.append(_indicator_finding(page.url, "response body", JAVA_SERIAL_B64, "Java serialized object in response"))

    # Check for .NET ViewState without MAC validation
    viewstate_match = re.search(r'id="__VIEWSTATE"[^>]+value="([^"]+)"', page.body)
    if viewstate_match:
        vs = viewstate_match.group(1)
        mac_match = re.search(r'id="__VIEWSTATEMAC"[^>]+value="([^"]+)"', page.body)
        if not mac_match or not mac_match.group(1):
            findings.append(Finding(
                title="ASP.NET ViewState Without MAC Validation",
                severity=Severity.HIGH,
                url=page.url,
                parameter="__VIEWSTATE",
                payload=None,
                evidence="__VIEWSTATE found without __VIEWSTATEMAC — ViewState tampering may be possible",
                description=(
                    "ViewState without MAC validation allows attackers to craft malicious ViewState payloads "
                    "that, when deserialized by the server, can lead to remote code execution."
                ),
                remediation=(
                    "Enable ViewState MAC validation in web.config: "
                    "<pages enableViewStateMac='true' viewStateEncryptionMode='Always' />"
                ),
                cwe="CWE-502",
                cvss=8.1,
                owasp_category="A08:2021 Software and Data Integrity Failures",
                standards=["ISO27001-8.23", "HIPAA-164.312a"],
                confidence=0.9,
            ))

    return findings


def _indicator_finding(url: str, location: str, value: str, label: str) -> Finding:
    return Finding(
        title=f"Potential Insecure Deserialization — {label}",
        severity=Severity.HIGH,
        url=url,
        parameter=location,
        payload=None,
        evidence=f"{label} signature detected in {location}: {value[:80]}",
        description=(
            "Insecure deserialization of untrusted data can lead to remote code execution, "
            "privilege escalation, or denial of service. This finding indicates serialised "
            "objects are being passed via HTTP — manual verification of server-side handling is required."
        ),
        remediation=(
            "Do not deserialize untrusted data. If serialization is required, "
            "use a safe format (JSON with schema validation) instead of native serialization. "
            "Implement integrity checks on serialized objects."
        ),
        cwe="CWE-502",
        cvss=8.1,
        owasp_category="A08:2021 Software and Data Integrity Failures",
        standards=["ISO27001-8.23", "HIPAA-164.312a"],
        confidence=0.7,
    )
