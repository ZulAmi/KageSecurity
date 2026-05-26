"""
CVE Check module — maps detected library versions to known CVEs.

Uses scanner/payloads/cve_signatures.yaml as the local database.
Optionally enriches findings with live NVD data when config.nvd_api_key is set.
"""
import re
import httpx
from typing import List, Optional
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.payloads import load_payloads

_sigs_cache: Optional[list] = None


def _get_signatures() -> list:
    global _sigs_cache
    if _sigs_cache is not None:
        return _sigs_cache
    data = load_payloads("cve_signatures")
    _sigs_cache = data.get("signatures", []) if data else []
    return _sigs_cache


def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _fetch_nvd(cve_id: str, api_key: str) -> Optional[dict]:
    """Query NVD API for a single CVE. Returns enriched data or None on failure."""
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {"apiKey": api_key} if api_key else {}
        resp = httpx.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return vulns[0].get("cve", {})
    except Exception:
        pass
    return None


def test(page: CrawlResult, client: httpx.Client, config=None) -> List[Finding]:
    findings = []
    signatures = _get_signatures()
    nvd_api_key = getattr(config, "nvd_api_key", None) if config else None

    for sig in signatures:
        pattern = sig.get("pattern", "")
        lib_name = sig.get("name", sig.get("library", "unknown"))
        versions_config = sig.get("versions", [])

        if not pattern:
            continue

        match = re.search(pattern, page.body, re.IGNORECASE)
        if not match:
            continue

        detected_version = match.group(1)

        for version_entry in versions_config:
            version_regex = version_entry.get("version_regex", "")
            if not version_regex:
                continue
            if not re.match(version_regex, detected_version):
                continue

            for cve in version_entry.get("cves", []):
                cve_id = cve.get("id", "")
                cvss = float(cve.get("cvss", 5.0))
                description = cve.get("description", "")
                cwe = cve.get("cwe", None)

                # Optionally enrich from NVD
                if nvd_api_key and cve_id:
                    nvd_data = _fetch_nvd(cve_id, nvd_api_key)
                    if nvd_data:
                        metrics = nvd_data.get("metrics", {})
                        cvss_data = (
                            metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31")
                            else metrics.get("cvssMetricV30", [{}])[0] if metrics.get("cvssMetricV30")
                            else metrics.get("cvssMetricV2", [{}])[0] if metrics.get("cvssMetricV2")
                            else {}
                        )
                        if cvss_data:
                            nvd_score = cvss_data.get("cvssData", {}).get("baseScore")
                            if nvd_score is not None:
                                cvss = float(nvd_score)
                        weaknesses = nvd_data.get("weaknesses", [])
                        if weaknesses:
                            descs = weaknesses[0].get("description", [])
                            for d in descs:
                                if d.get("lang") == "en":
                                    cwe = d.get("value", cwe)
                                    break

                severity = _cvss_to_severity(cvss)
                findings.append(Finding(
                    title=f"Known Vulnerable Component: {lib_name} {detected_version} ({cve_id})",
                    severity=severity,
                    url=page.url,
                    parameter=None,
                    payload=None,
                    evidence=f"Detected {lib_name} version {detected_version} — matches {cve_id} (CVSS {cvss})",
                    description=(
                        f"{description} "
                        f"Library: {lib_name} {detected_version}. "
                        f"Upgrade to the latest stable release to remediate."
                    ),
                    remediation=(
                        f"Upgrade {lib_name} to the latest version. "
                        f"Monitor {cve_id} at https://nvd.nist.gov/vuln/detail/{cve_id}. "
                        "Use a software composition analysis (SCA) tool to automate version tracking."
                    ),
                    cwe=cwe or "CWE-1035",
                    cvss=cvss,
                    owasp_category="A06:2021 Vulnerable and Outdated Components",
                    standards=["ISO27001-8.25", "ISO27001-8.8"],
                    confidence=0.9,
                ))

    return findings
