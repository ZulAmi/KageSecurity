import re
from scanner.core.scan_result import ScanResult, ComplianceReport, ComplianceControl

# Japan APPI (Act on Protection of Personal Information) — 2022 amendments
JP_PII_PATTERNS = [
    (re.compile(r'\d{12}'), "My Number (12-digit)"),
    (re.compile(r'0\d{1,4}[-\s]\d{1,4}[-\s]\d{4}'), "Japanese phone number"),
    (re.compile(r'〒\d{3}-\d{4}'), "Japanese postal code"),
    (re.compile(r'[一-龯ぁ-んァ-ン]{2,4}\s*[一-龯ぁ-んァ-ン]{2,4}'), "Japanese name pattern"),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "Email address"),
    (re.compile(r'password\s*[=:]\s*\S+', re.IGNORECASE), "Password in response"),
]

ARTICLES = [
    {
        "id": "Art.16",
        "name": "Prohibition of Use Beyond Stated Purpose",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Purpose limitation requires privacy policy review and data flow analysis.",
    },
    {
        "id": "Art.17",
        "name": "Appropriate Acquisition of Personal Information",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Acquisition methods require process review.",
    },
    {
        "id": "Art.18",
        "name": "Notification of Purpose at Acquisition",
        "finding_keywords": [],
        "always_manual": False,
        "check_privacy_policy": True,
        "manual_note": "Verify that purpose-of-use notice is displayed at all data collection points.",
    },
    {
        "id": "Art.20",
        "name": "Security Management Measures",
        "finding_keywords": ["TLS", "HTTPS", "Cryptographic", "Weak TLS", "SQL Injection", "XSS",
                             "Path Traversal", "SSRF", "Injection", "Deserialization", "CSRF",
                             "Cookie Missing", "Missing Security Header"],
        "manual_note": "Internal security management (policies, training, physical) requires manual assessment.",
    },
    {
        "id": "Art.21",
        "name": "Supervision of Employees",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Workforce training and supervision are policy-based controls.",
    },
    {
        "id": "Art.22",
        "name": "Supervision of Subcontractors",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Vendor management requires contractual and audit review.",
    },
    {
        "id": "Art.23",
        "name": "Handling of Sensitive Personal Information",
        "finding_keywords": ["PII Exposure", "Sensitive Data", "Verbose Error", "Stack Trace", "API Key"],
        "manual_note": "Classification and handling of sensitive PI requires manual data flow review.",
    },
    {
        "id": "Art.24",
        "name": "Restriction on Third-Party Provision",
        "finding_keywords": ["CORS", "Open Redirect", "SSRF", "Host Header"],
        "manual_note": "Consent mechanisms for data sharing with third parties require manual review.",
    },
    {
        "id": "Art.25",
        "name": "Records of Third-Party Provision",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Record-keeping practices require manual audit.",
    },
    {
        "id": "Art.26",
        "name": "Notification of Data Breach",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Breach response and notification procedures are policy-based.",
    },
    {
        "id": "Art.27",
        "name": "Disclosure of Retained Personal Information",
        "finding_keywords": ["Exposed File", "Version Disclosure", "Verbose Error", "Stack Trace",
                             "Source Code Disclosure", "Debug"],
        "manual_note": "Retention policies and deletion procedures require database and process review.",
    },
    {
        "id": "Art.28",
        "name": "Correction and Deletion of Personal Information",
        "finding_keywords": ["IDOR", "Broken Access", "Auth Bypass"],
        "manual_note": "Data subject rights (correction/deletion APIs) require manual functional testing.",
    },
]


def evaluate(scan_result: ScanResult) -> ComplianceReport:
    finding_titles = [f.title for f in scan_result.findings]
    controls = []

    pii_findings = _check_jp_pii_exposure(scan_result)
    has_privacy_notice = _check_privacy_notice(scan_result)

    for art in ARTICLES:
        if art.get("always_manual"):
            controls.append(ComplianceControl(
                id=art["id"], name=art["name"], status="manual",
                evidence=art["manual_note"],
            ))
            continue

        if art.get("check_privacy_policy"):
            if has_privacy_notice:
                status = "partial"
                evidence = "Privacy/purpose-of-use notice detected on crawled pages. Content review required."
            else:
                status = "fail"
                evidence = "No privacy notice or purpose-of-use disclosure detected on crawled pages."
            evidence += f" Manual review: {art['manual_note']}"
            controls.append(ComplianceControl(
                id=art["id"], name=art["name"], status=status, evidence=evidence,
            ))
            continue

        matched = [t for t in finding_titles if any(kw.lower() in t.lower() for kw in art.get("finding_keywords", []))]

        if art["id"] == "Art.23" and pii_findings:
            matched.extend(pii_findings)

        if matched:
            status = "fail"
            evidence = f"Findings indicate potential APPI gap: {', '.join(matched[:3])}"
        else:
            status = "pass"
            evidence = "No automated findings indicate a gap in this article."

        if art.get("manual_note"):
            status = "partial" if status == "pass" else status
            evidence += f" Manual review: {art['manual_note']}"

        controls.append(ComplianceControl(
            id=art["id"], name=art["name"], status=status,
            findings=matched, evidence=evidence,
        ))

    auto_controls = [c for c in controls if c.status != "manual"]
    passed = sum(1 for c in auto_controls if c.status in ("pass", "partial"))
    score = round((passed / len(auto_controls)) * 100, 1) if auto_controls else 0.0

    return ComplianceReport(standard="APPI", score=score, controls=controls)


def _check_jp_pii_exposure(scan_result: ScanResult) -> list:
    exposed = []
    for finding in scan_result.findings:
        evidence = finding.evidence or ""
        for pattern, label in JP_PII_PATTERNS:
            if pattern.search(evidence):
                exposed.append(f"{label} detected in response evidence at {finding.url}")
                break
    return list(dict.fromkeys(exposed))


def _check_privacy_notice(scan_result: ScanResult) -> bool:
    keywords = ["privacy", "personal information", "個人情報", "プライバシー", "利用目的",
                "privacy-policy", "kojin-joho"]
    for finding in scan_result.findings:
        url_lower = (finding.url or "").lower()
        evidence_lower = (finding.evidence or "").lower()
        if any(kw in url_lower or kw in evidence_lower for kw in keywords):
            return True
    return False
