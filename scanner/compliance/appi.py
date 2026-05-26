import re
from scanner.core.scan_result import ScanResult, ComplianceReport, ComplianceControl

# Japan APPI (Act on Protection of Personal Information) — 2022 amendments
# Primarily overlaps with GDPR but has Japan-specific PII patterns

JP_PII_PATTERNS = [
    (re.compile(r'\d{12}'), "My Number (12-digit)"),
    (re.compile(r'0\d{1,4}[-\s]\d{1,4}[-\s]\d{4}'), "Japanese phone number"),
    (re.compile(r'〒\d{3}-\d{4}'), "Japanese postal code"),
    (re.compile(r'[一-龯ぁ-んァ-ン]{2,4}\s*[一-龯ぁ-んァ-ン]{2,4}'), "Japanese name pattern"),
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
        "id": "Art.20",
        "name": "Security Management Measures",
        "finding_keywords": ["TLS", "HTTPS", "Cryptographic", "Weak TLS", "SQL Injection", "XSS", "Path Traversal", "SSRF"],
        "manual_note": "Internal security management (policies, training) requires manual assessment.",
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
        "id": "Art.24",
        "name": "Restriction on Third-Party Provision",
        "finding_keywords": ["CORS", "Open Redirect", "SSRF"],
        "manual_note": "Consent mechanisms for data sharing require manual review.",
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
        "manual_note": "Breach response procedures are policy-based.",
    },
    {
        "id": "Art.27",
        "name": "Disclosure of Retained Personal Information",
        "finding_keywords": ["Exposed File", "Version Disclosure", "Verbose Error"],
        "manual_note": "Retention policies require database and process review.",
    },
]


def evaluate(scan_result: ScanResult) -> ComplianceReport:
    finding_titles = [f.title for f in scan_result.findings]
    controls = []

    for art in ARTICLES:
        if art.get("always_manual"):
            controls.append(ComplianceControl(
                id=art["id"], name=art["name"], status="manual",
                evidence=art["manual_note"],
            ))
            continue

        matched = [t for t in finding_titles if any(kw.lower() in t.lower() for kw in art["finding_keywords"])]

        if matched:
            status = "fail"
            evidence = f"Findings indicate potential APPI gap: {', '.join(matched[:3])}"
        else:
            status = "pass"
            evidence = "No automated findings indicate a gap in this article."

        if art["manual_note"]:
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
