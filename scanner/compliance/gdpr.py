import re
from scanner.core.scan_result import ScanResult, ComplianceReport, ComplianceControl

PII_PATTERNS = [
    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),         # Email
    re.compile(r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b'),                             # US SSN
    re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'),                                    # Visa card
    re.compile(r'\b5[1-5][0-9]{14}\b'),                                            # Mastercard
    re.compile(r'\b(?:\+?44|0)7[0-9]{9}\b'),                                       # UK mobile
    re.compile(r'\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'),           # IPv4
]

PII_LABELS = ["Email address", "SSN pattern", "Visa card number", "Mastercard number", "UK phone number", "IP address"]

ARTICLES = [
    {
        "id": "Art.5",
        "name": "Principles of Processing (Data Minimisation)",
        "finding_keywords": ["PII Exposure", "Sensitive Data", "Verbose Error"],
        "manual_note": "Data minimisation requires code and process review.",
    },
    {
        "id": "Art.25",
        "name": "Data Protection by Design and by Default",
        "finding_keywords": ["Missing Security Header", "Cookie Missing", "CORS", "HTTPS"],
        "manual_note": "Full data protection by design review requires architecture assessment.",
    },
    {
        "id": "Art.32",
        "name": "Security of Processing (Encryption, Integrity, Availability)",
        "finding_keywords": ["TLS", "HTTPS", "Cryptographic", "Weak TLS", "Certificate", "SQL Injection", "XSS"],
        "manual_note": "",
    },
    {
        "id": "Art.33",
        "name": "Breach Notification",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Breach notification procedures are policy-based — cannot be tested via DAST.",
    },
    {
        "id": "Art.17",
        "name": "Right to Erasure",
        "finding_keywords": [],
        "manual_note": "Test deletion endpoints manually and verify data is removed from all systems.",
    },
    {
        "id": "Art.7",
        "name": "Conditions for Consent",
        "finding_keywords": [],
        "manual_note": "Cookie consent banner presence can be checked; legal review required for compliance.",
    },
    {
        "id": "Art.44",
        "name": "Cross-Border Data Transfers",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Data transfer mechanisms (SCCs, adequacy decisions) require legal/architectural review.",
    },
]


def evaluate(scan_result: ScanResult) -> ComplianceReport:
    finding_titles = [f.title for f in scan_result.findings]
    controls = []

    # PII exposure check across all crawled pages
    pii_findings = _check_pii_exposure(scan_result)

    for art in ARTICLES:
        if art.get("always_manual"):
            controls.append(ComplianceControl(
                id=art["id"], name=art["name"], status="manual",
                evidence=art["manual_note"],
            ))
            continue

        matched = [t for t in finding_titles if any(kw.lower() in t.lower() for kw in art["finding_keywords"])]

        if art["id"] == "Art.5" and pii_findings:
            matched.extend(pii_findings)

        if matched:
            status = "fail"
            evidence = f"Findings indicate potential GDPR gap: {', '.join(matched[:3])}"
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

    return ComplianceReport(standard="GDPR", score=score, controls=controls)


def _check_pii_exposure(scan_result: ScanResult) -> list:
    exposed = []
    for finding in scan_result.findings:
        if "error" in finding.title.lower() or "verbose" in finding.title.lower():
            exposed.append(f"Potential PII in error response at {finding.url}")
    return exposed
