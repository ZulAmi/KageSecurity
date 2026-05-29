import re
from scanner.core.scan_result import ScanResult, ComplianceReport, ComplianceControl

PII_PATTERNS = [
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "Email address"),
    (re.compile(r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b'), "US SSN pattern"),
    (re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'), "Visa card number"),
    (re.compile(r'\b5[1-5][0-9]{14}\b'), "Mastercard number"),
    (re.compile(r'\b3[47][0-9]{13}\b'), "Amex card number"),
    (re.compile(r'\b(?:\+?44|0)7[0-9]{9}\b'), "UK mobile number"),
    (re.compile(r'\b(?:\+?353|0)8[0-9]{8}\b'), "IE mobile number"),
    (re.compile(r'\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'), "IP address"),
    (re.compile(r'\b[A-Z]{2}[0-9]{6}[A-Z]\b'), "UK National Insurance number"),
    (re.compile(r'password\s*[=:]\s*\S+', re.IGNORECASE), "Password in response"),
]

ARTICLES = [
    {
        "id": "Art.5",
        "name": "Principles of Processing — Lawfulness, Fairness, Transparency",
        "finding_keywords": ["PII Exposure", "Sensitive Data", "Verbose Error", "API Key", "Password in Response"],
        "manual_note": "Data minimisation and purpose limitation require code and process review.",
    },
    {
        "id": "Art.9",
        "name": "Processing of Special Category Data",
        "finding_keywords": ["Sensitive Data", "PII Exposure", "Health Data", "Verbose Error"],
        "manual_note": "Identification of special category data requires data flow mapping.",
    },
    {
        "id": "Art.13",
        "name": "Transparency — Privacy Notice to Data Subjects",
        "finding_keywords": [],
        "always_manual": False,
        "manual_note": "Privacy notice completeness requires legal review; DAST checks for presence only.",
        "check_privacy_policy": True,
    },
    {
        "id": "Art.17",
        "name": "Right to Erasure",
        "finding_keywords": [],
        "manual_note": "Test deletion endpoints manually and verify data removal across all systems.",
    },
    {
        "id": "Art.22",
        "name": "Automated Decision-Making and Profiling",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Automated profiling logic requires code review and DPA assessment.",
    },
    {
        "id": "Art.25",
        "name": "Data Protection by Design and by Default",
        "finding_keywords": ["Missing Security Header", "Cookie Missing", "CORS", "HTTPS", "CSP",
                             "Clickjacking", "HSTS", "X-Frame-Options"],
        "manual_note": "Full data protection by design review requires architecture assessment.",
    },
    {
        "id": "Art.32",
        "name": "Security of Processing",
        "finding_keywords": ["TLS", "HTTPS", "Cryptographic", "Weak TLS", "Certificate",
                             "SQL Injection", "XSS", "SSRF", "Injection", "Deserialization"],
        "manual_note": "",
    },
    {
        "id": "Art.33",
        "name": "Breach Notification to Supervisory Authority",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Breach notification procedures are policy-based — cannot be tested via DAST.",
    },
    {
        "id": "Art.35",
        "name": "Data Protection Impact Assessment (DPIA)",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "DPIA is a documented process — requires manual review with DPO.",
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

    pii_findings = _check_pii_exposure(scan_result)
    has_privacy_policy = _check_privacy_policy(scan_result)

    for art in ARTICLES:
        if art.get("always_manual"):
            controls.append(ComplianceControl(
                id=art["id"], name=art["name"], status="manual",
                evidence=art["manual_note"],
            ))
            continue

        matched = [t for t in finding_titles if any(kw.lower() in t.lower() for kw in art.get("finding_keywords", []))]

        if art["id"] == "Art.5" and pii_findings:
            matched.extend(pii_findings)
        if art["id"] == "Art.9" and pii_findings:
            matched.extend([p for p in pii_findings if any(x in p for x in ["card", "SSN", "health"])])

        if art.get("check_privacy_policy"):
            if has_privacy_policy:
                status = "partial"
                evidence = "Privacy policy/notice link detected. Manual review of content required."
            else:
                status = "fail"
                evidence = "No privacy policy or privacy notice link detected on the crawled pages."
            evidence += f" Manual review: {art['manual_note']}"
            controls.append(ComplianceControl(
                id=art["id"], name=art["name"], status=status,
                findings=matched, evidence=evidence,
            ))
            continue

        if matched:
            status = "fail"
            evidence = f"Findings indicate potential GDPR gap: {', '.join(matched[:3])}"
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

    return ComplianceReport(standard="GDPR", score=score, controls=controls)


def _check_pii_exposure(scan_result: ScanResult) -> list:
    exposed = []
    for finding in scan_result.findings:
        if any(kw in finding.title.lower() for kw in ("error", "verbose", "pii", "sensitive", "disclosure")):
            exposed.append(f"Potential PII in response at {finding.url}")
    # Also scan raw crawled page bodies if available
    for finding in scan_result.findings:
        evidence = finding.evidence or ""
        for pattern, label in PII_PATTERNS:
            if pattern.search(evidence):
                exposed.append(f"{label} detected in response evidence")
                break
    return list(dict.fromkeys(exposed))  # deduplicate


def _check_privacy_policy(scan_result: ScanResult) -> bool:
    privacy_keywords = ["privacy", "privacy-policy", "privacy_policy", "privacypolicy",
                        "datenschutz", "data-protection", "cookie-policy"]
    for finding in scan_result.findings:
        url_lower = finding.url.lower()
        if any(kw in url_lower for kw in privacy_keywords):
            return True
    return False
