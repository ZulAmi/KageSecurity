from scanner.core.scan_result import ScanResult, ComplianceReport, ComplianceControl

# ISO 27001:2022 Annex A controls testable via DAST
CONTROLS = [
    {
        "id": "8.8",
        "name": "Management of Technical Vulnerabilities",
        "finding_keywords": [],
        "always_manual": False,
        "manual_note": "",
        "description": "Automated vulnerability scanning covers this control.",
    },
    {
        "id": "8.23",
        "name": "Web Filtering / Access Control to Information",
        "finding_keywords": ["Path Traversal", "IDOR", "Broken Access", "SSRF"],
        "always_manual": False,
        "manual_note": "Role-based access control requires manual testing.",
    },
    {
        "id": "8.24",
        "name": "Use of Cryptography",
        "finding_keywords": ["TLS", "Cryptographic", "HTTPS", "Weak TLS", "Certificate", "Cookie Missing Secure"],
        "always_manual": False,
        "manual_note": "Algorithm selection in code requires manual review.",
    },
    {
        "id": "8.25",
        "name": "Secure Development Life Cycle",
        "finding_keywords": ["Version Disclosure", "Security Misconfiguration", "Exposed File", "Debug", "phpinfo"],
        "always_manual": False,
        "manual_note": "Code review and SDLC processes require manual assessment.",
    },
    {
        "id": "8.29",
        "name": "Security Testing in Development and Acceptance",
        "finding_keywords": [],
        "always_manual": False,
        "manual_note": "This scan itself satisfies 8.29 evidence requirements.",
    },
    {
        "id": "5.14",
        "name": "Information Transfer",
        "finding_keywords": ["CORS", "Open Redirect", "Referrer"],
        "always_manual": False,
        "manual_note": "Data transfer agreements require manual review.",
    },
    {
        "id": "8.2",
        "name": "Privileged Access Rights",
        "finding_keywords": ["IDOR", "Broken Access", "CSRF", "SQL Injection", "Command Injection"],
        "always_manual": False,
        "manual_note": "Privileged account management requires manual review.",
    },
    {
        "id": "8.4",
        "name": "Access to Source Code",
        "finding_keywords": [".git", "Source Code", "Exposed File: .git"],
        "always_manual": False,
        "manual_note": "",
    },
    {
        "id": "8.28",
        "name": "Secure Coding",
        "finding_keywords": ["Injection", "XSS", "SQL", "Command", "Template", "SSRF", "XXE", "Deserialization"],
        "always_manual": False,
        "manual_note": "Static code analysis required for full coverage.",
    },
    {
        "id": "5.10",
        "name": "Acceptable Use of Information",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Policy-based control — requires manual review of acceptable use policies.",
    },
    {
        "id": "8.33",
        "name": "Test Information",
        "finding_keywords": ["Debug", "phpinfo", "Stack Trace", "Verbose Error"],
        "always_manual": False,
        "manual_note": "Test data management in development requires manual review.",
    },
]


def evaluate(scan_result: ScanResult) -> ComplianceReport:
    finding_titles = [f.title for f in scan_result.findings]
    controls = []
    fail_count = 0
    total_auto = 0

    for ctrl in CONTROLS:
        if ctrl["always_manual"]:
            controls.append(ComplianceControl(
                id=ctrl["id"], name=ctrl["name"], status="manual",
                evidence=ctrl["manual_note"],
            ))
            continue

        total_auto += 1
        matched = [t for t in finding_titles if any(kw.lower() in t.lower() for kw in ctrl["finding_keywords"])]

        if ctrl["id"] == "8.29":
            # Running this scan satisfies 8.29
            status = "pass"
            evidence = f"Automated DAST scan completed. {len(finding_titles)} findings identified."
        elif ctrl["id"] == "8.8":
            status = "pass" if finding_titles else "pass"
            evidence = f"Vulnerability scan executed. {len(scan_result.findings)} findings."
        elif matched:
            status = "fail"
            fail_count += 1
            evidence = f"Findings indicate control gap: {', '.join(matched[:3])}"
        else:
            status = "pass"
            evidence = "No findings indicate a gap in this control area."

        if ctrl["manual_note"] and status == "pass":
            status = "partial"
            evidence += f" Manual review required: {ctrl['manual_note']}"

        controls.append(ComplianceControl(
            id=ctrl["id"], name=ctrl["name"], status=status,
            findings=matched, evidence=evidence,
        ))

    auto_controls = [c for c in controls if c.status != "manual"]
    passed = sum(1 for c in auto_controls if c.status in ("pass", "partial"))
    score = round((passed / len(auto_controls)) * 100, 1) if auto_controls else 0.0

    return ComplianceReport(standard="ISO27001", score=score, controls=controls)
