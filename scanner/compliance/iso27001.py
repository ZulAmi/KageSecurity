from scanner.core.scan_result import ScanResult, ComplianceReport, ComplianceControl

# ISO 27001:2022 Annex A controls — all controls testable (fully or partially) via DAST
CONTROLS = [
    # --- People controls ---
    {
        "id": "5.10",
        "name": "Acceptable Use of Information",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Policy-based control — requires review of acceptable use policies.",
    },
    {
        "id": "5.14",
        "name": "Information Transfer",
        "finding_keywords": ["CORS", "Open Redirect", "Referrer"],
        "manual_note": "Data transfer agreements require manual review.",
    },
    {
        "id": "5.15",
        "name": "Access Control",
        "finding_keywords": ["IDOR", "Broken Access", "Auth Bypass", "Path Traversal", "Privilege Escalation"],
        "manual_note": "Role-based access control policies require manual review.",
    },

    # --- Technological controls ---
    {
        "id": "8.2",
        "name": "Privileged Access Rights",
        "finding_keywords": ["IDOR", "Broken Access", "CSRF", "SQL Injection", "Command Injection", "Privilege"],
        "manual_note": "Privileged account management and review cycles require manual audit.",
    },
    {
        "id": "8.4",
        "name": "Access to Source Code",
        "finding_keywords": [".git", "Source Code", "Exposed File: .git", "Git Repository"],
        "manual_note": "",
    },
    {
        "id": "8.5",
        "name": "Secure Authentication",
        "finding_keywords": ["Auth Bypass", "Default Credential", "Weak Password", "Username Enumeration",
                             "JWT", "Rate Limit", "Brute Force", "Session Fixation"],
        "manual_note": "MFA enforcement and password policy configuration require manual testing.",
    },
    {
        "id": "8.8",
        "name": "Management of Technical Vulnerabilities",
        "finding_keywords": [],
        "always_manual": False,
        "manual_note": "",
        "description": "Running this scan satisfies evidence of vulnerability management.",
    },
    {
        "id": "8.9",
        "name": "Configuration Management",
        "finding_keywords": ["Misconfiguration", "Debug", "phpinfo", "Exposed Panel", "Server-Status",
                             "Version Disclosure", "Exposed File", "Backup File", "Default Credential"],
        "manual_note": "Infrastructure configuration baselines require manual review.",
    },
    {
        "id": "8.11",
        "name": "Data Masking",
        "finding_keywords": ["PII Exposure", "Sensitive Data", "API Key", "Secret", "Verbose Error",
                             "Stack Trace", "Password in Response"],
        "manual_note": "Data masking in databases and code requires manual review.",
    },
    {
        "id": "8.12",
        "name": "Data Leakage Prevention",
        "finding_keywords": ["API Key", "Secret Exposure", "Sensitive Data", "PII", "Verbose Error",
                             "Stack Trace", "Source Code Disclosure"],
        "manual_note": "DLP policies and tooling require manual assessment.",
    },
    {
        "id": "8.20",
        "name": "Network Security",
        "finding_keywords": ["CORS", "Open Redirect", "SSRF", "Host Header", "Security Header"],
        "manual_note": "Network segmentation and firewall rules require infrastructure-level review.",
    },
    {
        "id": "8.23",
        "name": "Web Filtering / Access Control to Information",
        "finding_keywords": ["Path Traversal", "IDOR", "Broken Access", "SSRF"],
        "manual_note": "Role-based access control requires manual testing.",
    },
    {
        "id": "8.24",
        "name": "Use of Cryptography",
        "finding_keywords": ["TLS", "Cryptographic", "HTTPS", "Weak TLS", "Certificate", "Cookie Missing Secure"],
        "manual_note": "Algorithm selection in code requires manual review.",
    },
    {
        "id": "8.25",
        "name": "Secure Development Life Cycle",
        "finding_keywords": ["Version Disclosure", "Misconfiguration", "Exposed File", "Debug", "phpinfo"],
        "manual_note": "SDLC processes and code review gates require manual assessment.",
    },
    {
        "id": "8.26",
        "name": "Application Security Requirements",
        "finding_keywords": ["Injection", "XSS", "SSRF", "XXE", "SSTI", "CSRF", "Open Redirect",
                             "Deserialization", "Path Traversal", "Command Injection"],
        "manual_note": "Security requirements documentation requires manual review.",
    },
    {
        "id": "8.27",
        "name": "Secure System Architecture and Engineering",
        "finding_keywords": ["Missing Security Header", "CSP", "Clickjacking", "X-Frame-Options",
                             "Subresource Integrity", "Cookie Missing", "HSTS"],
        "manual_note": "Architecture design review requires manual assessment.",
    },
    {
        "id": "8.28",
        "name": "Secure Coding",
        "finding_keywords": ["Injection", "XSS", "SQL", "Command", "Template", "SSRF", "XXE", "Deserialization",
                             "Prototype Pollution", "Request Smuggling", "Padding Oracle"],
        "manual_note": "Static code analysis required for full coverage.",
    },
    {
        "id": "8.29",
        "name": "Security Testing in Development and Acceptance",
        "finding_keywords": [],
        "always_manual": False,
        "manual_note": "",
        "description": "Running this scan satisfies evidence of security testing.",
    },
    {
        "id": "8.31",
        "name": "Separation of Development, Test, and Production",
        "finding_keywords": ["Debug", "Stack Trace", "phpinfo", "Test Data", "Staging", "Verbose Error",
                             "Exposed File: .env"],
        "manual_note": "Environment separation policies require manual architecture review.",
    },
    {
        "id": "8.33",
        "name": "Test Information",
        "finding_keywords": ["Debug", "phpinfo", "Stack Trace", "Verbose Error", "Test Data"],
        "manual_note": "Test data management in development requires manual review.",
    },
]


def evaluate(scan_result: ScanResult) -> ComplianceReport:
    finding_titles = [f.title for f in scan_result.findings]
    controls = []

    for ctrl in CONTROLS:
        if ctrl.get("always_manual"):
            controls.append(ComplianceControl(
                id=ctrl["id"], name=ctrl["name"], status="manual",
                evidence=ctrl["manual_note"],
            ))
            continue

        matched = [t for t in finding_titles if any(kw.lower() in t.lower() for kw in ctrl.get("finding_keywords", []))]

        if ctrl["id"] in ("8.29", "8.8"):
            status = "pass"
            evidence = f"Automated DAST scan completed — {len(finding_titles)} findings identified. " + ctrl.get("description", "")
        elif matched:
            status = "fail"
            evidence = f"Findings indicate control gap: {', '.join(matched[:3])}"
        else:
            status = "pass"
            evidence = "No findings indicate a gap in this control area."

        if ctrl.get("manual_note") and status == "pass":
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
