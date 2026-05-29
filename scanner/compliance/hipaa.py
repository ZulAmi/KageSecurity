from scanner.core.scan_result import ScanResult, ComplianceReport, ComplianceControl

SAFEGUARDS = [
    # --- Administrative Safeguards (§164.308) ---
    {
        "id": "164.308(a)(1)(ii)(A)",
        "name": "Risk Analysis",
        "finding_keywords": [],
        "always_manual": False,
        "manual_note": "",
        "is_scan_evidence": True,
    },
    {
        "id": "164.308(a)(5)(ii)(C)",
        "name": "Log-In Monitoring",
        "finding_keywords": ["Username Enumeration", "Rate Limit", "Brute Force", "Auth Bypass"],
        "manual_note": "Login attempt logging requires server-level audit.",
    },
    {
        "id": "164.308(a)(5)(ii)(D)",
        "name": "Password Management",
        "finding_keywords": ["Default Credential", "Weak Password", "Auth Bypass", "Username Enumeration"],
        "manual_note": "Password complexity policy and reset flow require manual testing.",
    },
    {
        "id": "164.308(a)(6)(ii)",
        "name": "Response and Reporting",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Incident response procedures are policy-based and cannot be tested via DAST.",
    },

    # --- Technical Safeguards (§164.312) ---
    {
        "id": "164.312(a)(1)",
        "name": "Access Control — Unique User IDs",
        "finding_keywords": ["IDOR", "Broken Access", "SQL Injection", "Authentication", "Auth Bypass"],
        "manual_note": "User provisioning and deprovisioning require manual audit.",
    },
    {
        "id": "164.312(a)(2)(i)",
        "name": "Access Control — Emergency Access Procedure",
        "finding_keywords": [],
        "always_manual": True,
        "manual_note": "Emergency access procedures are policy-based and cannot be tested via DAST.",
    },
    {
        "id": "164.312(a)(2)(ii)",
        "name": "Access Control — Automatic Logoff",
        "finding_keywords": ["Session", "Cookie Missing", "JWT Missing Expiry", "Session Fixation"],
        "manual_note": "Session timeout configuration requires manual testing with authenticated sessions.",
    },
    {
        "id": "164.312(a)(2)(iii)",
        "name": "Encryption and Decryption of ePHI",
        "finding_keywords": ["TLS", "HTTPS", "Cryptographic", "Certificate", "Weak TLS", "Cookie Missing Secure"],
        "manual_note": "",
    },
    {
        "id": "164.312(b)",
        "name": "Audit Controls",
        "finding_keywords": ["Exposed File: access.log", "Exposed File: debug.log"],
        "always_manual": True,
        "manual_note": "Audit log completeness and protection require server-level access.",
    },
    {
        "id": "164.312(c)(1)",
        "name": "Integrity — Authentication of ePHI",
        "finding_keywords": ["CSRF", "Deserialization", "Subresource Integrity", "Request Smuggling"],
        "manual_note": "",
    },
    {
        "id": "164.312(c)(2)",
        "name": "Integrity — Mechanism to Authenticate ePHI",
        "finding_keywords": ["CSRF", "XSS", "SQL Injection", "Injection", "Deserialization"],
        "manual_note": "Hash/checksum validation on stored ePHI requires manual review.",
    },
    {
        "id": "164.312(d)",
        "name": "Person or Entity Authentication",
        "finding_keywords": ["Rate Limit", "Auth Bypass", "JWT", "Cookie Missing", "CSRF",
                             "Default Credential", "Username Enumeration"],
        "manual_note": "MFA implementation requires authenticated session testing.",
    },
    {
        "id": "164.312(e)(1)",
        "name": "Transmission Security — Guard Against Unauthorised Access",
        "finding_keywords": ["TLS", "HTTPS", "Weak TLS", "Certificate", "HTTP Not Enforced",
                             "CORS", "Open Redirect"],
        "manual_note": "",
    },
    {
        "id": "164.312(e)(2)(ii)",
        "name": "Transmission Security — Encryption",
        "finding_keywords": ["Cryptographic", "TLS", "Weak TLS", "HTTPS", "Cookie Missing Secure"],
        "manual_note": "",
    },
]


def evaluate(scan_result: ScanResult) -> ComplianceReport:
    finding_titles = [f.title for f in scan_result.findings]
    controls = []

    for sg in SAFEGUARDS:
        if sg.get("always_manual"):
            controls.append(ComplianceControl(
                id=sg["id"], name=sg["name"], status="manual",
                evidence=sg["manual_note"],
            ))
            continue

        if sg.get("is_scan_evidence"):
            controls.append(ComplianceControl(
                id=sg["id"], name=sg["name"], status="pass",
                evidence=f"Automated DAST risk analysis completed — {len(scan_result.findings)} findings identified.",
            ))
            continue

        matched = [t for t in finding_titles if any(kw.lower() in t.lower() for kw in sg.get("finding_keywords", []))]

        if matched:
            status = "fail"
            evidence = f"Findings indicate safeguard gap: {', '.join(matched[:3])}"
        else:
            status = "pass"
            evidence = "No automated findings indicate a gap in this safeguard."

        if sg.get("manual_note"):
            status = "partial" if status == "pass" else status
            evidence += f" Manual verification required: {sg['manual_note']}"

        controls.append(ComplianceControl(
            id=sg["id"], name=sg["name"], status=status,
            findings=matched, evidence=evidence,
        ))

    auto_controls = [c for c in controls if c.status != "manual"]
    passed = sum(1 for c in auto_controls if c.status in ("pass", "partial"))
    score = round((passed / len(auto_controls)) * 100, 1) if auto_controls else 0.0

    return ComplianceReport(standard="HIPAA", score=score, controls=controls)
