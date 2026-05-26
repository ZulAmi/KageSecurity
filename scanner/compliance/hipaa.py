from scanner.core.scan_result import ScanResult, ComplianceReport, ComplianceControl

SAFEGUARDS = [
    {
        "id": "164.312(a)(1)",
        "name": "Access Control — Unique User IDs",
        "finding_keywords": ["IDOR", "Broken Access", "SQL Injection", "Authentication"],
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
        "finding_keywords": ["Session", "Cookie", "JWT Missing Expiry"],
        "manual_note": "Session timeout configuration requires manual testing with authenticated sessions.",
    },
    {
        "id": "164.312(a)(2)(iii)",
        "name": "Access Control — Encryption and Decryption of ePHI",
        "finding_keywords": ["TLS", "HTTPS", "Cryptographic", "Certificate", "Weak TLS"],
        "manual_note": "",
    },
    {
        "id": "164.312(b)",
        "name": "Audit Controls",
        "finding_keywords": ["Exposed File: access.log", "Exposed File: debug.log", "Logging"],
        "always_manual": True,
        "manual_note": "Audit log completeness and protection require server-level access.",
    },
    {
        "id": "164.312(c)(1)",
        "name": "Integrity — Authentication of ePHI",
        "finding_keywords": ["CSRF", "Deserialization", "Subresource Integrity"],
        "manual_note": "",
    },
    {
        "id": "164.312(d)",
        "name": "Person or Entity Authentication",
        "finding_keywords": ["Rate Limit", "Authentication", "JWT", "Cookie Missing", "CSRF"],
        "manual_note": "MFA implementation requires authenticated session testing.",
    },
    {
        "id": "164.312(e)(1)",
        "name": "Transmission Security — Encryption in Transit",
        "finding_keywords": ["TLS", "HTTPS", "Weak TLS", "Certificate", "HTTP"],
        "manual_note": "",
    },
    {
        "id": "164.312(e)(2)(ii)",
        "name": "Transmission Security — Encryption",
        "finding_keywords": ["Cryptographic", "TLS", "Weak TLS", "HTTPS"],
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

        matched = [t for t in finding_titles if any(kw.lower() in t.lower() for kw in sg["finding_keywords"])]

        if matched:
            status = "fail"
            evidence = f"Findings indicate safeguard gap: {', '.join(matched[:3])}"
        else:
            status = "pass"
            evidence = "No automated findings indicate a gap in this safeguard."

        if sg["manual_note"]:
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
