import json
import os
import tempfile
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, PlainTextResponse, FileResponse
from sqlalchemy.orm import Session

from api.db import get_db
from api import models

router = APIRouter(prefix="/scans", tags=["reports"])


@router.get("/{scan_id}/report")
def get_report(scan_id: str, format: str = "json", db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "done":
        raise HTTPException(status_code=409, detail="Scan not complete yet")

    if format == "json":
        counts = {}
        for f in scan.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        data = {
            "summary": {
                "target": scan.target,
                "scan_id": scan.id,
                "status": scan.status,
                "pages_crawled": scan.pages_crawled,
                "duration_seconds": scan.duration_seconds,
                "total_findings": len(scan.findings),
                "by_severity": counts,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            },
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "owasp_category": f.owasp_category,
                    "url": f.url,
                    "parameter": f.parameter,
                    "payload": f.payload,
                    "evidence": f.evidence,
                    "description": f.description,
                    "remediation": f.remediation,
                    "cwe": f.cwe,
                    "cvss": f.cvss,
                    "confidence": f.confidence,
                    "verified": f.verified,
                    "false_positive_suppressed": f.false_positive_suppressed,
                    "ai_verdict": f.ai_verdict,
                    "ai_analysis": f.ai_analysis,
                    "ai_exploitability": f.ai_exploitability,
                    "ai_business_impact": f.ai_business_impact,
                    "ai_attack_scenario": f.ai_attack_scenario,
                    "standards": f.standards,
                }
                for f in scan.findings
                if not f.false_positive_suppressed
            ],
            "compliance": [
                {"standard": cr.standard, "score": cr.score, "controls": cr.controls}
                for cr in scan.compliance_results
            ],
        }
        return Response(
            content=json.dumps(data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="kagesec-{scan_id[:8]}.json"'},
        )

    elif format == "markdown":
        md = _build_markdown(scan)
        return PlainTextResponse(
            content=md,
            headers={"Content-Disposition": f'attachment; filename="kagesec-{scan_id[:8]}.md"'},
        )

    elif format == "pdf":
        return _build_pdf_response(scan, scan_id)

    raise HTTPException(status_code=400, detail="format must be 'json', 'markdown', or 'pdf'")


def _build_markdown(scan: models.Scan) -> str:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(
        [f for f in scan.findings if not f.false_positive_suppressed],
        key=lambda f: severity_order.get(f.severity, 5),
    )

    lines = [
        f"# KageSec Security Report",
        f"",
        f"**Target:** {scan.target}  ",
        f"**Scan ID:** {scan.id}  ",
        f"**Completed:** {scan.completed_at}  ",
        f"**Pages crawled:** {scan.pages_crawled}  ",
        f"**Duration:** {scan.duration_seconds:.1f}s  ",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|---|---|",
    ]

    counts: dict = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    for sev in ["critical", "high", "medium", "low", "info"]:
        if counts.get(sev):
            lines.append(f"| {sev.upper()} | {counts[sev]} |")

    lines += ["", "## Findings", ""]

    for f in findings:
        lines += [
            f"### [{f.severity.upper()}] {f.title}",
            f"",
            f"- **URL:** `{f.url}`",
            f"- **Parameter:** `{f.parameter or 'N/A'}`",
            f"- **CWE:** {f.cwe or 'N/A'}  **CVSS:** {f.cvss or 'N/A'}",
            f"- **OWASP:** {f.owasp_category or 'N/A'}",
            f"",
            f"**Evidence:** {f.evidence}",
            f"",
            f"**Description:** {f.description}",
            f"",
            f"**Remediation:** {f.remediation}",
            f"",
        ]
        if f.ai_verdict:
            lines += [
                f"**AI Verdict:** {f.ai_verdict.replace('_', ' ').title()}  "
                f"**Exploitability:** {f.ai_exploitability or 'unknown'}  "
                f"**Business Impact:** {f.ai_business_impact or 'unknown'}",
                "",
            ]
        if f.ai_analysis:
            lines += [f"**AI Analysis:** {f.ai_analysis}", ""]
        if f.ai_attack_scenario:
            lines += [f"**Attack Scenario:** {f.ai_attack_scenario}", ""]

    if scan.compliance_results:
        lines += ["## Compliance", ""]
        for cr in scan.compliance_results:
            lines += [f"### {cr.standard} — Score: {cr.score:.0f}/100", ""]
            lines += ["| Control | Name | Status |", "|---|---|---|"]
            for ctrl in cr.controls:
                lines.append(f"| {ctrl['id']} | {ctrl['name']} | {ctrl['status'].upper()} |")
            lines.append("")

    return "\n".join(lines)


@router.get("/{scan_id}/certificate")
def get_certificate(scan_id: str, db: Session = Depends(get_db)):
    """
    Generate a pentest certificate PDF for a completed scan.
    Only issued if the scan has zero unresolved critical/high findings.
    """
    scan = db.query(models.Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "done":
        raise HTTPException(status_code=409, detail="Scan not complete yet")

    try:
        from scanner.reporters.certificate_reporter import generate_certificate
        from scanner.core.scan_result import ScanResult, Finding, Severity, ComplianceReport, ComplianceControl
    except ImportError as e:
        raise HTTPException(status_code=501, detail=f"Certificate generation unavailable: {e}")

    result = ScanResult(target=scan.target, pages_crawled=scan.pages_crawled)
    for f in scan.findings:
        result.findings.append(Finding(
            title=f.title, severity=Severity(f.severity), url=f.url,
            parameter=f.parameter, payload=f.payload, evidence=f.evidence,
            description=f.description, remediation=f.remediation,
            false_positive_suppressed=getattr(f, "false_positive_suppressed", False),
        ))
    for cr in scan.compliance_results:
        rpt = ComplianceReport(standard=cr.standard, score=cr.score)
        result.compliance_reports.append(rpt)

    pdf_path = os.path.join(tempfile.gettempdir(), f"kagesec-cert-{scan_id[:8]}.pdf")
    try:
        generate_certificate(result, pdf_path, scan_id=scan_id)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=501, detail=str(e))

    with open(pdf_path, "rb") as fh:
        content = fh.read()
    try:
        os.unlink(pdf_path)
    except OSError:
        pass

    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="kagesec-cert-{scan_id[:8]}.pdf"'},
    )


def _build_pdf_response(scan: models.Scan, scan_id: str) -> Response:
    try:
        from scanner.reporters.pdf_reporter import generate_pdf
        from scanner.core.scan_result import (
            ScanResult, Finding, Severity, ComplianceReport, ComplianceControl
        )
    except ImportError as e:
        raise HTTPException(status_code=501, detail=f"PDF generation unavailable: {e}")

    # Reconstruct a minimal ScanResult from DB rows
    result = ScanResult(
        target=scan.target,
        pages_crawled=scan.pages_crawled,
        scan_duration_seconds=scan.duration_seconds,
    )
    for f in scan.findings:
        result.findings.append(Finding(
            title=f.title,
            severity=Severity(f.severity),
            url=f.url,
            parameter=f.parameter,
            payload=f.payload,
            evidence=f.evidence,
            description=f.description,
            remediation=f.remediation,
            cwe=f.cwe,
            cvss=f.cvss,
            confidence=f.confidence,
            verified=f.verified,
            false_positive_suppressed=getattr(f, "false_positive_suppressed", False),
            ai_verdict=getattr(f, "ai_verdict", None),
            ai_analysis=f.ai_analysis,
            ai_exploitability=getattr(f, "ai_exploitability", None),
            ai_business_impact=getattr(f, "ai_business_impact", None),
            ai_attack_scenario=getattr(f, "ai_attack_scenario", None),
            owasp_category=f.owasp_category,
            standards=f.standards or [],
        ))
    for cr in scan.compliance_results:
        report = ComplianceReport(standard=cr.standard, score=cr.score)
        for c in cr.controls:
            report.controls.append(ComplianceControl(
                id=c["id"], name=c["name"], status=c["status"],
                findings=c.get("findings", []), evidence=c.get("evidence", ""),
            ))
        result.compliance_reports.append(report)

    pdf_path = os.path.join(tempfile.gettempdir(), f"kagesec-{scan_id[:8]}.pdf")
    try:
        generate_pdf(result, pdf_path)
    except RuntimeError as e:
        raise HTTPException(status_code=501, detail=str(e))

    with open(pdf_path, "rb") as fh:
        content = fh.read()
    try:
        os.unlink(pdf_path)
    except OSError:
        pass

    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="kagesec-{scan_id[:8]}.pdf"'},
    )
