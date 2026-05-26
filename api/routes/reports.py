import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, PlainTextResponse
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
                    "ai_analysis": f.ai_analysis,
                    "standards": f.standards,
                }
                for f in scan.findings
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

    raise HTTPException(status_code=400, detail="format must be 'json' or 'markdown'")


def _build_markdown(scan: models.Scan) -> str:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(scan.findings, key=lambda f: severity_order.get(f.severity, 5))

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
        if f.ai_analysis:
            lines += [f"**AI Analysis:** {f.ai_analysis}", ""]

    if scan.compliance_results:
        lines += ["## Compliance", ""]
        for cr in scan.compliance_results:
            lines += [f"### {cr.standard} — Score: {cr.score:.0f}/100", ""]
            lines += ["| Control | Name | Status |", "|---|---|---|"]
            for ctrl in cr.controls:
                lines.append(f"| {ctrl['id']} | {ctrl['name']} | {ctrl['status'].upper()} |")
            lines.append("")

    return "\n".join(lines)
