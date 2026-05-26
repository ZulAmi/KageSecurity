from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from api.db import get_db
from api import models

router = APIRouter(prefix="/findings", tags=["findings"])


class FindingPatch(BaseModel):
    triage_status: Optional[str] = None   # open|in_progress|accepted_risk|false_positive|fixed
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    fix_verified: Optional[bool] = None


class FindingOut(BaseModel):
    id: str
    scan_id: str
    title: str
    severity: str
    owasp_category: Optional[str]
    url: str
    parameter: Optional[str]
    evidence: str
    cwe: Optional[str]
    cvss: Optional[float]
    confidence: float
    verified: bool
    ai_verdict: Optional[str]
    ai_analysis: Optional[str]
    triage_status: str
    assigned_to: Optional[str]
    sla_deadline: Optional[datetime]
    fixed_at: Optional[datetime]
    fix_verified: bool
    notes: str
    standards: List[str]

    model_config = {"from_attributes": True}


@router.patch("/{finding_id}", response_model=FindingOut)
def patch_finding(finding_id: str, body: FindingPatch, db: Session = Depends(get_db)):
    finding = db.query(models.Finding).filter_by(id=finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if body.triage_status is not None:
        valid = {"open", "in_progress", "accepted_risk", "false_positive", "fixed"}
        if body.triage_status not in valid:
            raise HTTPException(status_code=422, detail=f"triage_status must be one of {valid}")
        finding.triage_status = body.triage_status
        if body.triage_status == "fixed" and not finding.fixed_at:
            finding.fixed_at = datetime.now(timezone.utc)

    if body.assigned_to is not None:
        finding.assigned_to = body.assigned_to
    if body.notes is not None:
        finding.notes = body.notes
    if body.fix_verified is not None:
        finding.fix_verified = body.fix_verified

    db.commit()
    db.refresh(finding)
    return finding


@router.get("", response_model=List[FindingOut])
def list_findings(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    scan_id: Optional[str] = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    q = db.query(models.Finding)
    if scan_id:
        q = q.filter(models.Finding.scan_id == scan_id)
    if status:
        q = q.filter(models.Finding.triage_status == status)
    if severity:
        q = q.filter(models.Finding.severity == severity)
    q = q.order_by(models.Finding.sla_deadline.asc().nullslast())
    return q.offset(offset).limit(limit).all()


@router.get("/stats/mttr")
def mttr_stats(db: Session = Depends(get_db)):
    """Mean time to remediation by severity (days)."""
    results = {}
    for sev in ("critical", "high", "medium", "low"):
        fixed = db.query(models.Finding).filter(
            models.Finding.severity == sev,
            models.Finding.triage_status == "fixed",
            models.Finding.fixed_at.isnot(None),
        ).all()

        if not fixed:
            results[sev] = None
            continue

        total_days = 0.0
        count = 0
        for f in fixed:
            # Get the scan creation time as the "found at" timestamp
            scan = db.query(models.Scan).filter_by(id=f.scan_id).first()
            if scan and scan.completed_at and f.fixed_at:
                delta = f.fixed_at - scan.completed_at
                total_days += delta.total_seconds() / 86400
                count += 1

        results[sev] = round(total_days / count, 1) if count else None

    return {"mttr_days": results}


@router.get("/stats/sla")
def sla_stats(db: Session = Depends(get_db)):
    """Findings that have breached or are approaching their SLA deadline."""
    now = datetime.now(timezone.utc)
    breached = db.query(models.Finding).filter(
        models.Finding.sla_deadline < now,
        models.Finding.triage_status.notin_(["fixed", "accepted_risk", "false_positive"]),
    ).all()

    return {
        "breached_count": len(breached),
        "breached": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "url": f.url,
                "sla_deadline": f.sla_deadline.isoformat() if f.sla_deadline else None,
                "days_overdue": round((now - f.sla_deadline).total_seconds() / 86400, 1) if f.sla_deadline else None,
            }
            for f in breached
        ],
    }


@router.get("/scans/{scan_id}/diff/{baseline_id}")
def scan_diff(scan_id: str, baseline_id: str, db: Session = Depends(get_db)):
    """Compare two scans: new findings, fixed findings, recurring findings."""
    new_scan = db.query(models.Scan).filter_by(id=scan_id).first()
    baseline = db.query(models.Scan).filter_by(id=baseline_id).first()
    if not new_scan or not baseline:
        raise HTTPException(status_code=404, detail="Scan not found")

    def _fingerprint(f):
        return (f.title, f.url, f.parameter)

    new_fps = {_fingerprint(f): f for f in new_scan.findings}
    base_fps = {_fingerprint(f): f for f in baseline.findings}

    new_finding_fps = set(new_fps) - set(base_fps)
    fixed_fps = set(base_fps) - set(new_fps)
    recurring_fps = set(new_fps) & set(base_fps)

    def _serialize(f):
        return {"id": f.id, "title": f.title, "severity": f.severity,
                "url": f.url, "parameter": f.parameter}

    return {
        "scan_id": scan_id,
        "baseline_scan_id": baseline_id,
        "new_findings": [_serialize(new_fps[fp]) for fp in new_finding_fps],
        "fixed_findings": [_serialize(base_fps[fp]) for fp in fixed_fps],
        "recurring_findings": [_serialize(new_fps[fp]) for fp in recurring_fps],
        "summary": {
            "new": len(new_finding_fps),
            "fixed": len(fixed_fps),
            "recurring": len(recurring_fps),
        },
    }
