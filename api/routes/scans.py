import asyncio
import json
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from api.db import get_db
from api import models, schemas
from api.scanner_bridge import launch_scan, subscribe, unsubscribe

router = APIRouter(prefix="/scans", tags=["scans"])


def _scan_out(scan: models.Scan) -> schemas.ScanOut:
    counts = {}
    for f in scan.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return schemas.ScanOut(
        id=scan.id,
        target=scan.target,
        status=scan.status,
        pages_crawled=scan.pages_crawled,
        duration_seconds=scan.duration_seconds,
        error=scan.error,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        findings_count=len(scan.findings),
        findings_by_severity=counts,
    )


@router.get("", response_model=List[schemas.ScanOut])
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(models.Scan).order_by(models.Scan.created_at.desc()).all()
    return [_scan_out(s) for s in scans]


@router.post("", response_model=schemas.ScanOut, status_code=201)
def start_scan(body: schemas.StartScanRequest, db: Session = Depends(get_db)):
    scan = models.Scan(
        target=body.target,
        status="pending",
        config={
            "target": body.target,
            "max_depth": body.config.max_depth,
            "max_pages": body.config.max_pages,
            "modules": body.config.modules,
            "auth": body.config.auth,
            "compliance": body.config.compliance,
        },
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    launch_scan(scan.id, scan.config)
    return _scan_out(scan)


@router.get("/{scan_id}", response_model=schemas.ScanDetailOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = [schemas.FindingOut.model_validate(f) for f in scan.findings]
    compliance = [
        schemas.ComplianceResultOut(
            standard=cr.standard,
            score=cr.score,
            controls=cr.controls,
        )
        for cr in scan.compliance_results
    ]

    counts = {}
    for f in scan.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return schemas.ScanDetailOut(
        id=scan.id,
        target=scan.target,
        status=scan.status,
        pages_crawled=scan.pages_crawled,
        duration_seconds=scan.duration_seconds,
        error=scan.error,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        findings_count=len(scan.findings),
        findings_by_severity=counts,
        findings=findings,
        compliance_results=compliance,
    )


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


@router.websocket("/{scan_id}/progress")
async def scan_progress_ws(scan_id: str, websocket: WebSocket, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter_by(id=scan_id).first()
    if not scan:
        await websocket.close(code=4004)
        return

    await websocket.accept()

    # If scan already done, send current state immediately
    if scan.status in ("done", "failed"):
        await websocket.send_text(json.dumps({"type": "done", "status": scan.status}))
        return

    queue = subscribe(scan_id)
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_text(json.dumps(event, default=str))
                if event.get("type") in ("done", "error"):
                    break
            except asyncio.TimeoutError:
                # Heartbeat
                await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        pass
    finally:
        unsubscribe(scan_id, queue)
