"""
Runs a KageSec scan in a background thread and persists results to the DB.
Publishes progress events to an in-memory queue consumed by WebSocket clients.
"""
import os
import asyncio
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from collections import defaultdict

from sqlalchemy.orm import Session

from scanner.core.config import ScanConfig
from scanner.core.engine import run_scan
from api.db import SessionLocal
from api import models

# scan_id -> asyncio.Queue of progress dicts
_progress_queues: Dict[str, list] = defaultdict(list)
_loop: asyncio.AbstractEventLoop | None = None


def set_event_loop(loop: asyncio.AbstractEventLoop):
    global _loop
    _loop = loop


def subscribe(scan_id: str) -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue()
    _progress_queues[scan_id].append(q)
    return q


def unsubscribe(scan_id: str, q: asyncio.Queue):
    try:
        _progress_queues[scan_id].remove(q)
    except ValueError:
        pass


def _publish(scan_id: str, event: dict):
    if _loop is None:
        return
    for q in list(_progress_queues.get(scan_id, [])):
        asyncio.run_coroutine_threadsafe(q.put(event), _loop)


def launch_scan(scan_id: str, config_dict: dict):
    thread = threading.Thread(target=_run, args=(scan_id, config_dict), daemon=True)
    thread.start()


def _run(scan_id: str, config_dict: dict):
    db: Session = SessionLocal()
    try:
        db.query(models.Scan).filter_by(id=scan_id).update({"status": "running"})
        db.commit()
        _publish(scan_id, {"type": "status", "status": "running"})

        config = ScanConfig(
            target=config_dict["target"],
            max_depth=config_dict.get("max_depth", 3),
            max_pages=config_dict.get("max_pages", 100),
            modules=config_dict.get("modules"),
            auth=config_dict.get("auth"),
            compliance=config_dict.get("compliance", []),
        )

        api_key = os.getenv("ANTHROPIC_API_KEY")
        scan_result, _report_md = run_scan(config=config, api_key=api_key)

        _publish(scan_id, {
            "type": "progress",
            "pages_crawled": scan_result.pages_crawled,
            "findings_count": len(scan_result.findings),
        })

        # SLA deadlines: critical=3d, high=7d, medium=30d, low=90d
        _SLA_DAYS = {"critical": 3, "high": 7, "medium": 30, "low": 90}

        # Persist findings
        for f in scan_result.findings:
            db.add(models.Finding(
                scan_id=scan_id,
                title=f.title,
                severity=f.severity.value,
                owasp_category=f.owasp_category,
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
                false_positive_suppressed=f.false_positive_suppressed,
                ai_analysis=f.ai_analysis,
                ai_verdict=f.ai_verdict,
                ai_exploitability=f.ai_exploitability,
                ai_business_impact=f.ai_business_impact,
                ai_attack_scenario=f.ai_attack_scenario,
                standards=f.standards,
                sla_deadline=datetime.now(timezone.utc) + timedelta(days=_SLA_DAYS.get(f.severity.value, 30)),
            ))

        for cr in scan_result.compliance_reports:
            db.add(models.ComplianceResult(
                scan_id=scan_id,
                standard=cr.standard,
                score=cr.score,
                controls=[
                    {"id": c.id, "name": c.name, "status": c.status,
                     "findings": c.findings, "evidence": c.evidence}
                    for c in cr.controls
                ],
            ))

        db.query(models.Scan).filter_by(id=scan_id).update({
            "status": "done",
            "pages_crawled": scan_result.pages_crawled,
            "duration_seconds": scan_result.scan_duration_seconds,
            "completed_at": datetime.now(timezone.utc),
        })
        db.commit()
        _publish(scan_id, {"type": "done", "findings_count": len(scan_result.findings)})

    except Exception as e:
        db.query(models.Scan).filter_by(id=scan_id).update({"status": "failed", "error": str(e)})
        db.commit()
        _publish(scan_id, {"type": "error", "message": str(e)})
    finally:
        db.close()
        _progress_queues.pop(scan_id, None)
