"""
APScheduler-based cron runner for scheduled scans.
Started during FastAPI lifespan startup.
"""
import os
import uuid
import smtplib
import logging
from datetime import datetime, timezone
from email.mime.text import MIMEText
from typing import Optional

import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.orm import Session

from api.db import SessionLocal
from api import models, scanner_bridge

log = logging.getLogger(__name__)

_scheduler: Optional[AsyncIOScheduler] = None


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(timezone="UTC")
    return _scheduler


def start(loop=None):
    """Start the scheduler and load all enabled schedules from DB."""
    sched = get_scheduler()
    if sched.running:
        return
    sched.start()
    _load_schedules()


def stop():
    sched = get_scheduler()
    if sched.running:
        sched.shutdown(wait=False)


def _load_schedules():
    db = SessionLocal()
    try:
        for schedule in db.query(models.Schedule).filter_by(enabled=True).all():
            _add_job(schedule)
    finally:
        db.close()


def add_schedule(schedule: models.Schedule):
    """Register a newly created schedule with the running scheduler."""
    _add_job(schedule)


def remove_schedule(schedule_id: str):
    sched = get_scheduler()
    try:
        sched.remove_job(schedule_id)
    except Exception:
        pass


def _add_job(schedule: models.Schedule):
    sched = get_scheduler()
    try:
        trigger = CronTrigger.from_crontab(schedule.cron, timezone="UTC")
        sched.add_job(
            _run_scheduled_scan,
            trigger=trigger,
            id=schedule.id,
            replace_existing=True,
            args=[schedule.id],
        )
    except Exception as e:
        log.warning(f"Failed to add schedule {schedule.id}: {e}")


async def _run_scheduled_scan(schedule_id: str):
    db: Session = SessionLocal()
    try:
        schedule = db.query(models.Schedule).filter_by(id=schedule_id).first()
        if not schedule or not schedule.enabled:
            return

        scan_id = str(uuid.uuid4())

        # Create scan record
        scan = models.Scan(
            id=scan_id,
            target=schedule.target,
            status="pending",
            config=schedule.config,
        )
        db.add(scan)
        db.commit()

        # Update schedule last_run
        db.query(models.Schedule).filter_by(id=schedule_id).update({
            "last_run_at": datetime.now(timezone.utc),
            "last_scan_id": scan_id,
        })
        db.commit()

        config_dict = {"target": schedule.target, **schedule.config}
        scanner_bridge.launch_scan(scan_id, config_dict)

        log.info(f"Scheduled scan started: {scan_id} for {schedule.target}")

        # Notify on completion (best-effort — bridge publishes progress but we use polling)
        # Notification is sent after scan_bridge._run completes via the webhook/email fields.
        # For a full implementation use a scan-complete callback hook.
        if schedule.notify_email or schedule.notify_webhook:
            _schedule_notification(schedule, scan_id)

    except Exception as e:
        log.error(f"Scheduled scan error ({schedule_id}): {e}")
    finally:
        db.close()


def _schedule_notification(schedule: models.Schedule, scan_id: str):
    """Send email/webhook notification. Called after scan starts (not after completion)."""
    if schedule.notify_webhook:
        try:
            httpx.post(schedule.notify_webhook, json={
                "scan_id": scan_id,
                "target": schedule.target,
                "schedule_id": schedule.id,
                "event": "scan_started",
            }, timeout=5)
        except Exception:
            pass

    if schedule.notify_email:
        _send_email(
            to=schedule.notify_email,
            subject=f"KageSec: Scheduled scan started for {schedule.target}",
            body=f"Scan ID: {scan_id}\nTarget: {schedule.target}\n",
        )


def _send_email(to: str, subject: str, body: str):
    smtp_host = os.getenv("SMTP_HOST", "localhost")
    smtp_port = int(os.getenv("SMTP_PORT", "25"))
    smtp_from = os.getenv("SMTP_FROM", "kagesec@localhost")
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = to
        with smtplib.SMTP(smtp_host, smtp_port, timeout=5) as s:
            s.sendmail(smtp_from, [to], msg.as_string())
    except Exception as e:
        log.warning(f"Email notification failed: {e}")
