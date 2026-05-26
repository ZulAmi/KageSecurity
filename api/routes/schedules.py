from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db import get_db
from api import models

router = APIRouter(prefix="/schedules", tags=["schedules"])


class ScheduleCreate(BaseModel):
    target: str
    cron: str             # e.g. "0 2 * * *" — daily at 2am UTC
    config: dict = {}
    notify_email: Optional[str] = None
    notify_webhook: Optional[str] = None


class ScheduleOut(BaseModel):
    id: str
    target: str
    cron: str
    config: dict
    notify_email: Optional[str]
    notify_webhook: Optional[str]
    enabled: bool
    last_run_at: Optional[datetime]
    last_scan_id: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


@router.post("", response_model=ScheduleOut, status_code=201)
def create_schedule(body: ScheduleCreate, db: Session = Depends(get_db)):
    # Validate cron expression
    try:
        from apscheduler.triggers.cron import CronTrigger
        CronTrigger.from_crontab(body.cron)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid cron expression: {e}")

    schedule = models.Schedule(
        target=body.target,
        cron=body.cron,
        config=body.config,
        notify_email=body.notify_email,
        notify_webhook=body.notify_webhook,
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    # Register with live scheduler
    try:
        from api.scheduler import add_schedule
        add_schedule(schedule)
    except Exception:
        pass  # Scheduler may not be running in test mode

    return schedule


@router.get("", response_model=List[ScheduleOut])
def list_schedules(db: Session = Depends(get_db)):
    return db.query(models.Schedule).order_by(models.Schedule.created_at.desc()).all()


@router.get("/{schedule_id}", response_model=ScheduleOut)
def get_schedule(schedule_id: str, db: Session = Depends(get_db)):
    s = db.query(models.Schedule).filter_by(id=schedule_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return s


@router.patch("/{schedule_id}", response_model=ScheduleOut)
def toggle_schedule(schedule_id: str, enabled: bool, db: Session = Depends(get_db)):
    s = db.query(models.Schedule).filter_by(id=schedule_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Schedule not found")
    s.enabled = enabled
    db.commit()
    db.refresh(s)

    try:
        from api.scheduler import add_schedule, remove_schedule
        if enabled:
            add_schedule(s)
        else:
            remove_schedule(schedule_id)
    except Exception:
        pass

    return s


@router.delete("/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: str, db: Session = Depends(get_db)):
    s = db.query(models.Schedule).filter_by(id=schedule_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Schedule not found")
    db.delete(s)
    db.commit()

    try:
        from api.scheduler import remove_schedule
        remove_schedule(schedule_id)
    except Exception:
        pass
