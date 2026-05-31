"""
Scheduled scanning — ~/.kagesec/schedules.yaml

Modelled on Burp Enterprise's site-level scheduling (hourly/daily/weekly/monthly) and
Bright Security's YAML-based, API-first approach.  No daemon required — run
`kagesec schedule run` from your system crontab or a nightly CI step.

Schedule YAML format:
  schedules:
    - target: https://app.example.com
      interval: daily          # named: hourly | daily | weekly | monthly
                               # or cron expression: "0 2 * * *"
      last_run: null           # ISO-8601 timestamp; null = never run
      options:
        profile: quick
        modules: []            # empty list = all modules
        max_pages: 150
        level: 3
"""
from __future__ import annotations

import os
import re
import yaml
from datetime import datetime, timezone, timedelta
from typing import Any

_SCHEDULES_PATH = os.path.expanduser("~/.kagesec/schedules.yaml")

_NAMED_INTERVALS: dict[str, timedelta] = {
    "hourly":  timedelta(hours=1),
    "daily":   timedelta(days=1),
    "weekly":  timedelta(weeks=1),
    "monthly": timedelta(days=30),
}

# Minimal cron expression support: "minute hour dom month dow"
_CRON_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$"
)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def load_schedules() -> list[dict]:
    """Load schedules from ~/.kagesec/schedules.yaml. Returns [] if file absent."""
    try:
        with open(_SCHEDULES_PATH) as f:
            data = yaml.safe_load(f) or {}
        return data.get("schedules", [])
    except FileNotFoundError:
        return []
    except Exception:
        return []


def save_schedules(schedules: list[dict]) -> None:
    os.makedirs(os.path.dirname(_SCHEDULES_PATH), exist_ok=True)
    with open(_SCHEDULES_PATH, "w") as f:
        yaml.safe_dump({"schedules": schedules}, f, default_flow_style=False, sort_keys=False)


def add_schedule(
    target: str,
    interval: str,
    profile: str | None = None,
    modules: list[str] | None = None,
    max_pages: int | None = None,
    level: int | None = None,
) -> dict:
    """Add or replace a schedule for `target`. Returns the new schedule entry."""
    schedules = load_schedules()
    # Remove any existing entry for this target
    schedules = [s for s in schedules if s.get("target") != target]
    entry: dict[str, Any] = {
        "target":   target,
        "interval": interval,
        "last_run": None,
        "options":  {},
    }
    if profile:
        entry["options"]["profile"] = profile
    if modules:
        entry["options"]["modules"] = modules
    if max_pages is not None:
        entry["options"]["max_pages"] = max_pages
    if level is not None:
        entry["options"]["level"] = level
    schedules.append(entry)
    save_schedules(schedules)
    return entry


def remove_schedule(target: str) -> bool:
    """Remove a schedule by target URL. Returns True if found and removed."""
    schedules = load_schedules()
    before = len(schedules)
    schedules = [s for s in schedules if s.get("target") != target]
    if len(schedules) < before:
        save_schedules(schedules)
        return True
    return False


def mark_ran(target: str) -> None:
    """Update last_run timestamp for the given target to now."""
    schedules = load_schedules()
    now_str = datetime.now(timezone.utc).isoformat()
    for s in schedules:
        if s.get("target") == target:
            s["last_run"] = now_str
    save_schedules(schedules)


# ---------------------------------------------------------------------------
# Due-date logic
# ---------------------------------------------------------------------------

def is_due(schedule: dict) -> bool:
    """Return True if the schedule should run now."""
    last_run_str = schedule.get("last_run")
    interval     = schedule.get("interval", "daily")

    if not last_run_str:
        return True   # Never run → run now

    try:
        last_run = datetime.fromisoformat(last_run_str)
        if last_run.tzinfo is None:
            last_run = last_run.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return True

    now = datetime.now(timezone.utc)

    # Named interval
    if interval in _NAMED_INTERVALS:
        return now >= last_run + _NAMED_INTERVALS[interval]

    # Cron expression (simplified: check if we're past the next fire time)
    if _CRON_RE.match(str(interval)):
        return _cron_is_due(interval, last_run, now)

    # Unknown interval — treat as daily
    return now >= last_run + timedelta(days=1)


def get_due_schedules() -> list[dict]:
    """Return all schedules that are due to run."""
    return [s for s in load_schedules() if is_due(s)]


def next_run(schedule: dict) -> datetime | None:
    """Return the next scheduled run time, or None if indeterminate."""
    last_run_str = schedule.get("last_run")
    interval     = schedule.get("interval", "daily")

    if not last_run_str:
        return datetime.now(timezone.utc)

    try:
        last_run = datetime.fromisoformat(last_run_str)
        if last_run.tzinfo is None:
            last_run = last_run.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None

    if interval in _NAMED_INTERVALS:
        return last_run + _NAMED_INTERVALS[interval]
    return None


# ---------------------------------------------------------------------------
# Minimal cron support
# ---------------------------------------------------------------------------

def _cron_is_due(cron_expr: str, last_run: datetime, now: datetime) -> bool:
    """Very lightweight cron check: only supports exact minute/hour fields (no ranges/steps)."""
    parts = cron_expr.split()
    if len(parts) != 5:
        return False
    minute_f, hour_f = parts[0], parts[1]
    try:
        target_minute = int(minute_f) if minute_f != "*" else now.minute
        target_hour   = int(hour_f)   if hour_f   != "*" else now.hour
    except ValueError:
        return False

    # Find the last time this cron would have fired on or before now
    candidate = now.replace(minute=target_minute, second=0, microsecond=0)
    if hour_f != "*":
        candidate = candidate.replace(hour=target_hour)
    if candidate > now:
        candidate -= timedelta(days=1)

    return candidate > last_run
