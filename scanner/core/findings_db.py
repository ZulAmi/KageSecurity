"""
Persistent findings store — ~/.kagesec/findings.db (SQLite).

Every scan appends its findings here. The `kagesec history` command queries
trends: which findings persist across scans, which are new, MTTR, etc.

Schema
------
scans   (scan_id, target, started_at, duration_seconds, pages_crawled, total_findings)
findings(id, scan_id, target, title, severity, url, parameter, payload,
         owasp_category, cwe, cvss, confidence, verified, first_seen, last_seen, occurrences)

The `findings` table uses a composite natural key
  (target, title, url, parameter)
to track the same logical finding across multiple scans.
"""
from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.scan_result import ScanResult, Finding

_DB_PATH = os.path.expanduser("~/.kagesec/findings.db")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id          TEXT PRIMARY KEY,
    target           TEXT NOT NULL,
    started_at       REAL NOT NULL,
    duration_seconds REAL,
    pages_crawled    INTEGER DEFAULT 0,
    total_findings   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT NOT NULL,
    target       TEXT NOT NULL,
    title        TEXT NOT NULL,
    severity     TEXT NOT NULL,
    url          TEXT NOT NULL,
    parameter    TEXT,
    owasp_category TEXT,
    cwe          TEXT,
    cvss         REAL DEFAULT 0,
    confidence   REAL DEFAULT 0,
    verified     INTEGER DEFAULT 0,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    occurrences  INTEGER DEFAULT 1,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_target  ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_key     ON findings(target, title, url, parameter);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

@contextmanager
def _conn():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    con = sqlite3.connect(_DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        con.executescript(_SCHEMA)
        yield con
        con.commit()
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

def record_scan(scan_id: str, result: "ScanResult") -> None:
    """Persist a completed scan and all its findings."""
    now = time.time()
    summary = result.summary()
    with _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?)",
            (
                scan_id,
                result.target,
                now - result.scan_duration_seconds,
                result.scan_duration_seconds,
                result.pages_crawled,
                summary["total_findings"],
            ),
        )
        for f in result.findings:
            if f.false_positive_suppressed:
                continue
            _upsert_finding(con, scan_id, result.target, f, now)


def _upsert_finding(con, scan_id: str, target: str, f: "Finding", now: float) -> None:
    param = f.parameter or ""
    row = con.execute(
        "SELECT id, occurrences FROM findings WHERE target=? AND title=? AND url=? AND parameter=?",
        (target, f.title, f.url, param),
    ).fetchone()

    if row:
        con.execute(
            "UPDATE findings SET last_seen=?, occurrences=occurrences+1, scan_id=?, "
            "confidence=?, verified=? WHERE id=?",
            (now, scan_id, f.confidence, int(f.verified), row["id"]),
        )
    else:
        con.execute(
            "INSERT INTO findings (scan_id,target,title,severity,url,parameter,"
            "owasp_category,cwe,cvss,confidence,verified,first_seen,last_seen,occurrences) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
            (
                scan_id, target, f.title, f.severity.value, f.url, param,
                f.owasp_category, f.cwe, f.cvss, f.confidence, int(f.verified),
                now, now,
            ),
        )


# ---------------------------------------------------------------------------
# Query / reporting
# ---------------------------------------------------------------------------

def get_persisting_findings(target: str, min_occurrences: int = 2) -> list[dict]:
    """Return findings seen more than once for this target — the persistent risks."""
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM findings WHERE target=? AND occurrences>=? ORDER BY occurrences DESC",
            (target, min_occurrences),
        ).fetchall()
    return [dict(r) for r in rows]


def get_new_findings(target: str, since_scan_id: str) -> list[dict]:
    """Return findings first seen AFTER `since_scan_id` was recorded."""
    with _conn() as con:
        scan_time = con.execute(
            "SELECT started_at FROM scans WHERE scan_id=?", (since_scan_id,)
        ).fetchone()
        if not scan_time:
            return []
        rows = con.execute(
            "SELECT * FROM findings WHERE target=? AND first_seen > ? ORDER BY severity",
            (target, scan_time["started_at"]),
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan_history(target: str, limit: int = 10) -> list[dict]:
    """Return the last N scans for a target."""
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM scans WHERE target=? ORDER BY started_at DESC LIMIT ?",
            (target, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def trending_summary(target: str) -> dict:
    """Return a risk-trend summary for a target."""
    with _conn() as con:
        total = con.execute("SELECT COUNT(*) FROM findings WHERE target=?", (target,)).fetchone()[0]
        by_sev = {}
        for sev in ("critical", "high", "medium", "low", "info"):
            count = con.execute(
                "SELECT COUNT(*) FROM findings WHERE target=? AND severity=?", (target, sev)
            ).fetchone()[0]
            by_sev[sev] = count
        persisting = con.execute(
            "SELECT COUNT(*) FROM findings WHERE target=? AND occurrences>1", (target,)
        ).fetchone()[0]
        scans_run = con.execute(
            "SELECT COUNT(*) FROM scans WHERE target=?", (target,)
        ).fetchone()[0]
    return {
        "target": target,
        "total_unique_findings": total,
        "by_severity": by_sev,
        "persisting_across_scans": persisting,
        "scans_run": scans_run,
    }
