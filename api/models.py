import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Float, Integer, Boolean, DateTime, JSON, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from api.db import Base


def _now():
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, default="pending")   # pending|running|done|failed
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    pages_crawled: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    compliance_results: Mapped[list["ComplianceResult"]] = relationship("ComplianceResult", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    owasp_category: Mapped[str | None] = mapped_column(String, nullable=True)
    url: Mapped[str] = mapped_column(String, nullable=False)
    parameter: Mapped[str | None] = mapped_column(String, nullable=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    cwe: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    false_positive_suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    ai_analysis: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_verdict: Mapped[str | None] = mapped_column(String, nullable=True)
    ai_exploitability: Mapped[str | None] = mapped_column(String, nullable=True)
    ai_business_impact: Mapped[str | None] = mapped_column(String, nullable=True)
    ai_attack_scenario: Mapped[str | None] = mapped_column(Text, nullable=True)
    standards: Mapped[list] = mapped_column(JSON, default=list)
    # PTaaS lifecycle fields
    triage_status: Mapped[str] = mapped_column(String, default="open")  # open|in_progress|accepted_risk|false_positive|fixed
    assigned_to: Mapped[str | None] = mapped_column(String, nullable=True)
    sla_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fix_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str] = mapped_column(Text, default="")

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")


class Schedule(Base):
    __tablename__ = "schedules"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target: Mapped[str] = mapped_column(String, nullable=False)
    cron: Mapped[str] = mapped_column(String, nullable=False)  # e.g. "0 2 * * *"
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    notify_email: Mapped[str | None] = mapped_column(String, nullable=True)
    notify_webhook: Mapped[str | None] = mapped_column(String, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_id: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ScanDiff(Base):
    __tablename__ = "scan_diffs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    baseline_scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    new_findings: Mapped[list] = mapped_column(JSON, default=list)
    fixed_findings: Mapped[list] = mapped_column(JSON, default=list)
    recurring_findings: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ComplianceResult(Base):
    __tablename__ = "compliance_results"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), nullable=False)
    standard: Mapped[str] = mapped_column(String, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    controls: Mapped[list] = mapped_column(JSON, default=list)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="compliance_results")
