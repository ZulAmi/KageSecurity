from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict
from urllib.parse import urlparse, urlunparse


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

_SEVERITY_RANK = {s: i for i, s in enumerate(Severity)}


def _normalise_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))


@dataclass
class Finding:
    title: str
    severity: Severity
    url: str
    parameter: Optional[str]
    payload: Optional[str]
    evidence: str
    description: str
    remediation: str
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    verified: bool = False
    ai_analysis: Optional[str] = None
    owasp_category: Optional[str] = None   # e.g. "A03:2021 Injection"
    standards: List[str] = field(default_factory=list)  # ["ISO27001-8.24", "HIPAA-164.312c"]
    confidence: float = 1.0                # 0.0–1.0
    false_positive_suppressed: bool = False
    ai_verdict: Optional[str] = None       # "true_positive" | "false_positive" | "needs_manual_review"
    ai_exploitability: Optional[str] = None
    ai_business_impact: Optional[str] = None
    ai_attack_scenario: Optional[str] = None


@dataclass
class ComplianceControl:
    id: str        # e.g. "8.24", "164.312c"
    name: str
    status: str    # "pass" | "fail" | "partial" | "manual"
    findings: List[str] = field(default_factory=list)  # Finding titles that triggered this
    evidence: str = ""


@dataclass
class ComplianceReport:
    standard: str   # "ISO27001" | "HIPAA" | "GDPR" | "APPI"
    score: float    # 0–100
    controls: List[ComplianceControl] = field(default_factory=list)

    def summary(self) -> dict:
        counts = {"pass": 0, "fail": 0, "partial": 0, "manual": 0}
        for c in self.controls:
            counts[c.status] = counts.get(c.status, 0) + 1
        return {"standard": self.standard, "score": self.score, "controls": counts}


@dataclass
class ScanResult:
    target: str
    findings: List[Finding] = field(default_factory=list)
    compliance_reports: List[ComplianceReport] = field(default_factory=list)
    pages_crawled: int = 0
    scan_duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def deduplicate(self):
        """
        Three-pass deduplication:
        1. Drop exact duplicates (same url+param+title).
        2. Per (url, param) keep only the highest-severity finding — SQLi wins over XSS.
        3. Passive findings (parameter=None) are server-wide observations: keep only one
           instance per title across the whole scan (e.g. "Missing CSP" fires once, not
           once per crawled page).
        """
        # Pass 1: exact dedup
        seen: dict[tuple, Finding] = {}
        for f in self.findings:
            key = (_normalise_url(f.url), f.parameter, f.title)
            existing = seen.get(key)
            if existing is None or _SEVERITY_RANK[f.severity] < _SEVERITY_RANK[existing.severity]:
                seen[key] = f

        # Pass 2: per (url, param) keep highest severity
        best: dict[tuple, Finding] = {}
        for f in seen.values():
            if f.parameter is None:
                loc_key = (_normalise_url(f.url), None, f.title)
            else:
                loc_key = (_normalise_url(f.url), f.parameter)
            existing = best.get(loc_key)
            if existing is None or _SEVERITY_RANK[f.severity] < _SEVERITY_RANK[existing.severity]:
                best[loc_key] = f

        # Pass 3: for passive findings (no param), one per title across the whole scan
        global_passive: dict[str, Finding] = {}
        active_findings = []
        for f in best.values():
            if f.parameter is None:
                existing = global_passive.get(f.title)
                if existing is None or _SEVERITY_RANK[f.severity] < _SEVERITY_RANK[existing.severity]:
                    global_passive[f.title] = f
            else:
                active_findings.append(f)

        self.findings = active_findings + list(global_passive.values())

    def summary(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return {
            "target": self.target,
            "total_findings": len(self.findings),
            "by_severity": counts,
            "pages_crawled": self.pages_crawled,
            "duration_seconds": self.scan_duration_seconds,
        }
