import threading
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
    poc_curl: Optional[str] = None         # Gap 19 — ready-to-run curl command to reproduce

    def build_poc_curl(self, method: str = "GET", extra_headers: Optional[Dict] = None) -> str:
        """Gap 19 — generate a curl command reproducing this finding."""
        parts = [f"curl -sk -X {method.upper()}"]
        if extra_headers:
            for k, v in extra_headers.items():
                parts.append(f"-H '{k}: {v}'")
        if self.payload and method.upper() in ("POST", "PUT", "PATCH"):
            parts.append(f"--data '{self.payload}'")
        url = self.url
        if self.parameter and self.payload and method.upper() == "GET":
            from urllib.parse import urlparse, urlunparse, parse_qs
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[self.parameter] = [self.payload]
            from urllib.parse import urlencode as _enc
            url = urlunparse(parsed._replace(query=_enc(qs, doseq=True)))
        parts.append(f"'{url}'")
        cmd = " ".join(parts)
        self.poc_curl = cmd
        return cmd


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

    def __post_init__(self):
        # Internal dedup state — not part of the data model, not serialised
        self._dedup_map: dict = {}
        self._dedup_lock = threading.Lock()
        # Seed map from any pre-existing findings (e.g. loaded from checkpoint)
        for f in self.findings:
            self._dedup_map.setdefault(ScanResult._dedup_key(f), f)

    @staticmethod
    def _dedup_key(finding: Finding) -> tuple:
        """
        Dedup key matching industry practice (Burp Suite, OWASP ZAP, Astra):

        • Site-wide observations (parameter=None) — e.g. missing headers, CORS policy,
          TLS issues: keyed on (title, host) so they fire once per target regardless of
          how many pages were crawled.

        • Active findings (parameter set) — e.g. IDOR, XSS, SQLi: keyed on
          (title, host, path, parameter), intentionally ignoring the specific query-param
          value. This collapses IDOR on /post?id=1, /post?id=2 … /post?id=18 into one
          finding for "IDOR on /post via id parameter".
        """
        parsed = urlparse(finding.url)
        host = parsed.netloc
        if finding.parameter is None:
            return (finding.title, host)
        return (finding.title, host, parsed.path, finding.parameter)

    def add_finding(self, finding: Finding) -> bool:
        """
        Add a finding with real-time deduplication. Thread-safe.
        Returns True if the finding was accepted, False if deduplicated away.

        Callers can use the return value to decide whether to show a live notification.
        """
        key = ScanResult._dedup_key(finding)
        with self._dedup_lock:
            existing = self._dedup_map.get(key)
            if existing is not None:
                # Upgrade to higher severity if a better signal arrives later
                if _SEVERITY_RANK[finding.severity] < _SEVERITY_RANK[existing.severity]:
                    self._dedup_map[key] = finding
                return False
            self._dedup_map[key] = finding
            self.findings.append(finding)
            return True

    def deduplicate(self):
        """Rebuild findings from the dedup map to pick up any severity upgrades."""
        with self._dedup_lock:
            self.findings = list(self._dedup_map.values())

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
