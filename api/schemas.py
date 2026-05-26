from pydantic import BaseModel, HttpUrl
from typing import Optional, List
from datetime import datetime


class ScanConfigRequest(BaseModel):
    max_depth: int = 3
    max_pages: int = 100
    modules: Optional[List[str]] = None
    auth: Optional[dict] = None
    compliance: List[str] = []


class StartScanRequest(BaseModel):
    target: str
    config: ScanConfigRequest = ScanConfigRequest()


class FindingOut(BaseModel):
    id: str
    title: str
    severity: str
    owasp_category: Optional[str]
    url: str
    parameter: Optional[str]
    payload: Optional[str]
    evidence: str
    description: str
    remediation: str
    cwe: Optional[str]
    cvss: Optional[float]
    confidence: float
    verified: bool
    ai_analysis: Optional[str]
    standards: List[str]

    model_config = {"from_attributes": True}


class ComplianceControlOut(BaseModel):
    id: str
    name: str
    status: str
    findings: List[str]
    evidence: str


class ComplianceResultOut(BaseModel):
    standard: str
    score: float
    controls: List[dict]

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: str
    target: str
    status: str
    pages_crawled: int
    duration_seconds: float
    error: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]
    findings_count: int = 0
    findings_by_severity: dict = {}

    model_config = {"from_attributes": True}


class ScanDetailOut(ScanOut):
    findings: List[FindingOut] = []
    compliance_results: List[ComplianceResultOut] = []
