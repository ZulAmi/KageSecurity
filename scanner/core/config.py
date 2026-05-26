from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScanConfig:
    target: str
    max_depth: int = 3
    max_pages: int = 100
    modules: Optional[List[str]] = None  # None = run all modules
    auth: Optional[dict] = None          # {"type": "basic|cookie|bearer", "value": "..."}
    headers: Optional[dict] = None       # Extra headers injected on every request
    rate_limit_rps: int = 10             # Max requests per second
    timeout: int = 10
    compliance: List[str] = field(default_factory=list)  # ["iso27001","hipaa","gdpr","appi"]
    follow_robots: bool = False          # Respect robots.txt
