from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class LoginFlow:
    """Describes a multi-step browser login for authenticated scanning."""
    url: str
    username_selector: str
    password_selector: str
    submit_selector: str
    username: str
    password: str
    success_indicator: str
    totp_secret: Optional[str] = None


@dataclass
class ScanConfig:
    target: str
    max_depth: int = 3
    max_pages: int = 100
    modules: Optional[List[str]] = None      # None = run all modules
    auth: Optional[dict] = None              # {"type": "basic|cookie|bearer", "value": "..."}
    headers: Optional[dict] = None           # Extra headers injected on every request
    rate_limit_rps: int = 10
    timeout: int = 10
    compliance: List[str] = field(default_factory=list)
    follow_robots: bool = False
    browser: bool = False
    login_flow: Optional[LoginFlow] = None
    use_oob: bool = True
    oob_server: str = "oast.pro"
    openapi_spec: Optional[str] = None
    graphql_endpoint: Optional[str] = None
    resume_scan_id: Optional[str] = None
    nvd_api_key: Optional[str] = None
    template_dirs: Optional[List[str]] = None
    api_key: Optional[str] = None
    proxy: Optional[str] = None              # HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)
    passive: bool = False                    # Passive mode — no injection, headers/cookies/content only
    include_patterns: List[str] = field(default_factory=list)   # Glob patterns — only crawl matching URLs
    exclude_patterns: List[str] = field(default_factory=list)   # Glob patterns — skip matching URLs
