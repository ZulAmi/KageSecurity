from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class LoginFlow:
    """Describes a multi-step browser login for authenticated scanning."""
    url: str                          # Login page URL
    username_selector: str            # CSS selector for username input
    password_selector: str            # CSS selector for password input
    submit_selector: str              # CSS selector for submit button
    username: str
    password: str
    success_indicator: str            # URL substring OR CSS selector that appears post-login
    totp_secret: Optional[str] = None  # base32 TOTP secret for 2FA


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
    browser: bool = False                # Use Playwright headless browser (True) vs httpx (False)
    login_flow: Optional[LoginFlow] = None  # Multi-step login for authenticated scanning
    use_oob: bool = True                 # Use interactsh OOB callbacks for blind detection
    oob_server: str = "oast.pro"         # Interactsh-compatible OOB server
    openapi_spec: Optional[str] = None   # URL or file path to OpenAPI 3.x/Swagger 2.x spec
    graphql_endpoint: Optional[str] = None  # Explicit GraphQL endpoint URL
    resume_scan_id: Optional[str] = None    # Resume an interrupted scan by its checkpoint ID
    nvd_api_key: Optional[str] = None       # NVD API key for CVE enrichment (cve_check module)
