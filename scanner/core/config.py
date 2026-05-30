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
    nuclei_templates: bool = False             # Include ~10k Nuclei community templates (slow without AI key)
    api_key: Optional[str] = None
    ai_provider: Optional[str] = None    # anthropic | openai | gemini | mistral | ollama
    ai_model: Optional[str] = None       # optional model override
    proxy: Optional[str] = None              # HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)
    passive: bool = False                    # Passive mode — no injection, headers/cookies/content only
    include_patterns: List[str] = field(default_factory=list)   # Glob patterns — only crawl matching URLs
    exclude_patterns: List[str] = field(default_factory=list)   # Glob patterns — skip matching URLs
    har_file: Optional[str] = None                              # Path to .har file (skips live crawl)
    wsdl_url: Optional[str] = None           # SOAP/WSDL endpoint to scan (Gap 16)
    jwt_wordlist: Optional[str] = None       # Custom JWT secrets wordlist path (Gap 17)
    path_wordlist: Optional[str] = None      # Custom path discovery wordlist (Gap 10)
    param_wordlist: Optional[str] = None     # Custom parameter discovery wordlist (Gap 11)
    subdomain_wordlist: Optional[str] = None # Custom subdomain wordlist (Gap 12)
    scan_policy_file: Optional[str] = None   # Per-module scan policy YAML (Gap 25)
    force_full_scan: bool = False            # Ignore delta state, always do a full scan (Gap 28)
    retries: int = 0                         # HTTP request retry count on failure
    user_agent: Optional[str] = None         # Custom User-Agent string
    verbose: bool = False                    # Print each URL/module as it runs
    no_color: bool = False                   # Disable ANSI colors
    max_time_minutes: int = 0               # Hard scan time budget (0 = unlimited)
    extensions: Optional[List[str]] = None   # File extensions to append in path discovery
    filter_status_codes: Optional[List[int]] = None  # HTTP codes to suppress in discovery
    random_agent: bool = False              # Rotate User-Agent per request
    cookie_jar: Optional[str] = None        # Path to Netscape cookie jar file
    dbms: Optional[str] = None              # Target DBMS hint for SQLi (mysql/postgres/mssql/oracle/sqlite)
    level: int = 1                          # Scan aggressiveness 1-5
    risk: int = 1                           # Risk of side-effects 1-3
