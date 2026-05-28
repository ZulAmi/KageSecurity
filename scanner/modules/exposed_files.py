import httpx
from urllib.parse import urljoin, urlparse
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import is_spa_catchall

# Content-Types that are never a real .env / config / archive file
_HTML_CT = ("text/html",)
# Binary file extensions that must NOT be text/html to be real
_BINARY_EXTS = {".zip", ".tar.gz", ".gz", ".sql", ".sqlite", ".db", ".bak", ".7z"}

SENSITIVE_PATHS = [
    # Secrets & credentials
    (".env", Severity.CRITICAL, "Environment file with credentials/API keys"),
    (".env.local", Severity.CRITICAL, "Local environment file with credentials"),
    (".env.production", Severity.CRITICAL, "Production environment file"),
    (".env.backup", Severity.CRITICAL, "Backup environment file"),
    ("/.aws/credentials", Severity.CRITICAL, "AWS credentials file"),
    ("/.aws/config", Severity.HIGH, "AWS configuration file"),
    # Git
    (".git/config", Severity.HIGH, "Git repository configuration (may expose remote URLs/credentials)"),
    (".git/HEAD", Severity.MEDIUM, "Git HEAD file confirms repository exposure"),
    (".git/COMMIT_EDITMSG", Severity.MEDIUM, "Git commit messages may contain sensitive info"),
    (".gitignore", Severity.LOW, "Git ignore file reveals project structure"),
    # Config files
    ("config.php", Severity.CRITICAL, "PHP configuration file"),
    ("wp-config.php", Severity.CRITICAL, "WordPress configuration with database credentials"),
    ("configuration.php", Severity.CRITICAL, "Joomla configuration file"),
    ("settings.py", Severity.HIGH, "Django settings file"),
    ("application.properties", Severity.HIGH, "Spring Boot application properties"),
    ("application.yml", Severity.HIGH, "Spring Boot YAML config"),
    ("database.yml", Severity.HIGH, "Rails database configuration"),
    ("config.yml", Severity.MEDIUM, "Application configuration file"),
    ("web.config", Severity.MEDIUM, "IIS web configuration"),
    # Database files
    ("backup.sql", Severity.CRITICAL, "SQL database backup"),
    ("dump.sql", Severity.CRITICAL, "SQL database dump"),
    ("db.sqlite", Severity.CRITICAL, "SQLite database file"),
    ("database.db", Severity.CRITICAL, "Database file"),
    # Debug & admin
    ("phpinfo.php", Severity.HIGH, "PHP info page exposes server configuration"),
    ("info.php", Severity.HIGH, "PHP info page"),
    ("test.php", Severity.MEDIUM, "Test PHP file in production"),
    ("adminer.php", Severity.CRITICAL, "Adminer database management tool"),
    ("phpmyadmin/", Severity.HIGH, "phpMyAdmin database management interface"),
    ("admin/", Severity.MEDIUM, "Admin panel directory"),
    (".htpasswd", Severity.HIGH, "Apache htpasswd file with hashed credentials"),
    (".htaccess", Severity.LOW, "Apache access control file"),
    # Logs
    ("logs/error.log", Severity.HIGH, "Application error log"),
    ("log/error.log", Severity.HIGH, "Application error log"),
    ("access.log", Severity.MEDIUM, "Web server access log"),
    ("debug.log", Severity.HIGH, "Debug log file"),
    ("laravel.log", Severity.HIGH, "Laravel application log"),
    # Backups
    ("backup.zip", Severity.CRITICAL, "Application backup archive"),
    ("backup.tar.gz", Severity.CRITICAL, "Application backup archive"),
    ("site.zip", Severity.CRITICAL, "Site backup archive"),
    ("www.zip", Severity.CRITICAL, "Web root backup archive"),
    # Package/dependency files
    ("composer.json", Severity.LOW, "PHP dependency file (reveals stack)"),
    ("package.json", Severity.LOW, "Node.js dependency file (reveals stack)"),
    ("Gemfile", Severity.LOW, "Ruby dependency file (reveals stack)"),
    ("requirements.txt", Severity.LOW, "Python dependency file (reveals stack)"),
    # Other
    ("robots.txt", Severity.INFO, "Robots.txt may reveal hidden paths"),
    ("crossdomain.xml", Severity.MEDIUM, "Flash cross-domain policy"),
    ("clientaccesspolicy.xml", Severity.MEDIUM, "Silverlight cross-domain policy"),
    ("swagger.json", Severity.MEDIUM, "API documentation may expose all endpoints"),
    ("openapi.json", Severity.MEDIUM, "OpenAPI specification exposes API structure"),
    ("v1/swagger.json", Severity.MEDIUM, "Versioned API documentation"),
    ("api/swagger.json", Severity.MEDIUM, "API documentation"),
]

CONTENT_SIGNATURES = {
    # Environment files — must contain at least one KEY=value pattern
    ".env":             ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "DATABASE_URL", "APP_KEY", "JWT_SECRET", "REDIS_URL"],
    ".env.local":       ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "DATABASE_URL", "APP_KEY", "JWT_SECRET"],
    ".env.production":  ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "DATABASE_URL", "APP_KEY"],
    ".env.backup":      ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "DATABASE_URL"],
    # Git
    ".git/config":      ["[core]", "[remote"],
    ".git/HEAD":        ["ref:", "commit"],
    ".git/COMMIT_EDITMSG": [],  # any content is meaningful; checked via Content-Type
    # Config files
    "wp-config.php":            ["DB_PASSWORD", "table_prefix", "define("],
    "configuration.php":        ["public $password", "public $db"],
    "settings.py":              ["SECRET_KEY", "DATABASES", "INSTALLED_APPS"],
    "application.properties":   ["spring.datasource", "server.port", "spring.security"],
    "application.yml":          ["datasource:", "password:", "spring:"],
    "database.yml":             ["adapter:", "password:", "database:"],
    "web.config":               ["connectionStrings", "appSettings", "<configuration"],
    # PHP info pages
    "phpinfo.php":      ["PHP Version", "phpinfo()"],
    "info.php":         ["PHP Version", "phpinfo()"],
    # Database
    "backup.sql":       ["INSERT INTO", "CREATE TABLE", "LOCK TABLES"],
    "dump.sql":         ["INSERT INTO", "CREATE TABLE", "LOCK TABLES"],
    "db.sqlite":        ["SQLite format"],
    "database.db":      ["SQLite format"],
    # Admin tools
    "adminer.php":      ["Adminer", "adminer"],
    # Logs — must contain log-like patterns, not just HTML
    "logs/error.log":   ["[error]", "Exception", "Traceback", "Error:"],
    "log/error.log":    ["[error]", "Exception", "Traceback", "Error:"],
    "access.log":       ["GET /", "POST /", "HTTP/1"],
    "debug.log":        ["[debug]", "[error]", "Exception", "Traceback"],
    "laravel.log":      ["local.ERROR", "local.WARNING", "production.ERROR"],
    # API specs — must look like JSON/YAML specs, not HTML
    "swagger.json":     ['"swagger":', '"openapi":', '"paths":'],
    "openapi.json":     ['"openapi":', '"paths":', '"info":'],
    "v1/swagger.json":  ['"swagger":', '"openapi":', '"paths":'],
    "api/swagger.json": ['"swagger":', '"openapi":', '"paths":'],
}


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    # Only probe from the root of the target (once, not per-page)
    parsed = urlparse(page.url)
    if parsed.path not in ("", "/"):
        return []

    base = f"{parsed.scheme}://{parsed.netloc}"
    findings = []

    for path, severity, description in SENSITIVE_PATHS:
        url = urljoin(base + "/", path)
        try:
            resp = client.get(url, follow_redirects=False)
        except Exception:
            continue

        if resp.status_code not in (200, 206):
            continue

        # Reject SPA catch-all responses (React/Next.js returning index.html for all routes)
        if is_spa_catchall(resp):
            continue

        ct = resp.headers.get("content-type", "").lower()

        # Binary file extensions must not be served as text/html
        ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
        if any(path.endswith(be) for be in _BINARY_EXTS) and "text/html" in ct:
            continue

        # Verify content signatures — every path must either have known signatures
        # that appear in the body, or have a non-HTML Content-Type.
        filename = path.split("/")[-1]
        signatures = CONTENT_SIGNATURES.get(filename, [])
        if signatures:
            if not any(sig in resp.text for sig in signatures):
                continue
        else:
            # No signatures defined — only report if Content-Type is not text/html
            # (prevents SPA index.html being flagged for paths like /admin/, /backup/, etc.)
            if "text/html" in ct:
                continue

        findings.append(Finding(
            title=f"Sensitive File Exposed: {path}",
            severity=severity,
            url=url,
            parameter=None,
            payload=None,
            evidence=f"HTTP {resp.status_code} — {description}",
            description=f"The file `{path}` is publicly accessible. {description}.",
            remediation=(
                f"Block access to `{path}` via web server configuration. "
                "Move sensitive files outside the web root. "
                "Add to .gitignore and revoke any exposed credentials immediately."
            ),
            cwe="CWE-200",
            cvss=9.1 if severity == Severity.CRITICAL else 6.5,
            owasp_category="A05:2021 Security Misconfiguration",
            standards=["ISO27001-8.23", "ISO27001-8.25", "HIPAA-164.312a", "GDPR-Art32"],
            confidence=0.95 if signatures else 0.8,
        ))

    return findings
