import httpx
from urllib.parse import urljoin, urlparse
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

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
    ".env": ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "DATABASE_URL"],
    ".git/config": ["[core]", "[remote"],
    "wp-config.php": ["DB_PASSWORD", "table_prefix"],
    "phpinfo.php": ["PHP Version", "phpinfo()"],
    "backup.sql": ["INSERT INTO", "CREATE TABLE"],
    "db.sqlite": ["SQLite format"],
    "adminer.php": ["Adminer", "adminer"],
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

        # For some paths, verify content to reduce false positives
        filename = path.split("/")[-1]
        signatures = CONTENT_SIGNATURES.get(filename, [])
        if signatures and not any(sig in resp.text for sig in signatures):
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
