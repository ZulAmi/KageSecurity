# KageSec

**Open-source AI-first DAST scanner.** KageSec crawls your web application, runs 61 vulnerability modules and 50 CVE templates, and uses Claude AI to verify exploitability and generate actionable reports — competitive with Nuclei and ZAP out of the box.

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![Version](https://img.shields.io/badge/version-0.2.0--beta-orange)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

---

## Features at a Glance

- **61 vulnerability modules** — XSS, SQLi, SSRF, SSTI, XXE, deserialization, request smuggling, prototype pollution, and more
- **50 Nuclei-compatible CVE templates** — Log4Shell, ProxyShell, Spring4Shell, MOVEit, Citrix Bleed, and others
- **AI-powered verification** — Claude API confirms exploitability, researches CVEs, and writes the report
- **Headless browser crawling** — Playwright for SPAs and JavaScript-heavy apps
- **Full authentication support** — Bearer, cookie, OAuth2, multi-step login, TOTP 2FA
- **API & protocol scanning** — OpenAPI, GraphQL, gRPC, SOAP/WSDL, HAR import
- **7 report formats** — JSON, Markdown, PDF, SARIF 2.1.0, Burp XML, ZAP JSON; export to Jira or GitHub Issues
- **Compliance mapping** — Auto-maps findings to ISO 27001, HIPAA, GDPR, APPI
- **CI/CD ready** — GitHub Actions native action, `--fail-on high`, SARIF upload
- **Delta scanning** — Skips unchanged pages on repeat scans for faster CI runs
- **Plugin system** — Drop Python files into `~/.kagesec/plugins/` to add custom modules

---

## Installation

```bash
pip install kagesec
```

Optional extras:

```bash
pip install "kagesec[browser]"   # Playwright headless browser + WebSocket + TOTP
pip install "kagesec[pdf]"       # PDF report generation
pip install "kagesec[dns]"       # DNSSEC + subdomain enumeration
pip install "kagesec[browser,pdf,dns]"  # Everything
```

After installing the browser extra, initialize Playwright:

```bash
playwright install chromium
```

---

## Quick Start

```bash
# Basic scan — results in kagesec_report.json
kagesec scan https://target.example.com

# Full scan with AI verification and Markdown report
ANTHROPIC_API_KEY=sk-ant-... kagesec scan https://target.example.com --output markdown

# Browser mode for SPAs — crawl with Playwright
kagesec scan https://target.example.com --browser

# Aggressive scan (level 5, risk 3) with live output
kagesec scan https://target.example.com --level 5 --risk 3 --live

# Only run specific modules
kagesec scan https://target.example.com --modules xss sqli ssrf

# Scan multiple targets concurrently
kagesec scan --targets urls.txt --parallel 5 --output sarif

# Passive mode — no injection, headers and content only
kagesec scan https://target.example.com --passive

# Rate-limited scan through Burp proxy
kagesec scan https://target.example.com --proxy http://127.0.0.1:8080 --rate-limit 5
```

---

## Authentication

```bash
# Bearer token
kagesec scan https://api.example.com --auth-bearer eyJhbGc...

# Session cookie
kagesec scan https://app.example.com --auth-cookie "session=abc123"

# OAuth2 client credentials
kagesec scan https://api.example.com \
  --auth-oauth2-token-url https://auth.example.com/token \
  --auth-oauth2-client-id my-client \
  --auth-oauth2-client-secret my-secret

# Multi-step browser login (Playwright)
kagesec scan https://app.example.com \
  --browser \
  --login-url https://app.example.com/login \
  --login-user-selector "#email" \
  --login-pass-selector "#password" \
  --login-submit-selector "button[type=submit]" \
  --login-username admin@example.com \
  --login-password secret \
  --login-success "/dashboard"

# Login with TOTP 2FA
kagesec scan https://app.example.com \
  --browser \
  --login-url https://app.example.com/login \
  --login-username admin@example.com \
  --login-password secret \
  --login-totp-secret JBSWY3DPEHPK3PXP
```

---

## API & Protocol Scanning

```bash
# OpenAPI / Swagger spec (URL or local file)
kagesec scan https://api.example.com --openapi https://api.example.com/openapi.json
kagesec scan https://api.example.com --openapi ./openapi.yaml

# GraphQL endpoint
kagesec scan https://api.example.com --graphql https://api.example.com/graphql

# gRPC (Server Reflection)
kagesec scan grpc://api.example.com:50051 --grpc api.example.com:50051

# SOAP / WSDL
kagesec scan https://api.example.com --wsdl https://api.example.com/service?wsdl

# Import an HTTP Archive (HAR) instead of crawling
kagesec scan https://app.example.com --har ./session.har
```

---

## Modules

### Injection

| Module | Covers |
|--------|--------|
| `xss` | Reflected, stored, DOM-based, blind XSS, second-order, header injection |
| `sqli` | Error-based, time-blind, UNION, boolean, stacked queries, NoSQL, LDAP, OOB |
| `ssrf` | URL params, form inputs, headers, cloud metadata (AWS/Azure/GCP), OOB callbacks |
| `cmd_injection` | OS command injection via metachar + OOB confirmation |
| `ssti` | Server-side template injection — Jinja2, Freemarker, ERB |
| `csti` | Client-side template injection — Angular, Vue.js, React |
| `ssi` | Server-side include injection (Apache, nginx) |
| `xxe` | XML external entity + OOB exfiltration |
| `xpath` | XPath injection (error-based + boolean blind) |
| `crlf` | CRLF injection / HTTP response splitting |
| `log4j_deep` | Log4Shell (CVE-2021-44228) + variants, LDAP/RMI payloads |
| `shellshock` | Shellshock / bash injection (CVE-2014-6271) |
| `blind_xss` | Blind XSS with OOB callback confirmation |

### Authentication & Session

| Module | Covers |
|--------|--------|
| `jwt_attacks` | Weak secret cracking, algorithm confusion, `none` alg bypass |
| `oauth` | Token exposure, redirect bypass, implicit flow CSRF |
| `auth_bypass` | Default credentials, bypass filters, API key extraction |
| `session_fixation` | Session fixation + hijacking |
| `session_entropy` | Weak session token predictability |
| `csrf` | Missing token detection, weak token patterns |
| `username_enumeration` | Timing attacks + error message differences |

### Access Control

| Module | Covers |
|--------|--------|
| `idor` | Incremental ID enumeration + access control testing |
| `path_traversal` | `../` traversal, URL encoding, double encoding |
| `http_methods` | Unsafe HTTP methods (PUT, DELETE, TRACE, CONNECT) |

### Web Application

| Module | Covers |
|--------|--------|
| `open_redirect` | Protocol-relative + fragment bypass |
| `file_upload` | Extension blacklist bypass, MIME-type spoofing |
| `deserialization` | Java (ysoserial), Python (pickle), PHP unsafe deserialization |
| `cache_poisoning` | Header injection, param smuggling, Cache-Control abuse |
| `host_header` | SSRF via Host, password reset redirect abuse |
| `request_smuggling` | HTTP request smuggling — CL.TE, TE.CL, TE.TE desync |
| `prototype_pollution` | JavaScript prototype pollution |
| `padding_oracle` | CBC decryption via padding oracle |
| `http_param_pollution` | Backend parser confusion (IIS, Apache, Tomcat) |
| `business_logic` | Price manipulation, discount bypass, logical flaws |
| `race_condition` | Concurrent request race detection |
| `multistep_injection` | Multi-step wizard injection, sequential payload chains |
| `form_fuzz` | Form field fuzzing + input validation |

### API & Protocol

| Module | Covers |
|--------|--------|
| `graphql` | Introspection bypass, query injection, DoS |
| `websocket` | XSS in WS messages, auth bypass, injection |

### Headers & Configuration

| Module | Covers |
|--------|--------|
| `security_headers` | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| `cors` | Origin reflection, null origin, wildcard with credentials |
| `cookie_security` | Missing HttpOnly, Secure, SameSite flags |
| `clickjacking` | Missing X-Frame-Options / CSP frame-ancestors |
| `subresource_integrity` | Missing or weak SRI on external scripts |
| `crossdomain` | Flash/Silverlight crossdomain.xml misconfiguration |
| `tls` | Weak ciphers, self-signed, expired certs, OCSP stapling |

### Reconnaissance & Discovery

| Module | Covers |
|--------|--------|
| `path_discovery` | Wordlist-based directory and file fuzzing |
| `param_discovery` | Common GET/POST parameter detection |
| `exposed_files` | Backup and archive file discovery (`.bak`, `.zip`, `.sql`) |
| `robots_probe` | robots.txt path enumeration |
| `vhost_enum` | DNS-based virtual host enumeration |
| `subdomain_takeover` | CNAME/NS resolution check for unclaimed domains |
| `version_disclosure` | Server header, X-Powered-By, framework banners |
| `api_key_leak` | API key exposure in response headers and bodies |
| `breach` | HaveIBeenPwned credential exposure check |
| `waf_detect` | WAF/IPS fingerprinting (ModSecurity, F5, Cloudflare, etc.) |
| `waf_bypass` | Encoding/obfuscation — URL, Unicode, case mutation, comment injection |
| `coverage_check` | Crawl coverage metrics (pages, params, methods) |
| `debug_mode` | Debug mode enabled, stack trace disclosure, verbose error pages, server version leakage |
| `cve_check` | CVE fingerprinting from response signatures |
| `ai_cve` | Claude API: dynamic CVE research + targeted template generation |
| `dnssec` | DNSSEC validation failures |
| `rate_limit` | Insufficient rate limiting / missing brute-force protection |
| `captcha_check` | Weak CAPTCHA (client-side validation, predictable seeds) |
| `templates` | Nuclei-compatible YAML template runner |

---

## CVE Templates

50 Nuclei-compatible YAML templates covering high-impact CVEs:

**Notable coverage:**
- Log4Shell — CVE-2021-44228, CVE-2021-45046
- ProxyShell — CVE-2021-34473
- Spring4Shell — CVE-2022-22965
- Follina — CVE-2022-30190
- Text4Shell — CVE-2022-42889
- MOVEit RCE — CVE-2023-34362
- Citrix Bleed — CVE-2023-4966
- ConnectWise ScreenConnect — CVE-2024-1709
- Confluence RCE — CVE-2023-22515
- Exchange (ProxyNotShell) — CVE-2022-41082
- F5 BIG-IP — CVE-2022-1388
- Grafana path traversal — CVE-2021-43798
- Apache Log4j / Struts / mod_proxy, VMware vCenter, GitLab, Cisco, Fortinet, Minio, TeamCity, JetBrains, Jenkins, and more

**Additional template categories:**
- **Exposed panels** (7): Grafana, Jenkins, Kibana, Laravel Telescope, phpMyAdmin, Prometheus, Spring Boot Actuator
- **Misconfigurations** (7): `.env` exposure, `.git` exposure, GraphQL introspection open, Swagger/OpenAPI public, `phpinfo.php`, Apache server-status, backup files
- **AI-generated**: Claude generates targeted templates per detected stack and caches them for 30 days

Download community templates:

```bash
kagesec update-templates
```

---

## Reports & Output

```bash
# Default: JSON
kagesec scan https://target.example.com

# Markdown (human-readable, AI-written narrative)
kagesec scan https://target.example.com --output markdown

# PDF
kagesec scan https://target.example.com --output pdf

# SARIF 2.1.0 (GitHub Code Scanning)
kagesec scan https://target.example.com --output sarif

# Burp Suite XML
kagesec scan https://target.example.com --output burp

# OWASP ZAP JSON
kagesec scan https://target.example.com --output zap

# All formats at once
kagesec scan https://target.example.com --output all

# Export findings to Jira
kagesec issues --format jira \
  --jira-url https://company.atlassian.net \
  --jira-project SEC \
  --jira-token $JIRA_TOKEN \
  --min-severity high

# Export findings to GitHub Issues
kagesec issues --format github \
  --github-repo owner/repo \
  --github-token $GITHUB_TOKEN
```

---

## Compliance

```bash
# Generate compliance reports alongside scan results
kagesec scan https://target.example.com --compliance iso27001 gdpr hipaa appi
```

Findings are automatically mapped to controls in ISO 27001, HIPAA, GDPR, and APPI. Compliance scores and gap analysis are included in the report.

---

## CI/CD

### GitHub Actions — Native Action

```yaml
- name: KageSec Security Scan
  uses: zulhilmirahmat/kagesec@main
  with:
    target: https://staging.example.com
    api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    fail-on: high
    output: sarif

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: kagesec_report.sarif
```

### Exit Codes

```bash
# Fail the pipeline if any high or critical findings are found
kagesec scan https://target.example.com --fail-on high
```

Exit code `1` if findings at or above the specified severity are found; `0` otherwise.

### Delta Scanning (faster CI)

KageSec tracks crawl state across runs. Unchanged pages are skipped automatically. Use `--full` to force a complete re-scan.

---

## Advanced Usage

### Scan Profiles

```bash
kagesec scan https://target.example.com --profile quick      # Fast, low noise
kagesec scan https://target.example.com --profile full       # All modules, max depth
kagesec scan https://target.example.com --profile api        # API-focused
kagesec scan https://target.example.com --profile passive    # No injection
kagesec scan https://target.example.com --profile stealth    # Low rate, random UA
```

### Workflows

```bash
kagesec workflows                                          # List available workflows
kagesec scan https://target.example.com --workflow quick-web
kagesec scan https://wp.example.com --workflow wordpress
```

### Resume Interrupted Scans

```bash
kagesec scan https://target.example.com --resume <scan-id>
```

### Custom Plugins

Drop a Python file into `~/.kagesec/plugins/`:

```python
# ~/.kagesec/plugins/my_check.py
from scanner.core.scan_result import Finding, Severity

def test(page, client, **kwargs):
    if "X-Custom-Header" not in page.headers:
        return [Finding(
            title="Missing X-Custom-Header",
            severity=Severity.LOW,
            url=page.url,
        )]
    return []
```

### Out-of-Band (Blind) Detection

OOB callbacks via `oast.pro` are enabled by default for blind SQLi, blind XSS, SSRF, XXE, and command injection. Disable for air-gapped targets:

```bash
kagesec scan https://target.example.com --no-oob

# Use a self-hosted callback domain
kagesec scan https://target.example.com --oob-server callbacks.internal.example.com
```

### Notifications

```bash
kagesec scan https://target.example.com \
  --notify-slack https://hooks.slack.com/... \
  --notify-min-severity high
```

Supports Slack, Microsoft Teams, Discord, and generic JSON webhooks.

---

## CLI Reference

### Subcommands

| Command | Description |
|---------|-------------|
| `scan <target>` | Scan a target URL for vulnerabilities |
| `diff <baseline> <current>` | Compare two scan reports, fail on new findings |
| `serve` | Start HTTP API server (default: `0.0.0.0:8080`) |
| `export --scan-id ID` | Bundle a scan checkpoint + report into a zip |
| `import-scan <file>` | Import a previously exported scan |
| `history [<target>]` | Show finding trends from SQLite history |
| `suppress` | Manage false-positive suppression rules |
| `retest <finding-id>` | Re-run a specific finding |
| `issues` | Export findings to Jira or GitHub Issues |
| `workflows` | List available scan workflows |
| `config` | Manage persistent settings (`~/.kagesec/config.yaml`) |
| `update-templates` | Download Nuclei community templates |

### Key `scan` Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--depth N` | 3 | Crawl depth |
| `--max-pages N` | 100 | Max pages to crawl |
| `--level 1-5` | 1 | Scan aggressiveness |
| `--risk 1-3` | 1 | Risk tolerance |
| `--browser` | off | Playwright headless crawling |
| `--passive` | off | No injection — headers and content only |
| `--parallel N` | 1 | Concurrent multi-target scanning |
| `--live` | off | Print findings immediately as discovered |
| `--no-ai` | off | Skip Claude AI verification (faster) |
| `--fail-on LEVEL` | — | Exit 1 if findings at this severity or above |
| `--output FORMAT` | json | Report format |
| `--modules M1 M2` | all | Run only specific modules |
| `--profile NAME` | — | Apply a scan preset |
| `--workflow NAME` | — | Run a predefined workflow |
| `--resume ID` | — | Resume an interrupted scan |
| `--max-time MIN` | 0 | Hard time limit in minutes (0 = unlimited) |

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | For AI features | Claude API key for exploit verification, CVE research, and report generation |
| `NVD_API_KEY` | Optional | NVD API key for faster CVE enrichment (rate-limited without it) |

AI features degrade gracefully if `ANTHROPIC_API_KEY` is not set — the scan still runs with all modules and templates; only AI verification and AI report writing are skipped (equivalent to `--no-ai`).

---

## Stack

- **Language:** Python 3.12+
- **HTTP client:** httpx
- **Browser:** Playwright (Chromium)
- **AI layer:** Claude API (Anthropic) — `claude-sonnet-4-6` / `claude-opus-4-7`
- **Templates:** Nuclei-compatible YAML
- **Reports:** Jinja2 (PDF/HTML), WeasyPrint (PDF), SARIF 2.1.0

---

## Project Structure

```
kagesec/
├── cli/                    # CLI entrypoint (main.py, 12 subcommands)
├── scanner/
│   ├── core/               # Engine, crawlers, config, delta state, OOB, rate limiter
│   ├── modules/            # 61 vulnerability detection modules
│   ├── templates/          # Nuclei-compatible YAML (CVEs, misconfigs, panels)
│   ├── ai/                 # Claude API: verifier, reporter, CVE researcher, template selector
│   ├── reporters/          # PDF, SARIF, Burp XML, ZAP JSON, Jira, GitHub
│   ├── compliance/         # ISO 27001, HIPAA, GDPR, APPI mapping
│   ├── api/                # FastAPI HTTP server
│   └── utils/              # HTTP helpers, payload loading
├── tests/
│   ├── unit/
│   └── integration/        # DVWA, WebGoat, OWASP Juice Shop
├── helm/                   # Kubernetes Helm chart
├── Dockerfile
└── action.yml              # GitHub Actions composite action
```

---

## Contributing

Security researchers and developers welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
