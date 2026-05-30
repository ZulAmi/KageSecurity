# KageSec

**A security scanner that actually finds things.** KageSec crawls your web app, throws 61 vulnerability modules at it, runs 7,400+ CVE templates via a purpose-built Go engine, and — if you give it a Claude API key — uses AI to verify whether the findings are real or just vibes.

Think of it as Nuclei and ZAP had a baby, the baby learned Python and Go, and then the baby got really into AI.

## vs Nuclei CLI — Real Benchmark

Tested against [ginandjuice.shop](https://ginandjuice.shop) (PortSwigger's intentionally vulnerable app), same template directory (`~/.kagesec/nuclei-templates`), same concurrency (50):

| | KageSec (no AI, no browser) | Nuclei CLI |
|---|---|---|
| **Total scan time** | **34m 47s** | **5m 22s** |
| Pages / URLs scanned | 31 pages crawled | 1 URL |
| Templates run | 7,417 HTTP templates | 9,028 templates |
| Template findings | 24 | 25 |
| **Total findings** | **63** | **25** |
| OS Command Injection | ✅ CRITICAL | ❌ |
| Server-Side Template Injection | ✅ CRITICAL | ❌ |
| Client-Side Template Injection | ✅ CRITICAL | ❌ |
| DOM-Based XSS | ✅ HIGH | ❌ |
| Reflected XSS | ✅ HIGH | ❌ |
| Insecure Direct Object Reference | ✅ HIGH | ❌ |
| Blind XSS | ✅ HIGH | ❌ |
| SSI Injection | ✅ HIGH | ❌ |
| CSRF | ✅ MEDIUM | ❌ |
| Business Logic flaws | ✅ MEDIUM | ❌ |
| Hidden paths (/admin 403) | ✅ | ❌ |
| Subdomain discovery | ✅ | ❌ |
| Nuclei's 25 findings | ✅ (24 matched) | ✅ |

**KageSec takes longer because it does more.** The 34 minutes is almost entirely page crawling and per-page exploitation across 31 pages — the template engine itself completes in ~2 minutes concurrently. Nuclei fires templates at one URL and stops; it cannot find SSTI, DOM XSS, IDOR, or business logic flaws because it never crawls the application.

The template match rate is comparable (24 vs 25). The 38 additional findings are vulnerabilities that only exist if you actually test the application.

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![Go 1.22+](https://img.shields.io/badge/go-1.22%2B-00ADD8)
![Version](https://img.shields.io/badge/version-0.2.2--beta-orange)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
[![CI](https://github.com/ZulAmi/KageSecurity/actions/workflows/ci.yml/badge.svg)](https://github.com/ZulAmi/KageSecurity/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/kagesec)](https://pypi.org/project/kagesec/)

---

## Why this exists

I paid a security firm thousands of dollars to do a penetration test for my startup. Fair enough — you need a PTAA report, compliance asks for it, I get it.

Then, at the end of the engagement, the same firm casually mentioned they also offer an _automated DAST scanning service_. Ongoing. Recurring. Thousands of dollars a year. For a tool that runs automatically.

I sat with that for a moment.

I know Nuclei exists. It's great. It's the industry open-source standard and ProjectDiscovery has built something genuinely impressive. But the companies built on top of it will happily charge you enterprise pricing for what is, at its core, a YAML template runner with a nice UI.

So I built KageSec instead — open-source, AI-powered, and free. It runs the same categories of checks, uses Nuclei-compatible templates, and adds Claude AI on top to verify whether findings are actually exploitable (so you're not manually triaging 200 false positives at 11pm).

Then I took it further. KageSec ships a purpose-built Go template engine (`kagesec-engine`) that runs 7,400+ HTTP templates concurrently with 50 goroutines, streams findings in real-time, and scores each result with a confidence value (0.0–1.0) instead of Nuclei's binary match/no-match. It fingerprints your target stack and runs the most relevant templates first — so even a partial scan surfaces the highest-value findings. In testing: 7,417 templates against a live target in 73 seconds.

Zero subscription fees. Zero per-seat pricing. Zero "contact us for enterprise". Just clone it and run it.

---

## Go Template Engine

KageSec ships `kagesec-engine` — a purpose-built Go binary that handles the template execution phase. It is not a wrapper around Nuclei. It is a replacement.

### Why not just use Nuclei?

| Feature | Nuclei | kagesec-engine |
|---|---|---|
| Template selection | Tag filters only | Fingerprints the target stack, runs most relevant templates first |
| False positive scoring | Binary match / no-match | Confidence score 0.0–1.0 per finding |
| OOB templates | Creates findings on injection | Skipped — no unconfirmed false positives without a real callback listener |
| Output | JSON files or stdout | JSON Lines streamed in real-time — Python reads findings as they arrive |
| Auth context | Limited | Inherits all KageSec headers, cookies, and bearer tokens |
| Template coverage | 9,028 (incl. flow/js/code) | 7,417 HTTP templates — flow/javascript/code templates not yet supported |
| AI filtering | None | With API key, Claude narrows 7,400+ templates to 80-200 relevant ones |

In benchmark testing against a live target: **7,417 HTTP templates in ~2 minutes** with 50 goroutines, running concurrently alongside the page scan. Nuclei ran 9,028 templates in 5m 22s as a standalone scan — both matched ~25 findings from the same template set. KageSec's total scan time is higher because it crawls and exploits the full application; the template engine itself is the same speed class as Nuclei.

### Building the engine

**pip install users:** The binary is already bundled — nothing to build.

If you cloned the repo or want to rebuild:

```bash
# Requires Go 1.22+
cd engine
go build -o kagesec-engine .
```

The Python scanner looks for the binary in this order:
1. `scanner/_bin/kagesec-engine` — bundled (pip install)
2. `engine/kagesec-engine` — dev / cloned repo
3. Anywhere in `PATH`

If none are found, it falls back to the Python template runner automatically.

### Cross-compiling for CI / Docker

```bash
# Linux (for Docker/CI)
GOOS=linux GOARCH=amd64 go build -o kagesec-engine-linux-amd64 .

# Windows
GOOS=windows GOARCH=amd64 go build -o kagesec-engine-windows-amd64.exe .
```

---

## Claude Code Users

If you use Claude Code to build and deploy your apps, KageSec plugs in directly. Two ways to use it:

**Option 1 — Ask Claude to scan during a conversation:**

Once you add KageSec as an MCP server (see [Claude Code Integration](#claude-code-integration) below), you can just tell Claude:

> _"Scan this for security issues"_ or _"Deploy it and then run a security scan"_

Claude will call `kagesec_scan()` as a tool and report findings back in the conversation.

**Option 2 — Automatic scan on every deployment:**

The `.claude/` folder in this repo includes a hook that fires after any deployment Bash command (Vercel, Netlify, Heroku, Railway, Fly.io, AWS, etc.). Claude detects the live URL from the deployment output and starts a background scan automatically. No extra steps.

Check `reports/` when it's done.

---

## What it does

- **61 vulnerability modules** — XSS, SQLi, SSRF, SSTI, XXE, deserialization, request smuggling, prototype pollution, JWT attacks, and more. If it's in the OWASP Top 10, we've got a module for it.
- **Go template engine** — `kagesec-engine` runs 7,417 HTTP-compatible Nuclei templates with 50 goroutines, real-time streaming, confidence scoring, and stack-aware template ordering. Benchmarked at ~2 minutes for 7,417 templates — comparable match rate to Nuclei CLI (24 vs 25 on the same target), zero false positives from unconfirmed OOB callbacks.
- **50 built-in CVE templates** — Log4Shell, ProxyShell, Spring4Shell, MOVEit, Citrix Bleed, and the rest of the greatest hits. 10,000+ community templates available via `kagesec update-templates`.
- **AI verification** — Claude API checks whether findings are actually exploitable, so your report doesn't look like it was written by a panicking intern
- **Headless browser crawling** — Playwright handles SPAs and JS-heavy apps. Enabled by default because it's 2025 and everything is a React app
- **Full auth support** — Bearer tokens, cookies, OAuth2, multi-step logins, TOTP 2FA. If your app has a login page, we can get in
- **API scanning** — OpenAPI, GraphQL, gRPC, SOAP/WSDL, HAR import. REST or not, we're scanning it
- **5 report formats** — JSON, PDF, SARIF, Burp XML, ZAP JSON — all saved to the `reports/` folder so your project root stays clean
- **Compliance mapping** — ISO 27001, HIPAA, GDPR, APPI. For when your boss asks "are we compliant?" and you need a real answer
- **CI/CD native** — GitHub Actions, `--fail-on high`, SARIF upload. Break the build before the attacker breaks your users
- **Claude Code integration** — Runs automatically when you deploy via Claude Code. Your AI coding assistant now has a paranoid security sidekick

---

## Installation

```bash
pip install kagesec
```

The `kagesec-engine` Go binary is bundled in the wheel — no manual build step required. After install, `kagesec scan` automatically uses it.

Want the full experience?

```bash
pip install "kagesec[browser]"              # Playwright (you probably want this)
pip install "kagesec[pdf]"                  # PDF reports
pip install "kagesec[dns]"                  # DNSSEC + subdomain enumeration
pip install "kagesec[browser,pdf,dns]"      # The whole thing
```

After installing `browser` or `pdf`, grab Chromium:

```bash
playwright install chromium
```

---

## Quick Start

```bash
# Basic scan — finds stuff, saves reports to reports/
kagesec scan https://target.example.com

# With AI verification (actually useful, highly recommended)
ANTHROPIC_API_KEY=sk-ant-... kagesec scan https://target.example.com --output all

# Scan a React/Vue/Next.js SPA properly (browser is on by default)
kagesec scan https://target.example.com

# Disable browser for a faster, lighter scan
kagesec scan https://target.example.com --no-browser

# Only care about specific vulnerabilities?
kagesec scan https://target.example.com --modules xss sqli ssrf

# Scan multiple targets at once
kagesec scan --targets urls.txt --parallel 5 --output sarif

# Passive mode — look but don't touch
kagesec scan https://target.example.com --passive

# Slow and sneaky (useful if the target has a WAF)
kagesec scan https://target.example.com --profile stealth --rate-limit 2

# Through Burp for manual review alongside
kagesec scan https://target.example.com --proxy http://127.0.0.1:8080
```

---

## Authentication

KageSec can log into your app before scanning. Yes, even the annoying ones with 2FA.

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

# Multi-step browser login (clicks the form like a human)
kagesec scan https://app.example.com \
  --login-url https://app.example.com/login \
  --login-user-selector "#email" \
  --login-pass-selector "#password" \
  --login-submit-selector "button[type=submit]" \
  --login-username admin@example.com \
  --login-password secret \
  --login-success "/dashboard"

# 2FA with TOTP — yes really
kagesec scan https://app.example.com \
  --login-url https://app.example.com/login \
  --login-username admin@example.com \
  --login-password secret \
  --login-totp-secret JBSWY3DPEHPK3PXP
```

---

## API & Protocol Scanning

```bash
# OpenAPI / Swagger (URL or local file)
kagesec scan https://api.example.com --openapi https://api.example.com/openapi.json

# GraphQL
kagesec scan https://api.example.com --graphql https://api.example.com/graphql

# gRPC
kagesec scan grpc://api.example.com:50051 --grpc api.example.com:50051

# SOAP / WSDL (yes, some companies still use SOAP)
kagesec scan https://api.example.com --wsdl https://api.example.com/service?wsdl

# Import a HAR file (great for scanning authenticated flows you recorded in Chrome DevTools)
kagesec scan https://app.example.com --har ./session.har
```

---

## Claude Code Integration

KageSec can act as a tool inside Claude Code. When Claude deploys your app, KageSec can automatically scan it.

### Option 1 — MCP Server (Claude calls it as a tool)

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "kagesec": {
      "command": "python3",
      "args": ["-m", "scanner.mcp_server"],
      "cwd": "/path/to/KageSec"
    }
  }
}
```

Now Claude can call `kagesec_scan("https://your-app.com")` directly inside a conversation. Tell Claude: _"after you deploy, run a security scan"_ — and it will.

### Option 2 — PostToolUse Hook (auto-triggers on deployment)

The `.claude/settings.json` and `.claude/hooks/post_deploy_scan.py` files are already included in this repo. When Claude runs a deployment command (Vercel, Netlify, Heroku, Railway, Fly.io, AWS, etc.), the hook extracts the live URL from the output and kicks off a background scan automatically.

You don't have to do anything. Deploy → scan happens. Check `reports/` when it's done.

---

## Modules

### Injection

| Module          | Covers                                                                          |
| --------------- | ------------------------------------------------------------------------------- |
| `xss`           | Reflected, stored, DOM-based, blind XSS, second-order, header injection         |
| `sqli`          | Error-based, time-blind, UNION, boolean, stacked queries, NoSQL, LDAP, OOB      |
| `ssrf`          | URL params, form inputs, headers, cloud metadata (AWS/Azure/GCP), OOB callbacks |
| `cmd_injection` | OS command injection via metachar + OOB confirmation                            |
| `ssti`          | Server-side template injection — Jinja2, Freemarker, ERB                        |
| `csti`          | Client-side template injection — Angular, Vue.js, React                         |
| `ssi`           | Server-side include injection (Apache, nginx)                                   |
| `xxe`           | XML external entity + OOB exfiltration                                          |
| `xpath`         | XPath injection (error-based + boolean blind)                                   |
| `crlf`          | CRLF injection / HTTP response splitting                                        |
| `log4j_deep`    | Log4Shell (CVE-2021-44228) + variants, LDAP/RMI payloads                        |
| `shellshock`    | Shellshock / bash injection (CVE-2014-6271)                                     |
| `blind_xss`     | Blind XSS with OOB callback confirmation                                        |

### Authentication & Session

| Module                 | Covers                                                       |
| ---------------------- | ------------------------------------------------------------ |
| `jwt_attacks`          | Weak secret cracking, algorithm confusion, `none` alg bypass |
| `oauth`                | Token exposure, redirect bypass, implicit flow CSRF          |
| `auth_bypass`          | Default credentials, bypass filters, API key extraction      |
| `session_fixation`     | Session fixation + hijacking                                 |
| `session_entropy`      | Weak session token predictability                            |
| `csrf`                 | Missing token detection, weak token patterns                 |
| `username_enumeration` | Timing attacks + error message differences                   |

### Access Control

| Module           | Covers                                              |
| ---------------- | --------------------------------------------------- |
| `idor`           | Incremental ID enumeration + access control testing |
| `path_traversal` | `../` traversal, URL encoding, double encoding      |
| `http_methods`   | Unsafe HTTP methods (PUT, DELETE, TRACE, CONNECT)   |

### Web Application

| Module                 | Covers                                                        |
| ---------------------- | ------------------------------------------------------------- |
| `open_redirect`        | Protocol-relative + fragment bypass                           |
| `file_upload`          | Extension blacklist bypass, MIME-type spoofing                |
| `deserialization`      | Java (ysoserial), Python (pickle), PHP unsafe deserialization |
| `cache_poisoning`      | Header injection, param smuggling, Cache-Control abuse        |
| `host_header`          | SSRF via Host, password reset redirect abuse                  |
| `request_smuggling`    | HTTP request smuggling — CL.TE, TE.CL, TE.TE desync           |
| `prototype_pollution`  | JavaScript prototype pollution                                |
| `padding_oracle`       | CBC decryption via padding oracle                             |
| `http_param_pollution` | Backend parser confusion (IIS, Apache, Tomcat)                |
| `business_logic`       | Price manipulation, discount bypass, logical flaws            |
| `race_condition`       | Concurrent request race detection                             |
| `multistep_injection`  | Multi-step wizard injection, sequential payload chains        |
| `form_fuzz`            | Form field fuzzing + input validation                         |

### API & Protocol

| Module      | Covers                                     |
| ----------- | ------------------------------------------ |
| `graphql`   | Introspection bypass, query injection, DoS |
| `websocket` | XSS in WS messages, auth bypass, injection |

### Headers & Configuration

| Module                  | Covers                                                     |
| ----------------------- | ---------------------------------------------------------- |
| `security_headers`      | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| `cors`                  | Origin reflection, null origin, wildcard with credentials  |
| `cookie_security`       | Missing HttpOnly, Secure, SameSite flags                   |
| `clickjacking`          | Missing X-Frame-Options / CSP frame-ancestors              |
| `subresource_integrity` | Missing or weak SRI on external scripts                    |
| `crossdomain`           | Flash/Silverlight crossdomain.xml misconfiguration         |
| `tls`                   | Weak ciphers, self-signed, expired certs, OCSP stapling    |

### Reconnaissance & Discovery

| Module               | Covers                                                                                                      |
| -------------------- | ----------------------------------------------------------------------------------------------------------- |
| `path_discovery`     | Wordlist-based directory and file fuzzing                                                                   |
| `param_discovery`    | Common GET/POST parameter detection                                                                         |
| `exposed_files`      | Backup and archive file discovery (`.bak`, `.zip`, `.sql`)                                                  |
| `robots_probe`       | robots.txt path enumeration                                                                                 |
| `vhost_enum`         | DNS-based virtual host enumeration                                                                          |
| `subdomain_takeover` | CNAME/NS resolution check for unclaimed domains                                                             |
| `version_disclosure` | Server header, X-Powered-By, framework banners                                                              |
| `api_key_leak`       | API key exposure in response headers and bodies (context-aware, low false positives)                        |
| `breach`             | HaveIBeenPwned credential exposure check                                                                    |
| `waf_detect`         | WAF/IPS fingerprinting (ModSecurity, F5, Cloudflare, etc.)                                                  |
| `waf_bypass`         | Encoding/obfuscation — URL, Unicode, case mutation, comment injection                                       |
| `coverage_check`     | Crawl coverage metrics (pages, params, methods)                                                             |
| `debug_mode`         | Debug mode enabled, stack trace disclosure, verbose error pages                                             |
| `cve_check`          | CVE fingerprinting from response signatures                                                                 |
| `ai_cve`             | Claude API: dynamic CVE research + targeted template generation                                             |
| `dnssec`             | DNSSEC, SPF, DMARC validation                                                                               |
| `rate_limit`         | Insufficient rate limiting / missing brute-force protection                                                 |
| `captcha_check`      | Weak CAPTCHA (client-side validation, predictable seeds)                                                    |
| `templates`          | Nuclei-compatible YAML template runner (59 built-in; use `--nuclei-templates` for 7,400+ community HTTP templates) |

---

## CVE Templates

50 built-in Nuclei-compatible YAML templates covering the CVEs that actually matter:

- **Log4Shell** — CVE-2021-44228, CVE-2021-45046 (the one that ruined December 2021 for everyone)
- **ProxyShell** — CVE-2021-34473
- **Spring4Shell** — CVE-2022-22965
- **Follina** — CVE-2022-30190
- **Text4Shell** — CVE-2022-42889
- **MOVEit RCE** — CVE-2023-34362
- **Citrix Bleed** — CVE-2023-4966
- **ConnectWise ScreenConnect** — CVE-2024-1709
- **Confluence RCE** — CVE-2023-22515
- **Exchange ProxyNotShell** — CVE-2022-41082
- **F5 BIG-IP** — CVE-2022-1388
- Plus Apache, VMware vCenter, GitLab, Cisco, Fortinet, Minio, TeamCity, Jenkins, and more

**Extra template categories:**

- **Exposed panels** (7): Grafana, Jenkins, Kibana, Laravel Telescope, phpMyAdmin, Prometheus, Spring Boot Actuator
- **Misconfigurations** (7): `.env` exposure, `.git` exposure, GraphQL introspection open, Swagger/OpenAPI public, `phpinfo.php`, Apache server-status, backup files
- **AI-generated**: Claude generates targeted templates per detected stack and caches them for 30 days

Want the full Nuclei community templates?

```bash
kagesec update-templates

# Run with them — Go engine handles the load (~7,400 HTTP templates in ~2 min)
kagesec scan https://target.example.com --nuclei-templates
```

The Go engine runs all HTTP-compatible templates concurrently with no timeout. With an AI key, Claude also pre-selects the 80-200 most relevant templates for your stack — so you get targeted coverage faster with higher signal.

> **Note:** `kagesec update-templates` downloads ~10,900 YAML files. The Go engine loads the ~7,400 that use HTTP requests — templates using `flow:`, `javascript:`, `code:`, or `headless:` blocks are skipped. OOB-based templates are also skipped to avoid unconfirmed false positives. In benchmark testing, KageSec matched 24 findings vs Nuclei CLI's 25 on the same target and template set.

---

## Reports

All reports are saved to the `reports/` folder automatically.

```bash
# JSON (default — machine-readable, everything)
kagesec scan https://target.example.com

# PDF (nice-looking, shareable with stakeholders who don't read JSON)
kagesec scan https://target.example.com --output pdf

# All formats at once
kagesec scan https://target.example.com --output all

# SARIF (GitHub Code Scanning)
kagesec scan https://target.example.com --output sarif

# Burp Suite XML
kagesec scan https://target.example.com --output burp

# OWASP ZAP JSON
kagesec scan https://target.example.com --output zap

# Markdown (human-readable narrative — requires AI key)
ANTHROPIC_API_KEY=sk-ant-... kagesec scan https://target.example.com --output markdown

# Push findings to Jira
kagesec issues --format jira \
  --jira-url https://company.atlassian.net \
  --jira-project SEC \
  --jira-token $JIRA_TOKEN \
  --min-severity high

# Open GitHub Issues
kagesec issues --format github \
  --github-repo owner/repo \
  --github-token $GITHUB_TOKEN
```

---

## Compliance

```bash
kagesec scan https://target.example.com --compliance iso27001 gdpr hipaa appi
```

Findings map to a subset of controls in each standard — specifically the ones a DAST tool can actually test (encryption, authentication, injection, session management, TLS, data exposure). Controls that require a human auditor — physical security, HR policy, vendor contracts, incident response procedures — are flagged as "manual review required."

| Standard | Total Controls | DAST-Testable | KageSec Covers |
|----------|---------------|---------------|----------------|
| ISO 27001:2022 | 93 | ~20–25 | 20 (19 auto + 1 manual) |
| HIPAA | 75+ | ~15 | 14 (11 auto + 3 manual) |
| GDPR | 99 articles | ~10 | 10 (6 auto + 4 manual) |
| APPI | 87+ articles | ~10 | 12 (6 auto + 6 manual) |

This is not a substitute for a full compliance audit or a real auditor. It gives you evidence for the technical controls and flags the gaps — which is useful for audit prep, not for printing a certificate. No DAST tool covers all controls. Neither does Nuclei, ZAP, or anything else that only sees HTTP traffic.

---

## CI/CD

### GitHub Actions

Create `.github/workflows/security-scan.yml` in **your own repo**:

```yaml
name: Security Scan
on:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: KageSec Security Scan
        uses: ZulAmi/KageSecurity@main
        with:
          target: https://staging.example.com
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          fail-on: high
          output: sarif

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: reports/kagesec_report.sarif
```

Full examples (GitHub Actions + GitLab CI) are in the [`ci/`](ci/) folder.

### Break the build if something is actually bad

```bash
kagesec scan https://target.example.com --fail-on high
```

Exit code `1` if findings at or above the specified severity are found; `0` if you're good.

### Delta Scanning

KageSec remembers which pages it already scanned. Unchanged pages get skipped on repeat runs — so your CI scans get faster over time, not slower. Use `--full` to force a complete rescan.

---

## Advanced Usage

### Scan Profiles

```bash
kagesec scan https://target.example.com --profile quick      # Fast, low noise — good for CI
kagesec scan https://target.example.com --profile full       # Everything, max depth — go make coffee
kagesec scan https://target.example.com --profile api        # API-focused
kagesec scan https://target.example.com --profile passive    # Look, don't touch
kagesec scan https://target.example.com --profile stealth    # Low and slow, random User-Agent
```

### Workflows

```bash
kagesec workflows
kagesec scan https://target.example.com --workflow quick-web
kagesec scan https://wp.example.com --workflow wordpress
```

### Resume Interrupted Scans

Scan got killed halfway? Pick up where you left off:

```bash
kagesec scan https://target.example.com --resume <scan-id>
```

### Custom Plugins

Drop a Python file into `~/.kagesec/plugins/` and it runs alongside everything else:

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

Blind SQLi, blind XSS, SSRF, XXE, and command injection are verified via OOB callbacks through `oast.pro` by default. This catches vulnerabilities that don't show up in the response.

```bash
# Disable for air-gapped targets
kagesec scan https://target.example.com --no-oob

# Use your own callback domain
kagesec scan https://target.example.com --oob-server callbacks.internal.example.com
```

### Notifications

```bash
kagesec scan https://target.example.com \
  --notify-slack https://hooks.slack.com/... \
  --notify-min-severity high
```

Supports Slack, Teams, Discord, and generic JSON webhooks. Useful for setting up "page me if it finds anything critical" pipelines.

---

## CLI Reference

### Subcommands

| Command                     | Description                                           |
| --------------------------- | ----------------------------------------------------- |
| `scan <target>`             | Scan a target URL                                     |
| `diff <baseline> <current>` | Compare two reports, fail on new findings             |
| `serve`                     | Start HTTP API server (`0.0.0.0:8080`)                |
| `export --scan-id ID`       | Bundle a checkpoint + report into a zip               |
| `import-scan <file>`        | Import a previously exported scan                     |
| `history [<target>]`        | Show finding trends over time                         |
| `suppress`                  | Manage false-positive suppression rules               |
| `retest <finding-id>`       | Re-run a single finding                               |
| `issues`                    | Export to Jira or GitHub Issues                       |
| `workflows`                 | List available scan workflows                         |
| `config`                    | Manage persistent settings (`~/.kagesec/config.yaml`) |
| `update-templates`          | Download Nuclei community templates                   |

### Key `scan` Flags

| Flag                 | Default | Description                                                  |
| -------------------- | ------- | ------------------------------------------------------------ |
| `--depth N`          | 3       | Crawl depth                                                  |
| `--max-pages N`      | 100     | Max pages to crawl                                           |
| `--level 1-5`        | 1       | Scan aggressiveness                                          |
| `--risk 1-3`         | 1       | Risk tolerance                                               |
| `--browser`          | **on**  | Playwright headless crawling (use `--no-browser` to disable) |
| `--passive`          | off     | No injection — headers and content only                      |
| `--parallel N`       | 1       | Concurrent multi-target scanning                             |
| `--live`             | off     | Print findings as they're discovered                         |
| `--no-ai`            | off     | Skip Claude AI verification                                  |
| `--fail-on LEVEL`    | —       | Exit 1 if findings at this severity or above                 |
| `--output FORMAT`    | json    | Report format (json/pdf/sarif/burp/zap/all)                  |
| `--modules M1 M2`    | all     | Run only specific modules                                    |
| `--nuclei-templates` | off     | Include 10k+ Nuclei community templates                      |
| `--profile NAME`     | —       | Apply a scan preset                                          |
| `--workflow NAME`    | —       | Run a predefined workflow                                    |
| `--resume ID`        | —       | Resume an interrupted scan                                   |
| `--full`             | off     | Force full rescan (skip delta optimization)                  |
| `--max-time MIN`     | 0       | Hard time limit in minutes                                   |

---

## Environment Variables

| Variable            | Required        | Description                                                               |
| ------------------- | --------------- | ------------------------------------------------------------------------- |
| `ANTHROPIC_API_KEY` | For AI features | Claude API key for exploit verification, CVE research, and report writing |
| `NVD_API_KEY`       | Optional        | NVD API key for faster CVE enrichment                                     |

No API key? No problem. KageSec runs all 61 modules and produces full reports without one. You just won't get the AI triage layer or the narrative Markdown report.

---

## Stack

- **Orchestration:** Python 3.12+
- **Template engine:** Go 1.22+ (`kagesec-engine` — 50 goroutines, real-time JSON Lines output)
- **HTTP client:** httpx (Python), `net/http` (Go engine)
- **Browser:** Playwright (Chromium)
- **AI:** Claude API (Anthropic) — `claude-sonnet-4-6` / `claude-opus-4-7`
- **Templates:** Nuclei-compatible YAML (`gopkg.in/yaml.v3`)
- **Reports:** Jinja2, WeasyPrint (PDF), SARIF 2.1.0

---

## Project Structure

```
kagesec/
├── cli/                    # CLI entrypoint (main.py, 12 subcommands)
├── scanner/
│   ├── core/               # Engine, crawlers, config, delta state, OOB, rate limiter
│   ├── modules/            # 61 vulnerability detection modules
│   ├── templates/          # Built-in Nuclei-compatible YAML (CVEs, misconfigs, panels)
│   ├── ai/                 # Claude API: verifier, reporter, CVE researcher, template selector
│   ├── reporters/          # PDF, SARIF, Burp XML, ZAP JSON, Jira, GitHub
│   ├── compliance/         # ISO 27001, HIPAA, GDPR, APPI mapping
│   ├── api/                # HTTP API server
│   ├── mcp_server.py       # Claude Code MCP integration
│   └── utils/              # HTTP helpers, payload loading
├── engine/                 # Go template engine (kagesec-engine)
│   ├── main.go
│   ├── cmd/root.go         # CLI flags
│   ├── template/           # YAML loader, executor, matcher, selector
│   ├── runner/engine.go    # Goroutine pool, work distribution
│   ├── output/streamer.go  # JSON Lines real-time output
│   └── go.mod
├── .claude/
│   ├── settings.json       # Claude Code hooks config
│   └── hooks/
│       └── post_deploy_scan.py   # Auto-scan on deployment
├── tests/
│   ├── unit/
│   └── integration/        # DVWA, WebGoat, OWASP Juice Shop
├── reports/                # Scan output goes here (gitignored)
├── helm/                   # Kubernetes Helm chart
├── Dockerfile
└── action.yml              # GitHub Actions composite action
```

---

## Contributing

This project is, and probably always will be, a work in progress.

There's always another module to write, another CVE to template, another compliance control to map, or another edge case in a web framework that breaks everything in a fun new way. Security is a moving target and so is this tool.

If you want to work on it together — whether you're a security researcher, a developer who found a bug, someone who wants to add a module for a vulnerability type we don't cover yet, or just someone who paid too much for a PTAA and wants to commiserate — reach out.

📧 **zulhilmirahmat@protonmail.com**

Pull requests, issues, ideas, war stories about enterprise security vendors, all welcome.

---

## Legal Notice

**Use this on systems you own or have permission to test. That's it. That's the rule.**

KageSec actively sends attack payloads to targets. It is not a passive monitoring tool. Pointing it at someone else's server without permission is illegal in most jurisdictions — including the CFAA (US), Computer Misuse Act (UK), and similar laws worldwide. "I was just testing" is not a defence that has historically worked well in court.

The authors accept zero liability for misuse. This software is provided as-is.

Responsible use means:

- Written authorization before scanning anything you don't own
- Respect rate limits and don't take down production systems
- Disclose vulnerabilities responsibly to affected parties
- Follow all applicable laws in your jurisdiction

---

## License

MIT
