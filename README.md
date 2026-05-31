# KageSec

**A security scanner that actually finds things.** KageSec crawls your web app, throws 61 vulnerability modules at it, runs 7,400+ CVE templates via a purpose-built Go engine, and uses AI to verify whether the findings are real — so your report isn't 200 false positives that someone has to triage at 11pm.

Think of it as Nuclei and ZAP had a baby, the baby learned Python and Go, and then got really into AI and AppSec workflows.

## vs Nuclei CLI — Real Benchmark

Tested against [ginandjuice.shop](https://ginandjuice.shop) (PortSwigger's intentionally vulnerable app), same template directory (`~/.kagesec/nuclei-templates`), same concurrency (50):

| | KageSec (no AI, no browser) | Nuclei CLI |
|---|---|---|
| **Total scan time** | **29m 36s** | **5m 22s** |
| Pages / URLs scanned | 31 pages crawled | 1 URL |
| Templates run | 7,417 HTTP templates | 9,028 templates |
| Template findings | 24 | 25 |
| **Total findings** | **50** | **25** |
| **False positives** | **0** | unknown |
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

**KageSec takes longer because it does more.** Nuclei fires templates at one URL and stops. KageSec crawls 31 pages, runs exploitation modules per page, and runs the template engine concurrently — the template engine itself finishes in ~2 minutes. The extra time is spent finding the vulnerabilities Nuclei structurally cannot find: SSTI, DOM XSS, IDOR, business logic, CSRF.

The 50 findings are all real. Parameter discovery false positives — the classic DAST noise problem — are eliminated by a canary-based comparison baseline (the same approach used by Burp Param Miner and Arjun).

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![Go 1.22+](https://img.shields.io/badge/go-1.22%2B-00ADD8)
![Version](https://img.shields.io/badge/version-0.2.3--beta-orange)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
[![CI](https://github.com/ZulAmi/KageSecurity/actions/workflows/ci.yml/badge.svg)](https://github.com/ZulAmi/KageSecurity/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/kagesec)](https://pypi.org/project/kagesec/)

---

## Why this exists

I paid a security firm thousands of dollars to do a penetration test for my startup. Fair enough — you need a PTAA report, compliance asks for it, I get it.

Then, at the end of the engagement, the same firm casually mentioned they also offer an _automated DAST scanning service_. Ongoing. Recurring. Thousands of dollars a year. For a tool that runs automatically.

I sat with that for a moment.

I know Nuclei exists. It's great. It's the industry open-source standard and ProjectDiscovery has built something genuinely impressive. But the companies built on top of it will happily charge you enterprise pricing for what is, at its core, a YAML template runner with a nice UI.

So I built KageSec instead — open-source, AI-powered, and free. It runs the same categories of checks, uses Nuclei-compatible templates, and adds AI on top to verify whether findings are actually exploitable.

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

In benchmark testing: **7,417 HTTP templates in ~2 minutes** with 50 goroutines. Nuclei ran 9,028 templates in 5m 22s as a standalone scan — both matched ~25 findings from the same template set.

### Building the engine

**pip install users:** The binary is already bundled — nothing to build.

If you cloned the repo or want to rebuild:

```bash
# Requires Go 1.22+
cd engine
go build -o kagesec-engine .
```

### Cross-compiling for CI / Docker

```bash
# Linux (for Docker/CI)
GOOS=linux GOARCH=amd64 go build -o kagesec-engine-linux-amd64 .

# Windows
GOOS=windows GOARCH=amd64 go build -o kagesec-engine-windows-amd64.exe .
```

---

## Claude Code Users

If you use Claude Code to build and deploy your apps, KageSec plugs in directly.

**Option 1 — Ask Claude to scan during a conversation:**

Once you add KageSec as an MCP server (see [Claude Code Integration](#claude-code-integration) below), you can just tell Claude:

> _"Scan this for security issues"_ or _"Deploy it and then run a security scan"_

Claude will call `kagesec_scan()` as a tool and report findings back in the conversation.

**Option 2 — Automatic scan on every deployment:**

The `.claude/` folder includes a hook that fires after any deployment Bash command (Vercel, Netlify, Heroku, Railway, Fly.io, AWS, etc.). Claude detects the live URL from the deployment output and starts a background scan automatically. Check `reports/` when it's done.

---

## What it does

- **61 vulnerability modules** — XSS, SQLi, SSRF, SSTI, XXE, deserialization, request smuggling, prototype pollution, JWT attacks, and more. If it's in the OWASP Top 10, there's a module for it.
- **Go template engine** — `kagesec-engine` runs 7,417 HTTP-compatible Nuclei templates with 50 goroutines, real-time streaming, and confidence scoring. ~2 minutes for 7,417 templates. With an AI key, Claude narrows templates to 80-200 relevant ones for your stack.
- **5 AI providers** — Anthropic Claude, OpenAI GPT-4o, Google Gemini, Mistral, and Ollama (local, no key required). AI verifies exploitability, classifies findings, and writes a human-readable report. Auto-detected from environment variables — no config needed.
- **Zero false positives in parameter discovery** — canary-based comparison baseline matches the approach used by Burp Param Miner and Arjun. Two-tier wordlist (security-critical vs medium-confidence) with per-param attempt tracking.
- **Finding state tracking** — every scan compares against the previous scan. Findings are classified as `NEW`, `REPEATED`, `REGRESSED` (was fixed, broke again), or `RESOLVED` (fixed since last scan). Modelled on Burp Enterprise's issue tracking.
- **"Fix These First" prioritization** — after each scan, findings are scored by CVSS + AI exploitability verdict + finding state + severity tier and ranked. No more "here are 50 findings, good luck." Modelled on Bright Security's two-lens approach.
- **Scheduled scanning** — `kagesec schedule add <target> --interval daily` — saves to `~/.kagesec/schedules.yaml`, runs via `kagesec schedule run` from crontab or CI.
- **Session expiry detection** — `--login-logged-out REGEX` and `--login-logged-in REGEX` check every page response to detect expired sessions and re-authenticate mid-scan. Mirrors StackHawk's `loggedInIndicator`/`loggedOutIndicator` and ZAP's auth verification strategy.
- **Headless browser crawling** — Playwright handles SPAs and JS-heavy apps. Enabled by default.
- **Full auth support** — Bearer tokens, cookies, OAuth2, multi-step logins, TOTP 2FA, session expiry re-auth.
- **API scanning** — OpenAPI, GraphQL, gRPC, SOAP/WSDL, HAR import.
- **5 report formats** — JSON, PDF, SARIF, Burp XML, ZAP JSON — all saved to `reports/`.
- **Compliance mapping** — ISO 27001, HIPAA, GDPR, APPI.
- **CI/CD native** — GitHub Actions, `--fail-on high`, SARIF upload. Break the build before the attacker breaks your users.

---

## Installation

```bash
pip install kagesec
```

The `kagesec-engine` Go binary is bundled in the wheel — no manual build step required.

Want the full experience?

```bash
pip install "kagesec[browser]"              # Playwright (you probably want this)
pip install "kagesec[pdf]"                  # PDF reports
pip install "kagesec[dns]"                  # DNSSEC + subdomain enumeration
pip install "kagesec[browser,pdf,dns]"      # The whole thing
```

After installing `browser`, grab Chromium:

```bash
playwright install chromium
```

---

## Quick Start

```bash
# Basic scan — finds stuff, saves reports to reports/
kagesec scan https://target.example.com

# With AI verification (highly recommended — cuts false positives, scores exploitability)
ANTHROPIC_API_KEY=sk-ant-... kagesec scan https://target.example.com --output all

# Zero-cost AI with Ollama (local model, no API key)
kagesec scan https://target.example.com --output all

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

# Prevent Mac from sleeping during long scans
caffeinate -i kagesec scan https://target.example.com --nuclei-templates --stats
```

---

## AI Providers

KageSec supports 5 AI providers. It auto-detects whichever one you have configured — no flags needed.

```bash
# Anthropic Claude (recommended — best verification quality)
export ANTHROPIC_API_KEY=sk-ant-...

# OpenAI GPT-4o
export OPENAI_API_KEY=sk-...

# Google Gemini
export GEMINI_API_KEY=...

# Mistral
export MISTRAL_API_KEY=...

# Ollama — local model, zero cost, no key needed
# Just make sure Ollama is running: https://ollama.com
export OLLAMA_URL=http://localhost:11434   # optional, this is the default

# Override provider and model explicitly
kagesec scan https://target.example.com --ai-provider gemini --ai-model gemini-1.5-pro
```

Priority: Anthropic → OpenAI → Gemini → Mistral → Ollama. If none are available, the scan runs without AI and still produces full findings — you just won't get the verification layer or narrative report.

AI verification batches findings in groups of 10, classifies each as `true_positive`, `false_positive`, or `needs_manual_review`, and scores exploitability and business impact.

---

## Authentication

KageSec can log into your app before scanning — including detecting when the session expires mid-scan and re-authenticating automatically.

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

# 2FA with TOTP
kagesec scan https://app.example.com \
  --login-url https://app.example.com/login \
  --login-username admin@example.com \
  --login-password secret \
  --login-totp-secret JBSWY3DPEHPK3PXP

# Session expiry detection — re-authenticates mid-scan if the session drops
# (mirrors StackHawk loggedInIndicator/loggedOutIndicator + ZAP auth verification)
kagesec scan https://app.example.com \
  --login-url https://app.example.com/login \
  --login-username admin@example.com \
  --login-password secret \
  --login-success "/dashboard" \
  --login-logged-out "Sign in to your account|Session expired" \
  --login-logged-in "My Account|Welcome back" \
  --login-session-check https://app.example.com/account
```

**`--login-logged-out REGEX`** — regex matched against every page response body. If it fires (e.g. login form reappeared), the scanner re-authenticates before continuing.

**`--login-logged-in REGEX`** — regex that must be present in the response body to confirm a valid session. If absent, re-authenticate.

**`--login-session-check URL`** — a known-authenticated URL polled every 50 module runs to check session validity. If omitted, every crawled page is checked instead.

---

## Finding States & Prioritization

Every scan compares its findings against the previous scan for the same target. Findings appear in the output with state badges:

```
[+] Finding states: NEW 3 | REPEATED 18 | REGRESSED 1
[+] Resolved since last scan: 5 finding(s) fixed
    ✓ Missing CSP Header — https://example.com
    ✓ Clickjacking — https://example.com
    ...
```

| State | Meaning |
|---|---|
| `NEW` | First time this finding appeared on this target |
| `REPEATED` | Present in both the previous scan and this one — still not fixed |
| `REGRESSED` | Was resolved in a previous scan, now reappeared — needs urgent attention |
| `RESOLVED` | Was present before, no longer detected — fix confirmed |

After every scan, KageSec outputs a **Fix These First** section — findings ranked by priority score (CVSS + AI exploitability verdict + state bonus):

```
── FIX THESE FIRST ───────────────────────────────────────────
   1. [score 16.3] CRITICAL [NEW]       OS Command Injection
                   https://target.com/catalog  param=searchTerm
   2. [score 15.3] CRITICAL [REPEATED]  Client-Side Template Injection
                   https://target.com/catalog  param=searchTerm
   3. [score 14.3] HIGH     [REGRESSED] XSS — was fixed, broke again
                   https://target.com/search  param=q
   ...top 10 only...
────────────────────────────────────────────────────────────
```

Scoring: CVSS base (0–10) + AI true_positive (+3) + OOB verified (+2) + severity tier + REGRESSED bonus (+2.5).

---

## Scheduled Scanning

```bash
# Add a nightly scan
kagesec schedule add https://app.example.com --interval daily --level 3 --max-pages 150

# Weekly scan with a specific profile
kagesec schedule add https://app.example.com --interval weekly --profile full

# Cron expression
kagesec schedule add https://app.example.com --interval "0 2 * * *"

# List all schedules with next-run times
kagesec schedule list

# Remove a schedule
kagesec schedule remove https://app.example.com

# Run all due schedules (call this from system crontab or a nightly CI step)
kagesec schedule run
```

Schedules are stored in `~/.kagesec/schedules.yaml`. No daemon required — add `kagesec schedule run` to your crontab:

```bash
0 2 * * * kagesec schedule run
```

---

## Retesting Findings

After a fix is deployed, verify it without running the full scan:

```bash
# By index (0-based)
kagesec retest 0 --report reports/kagesec_report.json

# By title substring
kagesec retest "OS Command" --report reports/kagesec_report.json
kagesec retest "XSS" --report reports/kagesec_report.json
```

The retest first tries to replay the exact HTTP request from the `poc_curl` field (< 2s). If that's inconclusive, it re-runs the relevant detection module. Reports `STILL PRESENT` or `RESOLVED`.

---

## API & Protocol Scanning

```bash
# OpenAPI / Swagger (URL or local file)
kagesec scan https://api.example.com --openapi https://api.example.com/openapi.json

# GraphQL
kagesec scan https://api.example.com --graphql https://api.example.com/graphql

# gRPC
kagesec scan grpc://api.example.com:50051 --grpc api.example.com:50051

# SOAP / WSDL
kagesec scan https://api.example.com --wsdl https://api.example.com/service?wsdl

# Import a HAR file (great for scanning authenticated flows recorded in Chrome DevTools)
kagesec scan https://app.example.com --har ./session.har
```

---

## Claude Code Integration

### Option 1 — MCP Server

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

Now Claude can call `kagesec_scan("https://your-app.com")` directly inside a conversation.

### Option 2 — PostToolUse Hook

The `.claude/settings.json` and `.claude/hooks/post_deploy_scan.py` files are already included. When Claude runs a deployment command, the hook extracts the live URL and kicks off a background scan automatically.

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
| `business_logic`       | Price manipulation, boundary value bypass — flags on explicit success indicators only (OWASP WSTG approach) |
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
| `param_discovery`    | Hidden parameter detection — two-tier wordlist, canary-based FP prevention (Burp Param Miner approach)     |
| `exposed_files`      | Backup and archive file discovery (`.bak`, `.zip`, `.sql`)                                                  |
| `robots_probe`       | robots.txt path enumeration                                                                                 |
| `vhost_enum`         | DNS-based virtual host enumeration                                                                          |
| `subdomain_takeover` | CNAME/NS resolution check for unclaimed domains                                                             |
| `version_disclosure` | Server header, X-Powered-By, framework banners                                                              |
| `api_key_leak`       | API key exposure in response headers and bodies                                                             |
| `breach`             | HaveIBeenPwned credential exposure check                                                                    |
| `waf_detect`         | WAF/IPS fingerprinting (ModSecurity, F5, Cloudflare, etc.)                                                  |
| `waf_bypass`         | Encoding/obfuscation — URL, Unicode, case mutation, comment injection                                       |
| `coverage_check`     | Crawl coverage metrics (pages, params, methods)                                                             |
| `debug_mode`         | Debug mode enabled, stack trace disclosure, verbose error pages                                             |
| `cve_check`          | CVE fingerprinting from response signatures                                                                 |
| `ai_cve`             | AI-powered dynamic CVE research + targeted template generation                                              |
| `dnssec`             | DNSSEC, SPF, DMARC validation                                                                               |
| `rate_limit`         | Insufficient rate limiting / missing brute-force protection                                                 |
| `captcha_check`      | Weak CAPTCHA (client-side validation, predictable seeds)                                                    |
| `templates`          | Nuclei-compatible YAML template runner (59 built-in; `--nuclei-templates` for 7,400+ community HTTP templates) |

---

## CVE Templates

50 built-in Nuclei-compatible YAML templates covering the CVEs that actually matter:

- **Log4Shell** — CVE-2021-44228, CVE-2021-45046
- **ProxyShell** — CVE-2021-34473
- **Spring4Shell** — CVE-2022-22965
- **MOVEit RCE** — CVE-2023-34362
- **Citrix Bleed** — CVE-2023-4966
- **ConnectWise ScreenConnect** — CVE-2024-1709
- **Confluence RCE** — CVE-2023-22515
- Plus Apache, VMware vCenter, GitLab, Cisco, Fortinet, F5 BIG-IP, Minio, TeamCity, Jenkins

**Extra template categories:**

- **Exposed panels** (7): Grafana, Jenkins, Kibana, Laravel Telescope, phpMyAdmin, Prometheus, Spring Boot Actuator
- **Misconfigurations** (7): `.env` exposure, `.git` exposure, GraphQL introspection open, Swagger/OpenAPI public, `phpinfo.php`, Apache server-status, backup files
- **AI-generated**: Claude generates targeted templates per detected stack and caches them for 30 days

```bash
kagesec update-templates

# Run with them — Go engine handles the load (~7,400 HTTP templates in ~2 min)
kagesec scan https://target.example.com --nuclei-templates
```

---

## Reports

All reports are saved to the `reports/` folder automatically.

```bash
kagesec scan https://target.example.com --output json      # default
kagesec scan https://target.example.com --output pdf       # stakeholder-ready
kagesec scan https://target.example.com --output all       # every format at once
kagesec scan https://target.example.com --output sarif     # GitHub Code Scanning
kagesec scan https://target.example.com --output burp      # Burp Suite XML
kagesec scan https://target.example.com --output zap       # OWASP ZAP JSON

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

| Standard | Total Controls | DAST-Testable | KageSec Covers |
|----------|---------------|---------------|----------------|
| ISO 27001:2022 | 93 | ~20–25 | 20 (19 auto + 1 manual) |
| HIPAA | 75+ | ~15 | 14 (11 auto + 3 manual) |
| GDPR | 99 articles | ~10 | 10 (6 auto + 4 manual) |
| APPI | 87+ articles | ~10 | 12 (6 auto + 6 manual) |

---

## CI/CD

### GitHub Actions

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

Full examples in the [`ci/`](ci/) folder.

### Break the build on real findings

```bash
kagesec scan https://target.example.com --fail-on high
```

Exit code `1` if findings at or above the specified severity are found; `0` if clean.

### Delta Scanning

KageSec remembers which pages it already scanned. Unchanged pages get skipped on repeat runs — CI scans get faster over time. Use `--full` to force a complete rescan.

---

## Advanced Usage

### Scan Profiles

```bash
kagesec scan https://target.example.com --profile quick      # Fast, low noise — good for CI
kagesec scan https://target.example.com --profile full       # Everything, max depth
kagesec scan https://target.example.com --profile api        # API-focused
kagesec scan https://target.example.com --profile passive    # Look, don't touch
kagesec scan https://target.example.com --profile stealth    # Low and slow, random User-Agent
```

### Resume Interrupted Scans

```bash
kagesec scan https://target.example.com --resume <scan-id>
```

### Scan History & Trends

```bash
kagesec history https://target.example.com             # Summary with state breakdown
kagesec history https://target.example.com --scans     # All past scans
kagesec history https://target.example.com --persisting # Findings seen in multiple scans
```

### Suppress False Positives

```bash
kagesec suppress add --title "User Name Information"   # Suppress OSINT noise
kagesec suppress add --title "RDAP WHOIS"
kagesec suppress list
kagesec suppress remove <id>
```

### Custom Plugins

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

Supports Slack, Teams, Discord, and generic JSON webhooks.

---

## CLI Reference

### Subcommands

| Command                     | Description                                           |
| --------------------------- | ----------------------------------------------------- |
| `scan <target>`             | Scan a target URL                                     |
| `schedule`                  | Manage recurring scheduled scans                      |
| `retest <finding-id>`       | Re-run a single finding — fast path via poc_curl, falls back to module |
| `history [<target>]`        | Show finding trends and state over time               |
| `suppress`                  | Manage false-positive suppression rules               |
| `diff <baseline> <current>` | Compare two reports, fail on new findings             |
| `issues`                    | Export to Jira or GitHub Issues                       |
| `serve`                     | Start HTTP API server (`0.0.0.0:8080`)                |
| `export --scan-id ID`       | Bundle a checkpoint + report into a zip               |
| `import-scan <file>`        | Import a previously exported scan                     |
| `workflows`                 | List available scan workflows                         |
| `config`                    | Manage persistent settings (`~/.kagesec/config.yaml`) |
| `update-templates`          | Download Nuclei community templates                   |

### Key `scan` Flags

| Flag                          | Default | Description                                                  |
| ----------------------------- | ------- | ------------------------------------------------------------ |
| `--depth N`                   | 3       | Crawl depth                                                  |
| `--max-pages N`               | 100     | Max pages to crawl                                           |
| `--level 1-5`                 | 1       | Scan aggressiveness                                          |
| `--risk 1-3`                  | 1       | Risk tolerance (risk≥2 enables time-based SQLi)              |
| `--browser`                   | **on**  | Playwright headless crawling (`--no-browser` to disable)     |
| `--passive`                   | off     | No injection — headers and content only                      |
| `--live`                      | off     | Print findings as discovered                                 |
| `--stats`                     | off     | Progress bar on stderr                                       |
| `--no-ai`                     | off     | Skip AI verification                                         |
| `--ai-provider NAME`          | auto    | anthropic \| openai \| gemini \| mistral \| ollama           |
| `--fail-on LEVEL`             | —       | Exit 1 if findings at this severity or above                 |
| `--output FORMAT`             | json    | json / pdf / sarif / burp / zap / all                        |
| `--modules M1 M2`             | all     | Run only specific modules                                    |
| `--nuclei-templates`          | off     | Include 10k+ Nuclei community templates                      |
| `--profile NAME`              | —       | Apply a scan preset                                          |
| `--resume ID`                 | —       | Resume an interrupted scan                                   |
| `--full`                      | off     | Force full rescan (skip delta optimization)                  |
| `--max-time MIN`              | 0       | Hard time limit in minutes                                   |
| `--login-logged-out REGEX`    | —       | Re-auth trigger: regex matching response when session expires |
| `--login-logged-in REGEX`     | —       | Re-auth trigger: regex that must be present for valid session |
| `--login-session-check URL`   | —       | URL polled every 50 checks to verify session validity        |
| `--concurrency N`             | 8       | Module threads per page                                      |
| `--rate-limit RPS`            | 10      | HTTP requests per second                                     |

### `schedule` Subcommands

```bash
kagesec schedule add <target> --interval daily|weekly|hourly|monthly|"0 2 * * *"
kagesec schedule list
kagesec schedule remove <target>
kagesec schedule run
```

---

## Environment Variables

| Variable            | Required        | Description                                                               |
| ------------------- | --------------- | ------------------------------------------------------------------------- |
| `ANTHROPIC_API_KEY` | For AI features | Claude API — verified exploitability, CVE research, narrative report      |
| `OPENAI_API_KEY`    | Alternative AI  | GPT-4o as AI provider                                                     |
| `GEMINI_API_KEY`    | Alternative AI  | Google Gemini as AI provider                                              |
| `MISTRAL_API_KEY`   | Alternative AI  | Mistral Large as AI provider                                              |
| `OLLAMA_URL`        | Optional        | Ollama base URL (default: `http://localhost:11434`) — free local AI       |
| `NVD_API_KEY`       | Optional        | NVD API key for faster CVE enrichment                                     |

No AI key? KageSec runs all 61 modules and produces full reports without one. You just won't get the AI triage layer or the narrative Markdown report.

---

## Stack

- **Orchestration:** Python 3.12+
- **Template engine:** Go 1.22+ (`kagesec-engine` — 50 goroutines, real-time JSON Lines output)
- **HTTP client:** httpx (Python), `net/http` (Go engine)
- **Browser:** Playwright (Chromium)
- **AI:** Claude, GPT-4o, Gemini, Mistral, or Ollama (auto-detected)
- **Templates:** Nuclei-compatible YAML (`gopkg.in/yaml.v3`)
- **Reports:** Jinja2, WeasyPrint (PDF), SARIF 2.1.0
- **State store:** SQLite (`~/.kagesec/findings.db`) — finding history, trending, states

---

## Project Structure

```
kagesec/
├── cli/                    # CLI entrypoint (main.py, 13 subcommands)
├── scanner/
│   ├── core/               # Engine, crawlers, config, findings DB, scheduler, prioritizer
│   ├── modules/            # 61 vulnerability detection modules
│   ├── templates/          # Built-in Nuclei-compatible YAML (CVEs, misconfigs, panels)
│   ├── ai/                 # 5-provider AI: verifier, reporter, CVE researcher, template selector
│   ├── reporters/          # PDF, SARIF, Burp XML, ZAP JSON, Jira, GitHub
│   ├── compliance/         # ISO 27001, HIPAA, GDPR, APPI mapping
│   ├── api/                # HTTP API server
│   ├── mcp_server.py       # Claude Code MCP integration
│   └── utils/              # HTTP helpers, payload loading
├── engine/                 # Go template engine (kagesec-engine)
│   ├── main.go
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
├── reports/                # Scan output (gitignored)
├── Dockerfile
└── action.yml              # GitHub Actions composite action
```

---

## Contributing

This project is, and probably always will be, a work in progress. There's always another module to write, another CVE to template, another compliance control to map, or another edge case in a web framework that breaks everything in a fun new way.

If you want to work on it — security researcher, developer who found a bug, someone who wants to add a module, or someone who paid too much for a PTAA and wants to commiserate — reach out.

📧 **zulhilmirahmat@protonmail.com**

Pull requests, issues, ideas, war stories about enterprise security vendors — all welcome.

---

## Legal Notice

**Use this on systems you own or have permission to test. That's it. That's the rule.**

KageSec actively sends attack payloads to targets. It is not a passive monitoring tool. Pointing it at someone else's server without permission is illegal in most jurisdictions — including the CFAA (US), Computer Misuse Act (UK), and similar laws worldwide.

The authors accept zero liability for misuse. This software is provided as-is.

---

## License

MIT
