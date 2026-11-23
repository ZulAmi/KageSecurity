# KageSec Modules Reference

61 vulnerability detection modules. Each is a Python file in `scanner/modules/` implementing a `test(page, client) -> List[Finding]` function.

---

## Injection (13 modules)

| Module file | Title | What it tests |
|---|---|---|
| `xss.py` | Cross-Site Scripting | Reflected, stored, DOM-based, blind XSS, second-order, header injection |
| `sqli.py` | SQL Injection | Error-based, time-blind, UNION, boolean, stacked queries, NoSQL, LDAP, OOB |
| `ssrf.py` | Server-Side Request Forgery | URL params, form inputs, headers, cloud metadata (AWS/Azure/GCP IMDSv1), OOB callbacks |
| `cmd_injection.py` | OS Command Injection | Metachar injection (`; && |`), OOB DNS confirmation via interactsh |
| `ssti.py` | Server-Side Template Injection | Jinja2, Freemarker, ERB, Twig — math expression probing |
| `csti.py` | Client-Side Template Injection | AngularJS `{{7*7}}`, Vue.js `${7*7}`, React |
| `ssi.py` | Server-Side Include Injection | Apache/nginx SSI directives (`<!--#exec-->`) |
| `xxe.py` | XML External Entity | Inline DTD + OOB exfiltration, blind XXE via interactsh |
| `xpath.py` | XPath Injection | Error-based and boolean-blind XPath probing |
| `crlf.py` | CRLF Injection | HTTP response splitting via `%0d%0a` in headers |
| `log4j_deep.py` | Log4Shell | CVE-2021-44228 / CVE-2021-45046 — LDAP/RMI/DNS payloads |
| `shellshock.py` | Shellshock | CVE-2014-6271 — bash function injection in User-Agent / Referer |
| `blind_xss.py` | Blind XSS | Deferred OOB callback confirmation (fires when admin views page) |

---

## Authentication & Session (7 modules)

| Module file | Title | What it tests |
|---|---|---|
| `jwt_attacks.py` | JWT Attacks | Weak secret brute-force, `alg:none` bypass, algorithm confusion (RS256→HS256) |
| `oauth.py` | OAuth Misconfiguration | Token leakage in referrer, redirect_uri bypass, implicit flow CSRF |
| `auth_bypass.py` | Authentication Bypass | Default credentials, bypass filter mutations, API key exposure in responses |
| `session_fixation.py` | Session Fixation | Pre-auth session token reuse after login |
| `session_entropy.py` | Weak Session Entropy | Statistical randomness test on session tokens (sequential, low-bit) |
| `csrf.py` | CSRF | Missing token detection, weak token patterns (static, predictable) |
| `username_enumeration.py` | Username Enumeration | Timing differences and distinct error messages between valid/invalid users |

---

## Access Control (3 modules)

| Module file | Title | What it tests |
|---|---|---|
| `idor.py` | Insecure Direct Object Reference | Incremental numeric ID substitution + cross-user access verification |
| `path_traversal.py` | Path Traversal | `../` sequences, URL encoding, double encoding, null byte variants |
| `http_methods.py` | Unsafe HTTP Methods | PUT, DELETE, TRACE, CONNECT enabled on endpoints |

---

## Web Application (13 modules)

| Module file | Title | What it tests |
|---|---|---|
| `open_redirect.py` | Open Redirect | Protocol-relative URLs, fragment bypass, encoded redirects |
| `file_upload.py` | File Upload | Extension blacklist bypass, MIME-type spoofing, polyglot files |
| `deserialization.py` | Insecure Deserialization | Java (ysoserial gadgets), Python pickle, PHP `unserialize()` |
| `cache_poisoning.py` | Web Cache Poisoning | Header injection (`X-Forwarded-Host`), param cloaking, `Cache-Control` abuse |
| `host_header.py` | Host Header Injection | SSRF via `Host:` header, password-reset link manipulation |
| `request_smuggling.py` | HTTP Request Smuggling | CL.TE, TE.CL, TE.TE desync detection |
| `prototype_pollution.py` | Prototype Pollution | `__proto__` injection via query params and JSON body |
| `padding_oracle.py` | Padding Oracle | CBC-mode decryption oracle via response timing/error differences |
| `http_param_pollution.py` | HTTP Parameter Pollution | Duplicate parameter injection — IIS, Apache, Tomcat parser confusion |
| `business_logic.py` | Business Logic | Price manipulation, negative quantities, boundary value bypass — flags on explicit success indicators only |
| `race_condition.py` | Race Condition | Concurrent request burst on state-changing endpoints |
| `multistep_injection.py` | Multi-Step Injection | Sequential payload chains across multi-page wizard flows |
| `form_fuzz.py` | Form Fuzzing | Input validation bypass, oversized inputs, format string probes |

---

## API & Protocol (2 modules)

| Module file | Title | What it tests |
|---|---|---|
| `graphql.py` | GraphQL Security | Introspection enabled, query depth DoS, injection via arguments |
| `websocket.py` | WebSocket Security | XSS payloads in WS messages, authentication bypass, injection via WS frames |

---

## Headers & Configuration (7 modules)

| Module file | Title | What it tests |
|---|---|---|
| `security_headers.py` | Missing Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy |
| `cors.py` | CORS Misconfiguration | Origin reflection, `null` origin acceptance, `*` with credentials |
| `cookie_security.py` | Cookie Security | Missing `HttpOnly`, `Secure`, `SameSite` flags on session cookies |
| `clickjacking.py` | Clickjacking | Missing `X-Frame-Options` or `frame-ancestors` CSP directive |
| `subresource_integrity.py` | Missing SRI | External scripts/stylesheets without integrity hash |
| `crossdomain.py` | Crossdomain Policy | Permissive `crossdomain.xml` (Flash/Silverlight legacy) |
| `tls.py` | TLS/SSL Issues | Weak ciphers, expired certs, self-signed certs, HTTP-not-redirected-to-HTTPS |

---

## Reconnaissance & Discovery (19 modules)

| Module file | Title | What it tests |
|---|---|---|
| `path_discovery.py` | Path Discovery | Wordlist-based directory and file enumeration |
| `param_discovery.py` | Parameter Discovery | Hidden parameter detection — two-tier wordlist, canary-based FP prevention |
| `exposed_files.py` | Exposed Backup Files | `.bak`, `.zip`, `.sql`, `.tar.gz`, `.swp` at predictable paths |
| `robots_probe.py` | robots.txt Enumeration | Fetches and crawls paths listed in `Disallow:` rules |
| `vhost_enum.py` | Virtual Host Enumeration | DNS-based vhost discovery via wordlist |
| `subdomain_takeover.py` | Subdomain Takeover | CNAME/NS resolution check — detects unclaimed domains |
| `version_disclosure.py` | Version Disclosure | Server header, `X-Powered-By`, framework banners in responses |
| `api_key_leak.py` | API Key Exposure | API key patterns in response headers and body content |
| `breach.py` | Credential Exposure | HaveIBeenPwned API lookup for email addresses found on the target |
| `waf_detect.py` | WAF Detection | Fingerprints WAF/IPS (ModSecurity, F5, Cloudflare, Akamai, etc.) |
| `waf_bypass.py` | WAF Bypass | URL encoding, Unicode normalization, case mutation, comment injection |
| `coverage_check.py` | Crawl Coverage | Reports crawl metrics: pages, parameters, methods found |
| `debug_mode.py` | Debug Mode Enabled | Debug endpoints, stack traces in responses, verbose error pages |
| `cve_check.py` | CVE Fingerprinting | Matches response signatures against known CVE indicators |
| `ai_cve.py` | AI CVE Research | AI-generated targeted Nuclei templates for detected technology stack |
| `dnssec.py` | DNS Security | DNSSEC validation, SPF/DMARC record presence and strength |
| `rate_limit.py` | Rate Limit | Missing brute-force protection on login/API endpoints |
| `captcha_check.py` | Weak CAPTCHA | Client-side validation, predictable CAPTCHA seeds |
| `templates.py` | Nuclei Templates | Runs built-in YAML templates (59 bundled); `--nuclei-templates` for 7,400+ community HTTP templates |

---

## Module Development

### Minimal module

```python
# scanner/modules/my_check.py
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
import httpx

def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    # probe page.url ...
    if something_bad:
        findings.append(Finding(
            title="My Check Failed",
            severity=Severity.HIGH,
            url=page.url,
            parameter="id",
            payload="<probe>",
            evidence="Raw response excerpt",
            description="Explanation of the issue.",
            remediation="How to fix it.",
            cwe="CWE-79",
            cvss=7.5,
            owasp_category="A03:2021 Injection",
            standards=["ISO27001-8.28"],
            confidence=0.9,
        ))
    return findings
```

### Custom plugin (no code changes required)

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

KageSec auto-loads `.py` files from `~/.kagesec/plugins/` at startup.
