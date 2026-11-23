# Compliance Mapping

KageSec maps findings to four compliance standards. Use `--compliance` to generate a compliance-scoped report.

```bash
kagesec scan https://target.example.com --compliance iso27001 gdpr hipaa appi
```

---

## Coverage Summary

| Standard | Total Controls | DAST-Testable | KageSec Covers |
|---|---|---|---|
| ISO 27001:2022 | 93 | ~20–25 | 20 (19 auto + 1 manual) |
| HIPAA | 75+ | ~15 | 14 (11 auto + 3 manual) |
| GDPR | 99 articles | ~10 | 10 (6 auto + 4 manual) |
| APPI (Japan) | 87+ articles | ~10 | 12 (6 auto + 6 manual) |

"Auto" = fully automated DAST testing. "Manual" = KageSec flags the concern but human review is required for full verification.

---

## ISO 27001:2022

Relevant controls detected by KageSec:

| Control | Description | Modules |
|---|---|---|
| 8.8 — Vulnerability management | Known CVEs and misconfigurations | `cve_check`, `templates`, `ai_cve` |
| 8.9 — Configuration management | Debug mode, exposed admin panels | `debug_mode`, `templates` |
| 8.23 — Web filtering | Open redirect, SSRF | `open_redirect`, `ssrf` |
| 8.24 — Cryptography | TLS version, weak ciphers, HTTP without HTTPS | `tls` |
| 8.25 — Security in development | Injection flaws (XSS, SQLi, SSTI, etc.) | `xss`, `sqli`, `ssti`, `xxe`, `cmd_injection` |
| 8.26 — Application security requirements | Auth bypass, session fixation, IDOR | `auth_bypass`, `session_fixation`, `idor` |
| 8.28 — Secure coding | CSRF, parameter pollution, prototype pollution | `csrf`, `http_param_pollution`, `prototype_pollution` |
| 8.29 — Security testing | Coverage metrics, parameter discovery | `coverage_check`, `param_discovery` |

---

## HIPAA

HIPAA Technical Safeguards relevant to DAST:

| Safeguard | Description | Modules |
|---|---|---|
| 164.312(a)(1) — Access Control | Auth bypass, default credentials, IDOR | `auth_bypass`, `idor`, `jwt_attacks` |
| 164.312(a)(2)(iv) — Encryption | TLS, session token entropy | `tls`, `session_entropy` |
| 164.312(b) — Audit Controls | Debug mode, verbose errors exposing ePHI | `debug_mode`, `version_disclosure` |
| 164.312(c) — Integrity | Request tampering, HTTP parameter pollution | `http_param_pollution`, `cache_poisoning` |
| 164.312(d) — Authentication | Session fixation, CSRF, weak session tokens | `session_fixation`, `csrf`, `session_entropy` |
| 164.312(e) — Transmission Security | HTTP without HTTPS, TLS weaknesses | `tls` |

---

## GDPR

GDPR articles testable via DAST:

| Article | Description | Modules |
|---|---|---|
| Art. 5 — Data minimization | Exposed backup files, API key leaks | `exposed_files`, `api_key_leak` |
| Art. 25 — Data protection by design | Missing security headers, no HTTPS | `security_headers`, `tls` |
| Art. 32 — Security of processing | Injection vulnerabilities, auth weaknesses | `sqli`, `xss`, `auth_bypass`, `csrf` |
| Art. 33 — Breach notification | Credential exposure in HaveIBeenPwned | `breach` |
| Art. 35 — Data protection impact | SSRF, XXE enabling data exfiltration | `ssrf`, `xxe` |

---

## APPI (Japan)

Act on Protection of Personal Information articles testable via DAST:

| Article | Description | Modules |
|---|---|---|
| Art. 20 — Safety management measures | TLS, secure cookies, session management | `tls`, `cookie_security`, `session_entropy` |
| Art. 21 — Supervision of employees | Debug mode, verbose errors | `debug_mode` |
| Art. 22 — Supervision of contractors | API key leakage, exposed files | `api_key_leak`, `exposed_files` |
| Art. 24 — Third-party provision | CORS misconfiguration, open redirect | `cors`, `open_redirect` |
| Art. 26 — Notification of leakage | Credential exposure, version disclosure | `breach`, `version_disclosure` |

---

## Report Output

Compliance-scoped reports include:
- Control-by-control status (PASS / FAIL / MANUAL REVIEW REQUIRED)
- Mapping of each finding to specific control IDs
- Remediation guidance framed in compliance language

```bash
# JSON with compliance mapping
kagesec scan https://target.example.com --compliance iso27001 hipaa --output json

# PDF for auditors
kagesec scan https://target.example.com --compliance iso27001 gdpr hipaa appi --output pdf
```

Finding objects include a `standards` field listing the specific control IDs:

```json
{
  "title": "TLS Certificate Expired",
  "standards": ["ISO27001-8.24", "HIPAA-164.312e", "GDPR-Art32"]
}
```

---

## Limitations

DAST can only test what is externally observable. Controls that require:
- Access to source code (static analysis)
- Internal system configuration review
- Policy and process documentation review
- Database-level access controls
- Physical security measures

...are outside DAST scope and require separate assessment. KageSec marks these as "manual review required" in compliance reports.
