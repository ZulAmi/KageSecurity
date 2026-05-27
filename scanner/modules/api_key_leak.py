import re
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

# (pattern_name, regex, severity, cwe, hint)
_PATTERNS = [
    ("Google API Key",       r'AIza[0-9A-Za-z\-_]{35}',                          Severity.HIGH,     "CWE-312", "Restrict the key in Google Cloud Console to specific APIs and referrers."),
    ("Google OAuth Client",  r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', Severity.MEDIUM, "CWE-312", "Rotate and restrict OAuth client to authorised redirect URIs."),
    ("AWS Access Key ID",    r'AKIA[0-9A-Z]{16}',                                 Severity.CRITICAL, "CWE-312", "Revoke immediately via AWS IAM; use instance roles instead."),
    ("AWS Secret Key",       r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]', Severity.CRITICAL, "CWE-312", "Revoke immediately; never embed AWS secrets in client-side code."),
    ("Stripe Secret Key",    r'sk_live_[0-9a-zA-Z]{24,}',                         Severity.CRITICAL, "CWE-312", "Revoke in Stripe dashboard immediately; only use on server side."),
    ("Stripe Publishable",   r'pk_live_[0-9a-zA-Z]{24,}',                         Severity.LOW,      "CWE-312", "Publishable keys are public but confirm scope is restricted."),
    ("Stripe Test Key",      r'sk_test_[0-9a-zA-Z]{24,}',                         Severity.MEDIUM,   "CWE-312", "Test keys should not appear in production client-side code."),
    ("OpenAI API Key",       r'sk-[A-Za-z0-9]{48}',                               Severity.HIGH,     "CWE-312", "Revoke in OpenAI dashboard; keys must stay server-side only."),
    ("GitHub Token",         r'ghp_[0-9a-zA-Z]{36}',                              Severity.HIGH,     "CWE-312", "Revoke immediately via GitHub Settings → Developer settings."),
    ("GitHub OAuth Token",   r'gho_[0-9a-zA-Z]{36}',                              Severity.HIGH,     "CWE-312", "Revoke immediately via GitHub Settings → Developer settings."),
    ("GitHub Actions Token", r'ghs_[0-9a-zA-Z]{36}',                              Severity.HIGH,     "CWE-312", "Rotate via GitHub Actions secrets management."),
    ("Slack Bot Token",      r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}',        Severity.HIGH,     "CWE-312", "Revoke in Slack API dashboard and regenerate."),
    ("Slack App Token",      r'xapp-[0-9]-[A-Z0-9]{10}-[0-9]{13}-[a-f0-9]{64}',  Severity.HIGH,     "CWE-312", "Revoke in Slack API dashboard and regenerate."),
    ("Twilio Account SID",   r'AC[0-9a-fA-F]{32}',                                Severity.MEDIUM,   "CWE-312", "Audit Twilio usage logs; rotate credentials via Twilio Console."),
    ("Twilio Auth Token",    r'(?i)twilio.{0,20}[\'"][0-9a-fA-F]{32}[\'"]',       Severity.HIGH,     "CWE-312", "Rotate immediately via Twilio Console."),
    ("SendGrid API Key",     r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',      Severity.HIGH,     "CWE-312", "Revoke via SendGrid API Keys dashboard."),
    ("Firebase Config",      r'"apiKey"\s*:\s*"AIza[0-9A-Za-z\-_]{35}"',          Severity.MEDIUM,   "CWE-312", "Firebase web apiKey is public by design, but ensure database rules are locked down."),
    ("Mailgun API Key",      r'key-[0-9a-zA-Z]{32}',                              Severity.HIGH,     "CWE-312", "Revoke via Mailgun API Keys settings."),
    ("HuggingFace Token",    r'hf_[A-Za-z0-9]{36,}',                              Severity.HIGH,     "CWE-312", "Revoke via HuggingFace Settings → Access Tokens."),
    ("Generic Secret",       r'(?i)(password|secret|api[_-]?key|auth[_-]?token)\s*[:=]\s*[\'"][A-Za-z0-9+/=_\-]{20,}[\'"]', Severity.MEDIUM, "CWE-312", "Audit the exposed credential; rotate and move to environment variables."),
]

# URLs that are almost always false positives (CDN bundles, minified libs)
_FP_URL_FRAGMENTS = ("jquery", "bootstrap", "lodash", "react", "angular", "vue", "polyfill", "vendor", "chunk")


def test(page: CrawlResult, client) -> List[Finding]:
    if not page.body:
        return []

    # Only scan HTML and JS responses
    ct = page.headers.get("content-type", "")
    if not any(t in ct for t in ("html", "javascript", "json", "text")):
        return []

    url_lower = page.url.lower()
    if any(fp in url_lower for fp in _FP_URL_FRAGMENTS):
        return []

    findings = []
    seen: set[str] = set()

    for name, pattern, severity, cwe, remediation in _PATTERNS:
        for match in re.finditer(pattern, page.body):
            token = match.group(0)
            # Deduplicate: same key type + same first 16 chars
            dedup_key = f"{name}:{token[:16]}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Redact for display: show first 8 + last 4
            display = token[:8] + "…" + token[-4:] if len(token) > 12 else token[:4] + "…"

            findings.append(Finding(
                title=f"Exposed {name} in Client-Side Code",
                severity=severity,
                url=page.url,
                parameter=None,
                payload=None,
                evidence=f"Pattern '{name}' matched: {display}",
                description=(
                    f"A {name} was found embedded in the client-accessible page at {page.url}. "
                    "API keys and secrets exposed in HTML or JavaScript are readable by anyone who "
                    "views the page source, enabling unauthorised use of the associated service."
                ),
                remediation=remediation,
                owasp_category="A02:2021 Cryptographic Failures",
                cwe=cwe,
                cvss=_cvss(severity),
                confidence=0.80,
                standards={"OWASP": "A02:2021", "CWE": cwe},
            ))

    return findings


def _cvss(severity: Severity) -> float:
    return {Severity.CRITICAL: 9.1, Severity.HIGH: 7.5, Severity.MEDIUM: 5.3, Severity.LOW: 2.7}.get(severity, 0.0)
