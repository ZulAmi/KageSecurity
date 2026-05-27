import re
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

# Paths that strongly imply a human-interactive sensitive action
_SENSITIVE_PATH_PATTERNS = re.compile(
    r"/(login|signin|sign-in|register|signup|sign-up|forgot[_-]?password|reset[_-]?password"
    r"|password[_-]?reset|checkout|payment|pay|subscribe|contact|feedback|comment|review"
    r"|mfa|2fa|otp|verify|activate|register|create[_-]?account)",
    re.IGNORECASE,
)

# Patterns that indicate a CAPTCHA widget is present
_CAPTCHA_INDICATORS = [
    # reCAPTCHA v2 / v3
    r'google\.com/recaptcha',
    r'grecaptcha',
    r'g-recaptcha',
    r'data-sitekey',
    # hCaptcha
    r'hcaptcha\.com',
    r'h-captcha',
    # Cloudflare Turnstile
    r'challenges\.cloudflare\.com',
    r'cf-turnstile',
    # Arkose Labs / FunCaptcha
    r'arkoselabs\.com',
    r'funcaptcha',
    # Generic custom tokens
    r'captcha_token',
    r'captcha[_-]?response',
]
_CAPTCHA_RE = re.compile("|".join(_CAPTCHA_INDICATORS), re.IGNORECASE)


def test(page: CrawlResult, client) -> List[Finding]:
    if not page.body or not page.forms:
        return []

    if not _SENSITIVE_PATH_PATTERNS.search(page.url):
        # Also check form action URLs
        has_sensitive_form = any(
            _SENSITIVE_PATH_PATTERNS.search(f.get("action", ""))
            for f in page.forms
        )
        if not has_sensitive_form:
            return []

    # Page is sensitive — check for CAPTCHA presence
    if _CAPTCHA_RE.search(page.body):
        return []

    # Check for rate-limiting headers that might substitute for CAPTCHA on this page
    rate_headers = ("x-ratelimit-limit", "retry-after", "x-rate-limit")
    if any(h in page.headers for h in rate_headers):
        return []

    # Confirm there is at least one form with a text/password input (real form, not search)
    has_real_form = False
    for form in page.forms:
        for inp in form.get("inputs", []):
            if inp.get("type", "text") in ("text", "email", "password", "tel"):
                has_real_form = True
                break

    if not has_real_form:
        return []

    return [Finding(
        title="No CAPTCHA Protection on Sensitive Endpoint",
        severity=Severity.MEDIUM,
        url=page.url,
        parameter=None,
        payload=None,
        evidence=f"Sensitive form found at {page.url} with no CAPTCHA widget detected in page source.",
        description=(
            f"The page at {page.url} appears to handle a sensitive action (login, registration, "
            "password reset, or payment) but does not include any CAPTCHA or bot-detection challenge. "
            "This allows automated bots to perform brute-force attacks, credential stuffing, "
            "account creation spam, or automated form submission at scale."
        ),
        remediation=(
            "Integrate a CAPTCHA solution (Google reCAPTCHA v3, hCaptcha, or Cloudflare Turnstile) "
            "on all sensitive forms. For login endpoints, combine with account lockout and "
            "rate limiting for defence in depth."
        ),
        owasp_category="A07:2021 Identification and Authentication Failures",
        cwe="CWE-307",
        cvss=4.9,
        confidence=0.75,
        standards={"OWASP": "A07:2021", "CWE": "CWE-307"},
    )]
