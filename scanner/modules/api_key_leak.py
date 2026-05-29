"""
Secret and API key detection in client-accessible HTML/JS.

Improvements over Nuclei community templates:
- Context-aware: broad patterns require a nearby identifier within 150 chars
  (eliminates the false-positive Gemini/FCM/Razorpay hits Nuclei produces)
- Entropy gate: Generic Credential requires Shannon entropy > 3.5 on the value
- Placeholder filter: skips example/dummy/xxxx values
- Dedup by canonical token: a Firebase apiKey won't fire both Firebase (MEDIUM)
  and Google Gemini (HIGH) for the same key value
- Severity accuracy: Firebase web apiKey is MEDIUM (public by design),
  Razorpay Key ID is LOW (publishable), Stripe sk_live is CRITICAL
- Patterns ordered CRITICAL → LOW so highest-severity wins dedup races
"""
import re
import math
from typing import List

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

# (name, compiled_re, severity, cwe, remediation, context_re | None)
#
# context_re: compiled regex searched in the _CONTEXT_WINDOW chars BEFORE the
# match position.  None means the pattern prefix is specific enough on its own.
_PATTERNS: list[tuple] = [
    # ── CRITICAL ──────────────────────────────────────────────────────────────
    ("AWS Access Key ID",
     re.compile(r'AKIA[0-9A-Z]{16}'),
     Severity.CRITICAL, "CWE-312",
     "Revoke immediately via AWS IAM. Use instance roles or IAM Roles Anywhere instead.",
     None),

    ("AWS Secret Access Key",
     re.compile(r'(?i)aws.{0,30}secret.{0,30}[\'"][0-9a-zA-Z/+]{40}[\'"]'),
     Severity.CRITICAL, "CWE-312",
     "Revoke immediately via AWS IAM. Never embed AWS secrets in client-side code.",
     None),

    ("Stripe Secret Key",
     re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
     Severity.CRITICAL, "CWE-312",
     "Revoke in Stripe dashboard immediately. Secret keys must only be used server-side.",
     None),

    # ── HIGH ──────────────────────────────────────────────────────────────────
    # Gemini listed before generic Google key so it wins the dedup race
    ("Google Gemini API Key",
     re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
     Severity.HIGH, "CWE-312",
     "Revoke in Google AI Studio and regenerate. Gemini keys are server-side credentials "
     "and must never appear in client-side code.",
     re.compile(r'(?i)(gemini|generative.?ai|GEMINI_API_KEY)', re.IGNORECASE)),

    # Old OpenAI key format — T3BlbkFJ is base64("OpenAI"), near-zero false positive rate
    ("OpenAI API Key",
     re.compile(r'sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}'),
     Severity.HIGH, "CWE-312",
     "Revoke in OpenAI dashboard. Keys must stay server-side only.",
     None),

    ("OpenAI Project Key",
     re.compile(r'sk-proj-[A-Za-z0-9_\-]{48,}'),
     Severity.HIGH, "CWE-312",
     "Revoke in OpenAI dashboard. Keys must stay server-side only.",
     None),

    ("GitHub Personal Access Token",
     re.compile(r'ghp_[0-9a-zA-Z]{36}'),
     Severity.HIGH, "CWE-312",
     "Revoke immediately via GitHub Settings → Developer settings → Personal access tokens.",
     None),

    ("GitHub OAuth App Token",
     re.compile(r'gho_[0-9a-zA-Z]{36}'),
     Severity.HIGH, "CWE-312",
     "Revoke immediately via GitHub Settings → Developer settings.",
     None),

    ("GitHub Actions Token",
     re.compile(r'ghs_[0-9a-zA-Z]{36}'),
     Severity.HIGH, "CWE-312",
     "Rotate via GitHub Actions secrets management.",
     None),

    ("Slack Bot Token",
     re.compile(r'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}'),
     Severity.HIGH, "CWE-312",
     "Revoke in Slack API dashboard and regenerate.",
     None),

    ("Slack App Token",
     re.compile(r'xapp-[0-9]-[A-Z0-9]{10}-[0-9]{13}-[a-f0-9]{64}'),
     Severity.HIGH, "CWE-312",
     "Revoke in Slack API dashboard and regenerate.",
     None),

    ("SendGrid API Key",
     re.compile(r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}'),
     Severity.HIGH, "CWE-312",
     "Revoke via SendGrid API Keys dashboard.",
     None),

    ("HuggingFace Token",
     re.compile(r'hf_[A-Za-z0-9]{36,}'),
     Severity.HIGH, "CWE-312",
     "Revoke via HuggingFace Settings → Access Tokens.",
     None),

    ("Twilio Auth Token",
     re.compile(r'(?i)twilio.{0,30}[\'"][0-9a-fA-F]{32}[\'"]'),
     Severity.HIGH, "CWE-312",
     "Rotate immediately via Twilio Console.",
     None),

    # AAAA...APA91b structure is specific enough for near-zero false positives
    ("FCM Server Key (Legacy)",
     re.compile(r'AAAA[A-Za-z0-9_-]{7}:APA91[bB][A-Za-z0-9_-]{100,}'),
     Severity.HIGH, "CWE-312",
     "Migrate to FCM v1 API with service accounts. Revoke legacy keys in "
     "Firebase Console → Project settings → Cloud Messaging.",
     None),

    # "key-{32}" is too common — require a mailgun identifier nearby
    ("Mailgun API Key",
     re.compile(r'key-[0-9a-zA-Z]{32}'),
     Severity.HIGH, "CWE-312",
     "Revoke via Mailgun API Keys settings.",
     re.compile(r'(?i)(mailgun|mg\.)', re.IGNORECASE)),

    # ── MEDIUM ────────────────────────────────────────────────────────────────
    # Firebase web apiKey is public by design — MEDIUM not HIGH.
    # Listed before the generic Google API Key so the more specific pattern wins.
    ("Firebase Web API Key",
     re.compile(r'"apiKey"\s*:\s*"(AIza[0-9A-Za-z\-_]{35})"'),
     Severity.MEDIUM, "CWE-312",
     "Firebase web apiKey is intentionally public, but ensure Firestore/RTDB "
     "security rules deny unauthorised reads and writes.",
     None),

    # Generic Google API key (Maps, YouTube, Vision, etc.) — require context
    # because AIza prefix alone triggers Nuclei false positives
    ("Google API Key",
     re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
     Severity.MEDIUM, "CWE-312",
     "Restrict the key in Google Cloud Console to specific APIs and "
     "authorised referrers/IPs. Rotate if already exposed without restrictions.",
     re.compile(r'(?i)(maps|youtube|vision|translate|api[_\-]?key|google)', re.IGNORECASE)),

    # "AC" + 32 hex chars is too common — require twilio context
    ("Twilio Account SID",
     re.compile(r'AC[0-9a-fA-F]{32}'),
     Severity.MEDIUM, "CWE-312",
     "Audit Twilio usage logs; rotate credentials via Twilio Console.",
     re.compile(r'(?i)(twilio|account.?sid)', re.IGNORECASE)),

    ("Stripe Test Secret Key",
     re.compile(r'sk_test_[0-9a-zA-Z]{24,}'),
     Severity.MEDIUM, "CWE-312",
     "Test secret keys must not appear in production client-side code. "
     "Use environment variables.",
     None),

    # ── LOW ───────────────────────────────────────────────────────────────────
    # Client IDs are public by design (like Stripe pk_live / Razorpay Key ID)
    ("Google OAuth Client ID",
     re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
     Severity.LOW, "CWE-312",
     "Client IDs are public by design, but rotate the associated client secret "
     "and restrict authorised redirect URIs.",
     None),

    ("Stripe Publishable Key",
     re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),
     Severity.LOW, "CWE-312",
     "Publishable keys are public by design. Confirm only pk_ (never sk_) is used client-side.",
     None),

    # Razorpay Key ID is a publishable identifier — the dangerous one is rzp_*_secret
    ("Razorpay Key ID",
     re.compile(r'rzp_(live|test)_[a-zA-Z0-9]{14,}'),
     Severity.LOW, "CWE-312",
     "Razorpay Key ID is a public identifier. Ensure the Razorpay Key Secret is "
     "never exposed client-side.",
     None),

    # ── Context-anchored generic catch-all (lowest priority, entropy-gated) ──
    ("Generic Credential",
     re.compile(r'(?i)(password|secret|api[_-]?key|auth[_-]?token)\s*[:=]\s*[\'"][A-Za-z0-9+/=_\-]{20,}[\'"]'),
     Severity.MEDIUM, "CWE-312",
     "Audit the exposed credential. Rotate it and move server-side using "
     "environment variables or a secrets manager.",
     None),
]

# Common placeholder / example values that are not real secrets
_PLACEHOLDER_RE = re.compile(
    r'(?i)(example|your[_-]?api[_-]?key|insert[_-]?here|x{4,}|1{6,}|test123'
    r'|dummy|placeholder|sample|replace[_-]?me|changeme|todo|your[-_]?key)',
)

# Used to extract the canonical AIza... value from Firebase-style matches
# so that Firebase Web API Key and Google Gemini API Key dedup against each other
_GOOGLE_KEY_RE = re.compile(r'AIza[0-9A-Za-z\-_]{35}')

_FP_URL_FRAGMENTS = (
    "jquery", "bootstrap", "lodash", "react", "angular", "vue",
    "polyfill", "vendor", "chunk", "modernizr", "d3.min", "moment",
    "three.min", "underscore", "backbone", "ember", "knockout",
)

_CONTEXT_WINDOW = 150  # chars before match to search for context_re


def _entropy(s: str) -> float:
    if len(s) < 8:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def _canonical(token: str) -> str:
    """Normalise overlapping patterns to the same dedup key."""
    m = _GOOGLE_KEY_RE.search(token)
    return m.group(0) if m else token


def test(page: CrawlResult, client) -> List[Finding]:
    if not page.body:
        return []

    ct = page.headers.get("content-type", "")
    if not any(t in ct for t in ("html", "javascript", "json", "text")):
        return []

    url_lower = page.url.lower()
    if any(fp in url_lower for fp in _FP_URL_FRAGMENTS):
        return []

    findings: List[Finding] = []
    # Dedup by canonical token prefix — highest-severity pattern wins because
    # _PATTERNS is ordered CRITICAL → LOW
    seen: set[str] = set()

    for name, pattern, severity, cwe, remediation, context_re in _PATTERNS:
        for match in re.finditer(pattern, page.body):
            token = match.group(0)

            # Skip known placeholder / example values
            if _PLACEHOLDER_RE.search(token):
                continue

            # Context gate: required for patterns whose prefix is too common
            if context_re is not None:
                window_start = max(0, match.start() - _CONTEXT_WINDOW)
                window = page.body[window_start: match.start()]
                if not context_re.search(window):
                    continue

            # Entropy gate: Generic Credential must have a high-entropy value
            if name == "Generic Credential":
                val_m = re.search(r'[\'"]([A-Za-z0-9+/=_\-]{20,})[\'"]', token)
                if not val_m or _entropy(val_m.group(1)) < 3.5:
                    continue

            # Dedup: first (highest-priority) match for a canonical token wins
            canon = _canonical(token)[:16]
            if canon in seen:
                continue
            seen.add(canon)

            display = token[:8] + "…" + token[-4:] if len(token) > 12 else token[:4] + "…"
            confidence = 0.90 if context_re is None else 0.85

            findings.append(Finding(
                title=f"Exposed {name} in Client-Side Code",
                severity=severity,
                url=page.url,
                parameter=None,
                payload=None,
                evidence=f"Pattern '{name}' matched: {display}",
                description=(
                    f"A {name} was found embedded in the client-accessible resource at {page.url}. "
                    "Secrets exposed in HTML or JavaScript are readable by anyone viewing the source, "
                    "enabling unauthorised use of the associated service."
                ),
                remediation=remediation,
                owasp_category="A02:2021 Cryptographic Failures",
                cwe=cwe,
                cvss=_cvss(severity),
                confidence=confidence,
                standards={"OWASP": "A02:2021", "CWE": cwe},
            ))

    return findings


def _cvss(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 9.1,
        Severity.HIGH:     7.5,
        Severity.MEDIUM:   5.3,
        Severity.LOW:      2.7,
    }.get(severity, 0.0)
