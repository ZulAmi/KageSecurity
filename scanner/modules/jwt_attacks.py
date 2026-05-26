import base64
import json
import hmac
import hashlib
import httpx
from typing import List, Optional
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult


def _b64_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _parse_jwt(token: str) -> Optional[tuple]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None


def _find_jwt(page: CrawlResult) -> Optional[str]:
    for key, value in page.headers.items():
        if key.lower() == "authorization":
            if value.lower().startswith("bearer "):
                return value[7:]
        if key.lower() == "set-cookie" and "jwt" in value.lower():
            for part in value.split(";"):
                if "=" in part and "jwt" in part.lower():
                    return part.split("=", 1)[1].strip()
    return None


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    token = _find_jwt(page)
    if not token:
        return []

    parsed = _parse_jwt(token)
    if not parsed:
        return []

    header, payload, signature = parsed

    # Test 1: alg:none attack
    none_header = _b64_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    none_payload = _b64_encode(json.dumps(payload).encode())
    none_token = f"{none_header}.{none_payload}."

    try:
        resp = client.get(page.url, headers={"Authorization": f"Bearer {none_token}"})
        if resp.status_code == 200 and resp.text == _get_original(client, page):
            findings.append(Finding(
                title="JWT Algorithm None Attack — Signature Verification Bypassed",
                severity=Severity.CRITICAL,
                url=page.url,
                parameter="Authorization header",
                payload=none_token[:80] + "...",
                evidence="Server accepted JWT with alg:none (no signature), returned identical authenticated response",
                description=(
                    "The server accepts JWTs with algorithm set to 'none', meaning the signature is not verified. "
                    "An attacker can forge any JWT claims without knowing the secret key."
                ),
                remediation=(
                    "Reject JWTs with alg:none. Explicitly specify allowed algorithms in your JWT library. "
                    "Never rely on the algorithm specified in the JWT header itself."
                ),
                cwe="CWE-347",
                cvss=9.8,
                owasp_category="A07:2021 Identification and Authentication Failures",
                standards=["ISO27001-8.8", "HIPAA-164.312a", "GDPR-Art32"],
                confidence=1.0,
            ))
    except Exception:
        pass

    # Test 2: Weak HMAC secret (common secrets)
    if header.get("alg", "").startswith("HS"):
        weak_secrets = ["secret", "password", "123456", "key", "jwt_secret", "supersecret", "changeme", ""]
        signing_input = f"{token.rsplit('.', 1)[0]}".encode()
        for secret in weak_secrets:
            expected_sig = _b64_encode(
                hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            )
            if expected_sig == signature:
                findings.append(Finding(
                    title="JWT Signed with Weak Secret Key",
                    severity=Severity.CRITICAL,
                    url=page.url,
                    parameter="JWT signature",
                    payload=f"secret='{secret}'",
                    evidence=f"JWT signature verified with weak secret: '{secret}'",
                    description=(
                        "The JWT is signed with a trivially guessable secret. "
                        "An attacker can forge tokens with arbitrary claims including admin privileges."
                    ),
                    remediation=(
                        "Use a cryptographically random secret of at least 256 bits. "
                        "Rotate the secret immediately. Consider RS256 (asymmetric) instead of HS256."
                    ),
                    cwe="CWE-347",
                    cvss=9.8,
                    owasp_category="A07:2021 Identification and Authentication Failures",
                    standards=["ISO27001-8.24", "HIPAA-164.312a"],
                    confidence=1.0,
                ))
                break

    # Test 3: Missing expiry claim
    if "exp" not in payload:
        findings.append(Finding(
            title="JWT Missing Expiry Claim (exp)",
            severity=Severity.MEDIUM,
            url=page.url,
            parameter="JWT payload",
            payload=None,
            evidence=f"JWT payload does not contain 'exp' claim: {json.dumps(payload)[:120]}",
            description="JWTs without expiry never become invalid, meaning stolen tokens can be used indefinitely.",
            remediation="Always include an 'exp' claim. Set a short expiry (15 min for access tokens, longer for refresh tokens).",
            cwe="CWE-613",
            cvss=5.4,
            owasp_category="A07:2021 Identification and Authentication Failures",
            standards=["ISO27001-8.8", "HIPAA-164.312a"],
            confidence=1.0,
        ))

    return findings


def _get_original(client: httpx.Client, page: CrawlResult) -> str:
    try:
        return client.get(page.url).text
    except Exception:
        return ""
