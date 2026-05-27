"""
BREACH oracle check (CVE-2013-3587).

BREACH exploits HTTP compression (gzip/brotli/deflate) combined with secret
values that are reflected in the response body (CSRF token, session ID, etc.)
to recover secrets via adaptive chosen-plaintext attacks.

Conditions for vulnerability:
  1. Response is compressed (Content-Encoding: gzip/br/deflate)
  2. Response body contains what looks like a secret token (CSRF, session)
  3. The page accepts user-controlled query parameters that are reflected in body
"""
import re
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

_SECRET_PATTERNS = [
    re.compile(r'<input[^>]+name=["\']_?csrf[_-]?token["\'][^>]*value=["\']([A-Za-z0-9+/=_\-]{20,})["\']', re.IGNORECASE),
    re.compile(r'<meta[^>]+name=["\']csrf[_-]?token["\'][^>]*content=["\']([A-Za-z0-9+/=_\-]{20,})["\']', re.IGNORECASE),
    re.compile(r'"csrfToken"\s*:\s*"([A-Za-z0-9+/=_\-]{20,})"', re.IGNORECASE),
    re.compile(r'"authenticity_token"\s*:\s*"([A-Za-z0-9+/=_\-]{20,})"', re.IGNORECASE),
    # Session identifiers reflected in body (less common but possible)
    re.compile(r'name=["\']session[_-]?id["\'][^>]*value=["\']([A-Za-z0-9]{32,})["\']', re.IGNORECASE),
]

_COMPRESS_ENCODINGS = {"gzip", "br", "deflate", "compress", "zstd"}


def test(page: CrawlResult, client) -> List[Finding]:
    # Only HTML pages
    ct = page.headers.get("content-type", "")
    if "html" not in ct:
        return []

    # Check if compression is active
    encoding = page.headers.get("content-encoding", "").lower().strip()
    # httpx decompresses automatically, but the header still tells us compression was used
    if not encoding or encoding == "identity":
        # Check if server varies on Accept-Encoding (might compress for some clients)
        vary = page.headers.get("vary", "").lower()
        if "accept-encoding" not in vary:
            return []
        # Make a fresh request with Accept-Encoding to detect compression
        try:
            resp = client.get(page.url, headers={"Accept-Encoding": "gzip, deflate, br"})
            encoding = resp.headers.get("content-encoding", "").lower()
            if not encoding or encoding == "identity":
                return []
        except Exception:
            return []

    encoding_part = encoding.split(",")[0].strip()
    if encoding_part not in _COMPRESS_ENCODINGS:
        return []

    # Check if body contains secret tokens
    secret_found = None
    for pattern in _SECRET_PATTERNS:
        m = pattern.search(page.body)
        if m:
            secret_found = m.group(0)[:80]  # truncate for evidence
            break

    if not secret_found:
        return []

    # Check if user input is reflected (query param reflection = BREACH oracle)
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(page.url)
    qs = parse_qs(parsed.query)

    reflection_confirmed = False
    if qs:
        for param, values in qs.items():
            if values and values[0] in page.body:
                reflection_confirmed = True
                break

    confidence = 0.85 if reflection_confirmed else 0.60

    return [Finding(
        title="BREACH: HTTP Compression Oracle on Page with Secret Token",
        severity=Severity.MEDIUM,
        url=page.url,
        parameter=None,
        payload=None,
        evidence=(
            f"Content-Encoding: {encoding} | Secret token in body: {secret_found}"
            + (f" | Query param reflected in body (oracle confirmed)" if reflection_confirmed else "")
        ),
        description=(
            "The BREACH attack (CVE-2013-3587) allows an active network attacker to recover "
            "secret values (CSRF tokens, session IDs) from HTTPS-compressed responses by "
            "measuring response size differences while injecting chosen plaintext via query "
            f"parameters. This page uses {encoding} compression and contains a secret token "
            "in the response body, making it a candidate for BREACH exploitation."
        ),
        remediation=(
            "1. Disable HTTP compression for pages that contain CSRF tokens or session secrets. "
            "2. Randomise or mask CSRF tokens per request (token masking / double-submit pattern). "
            "3. Set a 'length=random_padding' query parameter to inflate response sizes unpredictably. "
            "4. Use the SameSite cookie attribute to reduce CSRF attack surface."
        ),
        owasp_category="A02:2021 Cryptographic Failures",
        cwe="CWE-311",
        cvss=5.9,
        confidence=confidence,
        standards={"OWASP": "A02:2021", "CWE": "CWE-311", "CVE": "CVE-2013-3587"},
    )]
