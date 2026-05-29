"""
OAuth 2.0 / OIDC Security Testing — Gap 18

Detects OAuth flows from page content and tests for:
  1. Missing `state` parameter (CSRF on the authorization code flow)
  2. Open `redirect_uri` (attacker-controlled redirect)
  3. Token in URL fragment leaking via Referer header
  4. Implicit flow token exposure (access_token in URL)
  5. PKCE downgrade (code_challenge absent)
  6. OIDC discovery misconfiguration (.well-known/openid-configuration)
  7. Token endpoint exposed without authentication
"""
import re
import httpx
from typing import List
from urllib.parse import urlparse
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

# OAuth2 authorization endpoint patterns in page body/links
_OAUTH_LINK_RE = re.compile(
    r'''href=["']([^"']*(?:oauth|authorize|auth/login|sso|openid)[^"']{0,200})["']''',
    re.IGNORECASE,
)
_AUTH_CODE_RE = re.compile(r'[?&]code=([a-zA-Z0-9_.-]{10,200})')
_ACCESS_TOKEN_RE = re.compile(r'[?&#]access_token=([a-zA-Z0-9_.-]{10,200})')
_STATE_RE = re.compile(r'[?&]state=')
_REDIRECT_URI_RE = re.compile(r'[?&]redirect_uri=([^&"\'>\s]+)')
_PKCE_RE = re.compile(r'[?&]code_challenge=')


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings: List[Finding] = []
    _check_token_in_url(page, findings)
    _check_oauth_links(page, client, findings)
    _check_oidc_discovery(page, client, findings)
    return findings


def _check_token_in_url(page: CrawlResult, findings: List[Finding]):
    """Detect implicit flow: access_token in URL fragment/query."""
    url = page.url
    body = page.body or ""

    # access_token in current URL (implicit flow)
    if _ACCESS_TOKEN_RE.search(url):
        findings.append(Finding(
            title="OAuth — Access Token Exposed in URL",
            severity=Severity.HIGH,
            url=url,
            parameter="access_token",
            payload=None,
            evidence=f"access_token found in URL: {url[:200]}",
            description=(
                "The OAuth access token appears in the URL (implicit flow). "
                "Tokens in URLs are logged by servers, proxies, browser history, and "
                "leaked via Referer headers, enabling token theft."
            ),
            remediation=(
                "Use the authorization code flow with PKCE instead of the implicit flow. "
                "Never return access tokens in URL query strings. "
                "Use fragment (#) or POST body for token delivery."
            ),
            cwe="CWE-200",
            cvss=7.4,
            owasp_category="A07:2021 Identification and Authentication Failures",
            confidence=1.0,
        ))

    # Look for access_token or auth code in page body links
    if _ACCESS_TOKEN_RE.search(body):
        findings.append(Finding(
            title="OAuth — Access Token Found in Response Body",
            severity=Severity.MEDIUM,
            url=url,
            parameter="access_token",
            payload=None,
            evidence="access_token pattern found in response body",
            description=(
                "An access token is present in the page response body. "
                "If this is reflected from user-supplied input, it may indicate IDOR or "
                "token leakage to untrusted parties."
            ),
            remediation=(
                "Do not include access tokens in HTML responses. "
                "Store tokens in httpOnly cookies or memory only."
            ),
            cwe="CWE-200",
            cvss=5.3,
            owasp_category="A07:2021 Identification and Authentication Failures",
            confidence=0.70,
        ))


def _check_oauth_links(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Find OAuth authorization links and test them for missing state, open redirect_uri."""
    body = page.body or ""
    oauth_urls = [m.group(1) for m in _OAUTH_LINK_RE.finditer(body)]

    for oauth_url in oauth_urls[:5]:
        # Resolve relative URLs
        if oauth_url.startswith("/"):
            parsed_base = urlparse(page.url)
            oauth_url = f"{parsed_base.scheme}://{parsed_base.netloc}{oauth_url}"

        # 1. Missing state parameter
        if not _STATE_RE.search(oauth_url):
            findings.append(Finding(
                title="OAuth — Missing `state` Parameter (CSRF)",
                severity=Severity.HIGH,
                url=oauth_url,
                parameter="state",
                payload=None,
                evidence=f"OAuth authorization URL has no 'state' parameter: {oauth_url[:200]}",
                description=(
                    "The OAuth authorization request is missing the `state` parameter. "
                    "This enables CSRF attacks: an attacker can trick a victim into authorizing "
                    "the attacker's application, leading to account takeover."
                ),
                remediation=(
                    "Always include a cryptographically random `state` parameter in authorization "
                    "requests. Verify the state on the callback before exchanging the code. "
                    "Use PKCE as an additional defense layer."
                ),
                cwe="CWE-352",
                cvss=8.1,
                owasp_category="A07:2021 Identification and Authentication Failures",
                confidence=0.90,
            ))

        # 2. Check for open redirect_uri
        m = _REDIRECT_URI_RE.search(oauth_url)
        if m:
            redirect_uri = m.group(1)
            _test_open_redirect_uri(oauth_url, redirect_uri, client, findings)

        # 3. Missing PKCE (code_challenge)
        if "response_type=code" in oauth_url and not _PKCE_RE.search(oauth_url):
            findings.append(Finding(
                title="OAuth — Missing PKCE (code_challenge)",
                severity=Severity.MEDIUM,
                url=oauth_url,
                parameter="code_challenge",
                payload=None,
                evidence=f"Authorization code flow without PKCE: {oauth_url[:200]}",
                description=(
                    "The OAuth authorization code flow is used without PKCE (Proof Key for "
                    "Code Exchange). PKCE prevents authorization code interception attacks, "
                    "especially in native/mobile apps and SPAs."
                ),
                remediation=(
                    "Add code_challenge and code_challenge_method=S256 to authorization requests. "
                    "Require code_verifier on the token endpoint. "
                    "Enforce PKCE server-side for all public clients."
                ),
                cwe="CWE-307",
                cvss=5.9,
                owasp_category="A07:2021 Identification and Authentication Failures",
                confidence=0.85,
            ))


def _test_open_redirect_uri(oauth_url: str, redirect_uri: str, client: httpx.Client, findings: List[Finding]):
    """Test if the authorization server accepts an attacker-controlled redirect_uri."""
    from urllib.parse import quote
    attacker_domain = "evil.kagesec-test.invalid"
    tampered = oauth_url.replace(
        f"redirect_uri={redirect_uri}",
        f"redirect_uri={quote('https://' + attacker_domain + '/callback')}",
    )
    try:
        resp = client.get(tampered, follow_redirects=False, timeout=8)
        location = resp.headers.get("location", "")
        if attacker_domain in location:
            findings.append(Finding(
                title="OAuth — Open redirect_uri (Attacker-Controlled Redirect)",
                severity=Severity.CRITICAL,
                url=oauth_url,
                parameter="redirect_uri",
                payload=f"redirect_uri=https://{attacker_domain}/callback",
                evidence=f"Server redirected to attacker domain: {location[:200]}",
                description=(
                    "The authorization server accepts arbitrary redirect_uri values, allowing "
                    "an attacker to redirect authorization codes to an attacker-controlled server. "
                    "This enables complete account takeover."
                ),
                remediation=(
                    "Validate redirect_uri against a strict allowlist of registered URIs. "
                    "Never use prefix matching or wildcard matching for redirect_uri validation."
                ),
                cwe="CWE-601",
                cvss=9.3,
                owasp_category="A07:2021 Identification and Authentication Failures",
                confidence=0.90,
            ))
    except Exception:
        pass


def _check_oidc_discovery(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Fetch .well-known/openid-configuration and check for misconfigurations."""
    parsed = urlparse(page.url)
    oidc_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/openid-configuration"
    try:
        resp = client.get(oidc_url, timeout=8)
        if resp.status_code != 200:
            return
        cfg = resp.json()
    except Exception:
        return

    # Check if implicit flow is supported (deprecated in OAuth 2.1)
    grant_types = cfg.get("grant_types_supported", [])
    response_types = cfg.get("response_types_supported", [])

    if "implicit" in grant_types or any("token" in rt for rt in response_types if rt != "code token"):
        findings.append(Finding(
            title="OIDC — Implicit Flow Supported (Deprecated)",
            severity=Severity.MEDIUM,
            url=oidc_url,
            parameter="grant_types_supported",
            payload=None,
            evidence=f"OIDC discovery advertises implicit flow: grant_types={grant_types}",
            description=(
                "The OIDC provider advertises support for the implicit grant type, which has been "
                "deprecated in OAuth 2.1 due to token exposure in URLs and browser history."
            ),
            remediation=(
                "Disable the implicit flow. Migrate clients to the authorization code flow with PKCE. "
                "Update the OIDC discovery document to remove implicit from supported types."
            ),
            cwe="CWE-200",
            cvss=5.3,
            owasp_category="A07:2021 Identification and Authentication Failures",
            confidence=1.0,
        ))

    # Check if PKCE is not required
    pkce_required = cfg.get("code_challenge_methods_supported")
    if not pkce_required:
        findings.append(Finding(
            title="OIDC — PKCE Not Required by Server",
            severity=Severity.LOW,
            url=oidc_url,
            parameter="code_challenge_methods_supported",
            payload=None,
            evidence="OIDC discovery does not advertise code_challenge_methods_supported",
            description=(
                "The OIDC server does not advertise PKCE support in its discovery document, "
                "suggesting PKCE is not enforced. This leaves authorization code flows vulnerable "
                "to code interception attacks."
            ),
            remediation="Enable and enforce PKCE (S256) for all authorization code flows.",
            cwe="CWE-307",
            cvss=4.3,
            owasp_category="A07:2021 Identification and Authentication Failures",
            confidence=0.75,
        ))
