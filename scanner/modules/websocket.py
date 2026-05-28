"""
WebSocket Security module.

Detects:
  1. Unencrypted WebSocket connections (ws:// instead of wss://)
  2. Missing Origin header validation (CSRF over WebSocket)
  3. Message injection (XSS/SQLi payloads in WS frames)

Requires Playwright-based crawl — silently returns [] when no WS connections
were captured (e.g., httpx crawler or pages with no WebSockets).
"""
import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

_INJECTION_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"--><script>alert(1)</script>",
    "' OR '1'='1",
    "{{7*7}}",
    ";id;",
    "../../../../etc/passwd",
    "${7*7}",
    "' AND SLEEP(3)--",
]

# Common WebSocket message formats to try when no observed messages exist (Gap 8)
_PROBE_FRAMES = [
    '{"type":"ping","data":"PAYLOAD"}',
    '{"action":"test","value":"PAYLOAD"}',
    '{"msg":"PAYLOAD"}',
    '{"data":"PAYLOAD"}',
    "PAYLOAD",
]


def test(page: CrawlResult, client: httpx.Client, config=None) -> List[Finding]:
    ws_conns = getattr(page, "websocket_connections", [])
    if not ws_conns:
        return []

    findings = []

    for ws in ws_conns:
        ws_url = ws.get("url", "")
        if not ws_url:
            continue

        # 1. Unencrypted WebSocket (ws:// not wss://)
        if ws_url.startswith("ws://"):
            findings.append(Finding(
                title="Unencrypted WebSocket Connection (ws://)",
                severity=Severity.MEDIUM,
                url=page.url,
                parameter=None,
                payload=None,
                evidence=f"WebSocket connection to {ws_url} uses ws:// (plaintext, not wss://)",
                description=(
                    "WebSocket connections over ws:// transmit data in plaintext. "
                    "An attacker with network access (coffee shop Wi-Fi, MITM) can intercept "
                    "and modify all messages, including authentication tokens and sensitive data."
                ),
                remediation=(
                    "Replace all ws:// connections with wss:// (WebSocket Secure over TLS). "
                    "Enforce HTTPS/WSS in your server configuration and CSP upgrade-insecure-requests."
                ),
                cwe="CWE-319",
                cvss=6.5,
                owasp_category="A02:2021 Cryptographic Failures",
                standards=["ISO27001-8.24", "HIPAA-164.312e", "GDPR-Art32"],
                confidence=1.0,
            ))

        # 2. Missing Origin validation (test with spoofed origin)
        _test_origin_validation(ws_url, page.url, findings)

        # 3. Message injection — replay observed frames or use probe frames (Gap 8)
        messages = ws.get("messages_sent", []) + ws.get("messages_received", [])
        _test_message_injection(ws_url, page.url, messages or [], findings)

    return findings


def _test_origin_validation(ws_url: str, page_url: str, findings: List[Finding]):
    """Attempt to connect with a spoofed Origin header. Successful handshake = no validation."""
    try:
        import websockets.sync.client as _ws_sync  # websockets >= 13
    except ImportError:
        try:
            import websockets  # websockets < 13
            _ws_sync = None
        except ImportError:
            return

    spoofed_origin = "https://evil.kagesec.attacker.com"

    try:
        if _ws_sync is not None:
            with _ws_sync.connect(
                ws_url,
                additional_headers={"Origin": spoofed_origin},
                open_timeout=5,
                close_timeout=3,
            ):
                findings.append(Finding(
                    title="Missing WebSocket Origin Validation",
                    severity=Severity.HIGH,
                    url=page_url,
                    parameter=None,
                    payload=f"Origin: {spoofed_origin}",
                    evidence=f"WebSocket {ws_url} accepted connection from spoofed Origin: {spoofed_origin}",
                    description=(
                        "The WebSocket endpoint does not validate the Origin header, allowing "
                        "cross-site WebSocket hijacking (CSWH). An attacker can use a malicious "
                        "page to make authenticated WebSocket requests on behalf of the victim."
                    ),
                    remediation=(
                        "Validate the Origin header on WebSocket upgrade requests. "
                        "Only allow connections from your own domain. "
                        "Implement a WebSocket-specific CSRF token for sensitive operations."
                    ),
                    cwe="CWE-346",
                    cvss=8.1,
                    owasp_category="A01:2021 Broken Access Control",
                    standards=["ISO27001-8.23", "HIPAA-164.312a"],
                    confidence=0.9,
                ))
        else:
            import asyncio
            import websockets as _ws_lib

            async def _check():
                async with _ws_lib.connect(
                    ws_url,
                    extra_headers={"Origin": spoofed_origin},
                    open_timeout=5,
                ):
                    return True

            result = asyncio.run(_check())
            if result:
                findings.append(Finding(
                    title="Missing WebSocket Origin Validation",
                    severity=Severity.HIGH,
                    url=page_url,
                    parameter=None,
                    payload=f"Origin: {spoofed_origin}",
                    evidence=f"WebSocket {ws_url} accepted connection from spoofed Origin: {spoofed_origin}",
                    description=(
                        "The WebSocket endpoint does not validate the Origin header, allowing "
                        "cross-site WebSocket hijacking (CSWH)."
                    ),
                    remediation=(
                        "Validate the Origin header on WebSocket upgrade requests. "
                        "Only allow connections from your own domain."
                    ),
                    cwe="CWE-346",
                    cvss=8.1,
                    owasp_category="A01:2021 Broken Access Control",
                    standards=["ISO27001-8.23", "HIPAA-164.312a"],
                    confidence=0.9,
                ))
    except Exception:
        pass


def _test_message_injection(
    ws_url: str,
    page_url: str,
    observed_messages: List[str],
    findings: List[Finding],
):
    """Send injection payloads and check if they are reflected in the response."""
    try:
        import websockets.sync.client as _ws_sync
    except ImportError:
        try:
            import websockets  # older API
            _ws_sync = None
        except ImportError:
            return

    # If no observed messages, probe with generic frame templates (Gap 8)
    frames_to_test = []
    if observed_messages:
        frames_to_test = [m for m in observed_messages[:3] if isinstance(m, str) and m.strip()]
    if not frames_to_test:
        frames_to_test = _PROBE_FRAMES

    for payload in _INJECTION_PAYLOADS:
        for original_msg in frames_to_test:
            injected = original_msg.replace("PAYLOAD", payload) if "PAYLOAD" in original_msg else original_msg[:200] + payload

            try:
                if _ws_sync is not None:
                    with _ws_sync.connect(ws_url, open_timeout=5, close_timeout=3) as ws:
                        ws.send(injected)
                        try:
                            response = ws.recv(timeout=3)
                        except Exception:
                            response = ""
                        if payload in str(response):
                            findings.append(_injection_finding(ws_url, page_url, payload, response))
                            return
                else:
                    import asyncio
                    import websockets as _ws_lib

                    async def _inject():
                        async with _ws_lib.connect(ws_url, open_timeout=5) as ws:
                            await ws.send(injected)
                            try:
                                return await asyncio.wait_for(ws.recv(), timeout=3)
                            except Exception:
                                return ""

                    response = asyncio.run(_inject())
                    if payload in str(response):
                        findings.append(_injection_finding(ws_url, page_url, payload, response))
                        return
            except Exception:
                continue


def _injection_finding(ws_url: str, page_url: str, payload: str, response: str) -> Finding:
    is_xss = "<script>" in payload or "onerror" in payload
    return Finding(
        title="WebSocket Message Injection" + (" (XSS)" if is_xss else " (SQLi/SSTI)"),
        severity=Severity.HIGH if not is_xss else Severity.CRITICAL,
        url=page_url,
        parameter=f"WebSocket: {ws_url}",
        payload=payload,
        evidence=f"Payload reflected in WebSocket response: {str(response)[:200]}",
        description=(
            "User-controlled data sent over WebSocket is reflected in server responses without "
            "sanitization, enabling injection attacks (XSS, SQLi, SSTI) via WebSocket frames."
        ),
        remediation=(
            "Sanitize and validate all WebSocket message content on the server side. "
            "Treat WebSocket messages as untrusted input identical to HTTP request parameters. "
            "Apply the same input validation and output encoding rules."
        ),
        cwe="CWE-79" if is_xss else "CWE-89",
        cvss=9.0 if is_xss else 8.0,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "HIPAA-164.312a", "GDPR-Art32"],
        confidence=0.95,
    )
