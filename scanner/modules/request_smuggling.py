"""
HTTP Request Smuggling detection — timing-based CL.TE and TE.CL probes.

Both probes send an HTTP/1.1 request with conflicting Content-Length and
Transfer-Encoding headers. If the front-end and back-end disagree on which
header to use, the request is "smuggled":

- CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
- TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length

A response time >= 3s after sending the ambiguous request is a strong signal
of smuggling, because the back-end is waiting for the rest of a "hung" body.
"""
import time
import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

_TIMING_THRESHOLD = 3.0  # seconds


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []

    if not page.url.startswith(("http://", "https://")):
        return findings

    _probe_cl_te(page.url, findings)
    if not findings:
        _probe_te_cl(page.url, findings)

    return findings


def _make_raw_client(url: str) -> httpx.Client:
    """HTTP/1.1 only client — smuggling only applies to HTTP/1.1."""
    return httpx.Client(
        http1=True,
        http2=False,
        verify=False,  # nosec B501 — intentional: scanning targets with self-signed certs
        follow_redirects=False,
        timeout=10,
    )


def _probe_cl_te(url: str, findings: List[Finding]):
    """
    CL.TE probe: Content-Length says 6 bytes, but body starts a chunked
    partial chunk (0\r\n\r\n) that hangs the TE-aware back-end.
    """
    body = b"0\r\n\r\nG"  # malformed terminator: back-end waits for more
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(body)),
        "Transfer-Encoding": "chunked",
        "Connection": "keep-alive",
    }
    elapsed = _timed_post(url, headers, body)
    if elapsed >= _TIMING_THRESHOLD:
        findings.append(_finding(url, "CL.TE", elapsed))


def _probe_te_cl(url: str, findings: List[Finding]):
    """
    TE.CL probe: TE header present but Content-Length disagrees.
    Front-end reads full chunked body; back-end reads only Content-Length bytes
    and leaves the remainder for the next "request".
    """
    body = b"1\r\nG\r\n0\r\n\r\n"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "4",
        "Transfer-Encoding": "chunked",
        "Connection": "keep-alive",
    }
    elapsed = _timed_post(url, headers, body)
    if elapsed >= _TIMING_THRESHOLD:
        findings.append(_finding(url, "TE.CL", elapsed))


def _timed_post(url: str, headers: dict, body: bytes) -> float:
    raw_client = _make_raw_client(url)
    try:
        start = time.time()
        raw_client.post(url, content=body, headers=headers)
        return time.time() - start
    except Exception:
        return 0.0
    finally:
        raw_client.close()


def _finding(url: str, variant: str, elapsed: float) -> Finding:
    return Finding(
        title=f"HTTP Request Smuggling ({variant})",
        severity=Severity.CRITICAL,
        url=url,
        parameter=None,
        payload=f"{variant} timing probe",
        evidence=f"Response delayed {elapsed:.1f}s after {variant} smuggling probe (threshold: {_TIMING_THRESHOLD}s)",
        description=(
            f"HTTP request smuggling ({variant}) allows attackers to inject requests into the "
            "front-end/back-end HTTP pipeline, bypassing security controls, poisoning other "
            "users' requests, and achieving web cache poisoning or credential theft."
        ),
        remediation=(
            "Configure your load balancer/reverse proxy to normalise Transfer-Encoding headers. "
            "Prefer HTTP/2 end-to-end. "
            "Reject requests with both Content-Length and Transfer-Encoding headers. "
            "Use `Content-Length` only on the back-end."
        ),
        cwe="CWE-444",
        cvss=9.8,
        owasp_category="A03:2021 Injection",
        standards=["ISO27001-8.23", "HIPAA-164.312a"],
        confidence=0.75,
    )
