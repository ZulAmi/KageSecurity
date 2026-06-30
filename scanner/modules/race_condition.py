"""
Race condition detection.

Strategy: send N identical requests concurrently against endpoints that create
records or modify numeric values (balance, inventory, counter, votes). Detect:
  - Multiple 201 Created responses (duplicate record creation)
  - Counter overshoot (e.g. balance deducted N times)
  - Inconsistent state signals in response body

Focus on POST forms that suggest transactional operations.
"""
import re
import threading
from typing import List
from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity

_RACE_KEYWORDS_URL = re.compile(
    r"/(purchase|buy|order|checkout|transfer|withdraw|redeem|apply|vote|like|claim"
    r"|coupon|promo|discount|referral|gift|topup|deposit|enroll|register|submit)",
    re.IGNORECASE,
)

_RACE_KEYWORDS_FORM = re.compile(
    r"(amount|qty|quantity|count|units|tokens|points|balance|price|coupon|promo|code|referral)",
    re.IGNORECASE,
)

_CONCURRENCY = 8
_RACE_TIMEOUT = 10


def test(page: CrawlResult, client) -> List[Finding]:
    findings = []

    for form in page.forms:
        action = form.get("action", page.url)
        method = form.get("method", "get").lower()
        if method != "post":
            continue

        # Only target forms that look transactional
        inputs = form.get("inputs", [])
        input_names = " ".join(i.get("name", "") for i in inputs)
        if not (_RACE_KEYWORDS_URL.search(action) or _RACE_KEYWORDS_FORM.search(input_names)):
            continue

        # Build a minimal payload
        data = {}
        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue
            itype = inp.get("type", "text")
            val = inp.get("value", "")
            if not val:
                val = _default_value(itype, name)
            data[name] = val

        finding = _race_probe(action, data, client)
        if finding:
            findings.append(finding)

    return findings


def _race_probe(url: str, data: dict, client) -> Finding | None:
    results: List[int] = []
    bodies: List[str] = []
    lock = threading.Lock()

    def send():
        try:
            resp = client.post(url, data=data, timeout=_RACE_TIMEOUT)
            with lock:
                results.append(resp.status_code)
                bodies.append(resp.text[:500] if hasattr(resp, "text") else "")
        except Exception:
            with lock:
                results.append(0)

    threads = [threading.Thread(target=send) for _ in range(_CONCURRENCY)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if not results:
        return None

    # Heuristic: if all requests fail authentication or CSRF validation → skip
    non_auth = [c for c in results if c not in (401, 403, 419, 422)]
    if len(non_auth) < 2:
        return None

    success_codes = [c for c in results if c in (200, 201, 202)]

    # Multiple 201s → duplicate record created
    created_count = results.count(201)
    if created_count >= 2:
        return _make_finding(url, data,
                             f"{created_count}/{_CONCURRENCY} requests returned HTTP 201 Created — "
                             "multiple records created from a single intended action.",
                             Severity.HIGH, 0.85)

    # All succeeded → possible duplicate processing
    if len(success_codes) == _CONCURRENCY:
        # Check if any body contains numeric values that might indicate duplication
        numeric_evidence = _find_numeric_duplication(bodies)
        if numeric_evidence:
            return _make_finding(url, data,
                                 f"All {_CONCURRENCY} concurrent requests succeeded (HTTP 200/201). "
                                 f"{numeric_evidence}",
                                 Severity.MEDIUM, 0.65)

    return None


def _find_numeric_duplication(bodies: List[str]) -> str:
    """Look for repeated identical monetary/counter values across responses."""
    amounts = []
    pattern = re.compile(r'(?:balance|amount|total|points?|credits?)["\s:]+([0-9]+(?:\.[0-9]{1,2})?)', re.IGNORECASE)
    for body in bodies:
        for m in pattern.finditer(body):
            amounts.append(m.group(1))
    if len(amounts) >= 3 and len(set(amounts)) == 1:
        return f"All responses contained identical value '{amounts[0]}' — likely idempotent, low risk."
    return ""


def _make_finding(url: str, data: dict, evidence: str, severity: Severity, confidence: float) -> Finding:
    return Finding(
        title="Potential Race Condition on Transactional Endpoint",
        severity=severity,
        url=url,
        parameter=str(list(data.keys())[:3]),
        payload=f"POST × {_CONCURRENCY} concurrent",
        evidence=evidence,
        description=(
            f"The endpoint {url} processed {_CONCURRENCY} simultaneous identical POST requests "
            "without appearing to reject duplicates. Race conditions on transactional endpoints "
            "(purchase, withdrawal, coupon redemption) can allow an attacker to double-spend, "
            "over-redeem rewards, or create duplicate records by firing parallel requests."
        ),
        remediation=(
            "Use database-level locking or idempotency keys to prevent duplicate processing. "
            "Apply optimistic locking (compare-and-swap) on numeric counters/balances. "
            "Implement unique constraints on idempotency tokens per request. "
            "Validate the operation atomically within a transaction."
        ),
        owasp_category="A04:2021 Insecure Design",
        cwe="CWE-362",
        cvss=7.5 if severity == Severity.HIGH else 5.9,
        confidence=confidence,
        standards=["OWASP-A04:2021", "CWE-362"],
    )


def _default_value(itype: str, name: str) -> str:
    if itype == "email":
        return "test@example.com"
    if itype == "password":
        return "Test1234!"
    if itype in ("number", "range"):
        return "1"
    if "amount" in name.lower() or "qty" in name.lower():
        return "1"
    return "test"
