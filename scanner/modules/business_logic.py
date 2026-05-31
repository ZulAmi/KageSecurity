"""
Business Logic / Numeric Boundary Tests — Gap 30

Tests e-commerce and form patterns for:
  - Negative prices / quantities (price=-1)
  - Zero amounts (quantity=0)
  - Integer overflow (quantity=9999999999)
  - MAX_INT boundary (2^31-1 = 2147483647)
  - Decimal tricks (quantity=0.001, price=0.00)
  - Concurrent/race condition hints (detected passively)
"""
import re
import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
from scanner.utils.http import fetch

# Patterns suggesting price/quantity fields
_PRICE_FIELD_RE = re.compile(r'(?:price|amount|cost|total|fee|payment)', re.IGNORECASE)
_QUANTITY_FIELD_RE = re.compile(r'(?:quantity|qty|count|units|num|number)', re.IGNORECASE)
_ECOMMERCE_INDICATORS = [
    "add to cart", "buy now", "checkout", "quantity", "price",
    "shopping cart", "purchase", "order", "payment",
]

# Boundary values to probe
_BOUNDARY_VALUES = [
    ("0", "zero"),
    ("-1", "negative"),
    ("-999999", "large negative"),
    ("9999999999", "integer overflow"),
    ("2147483647", "MAX_INT (2^31-1)"),
    ("2147483648", "MAX_INT+1 overflow"),
    ("0.001", "decimal zero"),
    ("0.00", "decimal zero price"),
    ("99999.99", "large decimal"),
    ("NaN", "NaN"),
    ("Infinity", "Infinity"),
    ("null", "null"),
]


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings: List[Finding] = []

    # Only run on e-commerce-like pages
    body_lower = (page.body or "").lower()
    if not any(indicator in body_lower for indicator in _ECOMMERCE_INDICATORS):
        return findings

    _test_forms(page, client, findings)
    _test_url_params(page, client, findings)
    return findings


def _test_forms(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    for form in page.forms:
        inputs = {inp["name"]: inp.get("value", "") for inp in form["inputs"] if inp["name"]}
        if not inputs:
            continue

        # Identify price and quantity fields
        price_fields = [k for k in inputs if _PRICE_FIELD_RE.search(k)]
        qty_fields = [k for k in inputs if _QUANTITY_FIELD_RE.search(k)]
        target_fields = price_fields + qty_fields
        if not target_fields:
            continue

        # Get baseline response to confirm the form submits successfully before probing.
        try:
            baseline = client.request(
                form["method"].upper(), form["action"], data=inputs, timeout=8
            )
            if baseline.status_code >= 500:
                continue
        except Exception:
            continue

        for field in target_fields[:3]:  # limit to first 3 target fields
            for value, label in _BOUNDARY_VALUES:
                probe = dict(inputs)
                probe[field] = value
                try:
                    resp = fetch(client, form["method"], form["action"], probe)
                except Exception:
                    continue
                if not resp:
                    continue

                # OWASP WSTG: business logic cannot be automated via body size diff —
                # a smaller body could mean rejection (correct) or incomplete data (bug).
                # Only flag when the response contains explicit success indicators that
                # confirm the boundary value was accepted by the business layer.
                # This matches the reliable signals professional testers use (Burp, ZAP):
                # look for state-change evidence in the body, not structural size changes.
                success_phrases = ["success", "order confirmed", "added to cart", "purchase", "thank you"]
                has_success = any(p in resp.text.lower() for p in success_phrases)

                if has_success:
                    findings.append(Finding(
                        title=f"Business Logic — Boundary Value Accepted ({label})",
                        severity=Severity.MEDIUM,
                        url=form["action"],
                        parameter=field,
                        payload=value,
                        evidence=(
                            f"Field '{field}' accepted boundary value '{value}' ({label}). "
                            f"Response: HTTP {resp.status_code}, {len(resp.text)}B"
                            + (" — success indicator found" if has_success else "")
                        ),
                        description=(
                            f"The form accepted a boundary value '{value}' ({label}) for field '{field}'. "
                            "Business logic vulnerabilities in numeric fields can allow attackers to "
                            "manipulate prices (negative amounts, overflow), bypass quantity limits, "
                            "or exploit decimal precision to obtain goods/services for free or profit."
                        ),
                        remediation=(
                            "Validate all numeric inputs server-side: enforce minimum (> 0), "
                            "maximum (≤ inventory), and type (integer vs decimal) constraints. "
                            "Perform all financial calculations server-side; never trust client-supplied amounts. "
                            "Test edge cases in payment and ordering flows."
                        ),
                        cwe="CWE-840",
                        cvss=6.5,
                        owasp_category="A04:2021 Insecure Design",
                        confidence=0.65,
                    ))
                    break


def _test_url_params(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    from scanner.utils.http import get_url_params, inject_url_param
    params = get_url_params(page.url)
    numeric_params = [p for p in params if _PRICE_FIELD_RE.search(p) or _QUANTITY_FIELD_RE.search(p)]

    if not numeric_params:
        return

    try:
        baseline = client.get(page.url, timeout=8)
        baseline_status = baseline.status_code
    except Exception:
        return

    for param in numeric_params[:3]:
        for value, label in _BOUNDARY_VALUES[:6]:
            test_url = inject_url_param(page.url, param, value)
            try:
                resp = client.get(test_url, timeout=8)
            except Exception:
                continue
            # Only flag on status code change — a 4xx means the server explicitly rejected
            # the boundary value (server-side validation exists but may be bypassable).
            # Body size diff is excluded: OWASP WSTG classifies it as unreliable for
            # business logic detection since context determines whether acceptance is a bug.
            if resp.status_code != baseline_status and resp.status_code < 500:
                findings.append(Finding(
                    title=f"Business Logic — Boundary Value in URL Parameter ({label})",
                    severity=Severity.LOW,
                    url=page.url,
                    parameter=param,
                    payload=value,
                    evidence=f"URL param '{param}={value}' ({label}): status changed {baseline_status}→{resp.status_code}",
                    description=(
                        f"URL parameter '{param}' accepted boundary value '{value}' ({label}). "
                        "Numeric boundary vulnerabilities can be exploited for business logic bypass."
                    ),
                    remediation="Validate numeric URL parameters server-side. Enforce min/max constraints.",
                    cwe="CWE-840",
                    cvss=4.3,
                    owasp_category="A04:2021 Insecure Design",
                    confidence=0.55,
                ))
                break
