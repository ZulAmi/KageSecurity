import json
import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []

    # Only run against GraphQL endpoints (detected by api_scanner or header hint)
    content_type = page.headers.get("content-type", "")
    is_graphql_endpoint = (
        "application/json" in content_type
        or page.headers.get("x-graphql-introspection") == "true"
    )
    if not is_graphql_endpoint:
        return findings

    _check_introspection(page, client, findings)
    _check_batch_abuse(page, client, findings)
    _check_field_suggestions(page, client, findings)
    return findings


def _check_introspection(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """Introspection enabled — schema is publicly readable (information disclosure)."""
    if page.headers.get("x-graphql-introspection") == "true":
        # The api_scanner already confirmed introspection — just report it
        findings.append(Finding(
            title="GraphQL Introspection Enabled",
            severity=Severity.MEDIUM,
            url=page.url,
            parameter=None,
            payload='{"query": "{ __schema { types { name } } }"}',
            evidence="GraphQL introspection query returned full schema definition",
            description=(
                "GraphQL introspection allows any client to query the full API schema, "
                "exposing all types, fields, queries, and mutations. This significantly "
                "aids attackers in understanding attack surface."
            ),
            remediation=(
                "Disable introspection in production. "
                "In Apollo Server: `introspection: false`. "
                "In Hasura: set HASURA_GRAPHQL_ENABLE_CONSOLE=false."
            ),
            cwe="CWE-200",
            cvss=5.3,
            owasp_category="A01:2021 Broken Access Control",
            standards=["ISO27001-8.23", "HIPAA-164.312a"],
            confidence=1.0,
        ))
        return

    # Try introspection ourselves
    try:
        resp = client.post(
            page.url,
            json={"query": "{ __schema { types { name } } }"},
            headers={"Content-Type": "application/json"},
            timeout=8,
        )
        data = resp.json()
        if "data" in data and "__schema" in data.get("data", {}):
            findings.append(Finding(
                title="GraphQL Introspection Enabled",
                severity=Severity.MEDIUM,
                url=page.url,
                parameter=None,
                payload='{"query": "{ __schema { types { name } } }"}',
                evidence="Introspection returned schema types list",
                description=(
                    "GraphQL introspection is enabled, exposing the full API schema to any client."
                ),
                remediation="Disable introspection in production environments.",
                cwe="CWE-200",
                cvss=5.3,
                owasp_category="A01:2021 Broken Access Control",
                standards=["ISO27001-8.23"],
                confidence=1.0,
            ))
    except Exception:
        pass


def _check_batch_abuse(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """
    Batch query DoS: send 100 aliases in one request.
    If the server responds with 100 data fields, batching is enabled and could be
    used for credential stuffing or rate-limit bypass.
    """
    aliases = " ".join([f"q{i}: __typename" for i in range(100)])
    query = f"{{ {aliases} }}"
    try:
        resp = client.post(
            page.url,
            json={"query": query},
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        data = resp.json().get("data", {})
        if len(data) >= 50:
            findings.append(Finding(
                title="GraphQL Batching / Alias Abuse Enabled",
                severity=Severity.MEDIUM,
                url=page.url,
                parameter=None,
                payload=f'{{"query": "{{ q0: __typename q1: __typename ... q99: __typename }}"}}',
                evidence=f"Server returned {len(data)} aliased results in a single request",
                description=(
                    "GraphQL servers that allow unlimited query aliases or batch requests can be "
                    "exploited to bypass rate limiting (e.g., credential stuffing with 1000 login "
                    "attempts per HTTP request)."
                ),
                remediation=(
                    "Implement query depth/complexity limits. "
                    "Use a GraphQL query cost analysis library (e.g., graphql-cost-analysis). "
                    "Limit maximum aliases per query."
                ),
                cwe="CWE-770",
                cvss=5.3,
                owasp_category="A04:2021 Insecure Design",
                standards=["ISO27001-8.23"],
                confidence=0.9,
            ))
    except Exception:
        pass


def _check_field_suggestions(page: CrawlResult, client: httpx.Client, findings: List[Finding]):
    """
    Field name suggestions reveal schema even when introspection is disabled.
    Send a query with a typo; if the error message says 'Did you mean X?', schema is leaking.
    """
    query = '{ doesNotExistKagesec }'
    try:
        resp = client.post(
            page.url,
            json={"query": query},
            headers={"Content-Type": "application/json"},
            timeout=8,
        )
        body = resp.text
        if "Did you mean" in body or "did you mean" in body:
            findings.append(Finding(
                title="GraphQL Field Suggestion Leakage",
                severity=Severity.LOW,
                url=page.url,
                parameter=None,
                payload='{"query": "{ doesNotExistKagesec }"}',
                evidence=f'Server returned field suggestion in error: "{body[:200]}"',
                description=(
                    "GraphQL field name suggestions in error messages reveal schema information "
                    "even when introspection is disabled, allowing attackers to enumerate the schema."
                ),
                remediation=(
                    "Disable field suggestions in production. "
                    "In Apollo Server: `fieldSuggestions: false`. "
                    "In graphql-js: override the error formatting function."
                ),
                cwe="CWE-200",
                cvss=3.7,
                owasp_category="A01:2021 Broken Access Control",
                standards=["ISO27001-8.23"],
                confidence=1.0,
            ))
    except Exception:
        pass
