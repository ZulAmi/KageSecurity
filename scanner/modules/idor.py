import re
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

INTEGER_PARAM_RE = re.compile(r'^\d+$')
UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    parsed = urlparse(page.url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    for param_name, values in params.items():
        original = values[0]

        if INTEGER_PARAM_RE.match(original):
            # Try incrementing and decrementing the integer ID
            candidates = [str(int(original) + 1), str(int(original) - 1)]
            _test_candidates(page.url, parsed, params, param_name, original, candidates, client, findings)

        elif UUID_RE.match(original):
            # For UUIDs we can't guess another valid one, but we can check if
            # a clearly invalid value returns a different (potentially revealing) response
            candidates = ["00000000-0000-0000-0000-000000000000"]
            _test_candidates(page.url, parsed, params, param_name, original, candidates, client, findings, is_uuid=True)

    return findings


def _test_candidates(
    original_url, parsed, params, param_name, original_value, candidates,
    client, findings, is_uuid=False
):
    try:
        orig_resp = client.get(original_url)
    except Exception:
        return

    if orig_resp.status_code not in (200, 206):
        return

    for candidate in candidates:
        new_params = dict(params)
        new_params[param_name] = [candidate]
        test_url = urlunparse(parsed._replace(query=urlencode(new_params, doseq=True)))

        try:
            test_resp = client.get(test_url)
        except Exception:
            continue

        if test_resp.status_code not in (200, 206):
            continue

        # Different content for a different ID = likely IDOR
        orig_len = len(orig_resp.text)
        test_len = len(test_resp.text)
        content_changed = abs(orig_len - test_len) > 50 or (
            test_resp.text[:200] != orig_resp.text[:200]
        )

        if content_changed and test_resp.status_code == 200:
            findings.append(Finding(
                title="Insecure Direct Object Reference (IDOR)" + (" — UUID" if is_uuid else ""),
                severity=Severity.HIGH,
                url=original_url,
                parameter=param_name,
                payload=candidate,
                evidence=(
                    f"Changing `{param_name}` from `{original_value}` to `{candidate}` "
                    f"returned HTTP 200 with different content "
                    f"(original: {orig_len} bytes, modified: {test_len} bytes)"
                ),
                description=(
                    "IDOR allows attackers to access other users' data by modifying resource identifiers. "
                    "This can expose personal information, medical records, or financial data."
                ),
                remediation=(
                    "Implement object-level authorization checks on every request. "
                    "Verify the requesting user owns or has permission to access the resource. "
                    "Use indirect references (UUIDs or opaque tokens) instead of sequential integers."
                ),
                cwe="CWE-639",
                cvss=7.5,
                owasp_category="A01:2021 Broken Access Control",
                standards=["ISO27001-8.23", "HIPAA-164.312a", "GDPR-Art5", "APPI-Art20"],
                confidence=0.75,
            ))
            break
