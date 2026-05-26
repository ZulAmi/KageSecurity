import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

REDIRECT_PARAMS = ["redirect", "next", "url", "return", "returnTo", "redir", "goto", "target", "dest"]
CANARY_HOST = "evil.com"
PAYLOADS = [
    f"https://{CANARY_HOST}",
    f"//{CANARY_HOST}",
    f"https://{CANARY_HOST}@trusted.com",
]


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    parsed = urlparse(page.url)
    params = parse_qs(parsed.query)

    for param_name in list(params.keys()):
        if param_name.lower() not in REDIRECT_PARAMS:
            continue

        for payload in PAYLOADS:
            new_params = dict(params)
            new_params[param_name] = [payload]
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = client.get(test_url, follow_redirects=False)
            except Exception:
                continue

            location = resp.headers.get("location", "")
            if CANARY_HOST in location:
                findings.append(Finding(
                    title="Open Redirect",
                    severity=Severity.MEDIUM,
                    url=page.url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Response redirected to: {location}",
                    description=(
                        "Open redirects allow attackers to craft links that appear "
                        "legitimate but redirect users to malicious sites — commonly "
                        "used in phishing attacks."
                    ),
                    remediation=(
                        "Validate redirect destinations against a whitelist. "
                        "Use relative paths instead of absolute URLs for internal redirects."
                    ),
                    cwe="CWE-601",
                    cvss=4.3,
                ))
                break

    return findings
