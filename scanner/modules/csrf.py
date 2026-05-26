import httpx
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult

CSRF_TOKEN_NAMES = {
    "csrf", "csrftoken", "_token", "authenticity_token", "__requestverificationtoken",
    "csrf_token", "xsrf-token", "_csrf", "anti_csrf",
}

STATE_CHANGING_METHODS = {"post", "put", "patch", "delete"}


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []

    for form in page.forms:
        if form["method"].lower() not in STATE_CHANGING_METHODS:
            continue

        input_names = {i["name"].lower() for i in form["inputs"] if i["name"]}
        has_csrf_token = bool(input_names & CSRF_TOKEN_NAMES)

        # Also check for custom header-based CSRF protection by trying without Referer/Origin
        if not has_csrf_token:
            # Try submitting with no CSRF-related headers
            data = {
                i["name"]: i.get("value", "test")
                for i in form["inputs"]
                if i["name"]
            }
            try:
                resp = client.request(
                    form["method"].upper(),
                    form["action"],
                    data=data,
                    headers={"Referer": "", "Origin": ""},
                )
                if resp.status_code not in (403, 405, 422, 419):
                    findings.append(Finding(
                        title="Missing CSRF Protection on State-Changing Form",
                        severity=Severity.MEDIUM,
                        url=form["action"],
                        parameter=None,
                        payload=None,
                        evidence=(
                            f"POST form at {form['action']} accepted submission without CSRF token. "
                            f"No anti-CSRF token field found. Response: HTTP {resp.status_code}"
                        ),
                        description=(
                            "Cross-Site Request Forgery allows attackers to trick authenticated users into "
                            "performing unintended actions (form submissions, account changes, fund transfers)."
                        ),
                        remediation=(
                            "Add a unique, unpredictable CSRF token to every state-changing form. "
                            "Validate the token server-side. Use SameSite=Strict cookies as a defence-in-depth measure."
                        ),
                        cwe="CWE-352",
                        cvss=6.5,
                        owasp_category="A01:2021 Broken Access Control",
                        standards=["ISO27001-8.8", "HIPAA-164.312a", "GDPR-Art32"],
                        confidence=0.8,
                    ))
            except Exception:
                pass

    return findings
