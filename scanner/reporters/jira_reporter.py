"""
Jira Issue Exporter — Gap 21

Creates Jira issues for each finding via the Jira REST API v3.

Usage:
  kagesec export --format jira report.json \
    --jira-url https://mycompany.atlassian.net \
    --jira-project VULN \
    --jira-token <PAT or Base64(email:token)>
"""
from __future__ import annotations

import httpx
from typing import List
from scanner.core.scan_result import ScanResult, Finding, Severity

_SEVERITY_PRIORITY = {
    Severity.CRITICAL: "Highest",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Lowest",
}

_SEVERITY_LABEL = {
    Severity.CRITICAL: "security-critical",
    Severity.HIGH: "security-high",
    Severity.MEDIUM: "security-medium",
    Severity.LOW: "security-low",
    Severity.INFO: "security-info",
}


def export_to_jira(
    result: ScanResult,
    jira_url: str,
    project_key: str,
    token: str,
    issue_type: str = "Bug",
    dry_run: bool = False,
) -> List[dict]:
    """
    Create Jira issues for each finding.

    *token* — Jira Personal Access Token or base64(email:api_token)
    Returns list of created issue dicts (with 'key' and 'url' fields).
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    client = httpx.Client(headers=headers, timeout=20)
    created = []

    for f in result.findings:
        if f.false_positive_suppressed:
            continue

        payload = _build_issue_payload(f, project_key, issue_type)
        if dry_run:
            created.append({"dry_run": True, "title": f.title, "payload": payload})
            continue

        try:
            resp = client.post(f"{jira_url.rstrip('/')}/rest/api/3/issue", json=payload)
            resp.raise_for_status()
            data = resp.json()
            issue_key = data.get("key", "")
            created.append({
                "key": issue_key,
                "url": f"{jira_url.rstrip('/')}/browse/{issue_key}",
                "title": f.title,
            })
        except Exception as e:
            created.append({"error": str(e), "title": f.title})

    client.close()
    return created


def _build_issue_payload(f: Finding, project_key: str, issue_type: str) -> dict:
    summary = f"{f.severity.upper()} — {f.title}"
    if len(summary) > 255:
        summary = summary[:252] + "..."

    body_parts = [
        f"*Severity:* {f.severity.upper()}",
        f"*URL:* {f.url}",
        f"*Parameter:* {f.parameter or 'N/A'}",
        f"*CVSS:* {f.cvss or 'N/A'}",
        f"*CWE:* {f.cwe or 'N/A'}",
        f"*OWASP:* {f.owasp_category or 'N/A'}",
        "",
        "*Evidence:*",
        f.evidence,
        "",
        "*Description:*",
        f.description,
        "",
        "*Remediation:*",
        f.remediation,
    ]
    if f.poc_curl:
        body_parts += ["", "*PoC (curl):*", f"{{code}}{f.poc_curl}{{code}}"]

    description = {
        "version": 1,
        "type": "doc",
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": "\n".join(body_parts)}],
            }
        ],
    }

    return {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
            "priority": {"name": _SEVERITY_PRIORITY.get(f.severity, "Medium")},
            "labels": ["kagesec", _SEVERITY_LABEL.get(f.severity, "security")],
        }
    }
