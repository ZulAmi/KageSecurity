"""
SARIF 2.1.0 exporter for GitHub Code Scanning / VS Code SARIF Viewer.
"""
from __future__ import annotations

import json
from scanner.core.scan_result import ScanResult, Finding, Severity

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_TOOL_NAME = "KageSec"
_TOOL_VERSION = "0.1.0"
_TOOL_URI = "https://github.com/kagesec/kagesec"

_SEVERITY_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def generate_sarif(result: ScanResult, out_path: str = "kagesec_report.sarif") -> str:
    findings = [f for f in result.findings if not f.false_positive_suppressed]

    rules: dict[str, dict] = {}
    run_results: list[dict] = []

    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id not in rules:
            rules[rule_id] = _build_rule(rule_id, finding)
        run_results.append(_build_result(rule_id, finding))

    sarif = {
        "version": _SARIF_VERSION,
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": _TOOL_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": run_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"kagesec scan {result.target}",
                    }
                ],
                "properties": {
                    "target": result.target,
                    "pagesCrawled": result.pages_crawled,
                    "scanDurationSeconds": result.scan_duration_seconds,
                },
            }
        ],
    }

    with open(out_path, "w") as fp:
        json.dump(sarif, fp, indent=2)
    return out_path


def _rule_id(finding: Finding) -> str:
    title = finding.title.lower().replace(" ", "-")
    bad = set(" /\\()[]{}#&%@!?,;:'\"<>")
    safe = "".join(c for c in title if c not in bad)
    return f"KS-{safe[:48]}"


def _build_rule(rule_id: str, finding: Finding) -> dict:
    return {
        "id": rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "helpUri": "https://owasp.org/www-project-top-ten/",
        "properties": {
            "tags": [finding.owasp_category or "security"],
            "precision": "high" if (finding.confidence or 0) >= 0.8 else "medium",
            "problem.severity": _SEVERITY_MAP.get(finding.severity, "warning"),
            "security-severity": _cvss_string(finding),
        },
        "defaultConfiguration": {
            "level": _SEVERITY_MAP.get(finding.severity, "warning"),
        },
    }


def _build_result(rule_id: str, finding: Finding) -> dict:
    message_parts = [finding.evidence or finding.description or finding.title]
    if finding.payload:
        message_parts.append(f"Payload: {finding.payload}")
    if finding.remediation:
        message_parts.append(f"Remediation: {finding.remediation}")

    result: dict = {
        "ruleId": rule_id,
        "level": _SEVERITY_MAP.get(finding.severity, "warning"),
        "message": {"text": "\n".join(message_parts)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.url,
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }
        ],
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "verified": finding.verified,
            "owaspCategory": finding.owasp_category,
            "cwe": finding.cwe,
            "cvss": finding.cvss,
            "parameter": finding.parameter,
            "payload": finding.payload,
        },
    }

    if finding.ai_verdict:
        result["properties"]["aiVerdict"] = finding.ai_verdict
    if finding.ai_analysis:
        result["properties"]["aiAnalysis"] = finding.ai_analysis

    return result


def _cvss_string(finding: Finding) -> str:
    if finding.cvss:
        return str(finding.cvss)
    fallback = {
        Severity.CRITICAL: "9.0",
        Severity.HIGH: "7.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "0.0",
    }
    return fallback.get(finding.severity, "5.0")
