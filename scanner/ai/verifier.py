import anthropic
from scanner.core.scan_result import Finding, ScanResult

SYSTEM_PROMPT = """You are a senior penetration tester reviewing automated DAST scan findings.
Your job is to:
1. Assess whether each finding is a true positive or likely false positive based on the evidence
2. Estimate real-world exploitability and business impact
3. Add any additional context or attack scenarios the automated scanner may have missed

Be concise and technical. Write for a developer audience who needs to understand and fix the issue."""


def verify_findings(scan_result: ScanResult, api_key: str) -> ScanResult:
    if not scan_result.findings:
        return scan_result

    client = anthropic.Anthropic(api_key=api_key)

    for finding in scan_result.findings:
        finding.ai_analysis = _analyze_finding(client, finding)
        finding.verified = "false positive" not in (finding.ai_analysis or "").lower()

    return scan_result


def _analyze_finding(client: anthropic.Anthropic, finding: Finding) -> str:
    prompt = f"""Analyze this automated scanner finding:

**Vulnerability**: {finding.title}
**Severity**: {finding.severity.value}
**URL**: {finding.url}
**Parameter**: {finding.parameter}
**Payload used**: {finding.payload}
**Evidence**: {finding.evidence}

Is this a true positive? What is the real-world exploitability and business impact?
If this is likely a false positive, explain why.
Keep your response under 150 words."""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=300,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    return message.content[0].text
