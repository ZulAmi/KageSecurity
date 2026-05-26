import anthropic
from scanner.core.scan_result import ScanResult

SYSTEM_PROMPT = """You are a security report writer for a professional pentesting firm.
Write clear, actionable security reports that developers and engineering managers can understand.
Be factual, not alarmist. Prioritize by business risk, not just CVSS score."""


def generate_report(scan_result: ScanResult, api_key: str) -> str:
    client = anthropic.Anthropic(api_key=api_key)

    findings_text = "\n\n".join([
        f"- [{f.severity.value.upper()}] {f.title} at {f.url} (param: {f.parameter})\n"
        f"  Evidence: {f.evidence}\n"
        f"  AI Analysis: {f.ai_analysis or 'Not verified'}"
        for f in scan_result.findings
    ])

    summary = scan_result.summary()

    prompt = f"""Generate a professional security scan report for:

**Target**: {scan_result.target}
**Pages crawled**: {summary['pages_crawled']}
**Scan duration**: {summary['duration_seconds']:.1f}s
**Total findings**: {summary['total_findings']}
**By severity**: {summary['by_severity']}

**Findings**:
{findings_text if findings_text else 'No vulnerabilities found.'}

Write the report in markdown with these sections:
1. Executive Summary (2-3 sentences, business-focused)
2. Risk Overview (severity breakdown table)
3. Findings (one subsection per finding with: description, evidence, remediation steps)
4. Recommendations (top 3 prioritized actions)"""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    return message.content[0].text
