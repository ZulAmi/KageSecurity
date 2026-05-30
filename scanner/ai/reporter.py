from scanner.core.scan_result import ScanResult
from scanner.ai.provider import complete as ai_complete

SYSTEM_PROMPT = """You are a security report writer for a professional pentesting firm.
Write clear, actionable security reports that developers and engineering managers can understand.
Be factual, not alarmist. Prioritize by business risk, not just CVSS score."""


def generate_report(scan_result: ScanResult, api_key: str, provider: str = "anthropic", model: str | None = None) -> str:
    active_findings = [f for f in scan_result.findings if not f.false_positive_suppressed]

    findings_text = "\n\n".join([
        f"- [{f.severity.value.upper()}] {f.title} at {f.url} (param: {f.parameter})\n"
        f"  Evidence: {f.evidence}\n"
        f"  AI Verdict: {f.ai_verdict or 'unverified'} | "
        f"Exploitability: {f.ai_exploitability or 'unknown'} | "
        f"Business Impact: {f.ai_business_impact or 'unknown'}\n"
        f"  Analysis: {f.ai_analysis or 'Not verified'}"
        + (f"\n  Attack Scenario: {f.ai_attack_scenario}" if f.ai_attack_scenario else "")
        for f in active_findings
    ])

    summary = scan_result.summary()
    suppressed_count = len(scan_result.findings) - len(active_findings)

    prompt = f"""Generate a professional security scan report for:

**Target**: {scan_result.target}
**Pages crawled**: {summary['pages_crawled']}
**Scan duration**: {summary['duration_seconds']:.1f}s
**Total findings (after FP suppression)**: {len(active_findings)} ({suppressed_count} suppressed as false positives)
**By severity**: {summary['by_severity']}

**Findings**:
{findings_text if findings_text else 'No vulnerabilities found.'}

Write the report in markdown with these sections:
1. Executive Summary (2-3 sentences, business-focused)
2. Risk Overview (severity breakdown table)
3. Findings (one subsection per finding with: description, evidence, AI analysis, remediation steps)
4. Recommendations (top 3 prioritized actions)"""

    return ai_complete(
        system=SYSTEM_PROMPT,
        user=prompt,
        api_key=api_key,
        provider=provider,
        model=model,
    )
