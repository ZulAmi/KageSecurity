import json
import anthropic
from scanner.core.scan_result import Finding, ScanResult

SYSTEM_PROMPT = """You are a senior penetration tester reviewing automated DAST scan findings.
Respond ONLY with a JSON object — no markdown fences, no prose — using exactly this schema:
{
  "verdict": "true_positive" | "false_positive" | "needs_manual_review",
  "confidence": <float 0.0-1.0>,
  "exploitability": "none" | "low" | "medium" | "high",
  "business_impact": "none" | "low" | "medium" | "high" | "critical",
  "analysis": "<1-3 sentences explaining your assessment>",
  "attack_scenario": "<concrete attack scenario if true_positive, else empty string>"
}

Guidelines:
- false_positive: payload appears in static content, evidence is coincidental, param is not user-controlled
- needs_manual_review: borderline evidence, insufficient context, confidence < 0.6
- true_positive: evidence directly confirms injection, execution, or data leakage"""


def verify_findings(scan_result: ScanResult, api_key: str) -> ScanResult:
    if not scan_result.findings:
        return scan_result

    client = anthropic.Anthropic(api_key=api_key)

    for finding in scan_result.findings:
        verdict = _analyze_finding(client, finding)
        _apply_verdict(finding, verdict, scan_result)

    return scan_result


def _analyze_finding(client: anthropic.Anthropic, finding: Finding) -> dict:
    prompt = (
        f"Vulnerability: {finding.title}\n"
        f"Severity: {finding.severity.value}\n"
        f"URL: {finding.url}\n"
        f"Parameter: {finding.parameter}\n"
        f"Payload: {finding.payload}\n"
        f"Evidence: {finding.evidence}\n"
        f"Description: {finding.description}"
    )

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=512,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = message.content[0].text.strip()
    # Strip markdown code fences if the model includes them despite instructions
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1].lstrip("json").strip() if len(parts) >= 2 else raw

    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {
            "verdict": "needs_manual_review",
            "confidence": 0.5,
            "exploitability": "low",
            "business_impact": "low",
            "analysis": raw[:400],
            "attack_scenario": "",
        }


def _apply_verdict(finding: Finding, verdict: dict, scan_result: ScanResult) -> None:
    v = verdict.get("verdict", "needs_manual_review")

    finding.ai_verdict = v
    finding.ai_analysis = verdict.get("analysis", "")
    finding.ai_exploitability = verdict.get("exploitability", "low")
    finding.ai_business_impact = verdict.get("business_impact", "low")
    finding.ai_attack_scenario = verdict.get("attack_scenario", "")

    # AI confidence caps the scanner's own confidence, never raises it
    ai_confidence = float(verdict.get("confidence", 0.5))
    finding.confidence = min(finding.confidence, ai_confidence)

    finding.verified = v == "true_positive"

    if v == "false_positive":
        finding.false_positive_suppressed = True
        scan_result.errors.append(
            f"[AI FP suppressed] {finding.title} @ {finding.url} param={finding.parameter}"
        )
