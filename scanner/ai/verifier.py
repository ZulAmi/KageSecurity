import json
from scanner.core.scan_result import Finding, ScanResult
from scanner.ai.provider import complete as ai_complete

_BATCH_SIZE = 10

SYSTEM_PROMPT = """You are a senior penetration tester reviewing automated DAST scan findings.
You will receive a JSON array of findings. Respond ONLY with a JSON array of the same length,
one object per finding, in the same order. Each object must use exactly this schema:
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
- true_positive: evidence directly confirms injection, execution, or data leakage
No markdown fences, no prose — only the JSON array."""

_DEFAULT_VERDICT = {
    "verdict": "needs_manual_review",
    "confidence": 0.5,
    "exploitability": "low",
    "business_impact": "low",
    "analysis": "AI analysis unavailable.",
    "attack_scenario": "",
}


def verify_findings(scan_result: ScanResult, api_key: str, provider: str = "anthropic", model: str | None = None) -> ScanResult:
    if not scan_result.findings:
        return scan_result

    findings = scan_result.findings
    for i in range(0, len(findings), _BATCH_SIZE):
        batch = findings[i : i + _BATCH_SIZE]
        verdicts = _analyze_batch(batch, api_key, provider, model)
        for finding, verdict in zip(batch, verdicts):
            _apply_verdict(finding, verdict, scan_result)

    return scan_result


def _analyze_batch(batch: list[Finding], api_key: str, provider: str, model: str | None) -> list[dict]:
    payload = [
        {
            "vulnerability": f.title,
            "severity": f.severity.value,
            "url": f.url,
            "parameter": f.parameter,
            "payload": f.payload,
            "evidence": f.evidence,
            "description": f.description,
        }
        for f in batch
    ]

    try:
        raw = ai_complete(
            system=SYSTEM_PROMPT,
            user=json.dumps(payload),
            api_key=api_key,
            provider=provider,
            model=model,
        ).strip()
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1].lstrip("json").strip() if len(parts) >= 2 else raw

        result = json.loads(raw)
        if isinstance(result, list) and len(result) == len(batch):
            return result
        if isinstance(result, dict):
            for v in result.values():
                if isinstance(v, list) and len(v) == len(batch):
                    return v
    except Exception:
        pass

    return [_DEFAULT_VERDICT.copy() for _ in batch]


def _apply_verdict(finding: Finding, verdict: dict, scan_result: ScanResult) -> None:
    v = verdict.get("verdict", "needs_manual_review")

    finding.ai_verdict = v
    finding.ai_analysis = verdict.get("analysis", "")
    finding.ai_exploitability = verdict.get("exploitability", "low")
    finding.ai_business_impact = verdict.get("business_impact", "low")
    finding.ai_attack_scenario = verdict.get("attack_scenario", "")

    ai_confidence = float(verdict.get("confidence", 0.5))
    if v == "true_positive":
        finding.confidence = max(finding.confidence, ai_confidence)
    elif v == "needs_manual_review":
        finding.confidence = min(finding.confidence, ai_confidence)

    finding.verified = v == "true_positive"

    if v == "false_positive":
        finding.false_positive_suppressed = True
        scan_result.errors.append(
            f"[AI FP suppressed] {finding.title} @ {finding.url} param={finding.parameter}"
        )
