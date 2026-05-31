"""
Smart vulnerability prioritization — "Fix These First".

Scoring model based on Bright Security's "two-lens" approach (exploitability + context)
and Wiz's contextual scoring (CVSS + runtime validation + attack path):

  Base score : CVSS (0–10)
  AI verdict : true_positive +3.0 | needs_manual_review +0.5
  OOB verified: +2.0  (out-of-band callback confirmed = highest confidence)
  Severity tier: critical +4 | high +3 | medium +2 | low +1
  State bonus : regressed +2.5 | new +0.5  (regressed = was fixed, broke again)

Findings marked as false positives are excluded entirely.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.scan_result import Finding

_SEVERITY_BONUS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_STATE_BONUS    = {"regressed": 2.5, "new": 0.5, "repeated": 0.0}


def prioritize(
    findings: "list[Finding]",
    scan_states: "dict[tuple, str]",
    top_n: int = 10,
) -> "list[tuple[float, Finding]]":
    """Return up to `top_n` findings sorted by priority score, highest first.

    Args:
        findings:    All findings from ScanResult (including suppressed).
        scan_states: {(title, url, parameter): "new"|"repeated"|"regressed"}
                     from ScanResult.scan_states (populated by findings_db.classify_scan).
        top_n:       Maximum number of entries to return.

    Returns:
        List of (score, Finding) tuples, sorted descending by score.
    """
    scored: list[tuple[float, Finding]] = []

    for f in findings:
        if f.false_positive_suppressed:
            continue

        score: float = f.cvss or 0.0

        # AI exploitability lens (Bright Security approach)
        if f.ai_verdict == "true_positive":
            score += 3.0
        elif f.ai_verdict == "needs_manual_review":
            score += 0.5

        # OOB-confirmed findings are highest confidence
        if f.verified:
            score += 2.0

        # Severity tier bonus
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        score += _SEVERITY_BONUS.get(sev.lower(), 0)

        # Cross-scan state bonus
        k = (f.title, f.url, f.parameter or "")
        state = scan_states.get(k, "new")
        score += _STATE_BONUS.get(state, 0.0)

        scored.append((score, f))

    scored.sort(key=lambda x: -x[0])
    return scored[:top_n]


def format_fix_first(
    scored: "list[tuple[float, Finding]]",
    scan_states: "dict[tuple, str]",
    no_color: bool = False,
) -> str:
    """Return the formatted 'Fix These First' CLI section."""
    if not scored:
        return ""

    _RESET  = "" if no_color else "\033[0m"
    _BOLD   = "" if no_color else "\033[1m"
    _RED    = "" if no_color else "\033[91m"
    _YELLOW = "" if no_color else "\033[93m"
    _CYAN   = "" if no_color else "\033[96m"
    _GREEN  = "" if no_color else "\033[92m"

    _STATE_COLOR = {
        "new":       _CYAN,
        "repeated":  _YELLOW,
        "regressed": _RED,
        "resolved":  _GREEN,
    }
    _SEV_COLOR = {
        "critical": _RED,
        "high":     _RED,
        "medium":   _YELLOW,
        "low":      _CYAN,
        "info":     "",
    }

    lines = [f"\n{_BOLD}── FIX THESE FIRST {'─' * 43}{_RESET}"]
    for i, (score, f) in enumerate(scored, 1):
        sev  = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        k    = (f.title, f.url, f.parameter or "")
        state = scan_states.get(k, "new").upper()
        sc   = _SEV_COLOR.get(sev.lower(), "")
        stc  = _STATE_COLOR.get(state.lower(), "")
        title_short = f.title[:60] + ("…" if len(f.title) > 60 else "")
        url_short   = f.url[:55]   + ("…" if len(f.url)   > 55 else "")
        param = f"  param={f.parameter}" if f.parameter else ""
        lines.append(
            f"  {_BOLD}{i:>2}.{_RESET} "
            f"[score {score:4.1f}] "
            f"{sc}{sev.upper():<8}{_RESET} "
            f"{stc}[{state}]{_RESET}  "
            f"{title_short}\n"
            f"       {url_short}{param}"
        )
    lines.append(f"{_BOLD}{'─' * 60}{_RESET}\n")
    return "\n".join(lines)
