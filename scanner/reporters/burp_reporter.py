"""
Burp Suite XML issue export.

Generates a Burp-compatible XML file that can be imported via:
  Burp Suite → Target → Site map → right-click → Import issues

Format reference: Burp Suite Professional "Export issues" XML schema.
"""
from __future__ import annotations

import html
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.scan_result import ScanResult

_SEVERITY_MAP = {
    "critical": "High",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Information",
}

_CONFIDENCE_MAP = {
    # KageSec confidence 0..1 → Burp confidence label
    lambda c: c >= 0.90: "Certain",
    lambda c: c >= 0.70: "Firm",
    lambda c: True:      "Tentative",
}


def _burp_confidence(c: float) -> str:
    if c >= 0.90:
        return "Certain"
    if c >= 0.70:
        return "Firm"
    return "Tentative"


def _e(text: str | None) -> str:
    """XML-escape a string."""
    return html.escape(str(text or ""), quote=False)


def generate_burp(result: "ScanResult", out_path: str) -> str:
    """Write Burp XML to *out_path* and return the path."""
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<issues>"]

    for f in result.findings:
        if f.false_positive_suppressed:
            continue

        sev = _SEVERITY_MAP.get(f.severity.value, "Information")
        conf = _burp_confidence(getattr(f, "confidence", 0.5))

        from urllib.parse import urlparse
        parsed = urlparse(f.url)
        host = parsed.hostname or ""
        lines.append("  <issue>")
        lines.append(f"    <serialNumber>{abs(hash(f.url + f.title))}</serialNumber>")
        lines.append("    <type>134217728</type>")  # generic custom issue type
        lines.append(f"    <name>{_e(f.title)}</name>")
        lines.append(f"    <host ip=\"\">{_e(host)}</host>")
        lines.append(f"    <path>{_e(parsed.path or '/')}</path>")
        lines.append(f"    <location>{_e(f.url)}</location>")
        lines.append(f"    <severity>{sev}</severity>")
        lines.append(f"    <confidence>{conf}</confidence>")
        lines.append(f"    <issueBackground>{_e(f.description)}</issueBackground>")
        lines.append(f"    <remediationBackground>{_e(f.remediation)}</remediationBackground>")
        lines.append(f"    <issueDetail>{_e(f.evidence)}</issueDetail>")
        if f.parameter:
            lines.append(f"    <parameter>{_e(f.parameter)}</parameter>")
        if f.payload:
            lines.append(f"    <request><![CDATA[{f.payload}]]></request>")
        cwe = getattr(f, "cwe", None)
        cvss = getattr(f, "cvss", None)
        if cwe or cvss:
            refs = []
            if cwe:
                refs.append(f"CWE: {_e(cwe)}")
            if cvss is not None:
                refs.append(f"CVSS: {cvss}")
            lines.append(f"    <references>{' | '.join(refs)}</references>")
        lines.append("  </issue>")

    lines.append("</issues>")

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return out_path
