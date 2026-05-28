"""
OWASP ZAP JSON alert export.

Generates a ZAP-compatible JSON file matching ZAP's /JSON/alert/view/alerts/
endpoint response format. Can be imported or compared against ZAP reports
using existing ZAP tooling and CI plugins.
"""
from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from scanner.core.scan_result import ScanResult

_RISK_MAP = {
    "critical": "3",  # ZAP: High
    "high":     "3",
    "medium":   "2",
    "low":      "1",
    "info":     "0",
}

_CONFIDENCE_MAP = {
    # KageSec 0..1 → ZAP confidence label integer
    "high":   "3",
    "medium": "2",
    "low":    "1",
}


def _zap_confidence(c: float) -> str:
    if c >= 0.90:
        return "3"  # High
    if c >= 0.70:
        return "2"  # Medium
    return "1"      # Low


def generate_zap(result: "ScanResult", out_path: str) -> str:
    """Write ZAP JSON to *out_path* and return the path."""
    alerts = []
    seen: dict[str, dict] = {}

    for f in result.findings:
        if f.false_positive_suppressed:
            continue

        risk = _RISK_MAP.get(f.severity.value, "0")
        conf = _zap_confidence(getattr(f, "confidence", 0.5))
        parsed = urlparse(f.url)

        key = f.title  # group instances by alert type
        if key not in seen:
            seen[key] = {
                "pluginid":    str(abs(hash(f.title)) % 1_000_000),
                "alertRef":    str(abs(hash(f.title)) % 1_000_000),
                "alert":       f.title,
                "name":        f.title,
                "riskcode":    risk,
                "confidence":  conf,
                "riskdesc":    _risk_label(risk),
                "desc":        f.description or "",
                "instances":   [],
                "count":       "0",
                "solution":    f.remediation or "",
                "otherinfo":   "",
                "reference":   _refs(f),
                "cweid":       _cwe_id(getattr(f, "cwe", None)),
                "wascid":      "0",
                "sourceid":    "3",  # Active scan
            }
        instance = {
            "uri":      f.url,
            "method":   "GET",
            "param":    f.parameter or "",
            "attack":   f.payload or "",
            "evidence": f.evidence or "",
            "otherinfo": "",
        }
        seen[key]["instances"].append(instance)
        seen[key]["count"] = str(len(seen[key]["instances"]))

    alerts = list(seen.values())

    site_name = ""
    if result.findings:
        first_url = result.findings[0].url
        parsed = urlparse(first_url)
        site_name = f"{parsed.scheme}://{parsed.netloc}"

    payload = {
        "@version": "2.14.0",
        "@generated": "",
        "site": [
            {
                "@name":    site_name,
                "@host":    urlparse(site_name).hostname or "",
                "@port":    str(urlparse(site_name).port or 443),
                "@ssl":     str(site_name.startswith("https")).lower(),
                "alerts":   alerts,
            }
        ],
    }

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    return out_path


def _risk_label(code: str) -> str:
    return {"3": "High (3)", "2": "Medium (2)", "1": "Low (1)", "0": "Informational (0)"}.get(code, "Informational (0)")


def _cwe_id(cwe: str | None) -> str:
    if not cwe:
        return "0"
    digits = "".join(c for c in (cwe or "") if c.isdigit())
    return digits or "0"


def _refs(f) -> str:
    parts = []
    cwe = getattr(f, "cwe", None)
    if cwe:
        parts.append(f"https://cwe.mitre.org/data/definitions/{_cwe_id(cwe)}.html")
    owasp = getattr(f, "owasp_category", None)
    if owasp:
        parts.append(owasp)
    return "\n".join(parts)
