"""
Pentest Certificate PDF generator.

Issued when a scan has zero critical/high findings OR all findings are marked fixed.
Rendered via Jinja2 + Playwright (same pipeline as pdf_reporter.py).
"""
import os
import tempfile
from datetime import datetime, timezone

from scanner.core.scan_result import ScanResult

_CERTIFICATE_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>KageSec Pentest Certificate</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Georgia', serif;
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    padding: 40px;
  }
  .cert {
    background: #fff;
    border-radius: 12px;
    padding: 60px 80px;
    max-width: 800px;
    width: 100%;
    text-align: center;
    border: 8px double #1a202c;
    position: relative;
  }
  .watermark {
    position: absolute; top: 20px; right: 24px;
    font-size: 11px; color: #a0aec0; letter-spacing: .1em; text-transform: uppercase;
  }
  .logo {
    font-family: 'Helvetica Neue', Arial, sans-serif;
    font-size: 16px; font-weight: 900; letter-spacing: .2em;
    border: 2px solid #1a202c; padding: 5px 12px; border-radius: 4px;
    display: inline-block; margin-bottom: 24px;
  }
  h1 { font-size: 36px; color: #1a202c; margin-bottom: 8px; }
  .subtitle { font-size: 16px; color: #718096; margin-bottom: 40px; font-style: italic; }
  .target { font-size: 24px; font-weight: bold; color: #2d3748; margin: 20px 0 8px; }
  .target-label { font-size: 13px; text-transform: uppercase; letter-spacing: .1em; color: #a0aec0; }
  .divider { border: none; border-top: 2px solid #e2e8f0; margin: 32px 0; }
  .stats { display: flex; justify-content: center; gap: 60px; margin: 24px 0; }
  .stat .value { font-size: 32px; font-weight: bold; color: #276749; }
  .stat .label { font-size: 12px; text-transform: uppercase; letter-spacing: .1em; color: #718096; }
  .check { color: #276749; }
  .date-block { margin-top: 32px; font-size: 13px; color: #718096; }
  .scan-id { font-family: monospace; font-size: 12px; color: #a0aec0; margin-top: 8px; }
  .seal {
    margin-top: 40px; display: inline-block;
    border: 3px solid #276749; border-radius: 50%;
    width: 80px; height: 80px; line-height: 80px;
    font-size: 32px; color: #276749;
  }
  .compliance-tags { margin-top: 20px; display: flex; justify-content: center; gap: 8px; flex-wrap: wrap; }
  .tag { background: #f0fff4; border: 1px solid #c6f6d5; color: #276749;
         padding: 4px 12px; border-radius: 9999px; font-size: 12px; font-weight: bold; }
</style>
</head>
<body>
<div class="cert">
  <div class="watermark">Scan ID: {{ scan_id }}</div>
  <div class="logo">KAGESEC</div>
  <h1>Security Assessment Certificate</h1>
  <div class="subtitle">This certifies that the following target passed automated security testing</div>

  <hr class="divider">

  <div class="target-label">Assessed Target</div>
  <div class="target">{{ target }}</div>

  <div class="stats">
    <div class="stat">
      <div class="value">{{ modules_run }}</div>
      <div class="label">Modules Run</div>
    </div>
    <div class="stat">
      <div class="value check">✓</div>
      <div class="label">No Critical / High Findings</div>
    </div>
    <div class="stat">
      <div class="value">{{ pages_crawled }}</div>
      <div class="label">Pages Tested</div>
    </div>
  </div>

  {% if compliance_standards %}
  <div class="compliance-tags">
    {% for std in compliance_standards %}
    <span class="tag">{{ std }}</span>
    {% endfor %}
  </div>
  {% endif %}

  <hr class="divider">

  <div class="seal">🛡</div>

  <div class="date-block">
    Issued on <strong>{{ date }}</strong><br>
    by KageSec Automated Security Platform
  </div>
  <div class="scan-id">Verifiable at: /api/scans/{{ scan_id }}</div>
</div>
</body>
</html>
"""


def _is_certifiable(scan_result: ScanResult) -> bool:
    active = [f for f in scan_result.findings if not f.false_positive_suppressed]
    critical_or_high = [
        f for f in active
        if f.severity.value in ("critical", "high") and f.triage_status not in ("fixed", "accepted_risk")
    ] if hasattr(active[0] if active else None, "triage_status") else [
        f for f in active if f.severity.value in ("critical", "high")
    ]
    return len(critical_or_high) == 0


def generate_certificate(
    scan_result: ScanResult,
    output_path: str,
    scan_id: str = "unknown",
    modules_run: int = 0,
) -> str:
    """
    Generate a pentest certificate PDF.
    Raises ValueError if the scan has unresolved critical/high findings.
    Raises RuntimeError if Playwright is not installed.
    """
    if not _is_certifiable(scan_result):
        raise ValueError(
            "Certificate cannot be issued: scan has unresolved critical or high findings. "
            "Resolve all critical/high findings first."
        )

    try:
        from jinja2 import Environment
    except ImportError:
        raise RuntimeError("jinja2 is required: pip install jinja2")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError("playwright is required: pip install playwright && playwright install chromium")

    compliance_standards = [cr.standard for cr in scan_result.compliance_reports if cr.score >= 70]

    env = Environment()
    template = env.from_string(_CERTIFICATE_TEMPLATE)
    html = template.render(
        target=scan_result.target,
        scan_id=scan_id,
        modules_run=modules_run or 24,
        pages_crawled=scan_result.pages_crawled,
        compliance_standards=compliance_standards,
        date=datetime.now(timezone.utc).strftime("%B %d, %Y"),
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
        f.write(html)
        html_path = f.name

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"file://{html_path}")
            page.wait_for_load_state("networkidle")
            page.pdf(
                path=output_path,
                format="A4",
                landscape=True,
                print_background=True,
                margin={"top": "10mm", "bottom": "10mm", "left": "10mm", "right": "10mm"},
            )
            browser.close()
    finally:
        os.unlink(html_path)

    return output_path
