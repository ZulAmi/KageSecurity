"""
PDF report generation using Playwright.

Renders a Jinja2 HTML template to a temp file, then uses
playwright.sync_api to print it as a PDF.

Falls back gracefully if Playwright is not installed.
"""
import os
import tempfile
from datetime import datetime, timezone
from typing import Optional

from scanner.core.scan_result import ScanResult

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>KageSec Security Report — {{ scan.target }}</title>
<style>
  :root {
    --red: #e53e3e; --orange: #dd6b20; --yellow: #d69e2e;
    --blue: #3182ce; --gray: #718096;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 13px;
         color: #1a202c; background: #fff; padding: 40px; }
  h1 { font-size: 28px; color: #1a202c; margin-bottom: 4px; }
  h2 { font-size: 18px; color: #2d3748; margin: 28px 0 10px; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; }
  h3 { font-size: 14px; margin: 18px 0 6px; }
  .subtitle { color: var(--gray); font-size: 13px; margin-bottom: 24px; }
  .meta { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 28px; }
  .meta-box { background: #f7fafc; border: 1px solid #e2e8f0; border-radius: 6px;
              padding: 12px 16px; }
  .meta-box .label { font-size: 11px; text-transform: uppercase; letter-spacing: .05em;
                     color: var(--gray); margin-bottom: 4px; }
  .meta-box .value { font-size: 22px; font-weight: 700; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px;
           font-weight: 700; text-transform: uppercase; letter-spacing: .05em; }
  .badge-critical { background: #fff5f5; color: var(--red); border: 1px solid var(--red); }
  .badge-high    { background: #fffaf0; color: var(--orange); border: 1px solid var(--orange); }
  .badge-medium  { background: #fffff0; color: var(--yellow); border: 1px solid #b7791f; }
  .badge-low     { background: #ebf8ff; color: var(--blue); border: 1px solid var(--blue); }
  .badge-info    { background: #f0fff4; color: #276749; border: 1px solid #276749; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 12px; }
  th { text-align: left; padding: 8px 10px; background: #f7fafc;
       border-bottom: 2px solid #e2e8f0; font-size: 11px; text-transform: uppercase; }
  td { padding: 8px 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
  .finding-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px;
                  margin-bottom: 16px; page-break-inside: avoid; }
  .finding-title { font-weight: 700; font-size: 14px; margin-bottom: 8px; }
  .finding-meta { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 10px;
                  font-size: 12px; color: var(--gray); }
  .finding-section { margin-top: 8px; }
  .finding-section .label { font-size: 11px; font-weight: 700; text-transform: uppercase;
                             color: var(--gray); margin-bottom: 2px; }
  .finding-section .value { font-size: 12px; background: #f7fafc; border-radius: 4px;
                             padding: 6px 8px; font-family: monospace; word-break: break-all; }
  .ai-verdict { margin-top: 8px; padding: 8px 10px; border-radius: 4px;
                font-size: 12px; background: #f0fff4; border: 1px solid #c6f6d5; }
  .ai-verdict .label { font-weight: 700; }
  .cover { text-align: center; padding: 80px 0; page-break-after: always; }
  .cover h1 { font-size: 36px; }
  .cover .target { font-size: 20px; color: var(--gray); margin-top: 8px; }
  .cover .date { margin-top: 40px; color: var(--gray); }
  .logo { font-size: 14px; font-weight: 900; letter-spacing: .1em; color: #1a202c;
          border: 2px solid #1a202c; padding: 4px 10px; border-radius: 4px;
          display: inline-block; margin-bottom: 20px; }
  .compliance-table td:nth-child(3) { font-weight: 700; }
  .status-pass    { color: #276749; }
  .status-fail    { color: var(--red); }
  .status-partial { color: var(--orange); }
  .status-manual  { color: var(--blue); }
  .page-break { page-break-before: always; }
</style>
</head>
<body>

<!-- Cover -->
<div class="cover">
  <div class="logo">KAGESEC</div>
  <h1>Security Assessment Report</h1>
  <div class="target">{{ scan.target }}</div>
  <div class="date">
    Generated {{ date }}<br>
    Duration: {{ "%.1f"|format(scan.scan_duration_seconds) }}s &nbsp;·&nbsp;
    Pages crawled: {{ scan.pages_crawled }}
  </div>
</div>

<!-- Summary -->
<h2>Executive Summary</h2>
<div class="meta">
  <div class="meta-box">
    <div class="label">Total Findings</div>
    <div class="value">{{ findings|length }}</div>
  </div>
  {% for sev in ["critical","high","medium","low","info"] %}
  {% set count = findings|selectattr("severity.value","equalto",sev)|list|length %}
  {% if count %}
  <div class="meta-box">
    <div class="label">{{ sev|upper }}</div>
    <div class="value" style="color: {{ severity_color(sev) }}">{{ count }}</div>
  </div>
  {% endif %}
  {% endfor %}
</div>

<!-- Findings table -->
<h2>Findings Overview</h2>
<table>
  <thead>
    <tr>
      <th>#</th><th>Severity</th><th>Title</th><th>URL</th><th>Parameter</th>
      <th>CVSS</th><th>CWE</th><th>AI Verdict</th>
    </tr>
  </thead>
  <tbody>
  {% for f in findings %}
    <tr>
      <td>{{ loop.index }}</td>
      <td><span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span></td>
      <td>{{ f.title }}</td>
      <td style="font-family:monospace;font-size:11px">{{ f.url|truncate(50) }}</td>
      <td>{{ f.parameter or "—" }}</td>
      <td>{{ f.cvss or "—" }}</td>
      <td>{{ f.cwe or "—" }}</td>
      <td>{{ f.ai_verdict or "unverified" }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>

<!-- Detailed findings -->
<h2 class="page-break">Detailed Findings</h2>
{% for f in findings %}
<div class="finding-card">
  <div class="finding-title">
    <span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span>
    &nbsp;{{ f.title }}
  </div>
  <div class="finding-meta">
    <span>📍 {{ f.url }}</span>
    {% if f.parameter %}<span>⚙️ Parameter: {{ f.parameter }}</span>{% endif %}
    {% if f.cwe %}<span>🔖 {{ f.cwe }}</span>{% endif %}
    {% if f.cvss %}<span>📊 CVSS: {{ f.cvss }}</span>{% endif %}
    {% if f.owasp_category %}<span>🛡 {{ f.owasp_category }}</span>{% endif %}
    <span>✅ Confidence: {{ "%.0f"|format(f.confidence * 100) }}%</span>
  </div>
  {% if f.payload %}
  <div class="finding-section">
    <div class="label">Payload</div>
    <div class="value">{{ f.payload|e }}</div>
  </div>
  {% endif %}
  <div class="finding-section">
    <div class="label">Evidence</div>
    <div class="value">{{ f.evidence|e }}</div>
  </div>
  <div class="finding-section">
    <div class="label">Description</div>
    <div class="value" style="font-family:inherit">{{ f.description }}</div>
  </div>
  <div class="finding-section">
    <div class="label">Remediation</div>
    <div class="value" style="font-family:inherit">{{ f.remediation }}</div>
  </div>
  {% if f.ai_verdict %}
  <div class="ai-verdict">
    <span class="label">AI Analysis —</span>
    Verdict: <strong>{{ f.ai_verdict }}</strong> |
    Exploitability: {{ f.ai_exploitability }} |
    Business Impact: {{ f.ai_business_impact }}
    {% if f.ai_analysis %}<br><em>{{ f.ai_analysis }}</em>{% endif %}
    {% if f.ai_attack_scenario %}<br><strong>Attack scenario:</strong> {{ f.ai_attack_scenario }}{% endif %}
  </div>
  {% endif %}
  {% if f.standards %}
  <div class="finding-section" style="margin-top:8px">
    <div class="label">Standards</div>
    <div style="font-size:11px;color:#718096">{{ f.standards|join(" · ") }}</div>
  </div>
  {% endif %}
</div>
{% endfor %}

{% if compliance %}
<h2 class="page-break">Compliance</h2>
{% for cr in compliance %}
<h3>{{ cr.standard }} — Score: {{ "%.0f"|format(cr.score) }}/100</h3>
<table class="compliance-table">
  <thead>
    <tr><th>Control</th><th>Name</th><th>Status</th><th>Evidence</th></tr>
  </thead>
  <tbody>
  {% for c in cr.controls %}
  <tr>
    <td>{{ c.id }}</td>
    <td>{{ c.name }}</td>
    <td class="status-{{ c.status }}">{{ c.status|upper }}</td>
    <td>{{ c.evidence }}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>
{% endfor %}
{% endif %}

</body>
</html>
"""


def _severity_color(sev: str) -> str:
    return {"critical": "#e53e3e", "high": "#dd6b20", "medium": "#b7791f",
            "low": "#3182ce", "info": "#276749"}.get(sev, "#718096")


def generate_pdf(scan_result: ScanResult, output_path: str) -> str:
    """
    Render the HTML report and convert it to a PDF via Playwright.
    Returns the output_path on success.
    Raises RuntimeError if Playwright is not installed.
    """
    try:
        from jinja2 import Environment
    except ImportError:
        raise RuntimeError("jinja2 is required for PDF generation: pip install jinja2")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError("playwright is required for PDF generation: pip install playwright && playwright install chromium")

    active_findings = [f for f in scan_result.findings if not f.false_positive_suppressed]

    env = Environment()
    env.globals["severity_color"] = _severity_color
    template = env.from_string(_HTML_TEMPLATE)

    html = template.render(
        scan=scan_result,
        findings=active_findings,
        compliance=scan_result.compliance_reports,
        date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )

    # Write HTML to temp file, then print to PDF
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
                margin={"top": "20mm", "bottom": "20mm", "left": "15mm", "right": "15mm"},
                print_background=True,
            )
            browser.close()
    finally:
        os.unlink(html_path)

    return output_path
