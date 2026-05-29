"""
PDF report generation using Playwright.

Renders a Jinja2 HTML template to a temp file, then uses
playwright.sync_api to print it as a PDF.

Falls back gracefully if Playwright is not installed.
"""
import os
import tempfile
from datetime import datetime, timezone

from scanner.core.scan_result import ScanResult, Finding

# ─── KageSec brand palette ────────────────────────────────────────────────────
# Primary: dark slate / deep violet.  Secondary accent: teal.
_PRIMARY     = "#0F172A"   # slate-900 — main dark
_ACCENT      = "#7C3AED"   # violet-600 — brand accent
_ACCENT_LT   = "#EDE9FE"   # violet-100 — light tint
_TEAL        = "#0D9488"   # teal-600  — secondary accent
_TEAL_LT     = "#CCFBF1"   # teal-100

_SEV_COLOR = {
    "critical": "#DC2626",   # red-600
    "high":     "#EA580C",   # orange-600
    "medium":   "#CA8A04",   # yellow-600
    "low":      "#2563EB",   # blue-600  (kept standard)
    "info":     "#059669",   # emerald-600
}
_SEV_BG = {
    "critical": "#FEF2F2",
    "high":     "#FFF7ED",
    "medium":   "#FEFCE8",
    "low":      "#EFF6FF",
    "info":     "#ECFDF5",
}

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>KageSec Security Report — {{ target }}</title>
<style>
/* ── Reset ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Helvetica Neue', Arial, sans-serif;
  font-size: 12px;
  color: #1E293B;
  background: #fff;
}

/* ── Page layout ── */
.page {
  width: 210mm;
  min-height: 297mm;
  padding: 16mm 15mm 18mm 15mm;
  page-break-after: always;
  position: relative;
}
.page:last-child { page-break-after: auto; }

/* ── Cover ── */
.cover {
  background: #0F172A;
  padding: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}
.cover-wordmark {
  font-size: 58px;
  font-weight: 900;
  letter-spacing: 0.14em;
  color: #fff;
  line-height: 1;
}
.cover-wordmark span { color: #7C3AED; }   /* accent on "SEC" */
.cover-tagline {
  font-size: 11px;
  letter-spacing: 0.3em;
  color: #94A3B8;
  text-transform: uppercase;
  margin-top: 6px;
  margin-bottom: 48px;
}
.cover-card {
  background: rgba(255,255,255,0.06);
  border: 1px solid rgba(124,58,237,0.35);
  border-radius: 12px;
  padding: 36px 44px 32px;
  text-align: center;
  max-width: 155mm;
  width: 100%;
}
.cover-report-type {
  font-size: 11px;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: #7C3AED;
  margin-bottom: 10px;
}
.cover-title {
  font-size: 24px;
  font-weight: 800;
  color: #fff;
  line-height: 1.25;
  margin-bottom: 8px;
}
.cover-subtitle {
  font-size: 13px;
  color: #94A3B8;
  margin-bottom: 28px;
}
.cover-target {
  display: inline-block;
  font-size: 14px;
  font-weight: 700;
  color: #0D9488;
  background: rgba(13,148,136,0.12);
  border: 1px solid rgba(13,148,136,0.30);
  border-radius: 6px;
  padding: 6px 14px;
  margin-bottom: 18px;
  word-break: break-all;
}
.cover-date { font-size: 11px; color: #64748B; }
.cover-disclaimer {
  position: absolute;
  bottom: 14mm;
  left: 0; right: 0;
  text-align: center;
  font-size: 9px;
  color: #475569;
  padding: 0 16mm;
}

/* ── Section headings ── */
.section-title {
  font-size: 18px;
  font-weight: 800;
  color: #0F172A;
  border-left: 4px solid #7C3AED;
  padding-left: 10px;
  margin-bottom: 14px;
}
.sub-title {
  font-size: 13px;
  font-weight: 700;
  color: #7C3AED;
  margin: 18px 0 8px;
  padding-bottom: 3px;
  border-bottom: 1px solid #EDE9FE;
}

/* ── Tables ── */
table { width: 100%; border-collapse: collapse; margin-bottom: 14px; font-size: 11px; }
th {
  text-align: left;
  padding: 7px 10px;
  background: #1E293B;
  color: #E2E8F0;
  font-size: 9.5px;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}
td { padding: 7px 10px; border-bottom: 1px solid #E2E8F0; vertical-align: top; }
tr:nth-child(even) td { background: #F8FAFC; }

/* ── Severity badges ── */
.badge {
  display: inline-block;
  padding: 2px 7px;
  border-radius: 9999px;
  font-size: 9.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.badge-critical { background: #FEF2F2; color: #DC2626; border: 1px solid #DC2626; }
.badge-high     { background: #FFF7ED; color: #EA580C; border: 1px solid #EA580C; }
.badge-medium   { background: #FEFCE8; color: #CA8A04; border: 1px solid #CA8A04; }
.badge-low      { background: #EFF6FF; color: #2563EB; border: 1px solid #2563EB; }
.badge-info     { background: #ECFDF5; color: #059669; border: 1px solid #059669; }

/* ── Stat cards (summary row) ── */
.stat-row { display: flex; gap: 10px; margin-bottom: 18px; }
.stat-card {
  flex: 1;
  background: #F8FAFC;
  border: 1px solid #E2E8F0;
  border-top: 3px solid #7C3AED;
  border-radius: 6px;
  padding: 10px 12px;
  text-align: center;
}
.stat-card .label {
  font-size: 8.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: #64748B;
  margin-bottom: 3px;
}
.stat-card .value { font-size: 24px; font-weight: 900; color: #0F172A; }
.stat-card.critical .value { color: #DC2626; }
.stat-card.high     .value { color: #EA580C; }
.stat-card.medium   .value { color: #CA8A04; }
.stat-card.low      .value { color: #2563EB; }
.stat-card.info     .value { color: #059669; }

/* ── TOC ── */
.toc-group { margin-bottom: 4px; }
.toc-group-title {
  font-size: 12px;
  font-weight: 700;
  color: #0F172A;
  margin-bottom: 3px;
  margin-top: 10px;
}
.toc-entry {
  display: flex;
  align-items: baseline;
  margin-bottom: 3px;
  padding-left: 12px;
  font-size: 11px;
  color: #374151;
}
.toc-dots {
  flex: 1;
  border-bottom: 1px dotted #CBD5E1;
  margin: 0 6px 3px;
}
.toc-page { font-size: 10px; color: #94A3B8; }

/* ── Finding cards ── */
.finding-card {
  border: 1px solid #E2E8F0;
  border-radius: 8px;
  margin-bottom: 18px;
  page-break-inside: avoid;
  overflow: hidden;
}
.finding-header {
  padding: 9px 13px;
  display: flex;
  align-items: center;
  gap: 9px;
  border-bottom: 1px solid rgba(0,0,0,0.07);
}
.finding-num { font-size: 10px; font-weight: 700; color: #64748B; white-space: nowrap; }
.finding-title-text { font-size: 13px; font-weight: 700; flex: 1; }
.finding-body { padding: 11px 13px; }
.finding-meta-row {
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  margin-bottom: 10px;
  font-size: 10px;
  color: #374151;
}
.finding-meta-row strong { color: #7C3AED; }

/* ── Detail blocks inside a finding ── */
.detail-block { margin-bottom: 10px; }
.detail-label {
  font-size: 9.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #7C3AED;
  margin-bottom: 3px;
}
.detail-value { font-size: 11px; color: #1E293B; line-height: 1.55; }
.detail-value.mono {
  font-family: 'Courier New', monospace;
  background: #F1F5F9;
  border-radius: 4px;
  padding: 5px 8px;
  font-size: 10px;
  word-break: break-all;
}

.step { background: #F8FAFC; border-left: 3px solid #7C3AED; padding: 6px 10px;
        margin-bottom: 5px; border-radius: 0 4px 4px 0; font-size: 11px; }
.step-label { font-weight: 700; color: #0F172A; font-size: 9.5px; margin-bottom: 2px; }

.ai-box {
  background: #F0FDF4;
  border: 1px solid #BBF7D0;
  border-radius: 6px;
  padding: 7px 10px;
  margin-bottom: 9px;
  font-size: 11px;
}
.ai-label { font-weight: 700; color: #065F46; font-size: 9.5px; text-transform: uppercase; margin-bottom: 2px; }

/* ── Compliance ── */
.status-pass    { color: #059669; font-weight: 700; }
.status-fail    { color: #DC2626; font-weight: 700; }
.status-partial { color: #EA580C; font-weight: 700; }
.status-manual  { color: #2563EB; font-weight: 700; }

/* ── Footer ── */
.page-footer {
  position: absolute;
  bottom: 9mm;
  left: 15mm; right: 15mm;
  font-size: 9px;
  color: #94A3B8;
  display: flex;
  justify-content: space-between;
  border-top: 1px solid #E2E8F0;
  padding-top: 4px;
}

/* ── Misc ── */
p { font-size: 11px; color: #374151; line-height: 1.6; margin-bottom: 8px; }
.muted { color: #64748B; }
@media print {
  .page { page-break-after: always; }
  .page:last-child { page-break-after: auto; }
}
</style>
</head>
<body>

<!-- ══════════════════════════════════════════════════════════ COVER ══ -->
<div class="page cover">
  <div class="cover-wordmark">KAGE<span>SEC</span></div>
  <div class="cover-tagline">AI-Powered DAST Scanner</div>
  <div class="cover-card">
    <div class="cover-report-type">Vulnerability Assessment Report</div>
    <div class="cover-title">Security Assessment &amp; Findings Report</div>
    <div class="cover-subtitle">Automated Full Scan</div>
    <div class="cover-target">{{ target }}</div>
    <div class="cover-date">Report Generated On <strong style="color:#E2E8F0">{{ date }}</strong></div>
  </div>
  <div class="cover-disclaimer">
    This report was generated by KageSec, an open-source AI-powered DAST scanner.
    Findings are based on automated testing and should be validated before remediation.
  </div>
</div>

<!-- ════════════════════════════════════════════════════════════ TOC ══ -->
<div class="page">
  <div class="section-title">Table of Contents</div>

  <div class="toc-group">
    <div class="toc-group-title">Overview</div>
    <div class="toc-entry"><span>Executive Summary</span><span class="toc-dots"></span><span class="toc-page">3</span></div>
    <div class="toc-entry"><span>Scope of the Assessment</span><span class="toc-dots"></span><span class="toc-page">3</span></div>
    <div class="toc-entry"><span>Resolution Statistics</span><span class="toc-dots"></span><span class="toc-page">3</span></div>
  </div>
  <div class="toc-group">
    <div class="toc-group-title">Scan Details</div>
    <div class="toc-entry"><span>Assessment Methodology</span><span class="toc-dots"></span><span class="toc-page">4</span></div>
    <div class="toc-entry"><span>Assessment Duration</span><span class="toc-dots"></span><span class="toc-page">4</span></div>
  </div>
  <div class="toc-group">
    <div class="toc-group-title">Vulnerabilities</div>
    <div class="toc-entry"><span>Vulnerabilities Overview Table</span><span class="toc-dots"></span><span class="toc-page">5</span></div>
    <div class="toc-entry"><span>Details of Vulnerabilities Found</span><span class="toc-dots"></span><span class="toc-page">6+</span></div>
  </div>
  {% if compliance %}
  <div class="toc-group">
    <div class="toc-group-title">Compliance</div>
    {% for cr in compliance %}
    <div class="toc-entry"><span>{{ cr.standard }} Report</span><span class="toc-dots"></span><span class="toc-page">—</span></div>
    {% endfor %}
  </div>
  {% endif %}
  <div class="toc-group">
    <div class="toc-group-title">Appendix</div>
    <div class="toc-entry"><span>Appendix A — Measurement Scales</span><span class="toc-dots"></span><span class="toc-page">—</span></div>
    <div class="toc-entry"><span>Appendix B — Resolution Status</span><span class="toc-dots"></span><span class="toc-page">—</span></div>
    <div class="toc-entry"><span>Appendix C — Risk Score</span><span class="toc-dots"></span><span class="toc-page">—</span></div>
  </div>
  <div class="page-footer"><span>KageSec Security Report</span><span>{{ target }}</span></div>
</div>

<!-- ═══════════════════════════════════════════════════════ OVERVIEW ══ -->
<div class="page">
  <div class="section-title">Overview</div>

  <div class="sub-title">Executive Summary</div>
  <p>
    KageSec performed an automated vulnerability assessment of <strong>1 target</strong>
    on <strong>{{ date }}</strong>. The scanner crawled
    <strong>{{ pages_crawled }}</strong> page{{ 's' if pages_crawled != 1 else '' }}
    and completed in <strong>{{ "%.1f"|format(duration) }}s</strong>.
  </p>
  <p>
    A total of <strong>{{ findings|length }} finding{{ 's' if findings|length != 1 else '' }}</strong> were reported.
    {% if findings %}
    The highest risk score was
    <strong>{{ "%.1f"|format(findings|map(attribute='risk_score')|max) }}</strong>,
    the lowest was
    <strong>{{ "%.1f"|format(findings|map(attribute='risk_score')|min) }}</strong>,
    and the average was
    <strong>{{ "%.1f"|format((findings|sum(attribute='risk_score')) / (findings|length)) }}</strong>
    (out of 10).
    {% endif %}
  </p>

  <div class="stat-row">
    <div class="stat-card">
      <div class="label">Total</div>
      <div class="value">{{ findings|length }}</div>
    </div>
    {% for sev in ["critical","high","medium","low","info"] %}
    {% set cnt = findings|selectattr("severity.value","equalto",sev)|list|length %}
    <div class="stat-card {{ sev }}">
      <div class="label">{{ sev }}</div>
      <div class="value">{{ cnt }}</div>
    </div>
    {% endfor %}
  </div>

  <div class="sub-title">Scope of the Assessment</div>
  <table>
    <thead><tr><th>Type</th><th>Target URL</th><th>Pages Crawled</th><th>Duration</th></tr></thead>
    <tbody>
      <tr>
        <td>Web Application</td>
        <td>{{ target }}</td>
        <td>{{ pages_crawled }}</td>
        <td>{{ "%.1f"|format(duration) }}s</td>
      </tr>
    </tbody>
  </table>

  <div class="sub-title">Resolution Statistics</div>
  <table>
    <thead>
      <tr><th>Status</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Total</th></tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Open</strong></td>
        {% for sev in ["critical","high","medium","low","info"] %}
        <td>{{ findings|selectattr("severity.value","equalto",sev)|list|length }}</td>
        {% endfor %}
        <td><strong>{{ findings|length }}</strong></td>
      </tr>
    </tbody>
  </table>
  <div class="page-footer"><span>KageSec Security Report</span><span>{{ target }}</span></div>
</div>

<!-- ════════════════════════════════════════════════ SCAN DETAILS ══ -->
<div class="page">
  <div class="section-title">Scan Details</div>

  <div class="sub-title">Assessment Methodology</div>
  <p>
    KageSec is an open-source, AI-powered Dynamic Application Security Testing (DAST) scanner.
    The assessment follows industry standards including the <strong>OWASP Top 10</strong>,
    OWASP Web Security Testing Guide (WSTG), and OWASP Application Security Verification
    Standard (ASVS).
  </p>
  <p>
    The scanner crawls the target application, submits crafted payloads across all discovered
    parameters and endpoints, and uses Claude AI to verify findings — reducing false positives
    and providing exploitability analysis with remediation guidance.
  </p>
  <p>
    All findings are from automated scanning. Manual verification is recommended for
    critical and high severity issues prior to remediation.
  </p>

  <div class="sub-title">Scan Authentication</div>
  <table>
    <thead><tr><th>Auth Type</th><th>Details</th></tr></thead>
    <tbody>
      <tr><td>{{ auth_type }}</td><td class="muted">{{ auth_value }}</td></tr>
    </tbody>
  </table>

  <div class="sub-title">Assessment Duration and Dates</div>
  <table>
    <thead><tr><th>Scan Mode</th><th>Target</th><th>Date</th><th>Duration</th></tr></thead>
    <tbody>
      <tr>
        <td>Automated DAST</td>
        <td>{{ target }}</td>
        <td>{{ date }}</td>
        <td>{{ "%.1f"|format(duration) }}s</td>
      </tr>
    </tbody>
  </table>
  <div class="page-footer"><span>KageSec Security Report</span><span>{{ target }}</span></div>
</div>

<!-- ════════════════════════════════ VULNERABILITY OVERVIEW TABLE ══ -->
<div class="page">
  <div class="section-title">Vulnerabilities</div>
  <div class="sub-title">Vulnerabilities Overview Table</div>
  <table>
    <thead>
      <tr>
        <th style="width:24px">No.</th>
        <th>Title</th>
        <th style="width:68px">Severity</th>
        <th style="width:58px">Risk Score</th>
        <th style="width:72px">AI Verdict</th>
        <th style="width:50px">Status</th>
      </tr>
    </thead>
    <tbody>
    {% for f in findings %}
      <tr>
        <td>{{ loop.index }}</td>
        <td>
          <strong>{{ f.title }}</strong><br>
          <span class="muted" style="font-size:9.5px">{{ f.url|truncate(75) }}</span>
        </td>
        <td><span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span></td>
        <td>{{ "%.1f"|format(f.risk_score) }}/10</td>
        <td>{{ f.ai_verdict or "—" }}</td>
        <td>Open</td>
      </tr>
    {% else %}
      <tr><td colspan="6" style="text-align:center" class="muted">No findings detected.</td></tr>
    {% endfor %}
    </tbody>
  </table>
  <div class="page-footer"><span>KageSec Security Report</span><span>{{ target }}</span></div>
</div>

<!-- ══════════════════════════════════════════ DETAILED FINDINGS ══ -->
<div class="page">
  <div class="section-title">Details of Vulnerabilities Found</div>

{% for f in findings %}
  <div class="finding-card">
    <div class="finding-header" style="background:{{ sev_bg(f.severity.value) }}; border-bottom:1px solid {{ sev_color(f.severity.value) }}22;">
      <span class="finding-num">{{ loop.index }}.</span>
      <span class="finding-title-text" style="color:{{ sev_color(f.severity.value) }}">{{ f.title }}</span>
      <span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span>
    </div>
    <div class="finding-body">
      <div class="finding-meta-row">
        <span><strong>Risk Score</strong> {{ "%.1f"|format(f.risk_score) }}/10</span>
        {% if f.cwe %}<span><strong>CWE</strong> {{ f.cwe }}</span>{% endif %}
        {% if f.cvss %}<span><strong>CVSS</strong> {{ "%.1f"|format(f.cvss) }}</span>{% endif %}
        {% if f.owasp_category %}<span><strong>OWASP</strong> {{ f.owasp_category }}</span>{% endif %}
        <span><strong>Confidence</strong> {{ "%.0f"|format(f.confidence * 100) }}%</span>
        <span><strong>Status</strong> Open</span>
      </div>

      <div class="detail-block">
        <div class="detail-label">Description</div>
        <div class="detail-value">{{ f.description }}</div>
      </div>

      <div class="detail-block">
        <div class="detail-label">Impact</div>
        <div class="detail-value">
          {% if f.ai_business_impact %}{{ f.ai_business_impact }}{% else %}Exploitation of this vulnerability could compromise the confidentiality, integrity, or availability of the application and its data.{% endif %}
        </div>
      </div>

      <div class="detail-block">
        <div class="detail-label">Affected Components</div>
        <div class="detail-value mono">{{ f.url }}{% if f.parameter %}&nbsp; → &nbsp;<strong>{{ f.parameter }}</strong>{% endif %}</div>
      </div>

      <div class="detail-block">
        <div class="detail-label">Steps to Reproduce</div>
        <div class="step">
          <div class="step-label">Step 1 — Send Request</div>
          <div>Target: <code>{{ f.url }}</code>{% if f.parameter %}, Parameter: <code>{{ f.parameter }}</code>{% endif %}</div>
        </div>
        {% if f.payload %}
        <div class="step">
          <div class="step-label">Step 2 — Payload</div>
          <div><code>{{ f.payload|e }}</code></div>
        </div>
        {% endif %}
        {% if f.evidence %}
        <div class="step">
          <div class="step-label">Actual Result / Evidence</div>
          <div>{{ f.evidence|e }}</div>
        </div>
        {% endif %}
        {% if f.ai_attack_scenario %}
        <div class="step">
          <div class="step-label">Attack Scenario</div>
          <div>{{ f.ai_attack_scenario }}</div>
        </div>
        {% endif %}
      </div>

      {% if f.ai_analysis or f.ai_verdict %}
      <div class="ai-box">
        <div class="ai-label">AI Analysis</div>
        {% if f.ai_verdict %}<div><strong>Verdict:</strong> {{ f.ai_verdict }}{% if f.ai_exploitability %} &nbsp;·&nbsp; <strong>Exploitability:</strong> {{ f.ai_exploitability }}{% endif %}</div>{% endif %}
        {% if f.ai_analysis %}<div style="margin-top:3px;color:#374151">{{ f.ai_analysis }}</div>{% endif %}
      </div>
      {% endif %}

      <div class="detail-block">
        <div class="detail-label">Suggested Fix</div>
        <div class="detail-value">{{ f.remediation }}</div>
      </div>

      {% if f.standards %}
      <div class="detail-block">
        <div class="detail-label">Standards</div>
        <div class="detail-value muted">{{ f.standards|join(" · ") }}</div>
      </div>
      {% endif %}
    </div>
  </div>

  {% if loop.index % 2 == 0 and not loop.last %}
  <div class="page-footer"><span>KageSec Security Report</span><span>{{ target }}</span></div>
  </div><div class="page">
  <div class="section-title" style="font-size:14px;margin-bottom:12px">Details of Vulnerabilities Found (continued)</div>
  {% endif %}
{% endfor %}

  <div class="page-footer"><span>KageSec Security Report</span><span>{{ target }}</span></div>
</div>

<!-- ═══════════════════════════════════════════════════ COMPLIANCE ══ -->
{% if compliance %}
{% for cr in compliance %}
<div class="page">
  <div class="section-title">Compliance — {{ cr.standard }}</div>
  <p>
    Score: <strong>{{ "%.0f"|format(cr.score) }}/100</strong>
    &nbsp;·&nbsp; Pass: {{ cr.controls|selectattr("status","equalto","pass")|list|length }}
    &nbsp;·&nbsp; Fail: {{ cr.controls|selectattr("status","equalto","fail")|list|length }}
    &nbsp;·&nbsp; Manual: {{ cr.controls|selectattr("status","equalto","manual")|list|length }}
  </p>
  <table>
    <thead><tr><th>Control</th><th>Name</th><th>Status</th><th>Evidence</th></tr></thead>
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
  <div class="page-footer"><span>KageSec Security Report</span><span>{{ target }}</span></div>
</div>
{% endfor %}
{% endif %}

<!-- ═══════════════════════════════════════════════════ APPENDIX ══ -->
<div class="page">
  <div class="section-title">Appendix</div>

  <div class="sub-title">Appendix A — Measurement Scales</div>
  <p>Severity ratings are determined using OWASP and CVSS industry standards.</p>
  <table>
    <thead><tr><th>Severity</th><th>Description</th><th>Risk Score</th></tr></thead>
    <tbody>
      <tr>
        <td><span class="badge badge-critical">Critical</span></td>
        <td>Immediately exploitable. Direct path to significant data breach, RCE, or full system compromise.</td>
        <td>8.0 – 10.0</td>
      </tr>
      <tr>
        <td><span class="badge badge-high">High</span></td>
        <td>Significant technical risk. Can breach confidentiality or integrity of sensitive data without chaining.</td>
        <td>6.0 – 7.9</td>
      </tr>
      <tr>
        <td><span class="badge badge-medium">Medium</span></td>
        <td>Does not in isolation expose data but can be chained with other issues to create significant risk.</td>
        <td>4.0 – 5.9</td>
      </tr>
      <tr>
        <td><span class="badge badge-low">Low</span></td>
        <td>Limited risk. Requires multiple conditions or additional vulnerabilities to be exploitable.</td>
        <td>2.0 – 3.9</td>
      </tr>
      <tr>
        <td><span class="badge badge-info">Info</span></td>
        <td>No direct security impact. Represents a best-practice deviation or security observation.</td>
        <td>0.0 – 1.9</td>
      </tr>
    </tbody>
  </table>

  <div class="sub-title">Appendix B — Resolution Status</div>
  <table>
    <thead><tr><th>Status</th><th>Meaning</th></tr></thead>
    <tbody>
      <tr><td><strong>Open</strong></td><td>Reported by the scanner. Not yet reviewed or remediated.</td></tr>
      <tr><td><strong>Verified</strong></td><td>AI-confirmed true positive; exploit evidence and scenario are available.</td></tr>
      <tr><td><strong>Needs Review</strong></td><td>Potential issue found. Manual confirmation is recommended before acting.</td></tr>
    </tbody>
  </table>

  <div class="sub-title">Appendix C — Risk Score</div>
  <p>
    Each finding is assigned a risk score from 0–10 derived from the CVSS base score
    (when available), severity class, confidence level, and AI exploitability assessment.
    Scores of <strong>7.0+</strong> warrant immediate attention; <strong>4.0–6.9</strong>
    should be addressed in the next sprint; <strong>below 4.0</strong> can be tracked
    as a security backlog item.
  </p>
  <div class="page-footer"><span>KageSec Security Report</span><span>{{ target }}</span></div>
</div>

</body>
</html>
"""


def _sev_color(sev: str) -> str:
    return _SEV_COLOR.get(sev, "#64748B")


def _sev_bg(sev: str) -> str:
    return _SEV_BG.get(sev, "#F8FAFC")


def _risk_score(f: Finding) -> float:
    """Derive a 0–10 risk score from CVSS or severity + confidence."""
    if f.cvss is not None:
        base = float(f.cvss)
    else:
        base = {
            "critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.5
        }.get(f.severity.value, 3.0)
    if f.ai_verdict == "true_positive":
        base = min(10.0, base + 0.3)
    elif f.ai_verdict == "false_positive":
        base = max(0.0, base - 1.5)
    base *= f.confidence
    return round(min(10.0, max(0.0, base)), 1)


def generate_pdf(
    scan_result: ScanResult,
    output_path: str,
    auth_type: str = "Unauthenticated",
    auth_value: str = "—",
) -> str:
    """
    Render the HTML report and print it to PDF via Playwright.
    Returns output_path on success.
    Raises RuntimeError if Playwright or jinja2 is not installed.
    """
    try:
        from jinja2 import Environment
    except ImportError:
        raise RuntimeError("jinja2 is required: pip install jinja2")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise RuntimeError(
            "playwright is required: pip install playwright && playwright install chromium"
        )

    active = [f for f in scan_result.findings if not f.false_positive_suppressed]

    class _Proxy:
        """Wraps a Finding and adds a computed risk_score attribute."""
        def __init__(self, f: Finding):
            self._f = f
            self.risk_score = _risk_score(f)
        def __getattr__(self, item):
            return getattr(self._f, item)

    proxies = [_Proxy(f) for f in active]

    env = Environment(autoescape=True)
    env.globals["sev_color"] = _sev_color
    env.globals["sev_bg"]    = _sev_bg
    template = env.from_string(_HTML_TEMPLATE)

    html = template.render(
        target=scan_result.target,
        findings=proxies,
        compliance=scan_result.compliance_reports,
        pages_crawled=scan_result.pages_crawled,
        duration=scan_result.scan_duration_seconds,
        date=datetime.now(timezone.utc).strftime("%B %d, %Y"),
        auth_type=auth_type,
        auth_value=auth_value,
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False, encoding="utf-8") as fh:
        fh.write(html)
        html_path = fh.name

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            pg = browser.new_page()
            pg.goto(f"file://{html_path}")
            pg.wait_for_load_state("networkidle")
            pg.pdf(
                path=output_path,
                format="A4",
                margin={"top": "0mm", "bottom": "0mm", "left": "0mm", "right": "0mm"},
                print_background=True,
            )
            browser.close()
    finally:
        os.unlink(html_path)

    return output_path
