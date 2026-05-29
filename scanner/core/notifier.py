"""
Webhook / Notification System — Gap 20

Sends real-time finding alerts to Slack, Microsoft Teams, Discord, or any
generic webhook URL. Integrated into the scan engine's finding_callback.

CLI flags:
  --notify-slack URL         Slack incoming webhook URL
  --notify-teams URL         MS Teams incoming webhook URL
  --notify-discord URL       Discord webhook URL
  --notify-webhook URL       Generic HTTP POST webhook (JSON payload)
  --notify-min-severity LEVEL  Only fire for findings at or above this severity
                             (critical|high|medium|low|info, default: medium)
"""
from __future__ import annotations

import httpx
from typing import Optional
from scanner.core.scan_result import Finding, Severity

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class Notifier:
    """
    Wraps multiple notification channels. Use as a finding_callback in run_scan().

    Example:
        notifier = Notifier.from_config(config)
        result, _ = run_scan(target, config, finding_callback=notifier)
    """

    def __init__(
        self,
        slack_url: Optional[str] = None,
        teams_url: Optional[str] = None,
        discord_url: Optional[str] = None,
        webhook_url: Optional[str] = None,
        min_severity: Severity = Severity.MEDIUM,
    ):
        self.slack_url = slack_url
        self.teams_url = teams_url
        self.discord_url = discord_url
        self.webhook_url = webhook_url
        self.min_severity = min_severity
        self._client = httpx.Client(timeout=10)

    @classmethod
    def from_config(cls, config) -> "Notifier":
        return cls(
            slack_url=getattr(config, "notify_slack", None),
            teams_url=getattr(config, "notify_teams", None),
            discord_url=getattr(config, "notify_discord", None),
            webhook_url=getattr(config, "notify_webhook", None),
            min_severity=_parse_severity(getattr(config, "notify_min_severity", "medium")),
        )

    def is_configured(self) -> bool:
        return any([self.slack_url, self.teams_url, self.discord_url, self.webhook_url])

    def __call__(self, finding: Finding):
        """finding_callback interface — called by the engine for each finding."""
        if _SEVERITY_RANK.get(finding.severity, 99) > _SEVERITY_RANK.get(self.min_severity, 2):
            return
        self.notify(finding)

    def notify(self, finding: Finding):
        if self.slack_url:
            self._send_slack(finding)
        if self.teams_url:
            self._send_teams(finding)
        if self.discord_url:
            self._send_discord(finding)
        if self.webhook_url:
            self._send_generic(finding)

    def _send_slack(self, finding: Finding):
        emoji = _SEVERITY_EMOJI.get(finding.severity, "⚪")
        text = (
            f"{emoji} *{finding.severity.upper()} — {finding.title}*\n"
            f"URL: {finding.url}\n"
            f"Evidence: {finding.evidence[:300]}"
        )
        try:
            self._client.post(self.slack_url, json={"text": text})
        except Exception:
            pass

    def _send_teams(self, finding: Finding):
        color = {
            Severity.CRITICAL: "FF0000",
            Severity.HIGH: "FF6600",
            Severity.MEDIUM: "FFCC00",
            Severity.LOW: "0099FF",
            Severity.INFO: "AAAAAA",
        }.get(finding.severity, "AAAAAA")

        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": finding.title,
            "sections": [{
                "activityTitle": f"**{finding.severity.upper()}** — {finding.title}",
                "facts": [
                    {"name": "URL", "value": finding.url},
                    {"name": "Parameter", "value": finding.parameter or "N/A"},
                    {"name": "CVSS", "value": str(finding.cvss or "N/A")},
                    {"name": "Evidence", "value": finding.evidence[:300]},
                ],
            }],
        }
        try:
            self._client.post(self.teams_url, json=card)
        except Exception:
            pass

    def _send_discord(self, finding: Finding):
        color_int = {
            Severity.CRITICAL: 0xFF0000,
            Severity.HIGH: 0xFF6600,
            Severity.MEDIUM: 0xFFCC00,
            Severity.LOW: 0x0099FF,
            Severity.INFO: 0xAAAAAA,
        }.get(finding.severity, 0xAAAAAA)

        embed = {
            "embeds": [{
                "title": f"{finding.severity.upper()} — {finding.title}",
                "description": finding.evidence[:500],
                "color": color_int,
                "fields": [
                    {"name": "URL", "value": finding.url[:200], "inline": False},
                    {"name": "Parameter", "value": finding.parameter or "N/A", "inline": True},
                    {"name": "CVSS", "value": str(finding.cvss or "N/A"), "inline": True},
                ],
            }]
        }
        try:
            self._client.post(self.discord_url, json=embed)
        except Exception:
            pass

    def _send_generic(self, finding: Finding):
        payload = {
            "title": finding.title,
            "severity": finding.severity.value,
            "url": finding.url,
            "parameter": finding.parameter,
            "payload": finding.payload,
            "evidence": finding.evidence,
            "cwe": finding.cwe,
            "cvss": finding.cvss,
            "owasp_category": finding.owasp_category,
            "confidence": finding.confidence,
            "poc_curl": finding.poc_curl,
        }
        try:
            self._client.post(self.webhook_url, json=payload)
        except Exception:
            pass

    def close(self):
        self._client.close()


def _parse_severity(s: str) -> Severity:
    try:
        return Severity(s.lower())
    except ValueError:
        return Severity.MEDIUM
