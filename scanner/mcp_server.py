"""
KageSec MCP Server

Exposes KageSec as a Claude Code tool via the Model Context Protocol.

Usage — add to ~/.claude/mcp.json:
{
  "mcpServers": {
    "kagesec": {
      "command": "python3",
      "args": ["-m", "scanner.mcp_server"],
      "cwd": "/path/to/KageSec"
    }
  }
}

Claude can then call:
  - kagesec_scan(url, ...)   → run a full security scan
  - kagesec_report(path)     → read a generated report
"""
from __future__ import annotations

import json
import os
import sys
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("kagesec")


@mcp.tool()
def kagesec_scan(
    url: str,
    depth: int = 2,
    max_pages: int = 20,
    output: str = "json",
    modules: str = "",
    no_ai: bool = True,
    no_oob: bool = True,
) -> str:
    """
    Run a KageSec security scan against a target URL.

    Args:
        url:       Target URL to scan (e.g. https://example.com)
        depth:     Crawl depth (default 2)
        max_pages: Maximum pages to crawl (default 20)
        output:    Report format: json, pdf, sarif, burp, zap, all (default json)
        modules:   Comma-separated module names to run (empty = all)
        no_ai:     Skip AI triage (default True — set False if ANTHROPIC_API_KEY is set)
        no_oob:    Skip out-of-band callbacks (default True)

    Returns:
        JSON string with findings summary and path to generated report.
    """
    cmd = [
        sys.executable, "-u", "-m", "cli.main", "scan", url,
        "--depth", str(depth),
        "--max-pages", str(max_pages),
        "--output", output,
        "--full",
    ]
    if modules:
        cmd += ["--modules"] + modules.split(",")
    if no_ai:
        cmd.append("--no-ai")
    if no_oob:
        cmd.append("--no-oob")

    cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            cwd=cwd,
        )
        output_text = proc.stdout + proc.stderr

        # Parse findings from the generated JSON report
        report_path = os.path.join(cwd, "reports", "kagesec_report.json")
        if os.path.exists(report_path):
            with open(report_path) as f:
                report = json.load(f)
            summary = report.get("summary", {})
            findings = report.get("findings", [])
            return json.dumps({
                "status": "complete",
                "url": url,
                "total_findings": summary.get("total_findings", 0),
                "by_severity": summary.get("by_severity", {}),
                "duration_seconds": summary.get("duration_seconds", 0),
                "report_path": report_path,
                "findings": findings[:20],  # first 20 to keep context manageable
                "scan_output": output_text[-2000:],  # last 2000 chars of CLI output
            }, indent=2)

        return json.dumps({
            "status": "complete",
            "url": url,
            "scan_output": output_text[-3000:],
            "error": "Report file not found — check scan_output for details",
        }, indent=2)

    except subprocess.TimeoutExpired:
        return json.dumps({"status": "timeout", "url": url, "error": "Scan exceeded 10 minute limit"})
    except Exception as e:
        return json.dumps({"status": "error", "url": url, "error": str(e)})


@mcp.tool()
def kagesec_read_report(report_path: str = "") -> str:
    """
    Read a KageSec JSON report from the reports/ folder.

    Args:
        report_path: Path to the report file. Defaults to reports/kagesec_report.json.

    Returns:
        Full JSON report contents.
    """
    cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not report_path:
        report_path = os.path.join(cwd, "reports", "kagesec_report.json")

    try:
        with open(report_path) as f:
            return f.read()
    except FileNotFoundError:
        return json.dumps({"error": f"Report not found: {report_path}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    mcp.run()
