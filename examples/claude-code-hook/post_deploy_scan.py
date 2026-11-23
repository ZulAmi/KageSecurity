"""
KageSec post-deploy hook for Claude Code — OPT-IN EXAMPLE.

When Claude runs a deployment command, this hook starts a KageSec scan of the
deployed URL in the background. It is deliberately conservative:

  * It only scans hosts listed in KAGESEC_HOOK_ALLOWED_HOSTS (comma-separated,
    e.g. "staging.example.com,preview.example.com"). Without that variable it
    does nothing — a URL scraped from command output (for example the GitHub
    remote printed by `git push`) is never scanned by accident.
  * It runs in passive mode (no attack payloads) unless KAGESEC_HOOK_ACTIVE=1.

Install: copy settings.example.json into your project's .claude/settings.json
(or merge its "hooks" block) and set KAGESEC_HOOK_ALLOWED_HOSTS.

Input (stdin): JSON with keys tool_name, tool_input, tool_response
Output: JSON with optional "message" shown to Claude, or empty to do nothing.
"""
import json
import os
import re
import subprocess
import sys


# Patterns that indicate a deployment just happened
_DEPLOY_PATTERNS = [
    r"vercel\s+(?:deploy|--prod)",
    r"netlify\s+deploy",
    r"heroku\s+.*push",
    r"git\s+push.*(?:heroku|main|master|prod|production)",
    r"flyctl\s+deploy",
    r"railway\s+up",
    r"aws\s+.*deploy",
    r"gcloud\s+.*deploy",
    r"kubectl\s+.*apply",
    r"docker\s+.*push",
    r"npm\s+run\s+deploy",
    r"yarn\s+deploy",
]

# Patterns to extract the deployed URL from command output
_URL_PATTERNS = [
    r"https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s]*)?",
]

_DEPLOY_RE = [re.compile(p, re.IGNORECASE) for p in _DEPLOY_PATTERNS]
_URL_RE = re.compile(r"https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s\"']*)?")


def _is_deployment(command: str) -> bool:
    return any(p.search(command) for p in _DEPLOY_RE)


def _allowed_hosts() -> set[str]:
    raw = os.getenv("KAGESEC_HOOK_ALLOWED_HOSTS", "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _extract_url(text: str, allowed: set[str]) -> str | None:
    """Return the first URL in *text* whose host is explicitly allow-listed."""
    from urllib.parse import urlparse

    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(".,)")
        host = (urlparse(url).hostname or "").lower()
        if host in allowed:
            return url
    return None


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    if data.get("tool_name") != "Bash":
        sys.exit(0)

    command = data.get("tool_input", {}).get("command", "")
    output = data.get("tool_response", {}).get("output", "")

    if not _is_deployment(command):
        sys.exit(0)

    allowed = _allowed_hosts()
    if not allowed:
        sys.exit(0)  # not configured — never scan anything

    url = _extract_url(output, allowed) or _extract_url(command, allowed)
    if not url:
        sys.exit(0)

    project_dir = os.getenv("CLAUDE_PROJECT_DIR") or os.getcwd()
    reports_dir = os.path.join(project_dir, "reports", "post-deploy")
    os.makedirs(reports_dir, exist_ok=True)
    log_path = os.path.join(reports_dir, "latest_scan.log")

    cmd = [
        "kagesec", "scan",
        "--depth", "2",
        "--max-pages", "20",
        "--no-ai", "--no-oob",
        "--output", "json",
        "--report-dir", reports_dir,
    ]
    active = os.getenv("KAGESEC_HOOK_ACTIVE", "") == "1"
    if not active:
        cmd.append("--passive")
    cmd += ["--", url]

    with open(log_path, "w") as log:
        subprocess.Popen(  # nosec B603 — fixed argv, URL host is allow-listed
            cmd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
        )

    mode = "active" if active else "passive"
    print(json.dumps({
        "message": (
            f"[KageSec] {mode} security scan started for {url} in the background.\n"
            f"Report: {reports_dir}/kagesec_report.json   Log: {log_path}"
        )
    }))


if __name__ == "__main__":
    main()
