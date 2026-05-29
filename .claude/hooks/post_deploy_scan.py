"""
KageSec Post-Deploy Hook

Claude Code calls this after every Bash tool use. If the command looks like a
deployment, extract the live URL and trigger a KageSec scan automatically.

Registered in .claude/settings.json as a PostToolUse hook on Bash.

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


def _extract_url(text: str) -> str | None:
    # Skip localhost and internal addresses
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(".,)")
        if not any(x in url for x in ("localhost", "127.0.0.1", "0.0.0.0", "internal")):
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

    url = _extract_url(output) or _extract_url(command)
    if not url:
        print(json.dumps({
            "message": "[KageSec] Deployment detected but could not extract a URL — run `kagesec scan <url>` manually."
        }))
        sys.exit(0)

    # Run the scan in the background so it doesn't block Claude
    kagesec_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    log_path = os.path.join(kagesec_dir, "reports", "latest_scan.log")
    os.makedirs(os.path.join(kagesec_dir, "reports"), exist_ok=True)

    subprocess.Popen(
        [
            sys.executable, "-u", "-m", "cli.main", "scan", url,
            "--depth", "2",
            "--max-pages", "20",
            "--no-ai", "--no-oob",
            "--output", "all",
            "--full",
        ],
        cwd=kagesec_dir,
        stdout=open(log_path, "w"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    print(json.dumps({
        "message": (
            f"[KageSec] Security scan started for {url} in the background.\n"
            f"Results will be written to reports/kagesec_report.* when complete.\n"
            f"Live log: {log_path}"
        )
    }))


if __name__ == "__main__":
    main()
