import os
import sys
import json
import argparse
import tempfile
import threading
import uuid as _uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner.core.engine import run_scan
from scanner.core.config import ScanConfig, LoginFlow
from scanner.core import policy as _policy

# Force line-buffered stdout so output appears immediately when redirected
# (e.g. piped to a file, run in CI, or captured by a background task runner)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)


def main():
    parser = argparse.ArgumentParser(
        prog="kagesec",
        description="KageSec — AI-powered web application security scanner",
    )
    sub = parser.add_subparsers(dest="command")

    # ------------------------------------------------------------------ scan
    scan_cmd = sub.add_parser("scan", help="Run a security scan against a target URL")
    scan_cmd.add_argument("target", nargs="?", help="Target URL (e.g. https://example.com)")
    scan_cmd.add_argument(
        "--targets", metavar="FILE",
        help="File with one target URL per line — runs scan against each and writes per-target reports",
    )
    scan_cmd.add_argument("--depth", type=int, default=3, help="Crawl depth (default: 3)")
    scan_cmd.add_argument("--max-pages", type=int, default=100, help="Max pages to crawl")
    scan_cmd.add_argument(
        "--output",
        choices=["json", "markdown", "pdf", "sarif", "burp", "zap", "all"],
        default="json",
        help=(
            "Report format(s) to generate. "
            "'json' — machine-readable (default); "
            "'markdown' — human-readable text report; "
            "'pdf' — professional PDF report (requires: pip install \"kagesec[pdf]\" && playwright install chromium); "
            "'sarif' — SARIF 2.1.0 for GitHub Code Scanning / VS Code; "
            "'burp' — Burp Suite XML issue import format; "
            "'zap' — OWASP ZAP JSON alert format; "
            "'all' — generate all formats."
        ),
    )
    scan_cmd.add_argument("--no-ai", action="store_true", help="Skip AI — no provider prompt, no verification")
    scan_cmd.add_argument("--ai-model", metavar="MODEL", help="Override the default model for the selected AI provider")
    scan_cmd.add_argument("--ollama-url", metavar="URL", help="Ollama base URL (default: http://localhost:11434)")
    scan_cmd.add_argument(
        "--compliance", nargs="+",
        choices=["iso27001", "hipaa", "gdpr", "appi"],
        help="Generate compliance reports (e.g. --compliance gdpr hipaa)",
    )
    scan_cmd.add_argument("--modules", nargs="+", help="Run only specific modules (e.g. --modules xss sqli)")
    scan_cmd.add_argument("--auth-bearer", metavar="TOKEN", help="Bearer token for authenticated scanning")
    scan_cmd.add_argument("--auth-cookie", metavar="NAME=VALUE", help="Session cookie (e.g. session=abc123)")
    scan_cmd.add_argument(
        "--auth-oauth2-token-url", metavar="URL",
        help="OAuth2 token endpoint for client credentials flow",
    )
    scan_cmd.add_argument("--auth-oauth2-client-id", metavar="ID", help="OAuth2 client ID")
    scan_cmd.add_argument("--auth-oauth2-client-secret", metavar="SECRET", help="OAuth2 client secret")
    scan_cmd.add_argument(
        "--proxy", metavar="URL",
        help="HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080) — routes all scan traffic through proxy",
    )
    scan_cmd.add_argument(
        "--passive", action="store_true",
        help="Passive mode — inspect headers/cookies/content only, no injection payloads (safe for production)",
    )
    scan_cmd.add_argument(
        "--follow-robots", action="store_true",
        help="Respect robots.txt Disallow rules during crawl (default: ignore)",
    )
    scan_cmd.add_argument(
        "--no-oob", action="store_true",
        help="Disable out-of-band callback server (use for air-gapped or rate-limited targets)",
    )
    scan_cmd.add_argument(
        "--oob-server", metavar="DOMAIN", default=None,
        help="Custom OOB callback domain (default: oast.pro)",
    )
    scan_cmd.add_argument(
        "--fail-on", choices=["critical", "high", "medium", "low"],
        help="Exit with code 1 if findings at this severity or above are found (CI/CD mode)",
    )
    scan_cmd.add_argument("--browser", action="store_true", default=True, help="Use Playwright headless browser (SPAs, JS content) [default: on]")
    scan_cmd.add_argument("--no-browser", action="store_false", dest="browser", help="Disable Playwright browser (faster, but misses JS-rendered content)")
    scan_cmd.add_argument("--login-url", metavar="URL", help="Login page URL for authenticated scanning")
    scan_cmd.add_argument("--login-user-selector", metavar="CSS", help="CSS selector for username field")
    scan_cmd.add_argument("--login-pass-selector", metavar="CSS", help="CSS selector for password field")
    scan_cmd.add_argument("--login-submit-selector", metavar="CSS", help="CSS selector for submit button")
    scan_cmd.add_argument("--login-username", metavar="VALUE", help="Username / email to login with")
    scan_cmd.add_argument("--login-password", metavar="VALUE", help="Password to login with")
    scan_cmd.add_argument("--login-success", metavar="INDICATOR", help="URL substring or CSS selector post-login")
    scan_cmd.add_argument("--login-totp-secret", metavar="BASE32", help="base32 TOTP secret for 2FA")
    scan_cmd.add_argument("--openapi", metavar="URL_OR_FILE", help="OpenAPI 3.x/Swagger 2.x spec for API scanning")
    scan_cmd.add_argument("--graphql", metavar="URL", help="GraphQL endpoint URL")
    scan_cmd.add_argument(
        "--grpc", metavar="HOST:PORT",
        help=(
            "gRPC endpoint to scan via Server Reflection (e.g. api.example.com:50051). "
            "Discovers all services/methods and fuzzes string fields for injection. "
            "Requires: pip install grpcio grpcio-reflection protobuf"
        ),
    )
    scan_cmd.add_argument("--resume", metavar="SCAN_ID", help="Resume an interrupted scan")
    scan_cmd.add_argument("--nvd-api-key", metavar="KEY", help="NVD API key for CVE enrichment")
    scan_cmd.add_argument("--templates", nargs="+", metavar="DIR", help="Extra YAML template directories")
    scan_cmd.add_argument("--skip-templates", action="store_true", help="Disable built-in YAML template scanning")
    scan_cmd.add_argument("--nuclei-templates", action="store_true", help="Include Nuclei community templates (~10k templates, slow without --api-key)")
    scan_cmd.add_argument(
        "--parallel", type=int, default=1, metavar="N",
        help="Number of targets to scan concurrently when using --targets (default: 1 = sequential)",
    )
    scan_cmd.add_argument(
        "--live", action="store_true",
        help="Print each finding immediately as it is discovered instead of waiting for scan completion",
    )
    scan_cmd.add_argument(
        "--include", nargs="+", metavar="PATTERN",
        help="Only crawl URLs matching these glob patterns (e.g. '*/api/*' '*/admin/*')",
    )
    scan_cmd.add_argument(
        "--exclude", nargs="+", metavar="PATTERN",
        help="Skip URLs matching these glob patterns (e.g. '*/logout*' '*.css' '*.js')",
    )
    scan_cmd.add_argument(
        "--concurrency", type=int, default=8, metavar="N",
        help="Number of module-threads per page (default: 8). Increase for fast targets, decrease to be polite.",
    )
    scan_cmd.add_argument(
        "--rate-limit", type=int, default=10, metavar="RPS",
        help="Maximum HTTP requests per second across the whole scan (default: 10).",
    )
    scan_cmd.add_argument(
        "--har", metavar="FILE",
        help="Import a .har file and scan all captured requests instead of crawling a live URL.",
    )
    scan_cmd.add_argument(
        "--workflow", metavar="NAME_OR_FILE",
        help=(
            "Run a YAML workflow that chains scan steps with conditions. "
            "Built-in: quick-web, wordpress. Custom: path to .yaml file or "
            "name from ~/.kagesec/workflows/. "
            "Use 'kagesec workflows' to list available workflows."
        ),
    )
    scan_cmd.add_argument(
        "--auto-update", action="store_true",
        help="Automatically download newer Nuclei templates if available (background, non-blocking).",
    )
    scan_cmd.add_argument(
        "--profile", metavar="NAME",
        help=(
            "Apply a named scan preset. Built-in: quick, full, api, passive, stealth. "
            "Custom profiles in ~/.kagesec/profiles/<name>.yaml. "
            "CLI flags override profile defaults."
        ),
    )
    scan_cmd.add_argument(
        "--wsdl", metavar="URL",
        help="SOAP/WSDL endpoint URL — fetches WSDL, discovers operations, and probes for XXE and verbose faults.",
    )
    scan_cmd.add_argument("--jwt-wordlist", metavar="FILE", help="Custom JWT secrets wordlist for weak secret cracking")
    scan_cmd.add_argument("--wordlist", metavar="FILE", help="Custom path discovery wordlist (overrides built-in)")
    scan_cmd.add_argument("--param-wordlist", metavar="FILE", help="Custom parameter discovery wordlist")
    scan_cmd.add_argument("--subdomain-wordlist", metavar="FILE", help="Custom subdomain enumeration wordlist")
    scan_cmd.add_argument("--policy", metavar="FILE", help="Scan policy YAML — per-module enable/strength/timeout overrides")
    scan_cmd.add_argument(
        "--full", action="store_true",
        help="Force a full scan — ignore delta state and re-scan all URLs even if unchanged since last scan",
    )
    scan_cmd.add_argument(
        "--notify-slack", metavar="URL",
        help="Slack incoming webhook URL — posts each finding above --notify-min-severity",
    )
    scan_cmd.add_argument(
        "--notify-teams", metavar="URL",
        help="Microsoft Teams incoming webhook URL",
    )
    scan_cmd.add_argument(
        "--notify-discord", metavar="URL",
        help="Discord webhook URL",
    )
    scan_cmd.add_argument(
        "--notify-webhook", metavar="URL",
        help="Generic JSON webhook URL (POST with finding payload)",
    )
    scan_cmd.add_argument(
        "--notify-min-severity", metavar="LEVEL",
        choices=["critical", "high", "medium", "low", "info"],
        default="high",
        help="Minimum severity to notify (default: high)",
    )
    scan_cmd.add_argument(
        "--timeout", type=int, default=10, metavar="SECONDS",
        help="Per-request HTTP timeout in seconds (default: 10)",
    )
    scan_cmd.add_argument(
        "--retries", type=int, default=0, metavar="N",
        help="Number of times to retry failed HTTP requests (default: 0)",
    )
    scan_cmd.add_argument(
        "--user-agent", metavar="UA",
        help="Custom User-Agent string (default: KageSec/1.0). Useful for WAF evasion or mobile path testing.",
    )
    scan_cmd.add_argument(
        "-H", "--header", dest="custom_headers", metavar="NAME:VALUE",
        action="append", default=[],
        help="Add a custom HTTP header to every request (e.g. -H 'X-Api-Key: abc'). Repeatable.",
    )
    scan_cmd.add_argument(
        "--max-time", type=int, default=0, metavar="MINUTES",
        help="Hard time limit for the scan in minutes (default: 0 = unlimited). Scan stops gracefully when exceeded.",
    )
    scan_cmd.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output — print each URL as it is crawled and each module as it runs.",
    )
    scan_cmd.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color codes in output (useful for log files and CI/CD pipelines).",
    )
    scan_cmd.add_argument(
        "--stats", action="store_true",
        help="Show a live progress bar on stderr while scanning (pages/modules completed, findings so far).",
    )
    scan_cmd.add_argument(
        "--extensions", metavar="LIST",
        help=(
            "Comma-separated file extensions to append during path discovery "
            "(e.g. '.php,.asp,.bak,.zip'). Appended to each wordlist entry."
        ),
    )
    scan_cmd.add_argument(
        "--filter-status", metavar="CODES",
        help=(
            "Comma-separated HTTP status codes to suppress in discovery output "
            "(e.g. '404,301' skips these from path/param discovery findings)."
        ),
    )
    scan_cmd.add_argument(
        "--random-agent", action="store_true",
        help="Rotate User-Agent string randomly per request from a built-in list.",
    )
    scan_cmd.add_argument(
        "--cookie-jar", metavar="FILE",
        help="Netscape-format cookie jar file — loads cookies for all scan requests.",
    )
    scan_cmd.add_argument(
        "--dbms", choices=["mysql", "postgres", "mssql", "oracle", "sqlite"],
        help="Specify the backend DBMS to tune SQLi payloads (auto-detected if omitted).",
    )
    scan_cmd.add_argument(
        "--level", type=int, default=1, choices=range(1, 6), metavar="1-5",
        help=(
            "Scan aggressiveness level (default: 1). Higher levels add more payloads, "
            "headers, and cookie injection. 1=safe, 3=standard, 5=maximum."
        ),
    )
    scan_cmd.add_argument(
        "--risk", type=int, default=1, choices=range(1, 4), metavar="1-3",
        help=(
            "Risk of side-effects (default: 1). Higher risks include time-based "
            "and heavy-weight payloads that may affect availability. 1=low, 3=high."
        ),
    )

    # ------------------------------------------------------------------ diff
    diff_cmd = sub.add_parser("diff", help="Compare two scan reports and show new / resolved findings")
    diff_cmd.add_argument("baseline", help="Baseline JSON report (earlier scan)")
    diff_cmd.add_argument("current", help="Current JSON report (later scan)")
    diff_cmd.add_argument(
        "--fail-on", choices=["critical", "high", "medium", "low"],
        help="Exit with code 1 if new findings at this severity or above are found",
    )
    diff_cmd.add_argument("--output", choices=["text", "json"], default="text", help="Diff output format")

    # ------------------------------------------------------------------ serve
    serve_cmd = sub.add_parser("serve", help="Start KageSec as an HTTP API server")
    serve_cmd.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")  # nosec B104
    serve_cmd.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")

    # ------------------------------------------------------------------ export
    export_cmd = sub.add_parser("export", help="Export a scan checkpoint for transfer to another machine")
    export_cmd.add_argument("--scan-id", required=True, metavar="ID", help="Scan ID to export")
    export_cmd.add_argument("--report", metavar="FILE", default="kagesec_report.json",
                            help="JSON report to bundle (default: kagesec_report.json)")
    export_cmd.add_argument("--out", metavar="FILE", default="kagesec_export.zip",
                            help="Output zip file (default: kagesec_export.zip)")

    # ------------------------------------------------------------------ import-scan
    import_cmd = sub.add_parser("import-scan", help="Import a previously exported scan checkpoint")
    import_cmd.add_argument("file", help="Exported zip file to import")

    # ------------------------------------------------------------------ history
    history_cmd = sub.add_parser("history", help="Show finding trends from past scans")
    history_cmd.add_argument("target", nargs="?", help="Filter by target URL")
    history_cmd.add_argument("--persisting", action="store_true", help="Show only findings seen in multiple scans")
    history_cmd.add_argument("--scans", action="store_true", help="Show scan history instead of findings")
    history_cmd.add_argument("--limit", type=int, default=10, help="Max rows to show (default: 10)")

    # ------------------------------------------------------------------ suppress
    suppress_cmd = sub.add_parser("suppress", help="Manage false-positive suppression rules")
    suppress_sub = suppress_cmd.add_subparsers(dest="suppress_action")

    supp_add = suppress_sub.add_parser("add", help="Add a suppression rule")
    supp_add.add_argument("--title", metavar="PATTERN", help="Suppress findings whose title contains this string")
    supp_add.add_argument("--url-pattern", metavar="GLOB", help="fnmatch glob matching finding URL (e.g. '*/admin/*')")
    supp_add.add_argument("--target", metavar="URL", help="Only suppress for this target (startswith match)")
    supp_add.add_argument("--note", metavar="TEXT", help="Reason for suppression (stored for audit trail)")

    suppress_sub.add_parser("list", help="List active suppression rules")

    supp_rm = suppress_sub.add_parser("remove", help="Remove a suppression rule by ID")
    supp_rm.add_argument("rule_id", help="Rule ID shown in 'suppress list'")

    # ------------------------------------------------------------------ retest
    retest_cmd = sub.add_parser("retest", help="Re-run a specific finding to verify if it still exists")
    retest_cmd.add_argument("finding_id", help="Finding index (0-based) or 'title:substring' to match")
    retest_cmd.add_argument("--report", metavar="FILE", default="kagesec_report.json",
                            help="JSON report file containing the finding (default: kagesec_report.json)")
    retest_cmd.add_argument("--api-key", metavar="KEY", help="Anthropic API key")
    retest_cmd.add_argument("--no-ai", action="store_true", help="Skip AI verification in retest")

    # ------------------------------------------------------------------ issues
    issues_cmd = sub.add_parser("issues", help="Export findings to Jira or GitHub Issues")
    issues_cmd.add_argument("--report", metavar="FILE", default="kagesec_report.json",
                            help="JSON report to export (default: kagesec_report.json)")
    issues_cmd.add_argument("--format", choices=["jira", "github"], required=True,
                            help="Export destination")
    issues_cmd.add_argument("--jira-url", metavar="URL", help="Jira instance base URL (e.g. https://myorg.atlassian.net)")
    issues_cmd.add_argument("--jira-project", metavar="KEY", help="Jira project key (e.g. SEC)")
    issues_cmd.add_argument("--jira-token", metavar="TOKEN", help="Jira API token (user:token base64 or bare token)")
    issues_cmd.add_argument("--github-repo", metavar="OWNER/REPO", help="GitHub repository (e.g. myorg/myapp)")
    issues_cmd.add_argument("--github-token", metavar="TOKEN", help="GitHub personal access token")
    issues_cmd.add_argument("--dry-run", action="store_true", help="Print what would be created without creating issues")
    issues_cmd.add_argument(
        "--min-severity", choices=["critical", "high", "medium", "low", "info"], default="medium",
        help="Only export findings at this severity or above (default: medium)",
    )

    # ------------------------------------------------------------------ workflows
    sub.add_parser("workflows", help="List available scan workflows")

    # ------------------------------------------------------------------ config
    config_cmd = sub.add_parser("config", help="View or set persistent default settings (~/.kagesec/config.yaml)")
    config_cmd.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"), action="append",
                            help="Set a config key (e.g. --set depth 5 --set output markdown)")
    config_cmd.add_argument("--unset", nargs="+", metavar="KEY", help="Remove config key(s)")
    config_cmd.add_argument("--show", action="store_true", help="Show current config (default action)")

    # ------------------------------------------------------------------ update-templates
    update_cmd = sub.add_parser(
        "update-templates",
        help="Download Nuclei community templates (~9,500 CVE/misconfiguration templates) filtered for KageSec compatibility",
    )
    update_cmd.add_argument(
        "--dir", metavar="PATH",
        default=os.path.expanduser("~/.kagesec/nuclei-templates"),
        help="Directory to save templates (default: ~/.kagesec/nuclei-templates/)",
    )
    update_cmd.add_argument(
        "--all", action="store_true",
        help="Keep all templates including unsupported types (flow/network/dns/headless). Default: compatible only.",
    )

    args = parser.parse_args()

    _print_disclaimer()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "history":
        _run_history(args)
        sys.exit(0)

    if args.command == "suppress":
        _run_suppress(args)
        sys.exit(0)

    if args.command == "retest":
        _run_retest(args)
        sys.exit(0)

    if args.command == "issues":
        _run_issues(args)
        sys.exit(0)

    if args.command == "workflows":
        from scanner.core.workflow import list_workflows
        names = list_workflows()
        if names:
            print("[+] Available workflows:")
            for n in names:
                print(f"    {n}")
        else:
            print("[*] No workflows found. Place .yaml files in ~/.kagesec/workflows/")
        sys.exit(0)

    if args.command == "config":
        _run_config(args)
        sys.exit(0)

    if args.command == "update-templates":
        _update_templates(args.dir, keep_all=getattr(args, "all", False))
        sys.exit(0)

    if args.command == "serve":
        from scanner.api.server import serve
        serve(host=args.host, port=args.port)
        sys.exit(0)

    if args.command == "export":
        _export_scan(args.scan_id, args.report, args.out)
        sys.exit(0)

    if args.command == "import-scan":
        _import_scan(args.file)
        sys.exit(0)

    if args.command == "diff":
        _run_diff(args)
        sys.exit(0)

    # ------------------------------------------------------------------ scan logic
    if not args.target and not getattr(args, "targets", None) and not getattr(args, "har", None):
        scan_cmd.error("provide a target URL, --targets FILE, or --har FILE")

    targets = _resolve_targets(args)

    if len(targets) > 1:
        _run_multi_target(targets, args)
    else:
        _run_single_target(targets[0], args, prefix="")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _interactive_ai_setup() -> tuple[str | None, str | None]:
    """Show a numbered provider menu when no AI key is configured.

    Returns (provider, api_key). Both are None if the user skips or if
    stdin is not a terminal (CI/CD environments).
    """
    import sys
    import getpass

    if not sys.stdin.isatty():
        print("[!] No AI key found — running without AI features.\n")
        return None, None

    _PROVIDERS = [
        ("anthropic", "Anthropic Claude",   "claude.ai/settings — recommended"),
        ("openai",    "OpenAI GPT-4o",      "platform.openai.com/api-keys"),
        ("gemini",    "Google Gemini",       "aistudio.google.com/app/apikey"),
        ("mistral",   "Mistral Large",       "console.mistral.ai"),
        ("ollama",    "Ollama (local)",      "no key needed — runs on your machine"),
    ]

    print("\n[?] No AI key detected.")
    print("    AI verification cuts false positives, scores exploitability,")
    print("    and writes a human-readable report. Select a provider:\n")

    for i, (_, name, hint) in enumerate(_PROVIDERS, 1):
        print(f"    {i}. {name}  —  {hint}")
    print(f"    {len(_PROVIDERS) + 1}. Skip — run without AI\n")

    try:
        raw = input(f"    > Choice [1-{len(_PROVIDERS) + 1}]: ").strip()
        choice = int(raw)
    except (ValueError, EOFError, KeyboardInterrupt):
        print()
        return None, None

    if choice < 1 or choice > len(_PROVIDERS) + 1:
        print("    Invalid choice — running without AI.\n")
        return None, None

    if choice == len(_PROVIDERS) + 1:
        print("    Skipping AI.\n")
        return None, None

    provider, name, _ = _PROVIDERS[choice - 1]

    if provider == "ollama":
        from scanner.ai.provider import _ollama_available
        if not _ollama_available():
            print("\n    [!] Ollama doesn't appear to be running at localhost:11434.")
            print("        Start it with: ollama serve\n")
            return None, None
        print("\n[*] Using Ollama (local)\n")
        return "ollama", None

    try:
        key = getpass.getpass(f"\n    > Paste your {name} API key (input hidden): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None, None

    if not key:
        print("    No key entered — running without AI.\n")
        return None, None

    print(f"\n[*] AI provider: {name}\n")
    return provider, key


def _print_disclaimer() -> None:
    print(
        "\n"
        "  KageSec — Authorized Security Testing Only\n"
        "  -------------------------------------------\n"
        "  This tool actively probes targets with attack payloads.\n"
        "  Use it ONLY on systems you own or have explicit written permission to test.\n"
        "  Unauthorized scanning may violate the CFAA, Computer Misuse Act, and\n"
        "  equivalent laws in your jurisdiction. The authors accept no liability\n"
        "  for misuse. By proceeding you confirm you are authorized to test this target.\n"
    )


def _resolve_targets(args) -> list[str]:
    if getattr(args, "targets", None):
        try:
            with open(args.targets) as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            return lines
        except FileNotFoundError:
            print(f"[!] Targets file not found: {args.targets}")
            sys.exit(1)
    if getattr(args, "har", None):
        # Derive target from the first entry in the HAR file
        if args.target:
            return [args.target]
        try:
            import json as _json
            from urllib.parse import urlparse as _up
            with open(args.har) as f:
                har = _json.load(f)
            first_url = har["log"]["entries"][0]["request"]["url"]
            p = _up(first_url)
            return [f"{p.scheme}://{p.netloc}"]
        except Exception:
            print("[!] Could not derive target from HAR — pass --target explicitly.")
            sys.exit(1)
    return [args.target]


def _run_multi_target(targets: list[str], args) -> None:
    parallel = getattr(args, "parallel", 1)
    print(f"[*] Multi-target scan: {len(targets)} targets  (parallel={parallel})")
    print()

    if parallel <= 1:
        any_fail = False
        for i, target in enumerate(targets, 1):
            print(f"[{i}/{len(targets)}] {target}")
            prefix = _safe_hostname(target)
            if _run_single_target(target, args, prefix=prefix):
                any_fail = True
            print()
        if any_fail:
            sys.exit(1)
        return

    # Concurrent path — each target in its own thread, output serialised with a lock
    _print_lock = threading.Lock()

    def _scan_one(i: int, target: str) -> int:
        prefix = _safe_hostname(target)
        with _print_lock:
            print(f"[{i}/{len(targets)}] Starting {target}")
        code = _run_single_target(target, args, prefix=prefix, print_lock=_print_lock)
        with _print_lock:
            print(f"[{i}/{len(targets)}] Done     {target}")
        return code

    any_fail = False
    with ThreadPoolExecutor(max_workers=parallel) as ex:
        futs = {ex.submit(_scan_one, i, t): t for i, t in enumerate(targets, 1)}
        for fut in as_completed(futs):
            if fut.result():
                any_fail = True

    if any_fail:
        sys.exit(1)


def _run_single_target(target: str, args, prefix: str, print_lock=None) -> int:
    """Run scan against one target. Returns 1 if --fail-on threshold is breached."""
    # Apply scan profile first (lowest priority), then persisted policy
    profile_name = getattr(args, "profile", None)
    if profile_name:
        from scanner.core import profiles as _profiles
        try:
            prof = _profiles.load(profile_name)
            _profiles.apply_to_namespace(prof, args)
        except ValueError as e:
            print(f"[!] {e}")
            sys.exit(1)

    # Apply persisted policy defaults (CLI overrides them via argparse defaults check)
    _policy.apply_to_namespace(_policy.load(), args)

    auth = _build_auth(args)
    login_flow = _build_login_flow(args)
    modules = _build_modules(args)

    config = ScanConfig(
        target=target,
        max_depth=args.depth,
        max_pages=args.max_pages,
        modules=modules,
        auth=auth,
        compliance=args.compliance or [],
        browser=args.browser,
        login_flow=login_flow,
        openapi_spec=args.openapi,
        graphql_endpoint=args.graphql,
        resume_scan_id=args.resume,
        nvd_api_key=args.nvd_api_key,
        template_dirs=args.templates or [],
        nuclei_templates=getattr(args, "nuclei_templates", False),
        proxy=getattr(args, "proxy", None),
        passive=getattr(args, "passive", False),
        follow_robots=getattr(args, "follow_robots", False),
        use_oob=not getattr(args, "no_oob", False),
        oob_server=getattr(args, "oob_server", None) or "oast.pro",
        include_patterns=getattr(args, "include", None) or [],
        exclude_patterns=getattr(args, "exclude", None) or [],
        rate_limit_rps=getattr(args, "rate_limit", 10),
        har_file=getattr(args, "har", None),
        wsdl_url=getattr(args, "wsdl", None),
        jwt_wordlist=getattr(args, "jwt_wordlist", None),
        path_wordlist=getattr(args, "wordlist", None),
        param_wordlist=getattr(args, "param_wordlist", None),
        subdomain_wordlist=getattr(args, "subdomain_wordlist", None),
        scan_policy_file=getattr(args, "policy", None),
        force_full_scan=getattr(args, "full", False),
        timeout=getattr(args, "timeout", 10),
        retries=getattr(args, "retries", 0),
        user_agent=getattr(args, "user_agent", None),
        verbose=getattr(args, "verbose", False),
        no_color=getattr(args, "no_color", False),
        max_time_minutes=getattr(args, "max_time", 0),
        headers=_parse_custom_headers(getattr(args, "custom_headers", [])),
        extensions=_parse_extensions(getattr(args, "extensions", None)),
        filter_status_codes=_parse_status_codes(getattr(args, "filter_status", None)),
        random_agent=getattr(args, "random_agent", False),
        cookie_jar=getattr(args, "cookie_jar", None),
        dbms=getattr(args, "dbms", None),
        level=getattr(args, "level", 1),
        risk=getattr(args, "risk", 1),
    )

    current_scan_id = args.resume or str(_uuid.uuid4())

    # env var overrides for GitHub Actions (KAGESEC_* vars set by action.yml)
    _env_no_ai = os.getenv("KAGESEC_NO_AI", "").lower() in ("1", "true", "yes")
    _env_passive = os.getenv("KAGESEC_PASSIVE", "").lower() in ("1", "true", "yes")
    _env_modules = os.getenv("KAGESEC_MODULES", "").split() or None
    _env_exclude = os.getenv("KAGESEC_EXCLUDE", "").split() or None

    if _env_no_ai:
        args.no_ai = True
    if _env_passive:
        config.passive = True
    if _env_modules and not config.modules:
        config.modules = _env_modules
    if _env_exclude and not config.exclude_patterns:
        config.exclude_patterns = _env_exclude

    api_key = None
    ai_provider = None
    ai_model = getattr(args, "ai_model", None)

    if not args.no_ai:
        from scanner.ai.provider import detect as detect_provider, provider_label

        ai_provider, api_key = detect_provider()

        if ai_provider:
            print(f"[*] AI provider: {provider_label(ai_provider, ai_model)}")
        else:
            # No key found anywhere — ask interactively
            ai_provider, api_key = _interactive_ai_setup()

    config.api_key = api_key
    config.ai_provider = ai_provider or "anthropic"
    config.ai_model = ai_model

    # Live findings callback — prints each finding as it is discovered
    _live = getattr(args, "live", False)
    _no_color = getattr(args, "no_color", False) or not sys.stdout.isatty()
    _severity_colours = {
        "critical": "\033[91m", "high": "\033[91m",
        "medium": "\033[93m", "low": "\033[94m", "info": "\033[96m",
    }
    _RESET = "\033[0m"

    def _live_print(finding):
        sev = finding.severity.value
        colour = "" if _no_color else _severity_colours.get(sev, "")
        reset = "" if _no_color else _RESET
        line = (
            f"{colour}[LIVE][{sev.upper():<8}]{reset} "
            f"{finding.title}  —  {finding.url}"
        )
        if print_lock:
            with print_lock:
                print(line, flush=True)
        else:
            print(line, flush=True)

    # Notifier — posts findings to Slack/Teams/Discord/webhook in real time
    _notifier = None
    _notify_slack = getattr(args, "notify_slack", None)
    _notify_teams = getattr(args, "notify_teams", None)
    _notify_discord = getattr(args, "notify_discord", None)
    _notify_webhook = getattr(args, "notify_webhook", None)
    if any([_notify_slack, _notify_teams, _notify_discord, _notify_webhook]):
        from scanner.core.notifier import Notifier
        from scanner.core.scan_result import Severity as _Severity
        _min_sev_str = getattr(args, "notify_min_severity", "high")
        _min_sev = _Severity(_min_sev_str)
        _notifier = Notifier(
            slack_url=_notify_slack,
            teams_url=_notify_teams,
            discord_url=_notify_discord,
            webhook_url=_notify_webhook,
            min_severity=_min_sev,
        )
        if _live:
            def finding_callback(finding):
                _live_print(finding)
                _notifier(finding)
        else:
            finding_callback = _notifier
    else:
        finding_callback = _live_print if _live else None

    mode_tags = []
    if config.passive:
        mode_tags.append("passive")
    if config.proxy:
        mode_tags.append(f"proxy={config.proxy}")
    if config.browser:
        mode_tags.append("browser")

    # First-run bootstrap: download Nuclei templates if not yet installed
    from scanner.core import updater as _updater
    if not getattr(args, "skip_templates", False):
        _updater.bootstrap_if_needed()
    # Non-blocking update check (prints a notice if templates are outdated)
    _updater.check_for_updates(auto=getattr(args, "auto_update", False))

    import datetime as _dt
    _scan_start_wall = _dt.datetime.now()
    print(f"[*] Scan ID: {current_scan_id}")
    print(f"[*] Started: {_scan_start_wall.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Target:  {target}")
    print(f"[*] Depth:   {config.max_depth}  |  Max pages: {config.max_pages}", end="")
    if mode_tags:
        print(f"  |  {', '.join(mode_tags)}", end="")
    print()
    if profile_name:
        print(f"[*] Profile: {profile_name}")
    if config.modules:
        print(f"[*] Modules: {', '.join(config.modules)}")
    if config.compliance:
        print(f"[*] Compliance: {', '.join(config.compliance).upper()}")
    print()

    # Progress bar (--stats) — renders on stderr so it doesn't pollute stdout reports
    _stats = getattr(args, "stats", False)
    _progress_cb = None
    if _stats and not _no_color:
        import time as _time
        _bar_start = _time.monotonic()

        def _progress_cb(done: int, total: int, findings: int):
            if total == 0:
                return
            pct = done / total
            filled = int(30 * pct)
            bar = "\033[92m" + "█" * filled + "\033[90m" + "░" * (30 - filled) + "\033[0m"
            elapsed = _time.monotonic() - _bar_start
            eta = (elapsed / pct - elapsed) if pct > 0 else 0
            line = (
                f"\r[{bar}] {pct * 100:5.1f}%  "
                f"{done}/{total} checks  "
                f"{findings} finding{'s' if findings != 1 else ''}  "
                f"eta {eta:.0f}s   "
            )
            sys.stderr.write(line)
            sys.stderr.flush()
            if done == total:
                sys.stderr.write("\r" + " " * len(line) + "\r")
                sys.stderr.flush()

    workflow_name = getattr(args, "workflow", None)
    if workflow_name:
        from scanner.core.workflow import load as _load_workflow, run_workflow as _run_workflow
        try:
            wf = _load_workflow(workflow_name)
        except ValueError as e:
            print(f"[!] {e}")
            sys.exit(1)
        result = _run_workflow(wf, config, api_key=api_key,
                               finding_callback=finding_callback,
                               concurrency=getattr(args, "concurrency", 8))
        report_md = None
    else:
        result, report_md = run_scan(
            config=config, api_key=api_key, scan_id=current_scan_id,
            finding_callback=finding_callback,
            concurrency=getattr(args, "concurrency", 8),
            progress_callback=_progress_cb,
        )

    # SOAP/WSDL scan (if --wsdl provided) — runs after the main scan
    wsdl_url = getattr(args, "wsdl", None)
    if wsdl_url:
        try:
            from scanner.core.soap_scanner import scan_wsdl
            import httpx as _httpx
            print(f"\n[*] SOAP/WSDL scan: {wsdl_url}")
            _soap_proxies = {"http://": config.proxy, "https://": config.proxy} if config.proxy else None
            with _httpx.Client(follow_redirects=True, timeout=15, verify=False, proxies=_soap_proxies) as _soap_client:  # nosec B501
                soap_findings = scan_wsdl(wsdl_url, _soap_client, config)
            if soap_findings:
                print(f"[+] SOAP findings: {len(soap_findings)}")
                result.findings.extend(soap_findings)
                for f in soap_findings:
                    if finding_callback:
                        finding_callback(f)
            else:
                print("[+] SOAP scan: no issues found")
        except Exception as e:
            print(f"[!] SOAP/WSDL scan failed: {e}")

    # gRPC scan (if requested) — runs after the main scan
    grpc_endpoint = getattr(args, "grpc", None)
    if grpc_endpoint:
        try:
            from scanner.core.grpc_scanner import scan_grpc
            print(f"\n[*] gRPC scan: {grpc_endpoint}")
            grpc_result = scan_grpc(grpc_endpoint, config)
            if grpc_result.error:
                print(f"[!] gRPC: {grpc_result.error}")
            else:
                print(f"[+] gRPC services: {len(grpc_result.services)}  methods: {len(grpc_result.methods)}")
                result.findings.extend(grpc_result.findings)
                for f in grpc_result.findings:
                    if finding_callback:
                        finding_callback(f)
        except Exception as e:
            print(f"[!] gRPC scan failed: {e}")

    summary = result.summary()
    dur = summary['duration_seconds']
    pages = summary['pages_crawled']
    _no_color_out = getattr(args, "no_color", False) or not sys.stdout.isatty()
    _G = "" if _no_color_out else "\033[92m"
    _R = "" if _no_color_out else "\033[0m"
    if dur > 0 and pages > 0:
        rate = pages / dur
        rps_hint = f"  (~{rate:.1f} pages/s)" if rate >= 1 else f"  (~{dur / pages:.0f}s/page)"
    else:
        rps_hint = ""
    _scan_end_wall = _dt.datetime.now()
    _mins, _secs = divmod(int(dur), 60)
    _dur_fmt = f"{_mins}m {_secs}s" if _mins else f"{_secs}s"
    print(f"\n{_G}[+] Scan complete{_R}")
    print(f"[+] Started:        {_scan_start_wall.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[+] Finished:       {_scan_end_wall.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[+] Duration:       {_dur_fmt}  ({dur:.1f}s){rps_hint}")
    print(f"[+] Pages crawled:  {pages}")
    print(f"[+] Findings:       {summary['total_findings']} total")
    for severity, count in summary["by_severity"].items():
        if count:
            sev_color = {"critical": "\033[91m", "high": "\033[91m", "medium": "\033[93m",
                         "low": "\033[94m", "info": "\033[96m"}.get(severity, "")
            sc = "" if _no_color_out else sev_color
            print(f"    {sc}{severity.upper():<12}{_R} {count}")

    if result.compliance_reports:
        print()
        print("[+] Compliance scores:")
        for cr in result.compliance_reports:
            passed = sum(1 for c in cr.controls if c.status == "pass")
            failed = sum(1 for c in cr.controls if c.status == "fail")
            manual = sum(1 for c in cr.controls if c.status == "manual")
            print(f"    {cr.standard:<12} {cr.score:.0f}/100  (pass:{passed} fail:{failed} manual:{manual})")

    slug = f"_{prefix}" if prefix else ""
    _write_reports(args, result, report_md, slug)

    if args.fail_on:
        severity_order = ["critical", "high", "medium", "low"]
        threshold_idx = severity_order.index(args.fail_on)
        for finding in result.findings:
            if severity_order.index(finding.severity.value) <= threshold_idx:
                print(f"\n[!] Failing CI: {args.fail_on.upper()} or above findings detected.")
                return 1
    return 0


def _write_reports(args, result, report_md, slug: str) -> None:
    import os
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)

    def _rpath(filename: str) -> str:
        return os.path.join(reports_dir, filename)

    if args.output in ("json", "all"):
        path = _rpath(f"kagesec_report{slug}.json")
        try:
            out = _findings_dict(result)
            with open(path, "w") as fp:
                # default=str converts any non-serializable value (e.g. set, Enum)
                # to its string representation rather than crashing
                json.dump(out, fp, indent=2, default=str)
            print(f"\n[+] JSON report:     {path}")
        except Exception as e:
            print(f"\n[!] Failed to write JSON report ({path}): {e}")
            import traceback
            traceback.print_exc()

    if report_md and args.output in ("markdown", "all"):
        path = _rpath(f"kagesec_report{slug}.md")
        with open(path, "w") as fp:
            fp.write(report_md)
        print(f"[+] Markdown report: {path}")

    if args.output in ("sarif", "all"):
        try:
            from scanner.reporters.sarif_reporter import generate_sarif
            sarif_path = generate_sarif(result, _rpath(f"kagesec_report{slug}.sarif"))
            print(f"[+] SARIF report:    {sarif_path}")
        except Exception as e:
            print(f"[!] SARIF generation failed: {e}")

    if args.output in ("pdf", "all"):
        try:
            from scanner.reporters.pdf_reporter import generate_pdf
            _auth_type, _auth_value = _auth_display(args)
            pdf_path = generate_pdf(
                result, _rpath(f"kagesec_report{slug}.pdf"),
                auth_type=_auth_type,
                auth_value=_auth_value,
            )
            print(f"[+] PDF report:      {pdf_path}")
        except RuntimeError as e:
            print(f"[!] PDF generation skipped: {e}")

    if args.output in ("burp", "all"):
        try:
            from scanner.reporters.burp_reporter import generate_burp
            burp_path = generate_burp(result, _rpath(f"kagesec_report{slug}.xml"))
            print(f"[+] Burp XML report: {burp_path}")
        except Exception as e:
            print(f"[!] Burp export failed: {e}")

    if args.output in ("zap", "all"):
        try:
            from scanner.reporters.zap_reporter import generate_zap
            zap_path = generate_zap(result, _rpath(f"kagesec_report{slug}_zap.json"))
            print(f"[+] ZAP JSON report: {zap_path}")
        except Exception as e:
            print(f"[!] ZAP export failed: {e}")


def _findings_dict(result) -> dict:
    summary = result.summary()
    return {
        "summary": summary,
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "owasp_category": f.owasp_category,
                "url": f.url,
                "parameter": f.parameter,
                "payload": f.payload,
                "evidence": f.evidence,
                "verified": f.verified,
                "confidence": f.confidence,
                "ai_verdict": f.ai_verdict,
                "ai_analysis": f.ai_analysis,
                "ai_exploitability": f.ai_exploitability,
                "ai_business_impact": f.ai_business_impact,
                "ai_attack_scenario": f.ai_attack_scenario,
                "cwe": f.cwe,
                "cvss": f.cvss,
                "remediation": f.remediation,
                "standards": f.standards,
                "poc_curl": f.poc_curl,
            }
            for f in result.findings
            if not f.false_positive_suppressed
        ],
        "compliance": [cr.summary() for cr in result.compliance_reports],
    }


# ---------------------------------------------------------------------------
# Diff subcommand
# ---------------------------------------------------------------------------

def _run_diff(args) -> None:
    try:
        with open(args.baseline) as f:
            baseline = json.load(f)
        with open(args.current) as f:
            current = json.load(f)
    except FileNotFoundError as e:
        print(f"[!] {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON: {e}")
        sys.exit(1)

    def _key(finding: dict) -> str:
        return f"{finding['title']}|{finding['url']}|{finding.get('parameter', '')}"

    baseline_keys = {_key(f): f for f in baseline.get("findings", [])}
    current_keys = {_key(f): f for f in current.get("findings", [])}

    new_findings = [f for k, f in current_keys.items() if k not in baseline_keys]
    resolved = [f for k, f in baseline_keys.items() if k not in current_keys]
    unchanged = [f for k, f in current_keys.items() if k in baseline_keys]

    if args.output == "json":
        print(json.dumps({
            "new": new_findings,
            "resolved": resolved,
            "unchanged_count": len(unchanged),
        }, indent=2))
    else:
        print(f"[+] New findings:      {len(new_findings)}")
        print(f"[+] Resolved findings: {len(resolved)}")
        print(f"[+] Unchanged:         {len(unchanged)}")

        if new_findings:
            print("\n--- NEW ---")
            for f in sorted(new_findings, key=lambda x: x.get("severity", "low")):
                print(f"  [{f['severity'].upper():<8}] {f['title']}")
                print(f"             {f['url']}")

        if resolved:
            print("\n--- RESOLVED ---")
            for f in resolved:
                print(f"  [{f['severity'].upper():<8}] {f['title']}")

    if args.fail_on:
        severity_order = ["critical", "high", "medium", "low"]
        threshold_idx = severity_order.index(args.fail_on)
        for f in new_findings:
            if severity_order.index(f.get("severity", "low")) <= threshold_idx:
                print(f"\n[!] New {args.fail_on.upper()}+ findings detected.")
                sys.exit(1)


# ---------------------------------------------------------------------------
# Auth / config builders
# ---------------------------------------------------------------------------

def _build_auth(args) -> dict | None:
    if getattr(args, "auth_oauth2_token_url", None):
        token = _fetch_oauth2_token(
            args.auth_oauth2_token_url,
            getattr(args, "auth_oauth2_client_id", ""),
            getattr(args, "auth_oauth2_client_secret", ""),
        )
        if token:
            return {"type": "bearer", "value": token}
        print("[!] OAuth2 token exchange failed — continuing unauthenticated.")
        return None

    if getattr(args, "auth_bearer", None):
        return {"type": "bearer", "value": args.auth_bearer}

    if getattr(args, "auth_cookie", None):
        name, _, value = args.auth_cookie.partition("=")
        return {"type": "cookie", "cookies": {name: value}}

    return None


def _fetch_oauth2_token(token_url: str, client_id: str, client_secret: str) -> str | None:
    try:
        import httpx
        resp = httpx.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            },
            timeout=15,
        )
        data = resp.json()
        token = data.get("access_token")
        if token:
            print(f"[+] OAuth2 token obtained (expires_in={data.get('expires_in', '?')}s)")
        return token
    except Exception as e:
        print(f"[!] OAuth2 error: {e}")
        return None


def _build_login_flow(args) -> "LoginFlow | None":
    if not getattr(args, "login_url", None):
        return None
    return LoginFlow(
        url=args.login_url,
        username_selector=args.login_user_selector or 'input[type="email"], input[name="username"], input[name="email"]',
        password_selector=args.login_pass_selector or 'input[type="password"]',
        submit_selector=args.login_submit_selector or 'button[type="submit"], input[type="submit"]',
        username=args.login_username or "",
        password=args.login_password or "",
        success_indicator=args.login_success or "/dashboard",
        totp_secret=args.login_totp_secret,
    )


def _build_modules(args) -> list[str] | None:
    modules = list(args.modules) if args.modules else None
    if getattr(args, "skip_templates", False):
        if modules is None:
            from scanner.core.engine import ALL_MODULES
            modules = [m.__name__.split(".")[-1] for m in ALL_MODULES if m.__name__.split(".")[-1] != "templates"]
        else:
            modules = [m for m in modules if m != "templates"]
    # --nuclei-templates forces the templates module on even when a profile
    # excluded it (e.g. --profile quick uses _INJECTION_MODULES only)
    if getattr(args, "nuclei_templates", False) and modules and "templates" not in modules:
        modules = modules + ["templates"]
    return modules


def _parse_extensions(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    exts = [e.strip() if e.strip().startswith(".") else f".{e.strip()}" for e in raw.split(",") if e.strip()]
    return exts or None


def _parse_status_codes(raw: str | None) -> list[int] | None:
    if not raw:
        return None
    codes = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            codes.append(int(part))
    return codes or None


def _parse_custom_headers(raw: list[str]) -> dict:
    """Parse ['-H', 'Name:Value', ...] into a dict."""
    headers = {}
    for item in raw:
        if ":" in item:
            name, _, value = item.partition(":")
            headers[name.strip()] = value.strip()
    return headers


def _auth_display(args) -> tuple[str, str]:
    if getattr(args, "auth_bearer", None):
        return "Bearer Token", f"{args.auth_bearer[:8]}…"
    if getattr(args, "auth_cookie", None):
        return "Session Cookie", args.auth_cookie.split("=")[0]
    if getattr(args, "login_url", None):
        return "Login Flow", args.login_url
    if getattr(args, "auth_oauth2_token_url", None):
        return "OAuth2", args.auth_oauth2_token_url
    return "Unauthenticated", "—"


def _safe_hostname(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url.replace("://", "_").replace("/", "_")


# ---------------------------------------------------------------------------
# export / import-scan
# ---------------------------------------------------------------------------

def _export_scan(scan_id: str, report_path: str, out_path: str) -> None:
    """
    Bundle a scan checkpoint + JSON report into a portable zip.
    The checkpoint is what --resume reads. The report is the finished output.
    Together they let someone on another machine either resume or review the scan.
    """
    import zipfile

    checkpoint = os.path.join(tempfile.gettempdir(), f"kagesec_{scan_id}.json")
    if not os.path.exists(checkpoint):
        print(f"[!] Checkpoint not found: {checkpoint}")
        print(f"    Make sure scan_id '{scan_id}' was run on this machine.")
        sys.exit(1)

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Always include the checkpoint
        zf.write(checkpoint, arcname=f"kagesec_{scan_id}.json")
        print(f"[+] Added checkpoint: {checkpoint}")

        # Include report if it exists
        if os.path.exists(report_path):
            zf.write(report_path, arcname=os.path.basename(report_path))
            print(f"[+] Added report:     {report_path}")
        else:
            print(f"[~] Report not found ({report_path}) — checkpoint only")

        # Metadata so import knows the scan_id without parsing filenames
        meta = json.dumps({"scan_id": scan_id, "exported_by": "kagesec"})
        zf.writestr("_meta.json", meta)

    print(f"[+] Exported to: {out_path}")
    print(f"    Transfer this file and run: kagesec import-scan {out_path}")


def _import_scan(zip_path: str) -> None:
    """
    Restore a checkpoint from an exported zip so --resume works on this machine.
    """
    import zipfile

    if not os.path.exists(zip_path):
        print(f"[!] File not found: {zip_path}")
        sys.exit(1)

    try:
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()

            # Read metadata
            if "_meta.json" in names:
                meta = json.loads(zf.read("_meta.json"))
                scan_id = meta.get("scan_id")
            else:
                # Fall back: find checkpoint file by name pattern
                checkpoints = [n for n in names if n.startswith("kagesec_") and n.endswith(".json")]
                if not checkpoints:
                    print("[!] No checkpoint found in the zip.")
                    sys.exit(1)
                scan_id = checkpoints[0].removeprefix("kagesec_").removesuffix(".json")

            # Restore checkpoint
            checkpoint_name = f"kagesec_{scan_id}.json"
            if checkpoint_name in names:
                dest = os.path.join(tempfile.gettempdir(), checkpoint_name)
                with open(dest, "wb") as f:
                    f.write(zf.read(checkpoint_name))
                print(f"[+] Checkpoint restored to: {dest}")

            # Restore report if present
            for name in names:
                if name.endswith(".json") and name != checkpoint_name and name != "_meta.json":
                    with open(name, "wb") as f:
                        f.write(zf.read(name))
                    print(f"[+] Report restored to:     {name}")

    except zipfile.BadZipFile:
        print(f"[!] Not a valid zip file: {zip_path}")
        sys.exit(1)

    print()
    print(f"[+] Scan ID: {scan_id}")
    print(f"    Resume with: kagesec scan <target> --resume {scan_id}")


# ---------------------------------------------------------------------------
# update-templates
# ---------------------------------------------------------------------------

# Nuclei template keys that KageSec cannot run — filter these out by default
_UNSUPPORTED_KEYS = ("flow:", "network:", "dns:", "headless:", "ssl:", "websocket:", "whois:")

# Directories inside nuclei-templates to skip entirely (non-HTTP content)
_SKIP_DIRS = {
    "dns", "network", "headless", "ssl", "whois",
    "workflows", ".github", "helpers", "fuzzing",
}


def _is_compatible(content: bytes) -> bool:
    """Return True if a template only uses features KageSec supports."""
    try:
        text = content.decode("utf-8", errors="ignore")
        return not any(key in text for key in _UNSUPPORTED_KEYS)
    except Exception:
        return False


def _run_history(args) -> None:
    from scanner.core.findings_db import (
        get_scan_history, get_persisting_findings, trending_summary
    )
    target = getattr(args, "target", None) or ""

    if getattr(args, "scans", False):
        rows = get_scan_history(target, limit=args.limit) if target else []
        if not rows:
            print("[*] No scan history found.")
            return
        print(f"{'Scan ID':<38} {'Target':<35} {'Findings':<10} {'Duration':>10}")
        print("-" * 95)
        for r in rows:
            import datetime
            ts = datetime.datetime.fromtimestamp(r["started_at"]).strftime("%Y-%m-%d %H:%M")
            print(f"{r['scan_id']:<38} {r['target']:<35} {r['total_findings']:<10} {r['duration_seconds']:>8.1f}s  {ts}")
        return

    if getattr(args, "persisting", False) and target:
        rows = get_persisting_findings(target)
        if not rows:
            print("[*] No persisting findings found.")
            return
        print(f"{'Severity':<10} {'Occurrences':<13} {'Title':<40} URL")
        print("-" * 100)
        for r in rows[:args.limit]:
            print(f"{r['severity'].upper():<10} {r['occurrences']:<13} {r['title'][:38]:<40} {r['url']}")
        return

    if target:
        summary = trending_summary(target)
        print(f"[+] Target: {summary['target']}")
        print(f"[+] Scans run:              {summary['scans_run']}")
        print(f"[+] Unique findings total:  {summary['total_unique_findings']}")
        print(f"[+] Persisting (multi-scan):{summary['persisting_across_scans']}")
        print("[+] By severity:")
        for sev, count in summary["by_severity"].items():
            if count:
                print(f"    {sev.upper():<12} {count}")
    else:
        print("[!] Provide a target URL: kagesec history https://example.com")
        print("    Options: --scans  --persisting  --limit N")


def _run_config(args) -> None:
    pol = _policy.load()

    if getattr(args, "unset", None):
        for key in args.unset:
            pol.pop(key, None)
        _policy.save(pol)
        print(f"[+] Unset: {', '.join(args.unset)}")
        return

    if getattr(args, "set", None):
        for key, raw_val in args.set:
            # Coerce common types
            if raw_val.lower() in ("true", "yes", "1"):
                val = True
            elif raw_val.lower() in ("false", "no", "0"):
                val = False
            else:
                try:
                    val = int(raw_val)
                except ValueError:
                    val = raw_val
            pol[key] = val
        _policy.save(pol)
        print(f"[+] Config updated: {_policy._CONFIG_PATH}")
        _policy.print_policy(_policy.load())
        return

    _policy.print_policy(pol)


def _run_suppress(args) -> None:
    from scanner.core.suppressions import (
        add_suppression, remove_suppression, load_suppressions
    )
    action = getattr(args, "suppress_action", None)
    if not action:
        print("Usage: kagesec suppress <add|list|remove>")
        print("  add    --title PATTERN [--url-pattern GLOB] [--target URL] [--note TEXT]")
        print("  list")
        print("  remove RULE_ID")
        return

    if action == "list":
        rules = load_suppressions()
        if not rules:
            print("[*] No suppression rules configured.")
            return
        print(f"{'ID':<10} {'Title contains':<30} {'URL pattern':<25} {'Target':<30} Note")
        print("-" * 110)
        for r in rules:
            print(
                f"{r.get('id', ''):<10} {(r.get('title_contains') or ''):<30} "
                f"{(r.get('url_pattern') or ''):<25} "
                f"{(r.get('target') or ''):<30} {r.get('note') or ''}"
            )
        return

    if action == "add":
        rule = add_suppression(
            title_contains=getattr(args, "title", None) or "",
            url_pattern=getattr(args, "url_pattern", None) or "*",
            target=getattr(args, "target", None) or "",
            note=getattr(args, "note", None) or "",
        )
        print(f"[+] Suppression rule added (ID: {rule['id']})")
        return

    if action == "remove":
        removed = remove_suppression(args.rule_id)
        if removed:
            print(f"[+] Rule {args.rule_id} removed.")
        else:
            print(f"[!] Rule {args.rule_id} not found.")
        return


def _run_retest(args) -> None:
    """Re-run a single finding to verify it still exists (Gap 22)."""
    import httpx
    from scanner.core.engine import ALL_MODULES
    from scanner.core.config import ScanConfig
    from scanner.core.crawler import CrawlResult

    report_path = getattr(args, "report", "kagesec_report.json")
    try:
        with open(report_path) as f:
            report = json.load(f)
    except FileNotFoundError:
        print(f"[!] Report not found: {report_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON: {e}")
        sys.exit(1)

    findings = report.get("findings", [])
    if not findings:
        print("[!] No findings in report.")
        sys.exit(1)

    # Resolve finding by index or title substring
    finding_id = args.finding_id
    target_finding = None
    if finding_id.isdigit():
        idx = int(finding_id)
        if 0 <= idx < len(findings):
            target_finding = findings[idx]
        else:
            print(f"[!] Index {idx} out of range (report has {len(findings)} findings).")
            sys.exit(1)
    elif finding_id.startswith("title:"):
        pattern = finding_id[6:].lower()
        matches = [f for f in findings if pattern in f.get("title", "").lower()]
        if not matches:
            print(f"[!] No findings matching title '{pattern}'.")
            sys.exit(1)
        target_finding = matches[0]
        if len(matches) > 1:
            print(f"[~] {len(matches)} findings matched — using first: {target_finding['title']}")
    else:
        # Try title substring without prefix
        pattern = finding_id.lower()
        matches = [f for f in findings if pattern in f.get("title", "").lower()]
        if not matches:
            print(f"[!] No findings matching '{finding_id}'. Use an index (0-N) or 'title:substring'.")
            sys.exit(1)
        target_finding = matches[0]

    url = target_finding.get("url", "")
    title = target_finding.get("title", "")
    severity = target_finding.get("severity", "")
    param = target_finding.get("parameter", "")
    payload = target_finding.get("payload", "")

    print("[*] Retesting finding:")
    print(f"    Title:     {title}")
    print(f"    Severity:  {severity.upper()}")
    print(f"    URL:       {url}")
    if param:
        print(f"    Parameter: {param}")
    if payload:
        print(f"    Payload:   {payload[:80]}")
    print()

    # Determine which module to use based on title keywords
    module_map = {
        "xss": "xss", "sqli": "sqli", "sql": "sqli", "injection": "sqli",
        "open redirect": "open_redirect", "redirect": "open_redirect",
        "csrf": "csrf", "ssrf": "ssrf", "xxe": "xxe",
        "jwt": "jwt_attacks", "header": "security_headers",
        "cors": "cors", "directory": "directory_listing",
        "traversal": "path_traversal", "upload": "file_upload",
        "deserialization": "deserialization", "graphql": "graphql",
        "host": "host_header", "csti": "csti",
        "business": "business_logic", "wizard": "multistep_injection",
        "blind xss": "blind_xss", "entropy": "session_entropy",
        "oauth": "oauth",
    }
    module_name = None
    title_lower = title.lower()
    for keyword, mod in module_map.items():
        if keyword in title_lower:
            module_name = mod
            break

    # Find the module object
    target_module = None
    if module_name:
        for mod in ALL_MODULES:
            if mod.__name__.split(".")[-1] == module_name:
                target_module = mod
                break

    from urllib.parse import urlparse
    parsed = urlparse(url)
    base_target = f"{parsed.scheme}://{parsed.netloc}"

    api_key = getattr(args, "api_key", None) or os.getenv("ANTHROPIC_API_KEY")
    config = ScanConfig(target=base_target, max_depth=1, max_pages=1)
    config.api_key = api_key if not getattr(args, "no_ai", False) else None

    with httpx.Client(follow_redirects=True, timeout=15, verify=False) as client:  # nosec B501
        try:
            resp = client.get(url, timeout=10)
            from bs4 import BeautifulSoup
            from scanner.core.crawler import CrawlResult
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = []
            for form in soup.find_all("form"):
                from urllib.parse import urljoin
                action = urljoin(url, form.get("action", url))
                inputs = [
                    {"name": inp.get("name", ""), "type": inp.get("type", "text"), "value": inp.get("value", "")}
                    for inp in form.find_all(["input", "textarea", "select"])
                ]
                forms.append({"action": action, "method": form.get("method", "get").lower(), "inputs": inputs})

            page = CrawlResult(
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                forms=forms,
            )
        except Exception as e:
            print(f"[!] Could not fetch {url}: {e}")
            sys.exit(1)

        if target_module:
            print(f"[*] Running module: {module_name}")
            try:
                new_findings = target_module.test(page, client, config)
            except TypeError:
                try:
                    new_findings = target_module.test(page, client)
                except Exception as e2:
                    print(f"[!] Module error: {e2}")
                    new_findings = []
        else:
            print("[~] Could not map finding to a specific module — running all active modules")
            new_findings = []
            for mod in ALL_MODULES:
                try:
                    res = mod.test(page, client, config)
                    new_findings.extend(res or [])
                except Exception:
                    pass

    # Report results
    if not new_findings:
        print("\n[+] RESOLVED — Finding no longer detected.")
        print("    The vulnerability may have been fixed or requires specific conditions.")
        sys.exit(0)

    matched = [f for f in new_findings if title_lower[:30] in f.title.lower()]
    if matched:
        print("\n[!] STILL VULNERABLE — Finding confirmed active.")
        for f in matched:
            print(f"    [{f.severity.value.upper():<8}] {f.title}")
            print(f"    URL: {f.url}")
            if f.evidence:
                print(f"    Evidence: {f.evidence[:120]}")
    else:
        print(f"\n[~] INCONCLUSIVE — {len(new_findings)} findings on this page but original not re-confirmed.")
        print("    The finding may require specific payload/session context to reproduce.")


def _run_issues(args) -> None:
    """Export findings to Jira or GitHub Issues (Gap 21)."""
    report_path = getattr(args, "report", "kagesec_report.json")
    try:
        with open(report_path) as f:
            report_data = json.load(f)
    except FileNotFoundError:
        print(f"[!] Report not found: {report_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON: {e}")
        sys.exit(1)

    min_sev = getattr(args, "min_severity", "medium")
    sev_order = ["critical", "high", "medium", "low", "info"]
    threshold_idx = sev_order.index(min_sev)
    findings = [
        f for f in report_data.get("findings", [])
        if sev_order.index(f.get("severity", "info")) <= threshold_idx
    ]

    if not findings:
        print(f"[*] No findings at {min_sev.upper()} or above to export.")
        return

    dry_run = getattr(args, "dry_run", False)

    from scanner.core.scan_result import Finding, Severity

    class _MockResult:
        def __init__(self):
            self.findings = []
            self.target = report_data.get("summary", {}).get("target", "unknown")
            self.compliance_reports = []

    mock = _MockResult()
    for fd in findings:
        try:
            sev = Severity(fd["severity"])
        except ValueError:
            sev = Severity.INFO
        mock.findings.append(Finding(
            title=fd["title"], severity=sev, url=fd["url"],
            parameter=fd.get("parameter"), payload=fd.get("payload"),
            evidence=fd.get("evidence"), description=fd.get("remediation", ""),
            remediation=fd.get("remediation", ""), cwe=fd.get("cwe", ""),
            cvss=fd.get("cvss", 0.0), owasp_category=fd.get("owasp_category", ""),
            confidence=fd.get("confidence", 0.0),
        ))

    if args.format == "jira":
        if not args.jira_url or not args.jira_project or not args.jira_token:
            print("[!] Jira export requires --jira-url, --jira-project, and --jira-token")
            sys.exit(1)
        from scanner.reporters.jira_reporter import export_to_jira
        export_to_jira(
            mock, args.jira_url, args.jira_project, args.jira_token,
            dry_run=dry_run,
        )

    elif args.format == "github":
        if not args.github_repo or not args.github_token:
            print("[!] GitHub export requires --github-repo and --github-token")
            sys.exit(1)
        from scanner.reporters.github_reporter import export_to_github
        export_to_github(mock, args.github_repo, args.github_token, dry_run=dry_run)


def _update_templates(dest_dir: str, keep_all: bool = False) -> None:
    import urllib.request
    import urllib.error
    import zipfile
    import io

    NUCLEI_ZIP = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"

    print("[*] Downloading Nuclei community templates")
    print(f"    Source:      {NUCLEI_ZIP}")
    print(f"    Destination: {dest_dir}")
    if not keep_all:
        print("    Filter:      compatible templates only (use --all to skip filtering)")
    print()

    try:
        os.makedirs(dest_dir, exist_ok=True)

        print("[*] Fetching archive (~50 MB) …")
        req = urllib.request.Request(
            NUCLEI_ZIP,
            headers={"User-Agent": "KageSec/1.0 template-updater"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:  # nosec B310
            data = resp.read()
        print(f"[+] Downloaded {len(data) // 1_048_576} MB")

        saved = skipped_unsupported = skipped_dir = 0

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            members = [m for m in zf.namelist() if m.endswith(".yaml")]
            print(f"[*] Processing {len(members):,} YAML files …")

            for member in members:
                # Strip the top-level repo dir (nuclei-templates-main/...)
                parts = member.split("/", 1)
                rel = parts[1] if len(parts) > 1 else member

                # Skip unsupported top-level directories
                top = rel.split("/")[0].lower()
                if top in _SKIP_DIRS:
                    skipped_dir += 1
                    continue

                content = zf.read(member)

                if not keep_all and not _is_compatible(content):
                    skipped_unsupported += 1
                    continue

                out_path = os.path.join(dest_dir, rel)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as dst:
                    dst.write(content)
                saved += 1

        # Save version stamp so auto-update check knows what's installed
        try:
            from scanner.core.updater import get_remote_version, save_local_version
            remote_ver = get_remote_version()
            if remote_ver:
                save_local_version(remote_ver)
                print(f"[+] Version: {remote_ver}")
        except Exception:
            pass

        print()
        print(f"[+] Saved:   {saved:,} compatible templates")
        if skipped_unsupported:
            print(f"[~] Skipped: {skipped_unsupported:,} unsupported (flow/network/dns/headless) — use --all to keep")
        if skipped_dir:
            print(f"[~] Skipped: {skipped_dir:,} from non-HTTP directories (dns/network/ssl/…)")
        print()
        print(f"[+] Templates saved to: {dest_dir}")
        print(f"[+] Use them: kagesec scan <target> --templates {dest_dir}")
        print("[+] Or make permanent: add to ~/.kagesec/config.yaml  (coming soon)")

    except urllib.error.URLError as e:
        print(f"[!] Network error: {e}")
        print("    Check your internet connection and try again.")
        sys.exit(1)
    except zipfile.BadZipFile:
        print("[!] Downloaded file is not a valid zip — try again.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Template update failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
