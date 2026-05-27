import os
import sys
import json
import argparse
import threading
import uuid as _uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from scanner.core.engine import run_scan
from scanner.core.config import ScanConfig, LoginFlow


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
        choices=["json", "markdown", "pdf", "sarif", "all"],
        default="json",
        help=(
            "Report format(s) to generate. "
            "'json' — machine-readable (default); "
            "'markdown' — human-readable text report; "
            "'pdf' — professional PDF report (requires playwright + jinja2); "
            "'sarif' — SARIF 2.1.0 for GitHub Code Scanning / VS Code; "
            "'all' — generate all formats."
        ),
    )
    scan_cmd.add_argument("--no-ai", action="store_true", help="Skip AI verification and CVE research")
    scan_cmd.add_argument("--api-key", metavar="KEY", help="Anthropic API key (overrides ANTHROPIC_API_KEY)")
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
        "--fail-on", choices=["critical", "high", "medium", "low"],
        help="Exit with code 1 if findings at this severity or above are found (CI/CD mode)",
    )
    scan_cmd.add_argument("--browser", action="store_true", help="Use Playwright headless browser (SPAs, JS content)")
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
    scan_cmd.add_argument("--resume", metavar="SCAN_ID", help="Resume an interrupted scan")
    scan_cmd.add_argument("--nvd-api-key", metavar="KEY", help="NVD API key for CVE enrichment")
    scan_cmd.add_argument("--templates", nargs="+", metavar="DIR", help="Extra YAML template directories")
    scan_cmd.add_argument("--skip-templates", action="store_true", help="Disable built-in YAML template scanning")
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
    serve_cmd.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
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

    # ------------------------------------------------------------------ update-templates
    update_cmd = sub.add_parser("update-templates", help="Download the latest community templates from GitHub")
    update_cmd.add_argument(
        "--dir", metavar="PATH",
        default=os.path.join(os.path.dirname(__file__), "..", "scanner", "templates", "community"),
        help="Directory to save downloaded templates (default: scanner/templates/community/)",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "update-templates":
        _update_templates(args.dir)
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
    if not args.target and not getattr(args, "targets", None):
        scan_cmd.error("provide a target URL or --targets FILE")

    targets = _resolve_targets(args)

    if len(targets) > 1:
        _run_multi_target(targets, args)
    else:
        _run_single_target(targets[0], args, prefix="")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_targets(args) -> list[str]:
    if getattr(args, "targets", None):
        try:
            with open(args.targets) as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            return lines
        except FileNotFoundError:
            print(f"[!] Targets file not found: {args.targets}")
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
        proxy=getattr(args, "proxy", None),
        passive=getattr(args, "passive", False),
        include_patterns=getattr(args, "include", None) or [],
        exclude_patterns=getattr(args, "exclude", None) or [],
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
    if not args.no_ai:
        api_key = getattr(args, "api_key", None) or os.getenv("ANTHROPIC_API_KEY")
    if not args.no_ai and not api_key:
        print("[!] No Anthropic API key — running without AI features.")
        print("    Set ANTHROPIC_API_KEY or pass --api-key <key> to enable AI.\n")

    config.api_key = api_key

    # Live findings callback — prints each finding as it is discovered
    _live = getattr(args, "live", False)
    _severity_colours = {
        "critical": "\033[91m", "high": "\033[91m",
        "medium": "\033[93m", "low": "\033[94m", "info": "\033[96m",
    }
    _RESET = "\033[0m"

    def _live_print(finding):
        sev = finding.severity.value
        colour = _severity_colours.get(sev, "")
        line = (
            f"{colour}[LIVE][{sev.upper():<8}]{_RESET} "
            f"{finding.title}  —  {finding.url}"
        )
        if print_lock:
            with print_lock:
                print(line, flush=True)
        else:
            print(line, flush=True)

    finding_callback = _live_print if _live else None

    mode_tags = []
    if config.passive:
        mode_tags.append("passive")
    if config.proxy:
        mode_tags.append(f"proxy={config.proxy}")
    if config.browser:
        mode_tags.append("browser")

    print(f"[*] Scan ID: {current_scan_id}")
    print(f"[*] Target:  {target}")
    print(f"[*] Depth:   {config.max_depth}  |  Max pages: {config.max_pages}", end="")
    if mode_tags:
        print(f"  |  {', '.join(mode_tags)}", end="")
    print()
    if config.modules:
        print(f"[*] Modules: {', '.join(config.modules)}")
    if config.compliance:
        print(f"[*] Compliance: {', '.join(config.compliance).upper()}")
    print()

    result, report_md = run_scan(
        config=config, api_key=api_key, scan_id=current_scan_id,
        finding_callback=finding_callback,
    )

    summary = result.summary()
    print(f"[+] Scan complete in {summary['duration_seconds']:.1f}s")
    print(f"[+] Pages crawled: {summary['pages_crawled']}")
    print(f"[+] Findings: {summary['total_findings']} total")
    for severity, count in summary["by_severity"].items():
        if count:
            print(f"    {severity.upper():<12} {count}")

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
    if args.output in ("json", "all"):
        path = f"kagesec_report{slug}.json"
        out = _findings_dict(result)
        with open(path, "w") as fp:
            json.dump(out, fp, indent=2)
        print(f"\n[+] JSON report:     {path}")

    if report_md and args.output in ("markdown", "all"):
        path = f"kagesec_report{slug}.md"
        with open(path, "w") as fp:
            fp.write(report_md)
        print(f"[+] Markdown report: {path}")

    if args.output in ("sarif", "all"):
        try:
            from scanner.reporters.sarif_reporter import generate_sarif
            sarif_path = generate_sarif(result, f"kagesec_report{slug}.sarif")
            print(f"[+] SARIF report:    {sarif_path}")
        except Exception as e:
            print(f"[!] SARIF generation failed: {e}")

    if args.output in ("pdf", "all"):
        try:
            from scanner.reporters.pdf_reporter import generate_pdf
            _auth_type, _auth_value = _auth_display(args)
            pdf_path = generate_pdf(
                result, f"kagesec_report{slug}.pdf",
                auth_type=_auth_type,
                auth_value=_auth_value,
            )
            print(f"[+] PDF report:      {pdf_path}")
        except RuntimeError as e:
            print(f"[!] PDF generation skipped: {e}")


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
    return modules


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

    checkpoint = f"/tmp/kagesec_{scan_id}.json"
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
                dest = f"/tmp/{checkpoint_name}"
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

def _update_templates(dest_dir: str) -> None:
    import urllib.request
    import zipfile
    import io

    REPO = "https://github.com/kagesec/templates/archive/refs/heads/main.zip"
    print(f"[*] Downloading community templates from {REPO}")
    print(f"[*] Destination: {dest_dir}")

    try:
        os.makedirs(dest_dir, exist_ok=True)
        with urllib.request.urlopen(REPO, timeout=30) as resp:
            data = resp.read()
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            count = 0
            for member in zf.namelist():
                if not member.endswith(".yaml"):
                    continue
                parts = member.split("/", 1)
                rel = parts[1] if len(parts) > 1 else member
                out_path = os.path.join(dest_dir, rel)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with zf.open(member) as src, open(out_path, "wb") as dst:
                    dst.write(src.read())
                count += 1
        print(f"[+] Downloaded {count} templates to {dest_dir}")
        print(f"[+] Use them with: kagesec scan <target> --templates {dest_dir}")
    except Exception as e:
        print(f"[!] Template update failed: {e}")
        print("    Contribute templates at: https://github.com/kagesec/templates")


if __name__ == "__main__":
    main()
