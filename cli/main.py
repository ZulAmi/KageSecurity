import os
import sys
import json
import argparse
from scanner.core.engine import run_scan
from scanner.core.config import ScanConfig


def main():
    parser = argparse.ArgumentParser(
        prog="kagesec",
        description="KageSec — AI-powered web application security scanner",
    )
    sub = parser.add_subparsers(dest="command")

    # scan subcommand
    scan_cmd = sub.add_parser("scan", help="Run a security scan against a target URL")
    scan_cmd.add_argument("target", help="Target URL (e.g. https://example.com)")
    scan_cmd.add_argument("--depth", type=int, default=3, help="Crawl depth (default: 3)")
    scan_cmd.add_argument("--max-pages", type=int, default=100, help="Max pages to crawl")
    scan_cmd.add_argument("--output", choices=["json", "markdown", "both"], default="both")
    scan_cmd.add_argument("--no-ai", action="store_true", help="Skip AI verification")
    scan_cmd.add_argument(
        "--compliance", nargs="+",
        choices=["iso27001", "hipaa", "gdpr", "appi"],
        help="Generate compliance reports (e.g. --compliance gdpr hipaa)"
    )
    scan_cmd.add_argument(
        "--modules", nargs="+",
        help="Run only specific modules (e.g. --modules xss sqli)"
    )
    scan_cmd.add_argument(
        "--auth-bearer", metavar="TOKEN",
        help="Bearer token for authenticated scanning"
    )
    scan_cmd.add_argument(
        "--auth-cookie", metavar="NAME=VALUE",
        help="Session cookie for authenticated scanning (e.g. session=abc123)"
    )
    scan_cmd.add_argument(
        "--fail-on", choices=["critical", "high", "medium", "low"],
        help="Exit with code 1 if findings at this severity or above are found (CI/CD mode)"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Build auth config
    auth = None
    if args.auth_bearer:
        auth = {"type": "bearer", "value": args.auth_bearer}
    elif args.auth_cookie:
        name, _, value = args.auth_cookie.partition("=")
        auth = {"type": "cookie", "cookies": {name: value}}

    config = ScanConfig(
        target=args.target,
        max_depth=args.depth,
        max_pages=args.max_pages,
        modules=args.modules,
        auth=auth,
        compliance=args.compliance or [],
    )

    api_key = None if args.no_ai else os.getenv("ANTHROPIC_API_KEY")
    if not args.no_ai and not api_key:
        print("[!] ANTHROPIC_API_KEY not set — running without AI verification.")
        print("    Set it to enable exploit verification and AI-generated reports.\n")

    print(f"[*] Target:   {args.target}")
    print(f"[*] Depth:    {config.max_depth}  |  Max pages: {config.max_pages}")
    if config.modules:
        print(f"[*] Modules:  {', '.join(config.modules)}")
    if config.compliance:
        print(f"[*] Compliance: {', '.join(config.compliance).upper()}")
    print()

    result, report_md = run_scan(config=config, api_key=api_key)

    summary = result.summary()
    print(f"[+] Scan complete in {summary['duration_seconds']:.1f}s")
    print(f"[+] Pages crawled: {summary['pages_crawled']}")
    print(f"[+] Findings: {summary['total_findings']} total")
    for severity, count in summary["by_severity"].items():
        if count:
            label = f"    {severity.upper()}:"
            print(f"{label:<16} {count}")

    if result.compliance_reports:
        print()
        print("[+] Compliance scores:")
        for cr in result.compliance_reports:
            passed = sum(1 for c in cr.controls if c.status == "pass")
            failed = sum(1 for c in cr.controls if c.status == "fail")
            manual = sum(1 for c in cr.controls if c.status == "manual")
            print(f"    {cr.standard:<12} {cr.score:.0f}/100  (pass:{passed} fail:{failed} manual:{manual})")

    if args.output in ("json", "both"):
        out = {
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
                    "ai_analysis": f.ai_analysis,
                    "cwe": f.cwe,
                    "cvss": f.cvss,
                    "remediation": f.remediation,
                    "standards": f.standards,
                }
                for f in result.findings
            ],
            "compliance": [cr.summary() for cr in result.compliance_reports],
        }
        with open("kagesec_report.json", "w") as fp:
            json.dump(out, fp, indent=2)
        print("\n[+] JSON report:     kagesec_report.json")

    if report_md and args.output in ("markdown", "both"):
        with open("kagesec_report.md", "w") as fp:
            fp.write(report_md)
        print("[+] Markdown report: kagesec_report.md")

    # CI/CD exit code
    if args.fail_on:
        severity_order = ["critical", "high", "medium", "low"]
        threshold_idx = severity_order.index(args.fail_on)
        for finding in result.findings:
            if severity_order.index(finding.severity.value) <= threshold_idx:
                print(f"\n[!] Failing CI: {args.fail_on.upper()} or above findings detected.")
                sys.exit(1)


if __name__ == "__main__":
    main()
