# KageSecurity — Claude Code Guide

## Project Overview

KageSec is an AI-powered DAST (dynamic application security testing) scanner. It crawls web applications, runs 64 vulnerability modules, executes 7,400+ Nuclei-compatible CVE templates via a Go engine, and uses AI to verify findings and eliminate false positives.

**Stack:** Python 3.12+, Go 1.22+, Playwright (browser), SQLite (state), httpx (HTTP), BeautifulSoup (HTML parsing), Jinja2 (reports)

---

## Key Commands

```bash
# Install in dev mode with all extras
pip install -e ".[all,dev]"

# Run the scanner
kagesec scan https://target.example.com

# Run unit tests (with coverage, as CI does)
pytest tests/unit/ -v --tb=short --cov=scanner --cov=cli

# Lint
ruff check scanner/ cli/ tests/unit/ examples/

# SAST
bandit -r scanner/ cli/ -ll -x scanner/templates/

# Dependency audit
pip-audit

# Build Go engine (requires Go 1.22+)
cd engine && go build -o ../scanner/_bin/kagesec-engine .

# Go checks
cd engine && go vet ./... && go test ./...
```

---

## Project Layout

```
KageSecurity/
├── cli/main.py              # CLI entrypoint — 14 subcommands, 85+ flags
├── scanner/
│   ├── core/                # Orchestration engine, crawlers, config, DB, scheduler
│   │   ├── engine.py        # Main scan loop and state machine
│   │   ├── crawler.py       # HTTP crawler
│   │   ├── browser_crawler.py # Playwright crawler for SPAs
│   │   ├── scan_result.py   # Finding dataclass (title, severity, CVSS, CWE, etc.)
│   │   ├── findings_db.py   # SQLite history and state tracking
│   │   ├── config.py        # ScanConfig dataclass (40+ fields)
│   │   ├── template_runner.py # YAML template execution
│   │   ├── js_extractor.py  # Inline script extraction (uses BeautifulSoup)
│   │   └── prioritizer.py   # CVSS + AI + state scoring for "Fix These First"
│   ├── modules/             # 64 vulnerability detection modules
│   ├── ai/                  # 5-provider AI (Claude, GPT-4o, Gemini, Mistral, Ollama)
│   ├── reporters/           # JSON, Markdown, PDF, SARIF, Burp XML, ZAP JSON
│   ├── compliance/          # ISO 27001, HIPAA, GDPR, APPI control mapping
│   ├── templates/           # Built-in Nuclei-compatible YAML (CVEs, misconfigs)
│   ├── api/                 # HTTP API server (kagesec serve)
│   ├── mcp_server.py        # MCP server (`kagesec mcp`)
│   └── utils/safe_paths.py  # safe_join / validate_scan_id for untrusted paths
├── engine/                  # Go template engine source
│   ├── main.go
│   ├── runner/engine.go     # 50-goroutine worker pool
│   └── output/streamer.go   # JSON Lines real-time output
├── examples/claude-code-hook/  # Opt-in post-deploy scan hook (allow-listed hosts only)
├── docs/                    # Architecture, modules, AI, CI/CD, compliance, deployment
├── tests/
│   ├── unit/                # pytest unit tests (conftest.py isolates ~/.kagesec)
│   ├── integration/         # Integration tests (DVWA, Juice Shop)
│   └── vulnerable_app.py    # Intentionally vulnerable Flask app — DO NOT deploy
├── .github/workflows/
│   ├── ci.yml               # Test+coverage, lint, SAST, dep-audit, Go, Helm
│   ├── codeql.yml           # CodeQL for Python, Go, Actions
│   ├── integration.yml      # Nightly scans of DVWA / Juice Shop / clean nginx
│   └── publish.yml          # CI gate → Docker + Helm + wheels/sdist → PyPI → GitHub Release
└── pyproject.toml           # Version, dependencies, extras
```

---

## Writing a New Module

Every module lives in `scanner/modules/<name>.py` and exposes a single synchronous
`test()` function. Modules are discovered automatically (`pkgutil` in
`scanner/core/engine.py`) — there is no registry.

```python
from typing import List
from scanner.core.scan_result import Finding, Severity
from scanner.core.crawler import CrawlResult
import httpx

def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings = []
    # probe page.url, page.body, page.headers, page.forms ...
    return findings
```

- `page` — `CrawlResult` with `.url`, `.status_code`, `.headers`, `.body`, `.forms`, `.links`
- `client` — shared rate-limited `httpx.Client` with auth headers, cookies, proxy and timeouts
- Optional kwargs, passed only if declared: `oob` (out-of-band server) and `config` (`ScanConfig`).
  Call modules through `engine._run_module()`, never positionally.
- Return `[]` (not `None`) when nothing is found
- Use `Severity.CRITICAL / HIGH / MEDIUM / LOW / INFO`
- Populate `cwe`, `cvss`, `owasp_category`, `remediation`, `evidence` for useful reports

---

## Finding States

Every finding is classified against the previous scan for the same target:

| State | Meaning |
|---|---|
| `NEW` | First occurrence |
| `REPEATED` | Still present since last scan |
| `REGRESSED` | Was resolved, reappeared |
| `RESOLVED` | No longer detected |

State logic lives in `scanner/core/findings_db.py`.

---

## AI Integration

AI providers are auto-detected from environment variables (priority order):

```
ANTHROPIC_API_KEY → OPENAI_API_KEY → GEMINI_API_KEY → MISTRAL_API_KEY → OLLAMA_URL
```

AI is used for:
- **Finding verification** — classifies each finding as `true_positive`, `false_positive`, or `needs_manual_review`
- **CVE research** — `ai_cve.py` module generates targeted Nuclei templates
- **Narrative report** — produces human-readable Markdown summary
- **Template selection** — narrows 7,400+ templates to 80–200 relevant for the detected stack

Without an API key, all 64 modules still run and produce full findings — just no AI triage.

---

## Release Process

1. Bump `version` in `pyproject.toml`
2. Open a PR → merge to `main`
3. After merge:
   ```bash
   git checkout main && git pull
   git tag v<version>
   git push origin v<version>
   ```
4. The `publish.yml` workflow builds and publishes Docker image to GHCR, Helm chart, and wheels to PyPI.

---

## CI Pipeline

| Job | Tool | What it checks |
|---|---|---|
| `test` | pytest + coverage | Unit tests on Python 3.12 and 3.13 (coverage floor 28%) |
| `lint` | ruff | Pinned rule set (`E4, E7, E9, F`) on `scanner/`, `cli/`, `tests/unit/`, `examples/` |
| `sast` | bandit | Medium+ severity issues (excludes `scanner/templates/`) |
| `deps` | pip-audit | Known CVEs in dependencies |
| `engine` | go | `go vet`, `go test -race`, build of the template engine |
| `helm` | helm | `helm lint` and `helm template` of the chart |
| `docker` | buildx | Builds the Docker image (no push) |

All jobs require `permissions: contents: read` (set at workflow level in `ci.yml`).

---

## MCP Server (Claude Code Integration)

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "kagesec": {"command": "kagesec", "args": ["mcp"]}
  }
}
```

Then ask Claude: _"Scan this for security issues"_ — it calls `kagesec_scan()` as a tool.

---

## Tests

Unit tests live in `tests/unit/`. The test suite covers:
- `test_scan_result.py` — Finding dataclass and severity ordering
- `test_template_runner.py` — YAML template execution
- `test_config.py` — ScanConfig validation
- `test_rate_limiter.py` — Token bucket rate limiting
- `test_sqli.py` — SQLi module logic
- `test_security_hardening.py` — API server auth, MCP validation, code-template gating, archive extraction
- `test_scan_reliability.py` — end-to-end engine/CLI behaviour against a local HTTP server
- `test_ai_verifier.py` — AI false-positive suppression and prompt-injection resistance

`tests/vulnerable_app.py` is a deliberately vulnerable Flask app used for integration testing. All CodeQL alerts on that file are suppressed with `# lgtm[...]` — do not remove those comments.

---

## Security Notes

- The scanner sends real attack payloads. Only target systems you own or have authorization to test.
- `tests/vulnerable_app.py` — intentionally vulnerable; never expose it publicly.
- TLS module uses `ssl.create_default_context()` with `ctx.minimum_version = ssl.TLSVersion.TLSv1_2` — do not lower the minimum version.
- `kagesec serve` binds to 127.0.0.1 and requires a bearer token; keep the API's config-field allowlist free of file paths and proxies.
- `code:` / `flow:` / `javascript:` templates run on the scanner host — they stay behind `--allow-code-templates`; AI-generated and downloaded templates must never get them.
- `--no-ai` (`ScanConfig.ai_enabled=False`) must prevent every AI provider call.
- Any path built from untrusted input (zip entries, scan IDs, MCP arguments) goes through `scanner/utils/safe_paths.py`.
