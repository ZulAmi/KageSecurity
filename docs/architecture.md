# KageSec Architecture

## Overview

KageSec is a dual-runtime DAST scanner: a Python orchestration layer drives the crawl and module execution, while a purpose-built Go binary (`kagesec-engine`) handles high-volume Nuclei-compatible template execution in parallel.

```
                        ┌──────────────────────────────┐
                        │         CLI / API Server      │
                        │         cli/main.py           │
                        └──────────────┬───────────────┘
                                       │
                        ┌──────────────▼───────────────┐
                        │         Scan Engine           │
                        │     scanner/core/engine.py    │
                        └──┬──────────┬────────────────┘
                           │          │
          ┌────────────────▼─┐   ┌───▼──────────────────┐
          │   HTTP Crawler   │   │   Browser Crawler     │
          │  crawler.py      │   │  browser_crawler.py   │
          │  (httpx)         │   │  (Playwright/Chromium)│
          └────────┬─────────┘   └───────────┬──────────┘
                   │                         │
          ┌────────▼─────────────────────────▼──────────┐
          │              Module Runner                   │
          │         64 modules × 8 threads per page      │
          │  scanner/modules/*.py  (Python)              │
          └────────────────────┬────────────────────────┘
                               │
          ┌────────────────────▼────────────────────────┐
          │            Go Template Engine               │
          │         scanner/_bin/kagesec-engine         │
          │    50 goroutines · 7,417 HTTP templates     │
          │    JSON Lines streamed → Python reads       │
          └────────────────────┬────────────────────────┘
                               │
          ┌────────────────────▼────────────────────────┐
          │              AI Layer                       │
          │   scanner/ai/ — Claude / GPT-4o / Gemini   │
          │   Mistral / Ollama (auto-detected)          │
          │   Verifies findings · generates CVE templates│
          └────────────────────┬────────────────────────┘
                               │
          ┌────────────────────▼────────────────────────┐
          │           Findings DB & State               │
          │       scanner/core/findings_db.py           │
          │     SQLite at ~/.kagesec/findings.db        │
          │   NEW · REPEATED · REGRESSED · RESOLVED     │
          └────────────────────┬────────────────────────┘
                               │
          ┌────────────────────▼────────────────────────┐
          │              Reporters                      │
          │  JSON · Markdown · PDF · SARIF · Burp · ZAP │
          │          scanner/reporters/                  │
          └──────────────────────────────────────────────┘
```

---

## Python Layer

### Crawlers

| File | Purpose |
|---|---|
| `scanner/core/crawler.py` | httpx-based URL crawler. Discovers links, forms, parameters. Respects scope and depth limits. |
| `scanner/core/browser_crawler.py` | Playwright headless Chromium crawler. Handles SPAs, JavaScript rendering, XHR/fetch interception. Runs in parallel with HTTP crawler. |
| `scanner/core/js_extractor.py` | Extracts inline `<script>` content and external JS references from HTML (uses BeautifulSoup). |
| `scanner/core/har_importer.py` | Replays HTTP Archive (HAR) files to import pre-recorded authenticated sessions. |

### Scan Engine

`scanner/core/engine.py` is the main orchestrator:
1. Initializes `ScanConfig` from CLI flags
2. Starts crawlers (HTTP + browser)
3. Feeds discovered pages into the module runner (thread pool)
4. Spawns `kagesec-engine` subprocess for template execution
5. Aggregates findings, deduplicates, computes states via `findings_db`
6. Passes findings to AI verifier
7. Runs prioritizer → "Fix These First" list
8. Calls reporters

### Module Runner

Each discovered page is run through every enabled module concurrently (default: 8 threads). Modules return `List[Finding]` — empty list if nothing detected.

```python
# scanner/modules/<name>.py
def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    ...
```

### Findings

`scanner/core/scan_result.py` defines the `Finding` dataclass:

| Field | Type | Notes |
|---|---|---|
| `title` | str | Short human-readable name |
| `severity` | `Severity` | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `url` | str | Affected endpoint |
| `parameter` | str \| None | Affected parameter name |
| `payload` | str \| None | Payload that triggered the finding |
| `evidence` | str | Raw response excerpt or observable behavior |
| `description` | str | Full explanation |
| `remediation` | str | Fix guidance |
| `cwe` | str | e.g. `"CWE-79"` |
| `cvss` | float | CVSS 3.1 base score |
| `owasp_category` | str | e.g. `"A03:2021 Injection"` |
| `standards` | list[str] | ISO/HIPAA/GDPR control IDs |
| `confidence` | float | 0.0–1.0, set by module |
| `state` | str | NEW / REPEATED / REGRESSED / RESOLVED |
| `poc_curl` | str \| None | Reproducible curl command |

---

## Go Engine (`kagesec-engine`)

A custom Go binary — not a Nuclei wrapper. Lives in `engine/`.

### Key differences from Nuclei

| Feature | Nuclei | kagesec-engine |
|---|---|---|
| Template selection | Tag filters | Fingerprints stack, prioritizes relevant templates |
| False positive scoring | Binary match | Confidence score 0.0–1.0 |
| OOB templates | Creates findings | Skipped (no unconfirmed callbacks) |
| Output | Files / stdout | JSON Lines streamed in real-time |
| Auth context | Limited | Inherits all KageSec headers + cookies |

### Goroutine architecture

```
main.go
  └─ runner/engine.go
       ├─ 50 worker goroutines
       │    └─ template/executor.go  (one template per goroutine slot)
       └─ output/streamer.go         (writes JSON Lines → stdout → Python reads)
```

Python reads the subprocess stdout line-by-line as findings arrive. No temp files. No polling.

### Building

```bash
cd engine
go build -ldflags="-s -w" -o ../scanner/_bin/kagesec-engine .
```

Cross-compile for Docker/CI:
```bash
GOOS=linux GOARCH=amd64 go build -o kagesec-engine-linux .
```

---

## AI Layer

`scanner/ai/` contains provider-specific adapters behind a common interface.

**Provider detection order:** `ANTHROPIC_API_KEY` → `OPENAI_API_KEY` → `GEMINI_API_KEY` → `MISTRAL_API_KEY` → `OLLAMA_URL`

### Verifier

Batches findings in groups of 10. For each batch, sends finding title + evidence + payload to the AI model and gets back:
- `verdict`: `true_positive` / `false_positive` / `needs_manual_review`
- `exploitability_score`: 1–10
- `business_impact`: narrative

### CVE Researcher (`ai_cve.py` module)

Takes the fingerprinted stack (server, framework, version) and asks the AI to:
1. Identify relevant CVEs for this stack
2. Generate Nuclei-compatible YAML templates
3. Cache templates for 30 days in `~/.kagesec/ai_templates/`

### Template Selector

When `--nuclei-templates` is set, narrows 7,400+ community templates to 80–200 most relevant for the detected technology stack using AI classification.

---

## State Store (SQLite)

`~/.kagesec/findings.db` — persists across scans.

Tables:
- `scans` — scan metadata (target, timestamp, scan_id)
- `findings` — all findings with their scan_id
- `schedules` — scheduled scan entries
- `suppressions` — false-positive suppression rules

Finding state is computed by comparing the current scan's fingerprint (target + title + parameter + url) against previous scans for the same target.

---

## Authentication Flow

```
CLI args
  → ScanConfig.auth_*
    → crawler initializes httpx.Client with auth headers/cookies
      → browser_crawler syncs cookies to Playwright context
        → mid-scan session check (every 50 module runs)
          → if logged-out regex fires → re-authenticate → continue
```

Supported methods: Bearer token, cookie jar, OAuth2 client credentials, multi-step browser login, TOTP 2FA.

---

## Report Pipeline

```
List[Finding]
  → findings_db (state classification)
  → prioritizer (CVSS + AI verdict + state bonus → sorted list)
  → reporters/
      ├── json_reporter.py
      ├── markdown_reporter.py
      ├── pdf_reporter.py (Playwright Chromium + Jinja2)
      ├── sarif_reporter.py (SARIF 2.1.0)
      ├── burp_reporter.py (Burp XML)
      └── zap_reporter.py (ZAP JSON)
```

All reports saved to `reports/` automatically.
