# KageSec — Remaining Gaps vs Nuclei / ZAP / Wapiti

Second audit completed 2026-05-27. Items are ordered by impact.

---

## Gap 1 — Concurrent multi-target (`--parallel N`)

**Current state:** `_run_multi_target` loops sequentially. 10 targets = 10× wall-clock time.  
**Nuclei:** goroutine pool, scans all targets in parallel.  
**Fix:** `ThreadPoolExecutor(N)` wrapping `_run_single_target`, merge result lists.  
**Status:** DONE — `--parallel N` added to `scan` subcommand; `cli/main.py:_run_multi_target`

---

## Gap 2 — Live findings stream (`--live`)

**Current state:** All findings printed only after the full scan completes.  
**Nuclei:** Prints each finding as it is discovered, with colour, real-time.  
**Fix:** Add `--live` flag; engine emits findings via callback/queue; CLI prints immediately.  
**Status:** DONE — `--live` flag + `finding_callback` param in `run_scan`; colour output per severity

---

## Gap 3 — Scope include / exclude URL patterns

**Current state:** Crawler stays on same origin but has no allow/deny glob patterns.  
**Nuclei:** `-iserver`, `-etags`, `-eid` etc. ZAP has context include/exclude regex.  
**Fix:** Add `include_patterns: list[str]` and `exclude_patterns: list[str]` to ScanConfig; filter in crawler.  
**Status:** DONE — `--include`/`--exclude` glob patterns; wired into both `Crawler` and `BrowserCrawler`

---

## Gap 4 — Template fuzzing (`payloads:` + `attack:` blocks)

**Current state:** Template requests use static paths/bodies. No parametric fuzzing inside templates.  
**Nuclei:** `payloads:` block defines wordlists; `attack: pitchfork | clusterbomb | batteringram` cartesian-products them into request variables.  
**Fix:** Parse `payloads:` and `attack:` in `_parse_template`; expand in `run_template` before executing requests.  
**Status:** DONE — `_expand_payloads` in `template_runner.py`; supports all 3 attack modes

---

## Gap 5 — Extractor chaining (`extractors:` block)

**Current state:** Template runner has no extractor support. Cannot pull a CSRF token from page A and use it in page B.  
**Nuclei:** `extractors:` (regex / xpath / json / kval) pull named variables that flow into subsequent requests.  
**Fix:** Parse `extractors:` in TemplateRequest; after each request run extractors and add to `variables` dict for next request.  
**Status:** DONE — `TemplateExtractor` dataclass + `_run_extractors`/`_extract_one`; types: regex, kval, json

---

## Gap 6 — WAF bypass payload variants

**Current state:** `waf_detect.py` fingerprints the WAF and surfaces an INFO finding but does nothing with the result.  
**Nuclei:** Has WAF-bypass templates; can route through alternate encodings.  
**Fix:** After WAF detection, swap active payloads to bypass variants (double-URL encoding, Unicode escapes, case mutation, chunked encoding headers).  
**Status:** DONE — `scanner/modules/waf_bypass.py`; 10 XSS + 10 SQLi bypass payloads; auto-discovers WAF then retests

---

## Gap 7 — Session re-authentication on expiry

**Current state:** Login flow runs once at crawler start; 401 or redirect-to-login mid-scan breaks coverage.  
**ZAP:** Re-authenticates automatically on 401 / redirect detection.  
**Fix:** In engine/crawler, detect 401 or URL matching `login_flow.url` in redirect chain → re-run `_authenticate` and retry the request.  
**Status:** DONE — `_reauth_if_needed` in `engine.py`; detects 401 + login-redirect; re-crawls affected pages

---

## Gap 8 — GitHub Actions native action

**Current state:** CI users must `pip install kagesec && kagesec scan ...` manually.  
**Nuclei:** Official `projectdiscovery/nuclei-action` Docker image + `action.yml`.  
**Fix:** Add `action.yml` (composite or Docker) + `Dockerfile` to repo root; publish to GitHub Marketplace.  
**Status:** DONE — `action.yml` + `Dockerfile` + `.github/workflows/kagesec-scan.yml` sample workflow; env var pass-through for CI

---

## Gap 9 — Validated accuracy test harness

**Current state:** No automated tests against known-vulnerable apps.  
**Industry standard:** DVWA, WebGoat, Juice Shop, bWAPP — validate true-positive rate and zero false-positives on hardened targets.  
**Fix:** Add `tests/integration/` with Docker Compose for DVWA + WebGoat + a clean nginx; pytest assertions on finding counts / severity.  
**Status:** DONE — `tests/integration/docker-compose.yml` + 3 test files (DVWA, Juice Shop, clean-nginx false-positive baseline)

---

## Priority order for implementation

| # | Gap | Effort | Impact |
|---|-----|--------|--------|
| 1 | Concurrent multi-target | Medium | High |
| 2 | Live findings stream | Low | High |
| 3 | Scope include/exclude | Low | Medium |
| 4 | Template fuzzing (payloads/attack) | High | High |
| 5 | Extractor chaining | Medium | Medium |
| 6 | WAF bypass variants | Medium | High |
| 7 | Session re-auth | Medium | Medium |
| 8 | GitHub Actions action | Low | Medium |
| 9 | Accuracy test harness | High | High |
