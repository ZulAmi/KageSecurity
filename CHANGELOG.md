# Changelog

All notable changes to KageSec are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] - 2026-11-23

### Security
- `kagesec serve` now binds to `127.0.0.1` by default and requires a bearer token
  (`--token` or `KAGESEC_API_TOKEN`; a random one is printed if neither is set).
  POST bodies must be `application/json`, only an allowlist of scan options is accepted
  (no file paths, proxy, template directories or code templates), and scans run on a
  bounded queue.
- Templates with `code:`, `flow:` or `javascript:` sections are no longer loaded unless
  `--allow-code-templates` is passed. AI-generated templates are validated and never
  contain host-executing sections. Code templates run with a scrubbed environment, so
  API keys and cloud credentials are not visible to them.
- `--no-ai` now disables every AI provider call. Previously the engine re-detected
  `ANTHROPIC_API_KEY`/Ollama and could still send findings to a provider.
- The MCP server validates its arguments (http(s) URLs only, known module names, no
  CLI flag injection), writes each scan to its own report directory, and only reads
  reports from that directory.
- AI verification treats target-supplied text as untrusted: fields are truncated, the
  prompt tells the model to ignore instructions inside them, a finding is only
  suppressed as a false positive at ≥ 0.8 confidence, and never when its evidence
  contains text that looks like instructions to an AI reviewer. Malformed model output
  no longer crashes the scan.
- `import-scan` and template downloads reject archive entries that would write outside
  their destination directory.
- Scan checkpoints moved from the shared temp directory to `~/.kagesec/checkpoints/`
  with owner-only permissions.
- The repository no longer ships a Claude Code hook that could start active scans
  automatically; an opt-in, allow-listed version lives in `examples/claude-code-hook/`.

### Fixed
- Authenticated scans with supplied cookies (`--auth-cookie`, `--cookie-jar`) no longer
  turn anonymous partway through. A fuzzing request that made the server issue a new
  cookie used to leave both values in the shared cookie jar (e.g.
  `security=low; security=impossible`), so modules that ran later saw only the login
  page. Supplied cookies now stay authoritative for the whole scan.
- `--fail-on` now actually exits with code 1 for single-target scans (the exit code
  was previously discarded), accepts `info`, no longer crashes when INFO findings are
  present, and ignores findings the AI marked as false positives. Same for `diff`.
- A plain `pip install kagesec` no longer crashes on the first scan: without
  Playwright the scan falls back to the HTTP crawler with a warning.
- `--proxy` and `--wsdl` work with httpx 0.28, and the HTTP crawler now routes through
  the proxy too.
- Findings on pages skipped by delta scanning are no longer reported as RESOLVED.
- Host-level findings (e.g. missing security headers) no longer flip between NEW and
  RESOLVED depending on which page reported them first.
- Browser logins (`--login-*`) now carry over to the attack phase: session cookies are
  copied into the HTTP client the modules use.
- `-H/--header` no longer removes the bearer token in the browser crawler.
- `--exclude`/`--include` now apply to URLs found in sitemaps, JavaScript bundles and
  XHR traffic, not only to `<a href>` links.
- Template scans through the Go engine now send the scan's auth headers.
- `retest` uses the module that produced the finding, no longer crashes on modules that
  take an `oob` argument, and exits 0 (not reproduced), 1 (still present) or
  2 (inconclusive).
- `--resume` restores the findings from before the interruption.
- An explicit option such as `--depth 3` is no longer overridden by
  `~/.kagesec/config.yaml` just because it equals the default; `browser: false` in the
  config file now works. Precedence is CLI > `--profile` > config file > defaults.
- An explicit `--rate-limit` is honoured exactly.
- The browser crawler no longer hangs if every browser worker fails to start.
- The legal notice is printed to stderr and only for commands that send traffic, so
  `diff --output json` and the MCP stdio stream stay machine-readable.

### Changed
- Plain HTTP on a loopback address (`localhost`, `127.0.0.1`, `::1`) is reported as
  INFO instead of HIGH, since that traffic can't be intercepted on a network. HTTP on
  any other host is still HIGH.
- Delta scanning is now opt-in with `--delta`; full scans are the default. `--full`
  is kept for compatibility.
- Nuclei community templates are only downloaded or update-checked when
  `--nuclei-templates` is used, and downloads are pinned to the release tag that is
  recorded as the installed version.
- Scan problems (module crashes, timeouts, skipped pages) are shown at the end of the
  scan, included in the JSON report under `errors`, and added to SARIF as
  `toolExecutionNotifications`.
- Each finding records the `module` that produced it.
- New `--report-dir` option; the GitHub Action's `report-path` and `findings-count`
  outputs are now set.
- New `kagesec mcp` command and `[mcp]` extra (`[claude]` remains as an alias).
- Version strings in the User-Agent, SARIF output and API come from the installed
  package version.

### Testing
- The integration suite (DVWA, Juice Shop, clean nginx) now runs nightly in CI and
  passes. It authenticates to DVWA properly, uses the browser crawler for Juice Shop,
  and asserts on the exact finding titles.

### Deployment and packaging
- **Docker:** the image now includes the Go template engine, runs as a non-root user
  (UID 10001), and uses `/work` as its working directory. Mount reports at
  `/work/reports` (previously `/app/reports`); add `--user "$(id -u):$(id -g)"` when
  bind-mounting on Linux. Images are published for linux/amd64 and linux/arm64.
- **GitHub Action:** now a composite action that installs KageSec from the action's own
  source instead of building a Docker image on every run. New `browser` and
  `report-dir` inputs; the `report-path` and `findings-count` outputs work.
- **Helm:** API keys and auth tokens are passed from a Secret (created from the
  existing values, or `existingSecret`) instead of plain env values and arguments; the
  missing reports PersistentVolumeClaim is added; the Job runs non-root with a
  read-only root filesystem. The image tag defaults to the chart's appVersion.
- **PyPI:** releases now include a source distribution and a Linux aarch64 wheel.
- `KAGESEC_AUTH_BEARER`, `KAGESEC_AUTH_COOKIE` and `NVD_API_KEY` can be set as
  environment variables instead of command-line flags.
- License metadata uses an SPDX expression (`license = "MIT"`); building from source
  needs setuptools 77 or newer.

### Dependencies
- Docker build image: Go 1.27. CI and the Action use `actions/setup-python@v7`,
  `actions/setup-go@v7` and `docker/setup-qemu-action@v4`.

## Earlier releases

Versions up to 0.3.2 predate this changelog; see the
[git tags](https://github.com/ZulAmi/KageSecurity/tags) for their history.
