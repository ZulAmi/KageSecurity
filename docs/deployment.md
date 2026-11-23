# KageSec Deployment Guide

## Release Workflow

Every release follows this sequence — the version bump must be on `main` before tagging, because `publish.yml` builds from the tagged commit.

```
1. Edit pyproject.toml → bump version (e.g. 0.3.1)
2. git checkout -b bump/<version>
3. git add pyproject.toml && git commit -m "chore: bump version to <version>"
4. git push -u origin bump/<version>
5. Open PR → merge to main
6. git checkout main && git pull
7. git tag v<version>
8. git push origin v<version>   ← triggers publish.yml
```

Pushing a `v*.*.*` tag is the only trigger for the publish workflow. Do not tag before the version bump lands on `main` — PyPI rejects re-uploads of the same filename.

---

## What `publish.yml` Does

| Job | Output | Trigger |
|---|---|---|
| `verify` | Full CI suite (tests, lint, SAST, dependency audit, Go, Helm) | tag push — nothing below runs if it fails |
| `build-and-push` | Multi-arch Docker image (amd64 + arm64) → `ghcr.io/zulami/kagesecurity`, with SBOM and provenance | after `verify` |
| `publish-helm` | Helm chart → `oci://ghcr.io/zulami`, chart version = tag | after Docker build |
| `build-wheel` | Platform wheels (Linux x64/arm64, macOS arm64/x64, Windows x64) bundling the Go engine | after `verify` |
| `build-sdist` | Source distribution (installs anywhere; uses the Python template runner) | after `verify` |
| `publish-pypi` | Wheels + sdist → PyPI (`kagesec`) | after all builds |
| `github-release` | GitHub Release with the distributions and generated notes | after PyPI + Docker |

Docker and Helm use `GITHUB_TOKEN` (no extra secrets needed). PyPI uses OIDC trusted publishing (`id-token: write` on the `publish-pypi` job, `release` environment).

---

## Docker

### Pull and run

```bash
docker pull ghcr.io/zulami/kagesecurity:latest

docker run --rm ghcr.io/zulami/kagesecurity \
  scan https://target.example.com

# With AI verification, keeping the reports
docker run --rm --user "$(id -u):$(id -g)" \
  -e ANTHROPIC_API_KEY \
  -v "$PWD/reports:/work/reports" \
  ghcr.io/zulami/kagesecurity \
  scan --output all -- https://target.example.com
```

### Build locally

```bash
docker build -t kagesec .

docker run --rm kagesec scan https://target.example.com
```

The `Dockerfile` is multi-stage: it builds the Go template engine, builds a wheel that bundles it, and installs that wheel with `[all]` extras plus Playwright Chromium on `python:3.12-slim-bookworm`. The image runs as a non-root user (UID 10001) with `/work` as the working directory.

### Persist reports

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/reports:/work/reports" \
  kagesec scan --output all -- https://target.example.com
```

Reports are written to `/work/reports/` inside the container. `--user` lets the container write to the mounted directory with your own UID.

---

## pip (Direct Install)

```bash
# Core scanner
pip install kagesec

# Recommended — browser crawling + all AI providers
pip install "kagesec[all]"
playwright install chromium

# Run
kagesec scan https://target.example.com
```

### Optional extras

| Extra | Installs |
|---|---|
| `browser` | Playwright (headless Chromium for SPAs) |
| `pdf` | PDF report generation (renders HTML with Playwright Chromium) |
| `dns` | dnspython for DNSSEC/subdomain checks |
| `mcp` | MCP server for Claude Code integration (`claude` is a deprecated alias) |
| `openai` | GPT-4o provider |
| `gemini` | Google Gemini provider |
| `mistral` | Mistral Large provider |
| `all-ai` | All AI provider SDKs |
| `all` | Everything above |

---

## Kubernetes / Helm

```bash
# Add registry (Helm OCI)
helm pull oci://ghcr.io/zulami/kagesec --version <version>

# Install into cluster
helm install kagesec oci://ghcr.io/zulami/kagesec \
  --set scan.target=https://your-app.example.com \
  --set existingSecret=kagesec-secrets      # or --set anthropicApiKey=...
```

API keys and auth tokens are passed to the scanner as environment variables from a
Secret — either one the chart creates from `anthropicApiKey` / `nvdApiKey` /
`auth.bearer` / `auth.cookie`, or your own via `existingSecret` (keys
`ANTHROPIC_API_KEY`, `NVD_API_KEY`, `KAGESEC_AUTH_BEARER`, `KAGESEC_AUTH_COOKIE`).
The Job runs as non-root with a read-only root filesystem. Set `reports.enabled=true`
to keep reports on a PersistentVolumeClaim.

Chart source: `helm/kagesec/` in this repo.

---

## GitHub Actions (Scan on Deploy)

```yaml
name: Security Scan
on:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - name: KageSec Security Scan
        id: kagesec
        uses: ZulAmi/KageSecurity@main   # pin a release tag in real pipelines
        with:
          target: https://staging.example.com
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          fail-on: high
          output: sarif

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v4
        if: always() && steps.kagesec.outputs.report-path != ''
        with:
          sarif_file: ${{ steps.kagesec.outputs.report-path }}
```

The composite action is defined in `action.yml`. It builds the Go engine and installs
KageSec from the action's own source (so the action ref and scanner version always
match), runs the scan, and sets the `report-path` and `findings-count` outputs.

### Break the build on findings

```bash
kagesec scan https://target.example.com --fail-on high
# Exit code 1 if HIGH or CRITICAL findings exist, 0 if clean
```

### CI environment variables

| Variable | Effect |
|---|---|
| `KAGESEC_NO_AI=1` | Disable AI verification |
| `KAGESEC_PASSIVE=1` | No injection — headers/content only |
| `KAGESEC_MODULES="xss sqli"` | Restrict to these modules |
| `KAGESEC_EXCLUDE="*/logout*"` | Skip URL patterns |

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Recommended | Claude AI — best verification quality |
| `OPENAI_API_KEY` | Alternative | GPT-4o provider |
| `GEMINI_API_KEY` | Alternative | Google Gemini provider |
| `MISTRAL_API_KEY` | Alternative | Mistral Large provider |
| `OLLAMA_URL` | Optional | Local Ollama (default: `http://localhost:11434`) |
| `NVD_API_KEY` | Optional | Faster CVE enrichment from NVD |

KageSec scans without AI — all 64 modules still run, findings are full quality, but there's no exploitability scoring or narrative report.

---

## Scheduled Scanning

```bash
# Add a daily scan
kagesec schedule add https://app.example.com --interval daily

# Run due schedules (call from crontab)
kagesec schedule run

# Crontab entry — 2am daily
0 2 * * * kagesec schedule run
```

Schedules are stored in `~/.kagesec/schedules.yaml`. No daemon required.

---

## Version History

See [CHANGELOG.md](../CHANGELOG.md) for current changes.

| Version | Notes |
|---|---|
| `0.3.1` | CodeQL security alert remediation, explicit TLS minimum version |
| `0.3.0` | Initial public release |
