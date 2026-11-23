# CI/CD Integration

KageSec is designed to run in CI pipelines. Exit code `1` when findings meet the severity threshold, `0` when clean — so it can break the build.

---

## GitHub Actions

### Using the composite action (simplest)

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
        uses: ZulAmi/KageSecurity@main
        with:
          target: https://staging.example.com
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          fail-on: high
          output: sarif

      - name: Upload to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: reports/kagesec_report.sarif
```

### Direct pip install

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v7

      - name: Install KageSec
        run: |
          pip install "kagesec[browser]"
          playwright install chromium

      - name: Run security scan
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          kagesec scan https://staging.example.com \
            --fail-on high \
            --output sarif \
            --no-browser

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: reports/kagesec_report.sarif
```

### Delta scanning (faster CI)

Pass `--delta` to only test pages whose content changed since the last scan of the same target. Unchanged pages are not re-tested, so their earlier findings stay open rather than being reported as resolved. Full scans are the default.

---

## GitLab CI

```yaml
kagesec-scan:
  image: ghcr.io/zulami/kagesecurity:latest
  stage: test
  variables:
    TARGET: https://staging.example.com
  script:
    - kagesec scan $TARGET --fail-on high --output sarif --no-browser
  artifacts:
    reports:
      sast: reports/kagesec_report.sarif
    when: always
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

---

## Docker in CI

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -e ANTHROPIC_API_KEY \
  -v "$PWD/reports:/work/reports" \
  ghcr.io/zulami/kagesecurity:<version> \
  scan --fail-on high --output sarif -- https://staging.example.com
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on` severity |
| `1` | One or more findings at or above `--fail-on` severity |
| `2` | Scan error (target unreachable, config error) |

```bash
kagesec scan https://target.example.com --fail-on high
echo "Exit: $?"
```

Severity levels (in order): `info` → `low` → `medium` → `high` → `critical`

---

## Report Upload

### GitHub Security tab (SARIF)

```bash
kagesec scan https://target.example.com --output sarif
# Produces: reports/kagesec_report.sarif
```

Upload with `github/codeql-action/upload-sarif@v4` — findings appear in the **Security → Code scanning** tab.

### Jira Issues

```bash
kagesec issues --format jira \
  --jira-url https://company.atlassian.net \
  --jira-project SEC \
  --jira-token $JIRA_TOKEN \
  --min-severity high
```

### GitHub Issues

```bash
kagesec issues --format github \
  --github-repo owner/repo \
  --github-token $GITHUB_TOKEN
```

---

## CI Environment Variables

Override CLI behaviour without changing the pipeline command:

| Variable | Effect |
|---|---|
| `KAGESEC_NO_AI=1` | Disable AI verification |
| `KAGESEC_PASSIVE=1` | No injection — headers and content only |
| `KAGESEC_MODULES="xss sqli"` | Restrict to these modules |
| `KAGESEC_EXCLUDE="*/logout*"` | Skip URL patterns |

---

## Recommended CI Workflow

```
PR opened
  → kagesec scan staging --fail-on high --no-browser --output sarif
    → Upload SARIF to GitHub Security tab
      → If exit 1 → block merge
        → Dev fixes → re-run

Merge to main
  → Full scan: kagesec scan staging --output all
    → Notify Slack on HIGH+
      → SARIF uploaded
        → Findings compared to previous scan (NEW vs REPEATED)
```

---

## Scan Profiles for CI

| Profile | Use case |
|---|---|
| `--profile quick` | Fast PR checks — low noise, key modules only |
| `--profile full` | Nightly or pre-release — all modules, max depth |
| `--profile api` | API-first targets — OpenAPI/GraphQL focus |
| `--profile passive` | Read-only environments — no injection |

```bash
kagesec scan https://target.example.com --profile quick --fail-on high
```
