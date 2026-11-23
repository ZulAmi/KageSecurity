# Contributing to KageSec

Thanks for helping. Bug fixes, new checks, false-positive fixes, docs, and test
targets are all welcome. The bar is "make it better than it was" — and for detection
changes, "prove it with a test".

Please read the [Code of Conduct](CODE_OF_CONDUCT.md). Security issues in KageSec
itself go through [private reporting](SECURITY.md), not public issues.

---

## Development setup

```bash
git clone https://github.com/ZulAmi/KageSecurity
cd KageSecurity
python -m venv .venv && source .venv/bin/activate
pip install -e ".[all,dev]"
playwright install chromium          # only needed for the browser crawler / PDF reports
```

The Go template engine is optional for development (KageSec falls back to a Python
template runner without it). To build it you need Go 1.22+:

```bash
cd engine && go build -o ../scanner/_bin/kagesec-engine . && cd ..
```

## Checks to run before opening a PR

```bash
pytest tests/unit/                        # fast, no network — must pass
ruff check scanner/ cli/ tests/unit/      # lint
bandit -r scanner/ cli/ -ll -x scanner/templates/
cd engine && go vet ./... && go test ./...   # if you touched the Go engine
```

CI runs the same checks on Python 3.12 and 3.13.

Integration tests scan real, intentionally vulnerable apps in Docker and take a few
minutes:

```bash
docker compose -f tests/integration/docker-compose.yml up -d
pytest tests/integration/ -v
```

---

## Writing a detection module

Modules live in `scanner/modules/<name>.py` and are discovered automatically — there
is no registry to update. A module is a module-level, **synchronous** `test()` function:

```python
from __future__ import annotations

from typing import List

import httpx

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity


def test(page: CrawlResult, client: httpx.Client) -> List[Finding]:
    findings: List[Finding] = []
    if "text/html" not in page.headers.get("content-type", ""):
        return findings

    resp = client.get(page.url, params={"q": "kagesec-probe"})
    if "kagesec-probe" in resp.text:   # real modules need a much stronger signal than this
        findings.append(Finding(
            title="Example Reflection",
            severity=Severity.LOW,
            url=page.url,
            parameter="q",
            payload="kagesec-probe",
            evidence=resp.text[:200],
            description="What the issue is and why it matters.",
            remediation="How to fix it.",
            cwe="CWE-79",
            owasp_category="A03:2021 Injection",
        ))
    return findings
```

What you get:

- `page` — a `CrawlResult` with `.url`, `.status_code`, `.headers`, `.body`, `.forms`
  (list of `{"action", "method", "inputs"}`) and `.links`.
- `client` — a shared, rate-limited `httpx.Client` that already carries the scan's auth
  headers, cookies, proxy and timeouts. Always use it rather than creating your own.
- Optional keyword parameters, passed only if your function declares them:
  `oob` (out-of-band callback server for blind bugs) and `config` (the `ScanConfig`).

Rules:

- Return a list, never `None`. Return `[]` when nothing is found.
- Fill in `cwe`, `owasp_category`, `remediation` and `evidence` — reports and
  compliance mapping depend on them.
- **Prove it before you report it.** Compare against a baseline response, confirm with
  a second payload, and avoid matching strings that appear on the page anyway. A
  noisy module costs users more time than a missing one.
- Keep requests non-destructive by default. Anything that changes state, sends many
  requests, or could affect availability must respect `config.risk` / `config.level`
  and stay out of `--passive` mode.
- Host-level checks (TLS, DNS, headers that are the same on every page) should not
  repeat work for every crawled page.

### Testing a module

Every detection change needs a test that shows **both** sides: the module reports the
vulnerable case and stays quiet on the safe one. `tests/unit/conftest.py` provides a
`local_site` fixture (a tiny local HTTP server) and keeps tests away from your real
`~/.kagesec` directory; see `tests/unit/test_scan_reliability.py` for examples of
running the engine against it.

---

## Templates

KageSec runs Nuclei-compatible YAML templates. Built-in ones live in
`scanner/templates/`. Templates with `code:`, `flow:` or `javascript:` sections run
code on the scanner host and are only loaded with `--allow-code-templates`, so
contributed built-in templates must not use them.

---

## Pull requests

1. Fork and branch off `main`.
2. Keep each PR focused — one module, one fix, or one feature.
3. Add or update tests, and note user-visible changes in `CHANGELOG.md` under *Unreleased*.
4. Fill in the PR template.

Not sure an idea fits? Open an issue first — the "New check / module idea" template
asks the questions we'd ask anyway.
