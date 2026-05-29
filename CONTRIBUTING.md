# Contributing to KageSec

KageSec is always a work in progress. If you've found a bug, have an idea for a new module, or want to help make this better — reach out or send a PR. The bar for contributing is just "make it better than it was."

---

## Getting started

```bash
git clone https://github.com/ZulAmi/KageSecurity
cd KageSecurity
pip install -e ".[all,dev]"
playwright install chromium
```

Run tests:

```bash
pytest tests/
```

---

## Adding a module

Every module lives in `scanner/modules/`. A module is a function that takes a `ScanConfig` and returns a list of `Finding` objects.

Minimal skeleton:

```python
from scanner.core.scan_result import Finding, ScanConfig
import httpx

async def run(config: ScanConfig) -> list[Finding]:
    findings = []
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.get(config.target)
        if "something suspicious" in resp.text:
            findings.append(Finding(
                title="My Finding",
                severity="medium",
                url=config.target,
                evidence=resp.text[:200],
            ))
    return findings
```

Then register it in `scanner/core/engine.py` in the module list.

---

## Submitting a PR

1. Fork, branch off `main`
2. Keep the change focused — one module or one fix per PR
3. Make sure `pytest tests/` passes
4. Open a PR with a short description of what it does and why

If you're not sure whether an idea fits, open an issue first or just email me at `zulhilmirahmat@protonmail.com`. Happy to chat.
