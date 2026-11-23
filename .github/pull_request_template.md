## What does this change?

<!-- One or two sentences. Link the issue if there is one: "Fixes #123". -->

## Why?

## How was it tested?

<!-- e.g. new unit test in tests/unit/, scanned tests/vulnerable_app.py, ran against DVWA -->

## Checklist

- [ ] `pytest tests/unit/` passes
- [ ] `ruff check scanner/ cli/ tests/unit/` passes
- [ ] New or changed detection logic has a test for a vulnerable **and** a safe response
- [ ] User-visible changes are noted in `CHANGELOG.md` under *Unreleased*
- [ ] No secrets, tokens, or private hostnames in code, tests, or fixtures
