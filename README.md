# KageSec

Open-source AI-powered web application security scanner.

KageSec crawls your web application, tests for common vulnerabilities, and uses AI to verify exploitability and generate actionable reports — no human pentester required for the first pass.

## Features

- Automated DAST scanning (XSS, SQLi, SSRF, open redirects, secrets exposure)
- AI-powered exploit verification — confirms if findings are actually exploitable
- Clean HTML/JSON/Markdown reports
- CLI for local use and CI/CD integration
- Web dashboard for managing scans and reviewing results

## Stack

- **Scanner engine**: Python 3.12+
- **Dashboard**: React + TypeScript (Next.js)
- **AI layer**: Claude API (Anthropic)

## Quick Start

```bash
# Install
pip install kagesec

# Run a scan
kagesec scan https://your-app.com

# Generate report
kagesec report --format html
```

## Project Structure

```
kagesec/
├── scanner/          # Python scanner engine
│   ├── core/         # Crawler, HTTP client, session management
│   ├── modules/      # Vulnerability detection modules (XSS, SQLi, etc.)
│   ├── ai/           # Claude API integration for verification + reporting
│   └── utils/        # Helpers, payload lists, encoding utils
├── dashboard/        # Next.js web dashboard
├── reports/          # Report templates
└── cli/              # CLI entrypoint
```

## Modules

| Module | Status | Covers |
|---|---|---|
| XSS | 🚧 In progress | Reflected, stored, DOM-based |
| SQLi | 🚧 In progress | Error-based, blind, time-based |
| SSRF | 🚧 In progress | URL params, headers |
| Open Redirect | 🚧 In progress | Query params, path |
| Secrets Exposure | 🚧 In progress | API keys, tokens in responses |
| IDOR | 📋 Planned | Object reference tampering |
| Auth bypass | 📋 Planned | JWT, session fixation |

## Contributing

Security researchers and developers welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
# kagesec
