# Security Policy

KageSec is a security tool, so vulnerabilities in KageSec itself matter twice: they
can hurt the people running it, and the machines it runs on usually hold credentials
for the systems being tested.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:

1. Go to the [Security tab](https://github.com/ZulAmi/KageSecurity/security) of the repository.
2. Click **Report a vulnerability** and fill in the form.

Include the KageSec version (`pip show kagesec`), how to reproduce the issue, and what
an attacker gains. A proof of concept helps a lot.

We aim to acknowledge reports within a week and to agree a disclosure date with you
once a fix is ready. Reporters are credited in the release notes unless they prefer
otherwise.

## Supported versions

Security fixes go into the latest minor release. Please upgrade before reporting.

## What is in scope

Issues in KageSec's own code, for example:

- the API server (`kagesec serve`) — authentication bypass, request forgery, reading local files
- the MCP server (`kagesec mcp`) — argument injection, file access outside the reports directory
- template handling — code execution on the scanner host from templates that were not opted in
  with `--allow-code-templates`, including AI-generated or downloaded templates
- report generation — script injection into HTML/PDF reports from attacker-controlled evidence
- archive handling — path traversal in `import-scan` or template downloads
- secrets (API keys, auth tokens, cookies) leaking into logs, reports, or third-party services
  when the user has not asked for that (for example, AI calls despite `--no-ai`)
- a scanned target being able to make KageSec misbehave (crash it, hide its own findings,
  or attack the machine running the scan)

## What is out of scope

- Vulnerabilities KageSec finds in *other* applications — report those to their owners.
- `tests/vulnerable_app.py` and the containers in `tests/integration/` — they are
  intentionally vulnerable test targets and must never be deployed.
- Findings that require the attacker to already control the scanner's configuration,
  environment variables, or `~/.kagesec` directory.
- Missing hardening with no demonstrated impact.

## Safe harbour

Good-faith research that follows this policy, avoids privacy violations and service
disruption, and only tests systems you own or are authorised to test is welcome. We
will not pursue legal action over it.
