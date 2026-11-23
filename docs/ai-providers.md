# AI Providers

KageSec supports 5 AI providers. No provider is required — all 61 modules run and produce full findings without one. AI adds a verification and triage layer on top.

---

## Provider Detection Order

KageSec auto-detects providers from environment variables, highest priority first:

```
1. Anthropic Claude   → ANTHROPIC_API_KEY
2. OpenAI GPT-4o      → OPENAI_API_KEY
3. Google Gemini      → GEMINI_API_KEY
4. Mistral Large      → MISTRAL_API_KEY
5. Ollama (local)     → OLLAMA_URL (or default http://localhost:11434)
```

Set only one key and it will be used automatically. Set multiple and Anthropic takes precedence.

---

## Setup

### Anthropic Claude (recommended)

Best verification quality. Uses Claude for finding verification, CVE research, narrative reports, and template selection.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
kagesec scan https://target.example.com
```

Install the SDK extra if running from source:
```bash
pip install "kagesec[mcp]"
```

### OpenAI GPT-4o

```bash
export OPENAI_API_KEY=sk-...
pip install "kagesec[openai]"
kagesec scan https://target.example.com
```

### Google Gemini

```bash
export GEMINI_API_KEY=...
pip install "kagesec[gemini]"
kagesec scan https://target.example.com
```

### Mistral Large

```bash
export MISTRAL_API_KEY=...
pip install "kagesec[mistral]"
kagesec scan https://target.example.com
```

### Ollama (local, zero cost)

Run models on your machine. No API key, no data leaves your network.

```bash
# Install Ollama: https://ollama.com
ollama pull llama3

export OLLAMA_URL=http://localhost:11434   # optional — this is the default
kagesec scan https://target.example.com
```

---

## What AI Does

### 1. Finding Verification

Batches findings in groups of 10 and classifies each:

| Verdict | Meaning |
|---|---|
| `true_positive` | Confirmed real finding — appears in report |
| `false_positive` | Scanner noise — filtered from output |
| `needs_manual_review` | Inconclusive — flagged for human triage |

For each confirmed finding, AI also scores:
- **Exploitability** (1–10)
- **Business impact** (short narrative)

### 2. CVE Research (`ai_cve` module)

The `ai_cve` module fingerprints the target stack (server, framework, CMS, version strings from headers/responses) and asks the AI to:
1. Identify CVEs relevant to this specific stack
2. Generate Nuclei-compatible YAML templates
3. Cache results for 30 days in `~/.kagesec/ai_templates/`

Generated templates are fed directly into the Go engine.

### 3. Template Selection

When running with `--nuclei-templates` (7,400+ community templates), AI narrows the set to 80–200 most relevant for the detected technology stack. Reduces scan time by 10–20× without missing coverage for the target's actual stack.

### 4. Narrative Report

When output includes `markdown` or `pdf`, AI writes a human-readable executive summary with:
- Overall risk rating
- Top 5 most critical findings with business impact
- Remediation priority order
- Compliance posture (ISO 27001 / HIPAA / GDPR / APPI)

---

## CLI Flags

```bash
# Override provider model
kagesec scan https://target.example.com --ai-model claude-opus-4-8

# Skip AI entirely
kagesec scan https://target.example.com --no-ai

# Custom Ollama endpoint
kagesec scan https://target.example.com --ollama-url http://10.0.0.5:11434
```

---

## Interactive Prompt (TTY Only)

If no AI key is detected and stdin is a terminal, KageSec shows a provider selection menu at startup:

```
[?] No AI key detected.
    AI verification cuts false positives, scores exploitability,
    and writes a human-readable report. Select a provider:

    1. Anthropic Claude  —  claude.ai/settings — recommended
    2. OpenAI GPT-4o     —  platform.openai.com/api-keys
    3. Google Gemini     —  aistudio.google.com/app/apikey
    4. Mistral Large     —  console.mistral.ai
    5. Ollama (local)    —  no key needed — runs on your machine
    6. Skip — run without AI
```

In CI (non-TTY), this prompt is skipped automatically and the scan runs without AI.

---

## All AI SDKs

```bash
pip install "kagesec[all-ai]"
# Installs: anthropic, openai, google-generativeai, mistralai, mcp
```

---

## Privacy

- Finding evidence (URL, payload, response excerpt) is sent to the AI provider for verification.
- If data privacy is a concern, use **Ollama** — everything stays on your machine.
- To disable AI entirely in CI: `KAGESEC_NO_AI=1` or `--no-ai`.
