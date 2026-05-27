"""
AI-powered template generator.

Design:
  Claude IS the template library. Given a fingerprinted tech stack, it generates
  targeted YAML templates — CVEs, misconfigs, exposed panels, version-specific
  checks — for exactly what was detected on the target.

  Benefits over a static template library:
  - Always current: Claude's knowledge covers recent CVEs without manual updates
  - Precision: 20-40 relevant templates instead of 10,000 generic ones
  - No downloads: ~5KB cached YAML per unique stack, not gigabytes
  - Human-inspectable: cached templates are real YAML files you can read and modify

  Cache:
  - Location: ~/.kagesec/template_cache/{stack_hash}/
  - TTL: 30 days per unique stack fingerprint
  - Hit: zero Claude calls, templates loaded from disk instantly
  - Miss: one Claude call → YAML files written to cache → used immediately
"""

from __future__ import annotations

import os
import re
import json
import time
import hashlib
import anthropic

_CACHE_DIR = os.path.expanduser("~/.kagesec/template_cache")
_CACHE_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days
_META_FILE = "_meta.json"

_YAML_FORMAT = """
id: <unique-kebab-case-id>
info:
  name: <Human-readable name>
  severity: critical | high | medium | low | info
  cve: CVE-YYYY-NNNNN          # omit if not a CVE
  cvss: 9.8                    # omit if not a CVE
  cwe: CWE-22                  # omit if unknown
  owasp: "A06:2021"
  tags: [tag1, tag2]
  description: >
    One paragraph — what the vulnerability is and what an attacker gains.
  remediation: >
    Specific action: version to upgrade to, config change, or header to add.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/exact/path"
    headers:                   # omit if no special headers needed
      X-Custom: value
    body: null                 # omit or set POST body as a string
    matchers-condition: and    # and | or
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body             # body | header
        words:
          - "signature string"
      - type: regex
        part: body
        regex:
          - "root:[x*]:0:0:"
      - type: header
        header: server
        words:
          - "Apache"

Variables usable in path / headers / body:
  {{BaseURL}}  — https://example.com
  {{Hostname}} — example.com
  {{Path}}     — /current/page/path
  {{Scheme}}   — https
  {{Port}}     — 443
"""

_SYSTEM_PROMPT = f"""You are a security researcher generating KageSec YAML vulnerability templates.

Given a detected web application technology stack, generate targeted YAML templates that check
for known CVEs, common misconfigurations, exposed admin panels, and version-specific attack
vectors relevant to the exact technologies and versions detected.

Each template must follow this YAML schema exactly:
{_YAML_FORMAT}

Respond ONLY with a valid JSON array. No markdown, no prose. Each element:
{{
  "filename": "CVE-2021-44228.yaml",   // CVE ID if applicable, else descriptive name
  "content": "<full YAML as a string>"
}}

Rules:
- Generate 20-40 templates tailored to the detected stack. Quality over quantity.
- Only include templates where the detected version is plausibly vulnerable.
- Mix CVE checks, version disclosures, exposed panels, and misconfigs.
- Verification must be safe and read-only: path traversal probes, error disclosure,
  version fingerprints, header checks. Never account creation, writes, or DoS.
- Matchers must be specific enough to avoid false positives.
- If a CVE has a well-known fingerprint, include it. If not, skip it.
- The JSON must be valid — escape quotes and newlines inside the "content" string.
"""


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _stack_hash(fingerprints: dict[str, str]) -> str:
    stable = json.dumps(sorted(fingerprints.items()), sort_keys=True)
    return hashlib.sha256(stable.encode()).hexdigest()[:16]


def _cache_dir_for(fingerprints: dict[str, str]) -> str:
    return os.path.join(_CACHE_DIR, _stack_hash(fingerprints))


def _cache_is_fresh(cache_dir: str) -> bool:
    meta = os.path.join(cache_dir, _META_FILE)
    try:
        with open(meta) as f:
            data = json.load(f)
        return time.time() - data.get("ts", 0) < _CACHE_TTL_SECONDS
    except Exception:
        return False


def _write_cache(cache_dir: str, fingerprints: dict[str, str], templates: list[dict]) -> None:
    os.makedirs(cache_dir, exist_ok=True)
    for item in templates:
        fname = _safe_filename(item.get("filename", "template.yaml"))
        path = os.path.join(cache_dir, fname)
        try:
            with open(path, "w") as f:
                f.write(item["content"])
        except Exception:
            pass
    meta = os.path.join(cache_dir, _META_FILE)
    try:
        with open(meta, "w") as f:
            json.dump({"ts": time.time(), "stack": fingerprints, "count": len(templates)}, f)
    except Exception:
        pass


def _safe_filename(name: str) -> str:
    name = re.sub(r"[^\w.\-]", "_", name)
    if not name.endswith(".yaml"):
        name += ".yaml"
    return name


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_templates(fingerprints: dict[str, str], api_key: str) -> str | None:
    """
    Return a path to a directory of YAML templates for this tech stack.
    Uses cache if fresh; calls Claude once on a miss.
    Returns None if generation fails.
    """
    if not fingerprints or not api_key:
        return None

    cache_dir = _cache_dir_for(fingerprints)

    if _cache_is_fresh(cache_dir):
        return cache_dir

    # Cache miss — ask Claude to generate templates
    tech_summary = "\n".join(f"  - {k}: {v}" for k, v in fingerprints.items())
    prompt = (
        f"Technology stack detected on the target:\n{tech_summary}\n\n"
        "Generate targeted YAML templates for this exact stack. "
        "Return a JSON array of {filename, content} objects."
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=8192,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text.strip()
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1].lstrip("json").strip() if len(parts) >= 2 else raw

        templates = json.loads(raw)
        if not isinstance(templates, list) or not templates:
            return None

        _write_cache(cache_dir, fingerprints, templates)
        return cache_dir

    except Exception:
        return None
