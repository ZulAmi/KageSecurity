"""
AI-powered template selector.

Problem: 10,000+ templates running against every page = hours of scan time and noise.

Solution:
  1. Fingerprint the target stack (Apache 2.4.49, WordPress 5.8, PHP 7.4 …)
  2. Ask Claude ONE question: "which template tags/CVE IDs are relevant for this stack?"
  3. Filter the full template list locally — no size limit, zero extra API calls
  4. Run 50–200 targeted templates instead of 10,000+

The Claude call is intentionally tiny:
  - Input:  ~500 tokens  (fingerprints)
  - Output: ~200 tokens  (tag/CVE list)
  - Cost:   ~$0.001 per scan

Cache location: ~/.kagesec/selector_cache/{stack_hash}.json
Cache TTL:      7 days  (shorter than template-gen cache — stack tags don't need regenerating often)

Template matching rules:
  - Match by tag intersection with AI-selected tags
  - Match by CVE ID
  - Match by keyword in template ID or name
  - Always include templates tagged: generic, common, misconfiguration, exposure,
    security-misconfiguration, tech, default  (baseline checks for any target)
"""
from __future__ import annotations

import json
import os
import time
import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.template_runner import Template

_CACHE_DIR = os.path.expanduser("~/.kagesec/selector_cache")
_CACHE_TTL = 7 * 24 * 60 * 60   # 7 days

# These tags are always included regardless of what the AI returns
_ALWAYS_INCLUDE_TAGS = {
    "generic", "common", "misconfiguration", "misconfig",
    "exposure", "exposure-config", "default",
    "tech", "detect", "fingerprint",
    "security-misconfiguration", "network",
    "panel", "login", "admin",
    "info", "osint",
}

_SYSTEM_PROMPT = """\
You are a security expert helping select vulnerability scan templates for a web application.

Given a detected technology stack, return a JSON object with THREE fields:
{
  "tags": ["tag1", "tag2", ...],
  "cve_ids": ["CVE-YYYY-NNNNN", ...],
  "keywords": ["keyword1", "keyword2", ...]
}

Rules:
- "tags": template category tags relevant to this stack
  (e.g. "wordpress", "apache", "php", "cve", "rce", "sqli", "lfi", "ssrf", "deserialization")
- "cve_ids": specific CVE IDs known to affect the EXACT versions detected
  (be precise — only include CVEs that match the detected version ranges)
- "keywords": words that would appear in relevant template IDs or names
  (e.g. "xmlrpc", "wp-admin", "log4j", "struts", "confluence-rce")

Be specific to the EXACT versions detected. Prefer precision over recall.
Return ONLY the JSON object. No markdown, no prose.
"""


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _stack_hash(fp: dict[str, str]) -> str:
    stable = json.dumps(sorted(fp.items()), sort_keys=True)
    return hashlib.sha256(stable.encode()).hexdigest()[:16]


def _cache_path(fp: dict[str, str]) -> str:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    return os.path.join(_CACHE_DIR, f"{_stack_hash(fp)}.json")


def _load_cache(fp: dict[str, str]) -> dict | None:
    try:
        with open(_cache_path(fp)) as f:
            data = json.load(f)
        if time.time() - data.get("ts", 0) < _CACHE_TTL:
            return data
    except Exception:
        pass
    return None


def _save_cache(fp: dict[str, str], selection: dict) -> None:
    try:
        with open(_cache_path(fp), "w") as f:
            json.dump({"ts": time.time(), "stack": fp, **selection}, f)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# AI call
# ---------------------------------------------------------------------------

def _ask_ai(fp: dict[str, str], api_key: str, provider: str = "anthropic", model: str | None = None) -> dict:
    """Ask the configured AI provider which tags/CVEs are relevant for this stack."""
    from scanner.ai.provider import complete as ai_complete

    # For template selection we want the cheapest/fastest model per provider
    _cheap = {
        "anthropic": "claude-haiku-4-5-20251001",
        "openai":    "gpt-4o-mini",
        "gemini":    "gemini-1.5-flash",
        "mistral":   "mistral-small-latest",
    }
    resolved_model = model or _cheap.get(provider)

    if fp:
        tech_lines = "\n".join(f"  - {k}: {v}" for k, v in fp.items())
        prompt = (
            f"Technology stack detected:\n{tech_lines}\n\n"
            "Which template tags, CVE IDs, and keywords are most relevant?"
        )
    else:
        prompt = (
            "No specific tech stack was detected on this target. "
            "Select the most important and broadly applicable template categories "
            "for a modern web application. Focus on: XSS, SQLi, SSRF, RCE, LFI, "
            "path traversal, file upload, deserialization, SSTI, XXE, open redirect, "
            "exposed sensitive files, and common misconfigurations. "
            "Return broad tags that cover generic web vulnerabilities."
        )

    raw = ai_complete(
        system=_SYSTEM_PROMPT,
        user=prompt,
        api_key=api_key,
        provider=provider,
        model=resolved_model,
    ).strip()
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1].lstrip("json").strip() if len(parts) >= 2 else raw

    data = json.loads(raw)
    return {
        "tags":     {t.lower() for t in data.get("tags", [])},
        "cve_ids":  {c.upper() for c in data.get("cve_ids", [])},
        "keywords": {k.lower() for k in data.get("keywords", [])},
    }


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def _template_is_relevant(template: "Template", selection: dict) -> bool:
    tags     = selection["tags"]
    cve_ids  = selection["cve_ids"]
    keywords = selection["keywords"]

    # Always include baseline categories
    t_tags_lower = {t.lower() for t in template.tags}
    if t_tags_lower & _ALWAYS_INCLUDE_TAGS:
        return True

    # Tag intersection
    if t_tags_lower & tags:
        return True

    # CVE ID match
    if template.cve and template.cve.upper() in cve_ids:
        return True

    # Keyword in template id or name
    id_lower   = template.id.lower()
    name_lower = template.name.lower()
    if any(kw in id_lower or kw in name_lower for kw in keywords):
        return True

    # Tag-based keyword match (e.g. template tagged "apache" matches keyword "apache")
    if any(kw in t_tags_lower for kw in keywords):
        return True

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def select_templates(
    fingerprints: dict[str, str],
    all_templates: "list[Template]",
    api_key: str,
    provider: str = "anthropic",
    model: str | None = None,
) -> "list[Template]":
    """
    Return the subset of `all_templates` relevant for the detected `fingerprints`.

    Falls back to all templates if AI selection fails.
    """
    if not api_key or not all_templates:
        return all_templates

    # Cache hit
    cached = _load_cache(fingerprints)
    if cached:
        selection = {
            "tags":     set(cached.get("tags", [])),
            "cve_ids":  set(cached.get("cve_ids", [])),
            "keywords": set(cached.get("keywords", [])),
        }
    else:
        try:
            selection = _ask_ai(fingerprints, api_key, provider=provider, model=model)
            _save_cache(fingerprints, {
                "tags":     list(selection["tags"]),
                "cve_ids":  list(selection["cve_ids"]),
                "keywords": list(selection["keywords"]),
            })
        except Exception:
            return all_templates   # fallback: run everything

    selected = [t for t in all_templates if _template_is_relevant(t, selection)]

    # Safety net: if AI was too aggressive and filtered everything, fall back
    if not selected:
        return all_templates

    return selected


def summarise_selection(fingerprints: dict, selected: list, total: int) -> str:
    """Human-readable summary for CLI output."""
    pct = 100 * len(selected) // total if total else 0
    if fingerprints:
        stack = ", ".join(f"{v}" for v in list(fingerprints.values())[:4])
    else:
        stack = "no stack detected — generic selection"
    return (
        f"[AI] Stack: {stack} → "
        f"selected {len(selected)}/{total} templates ({pct}%)"
    )
