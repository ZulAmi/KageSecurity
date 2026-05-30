"""
AI provider abstraction for KageSec.

Supported providers (auto-detected from environment, or explicit):
  anthropic  — Claude (ANTHROPIC_API_KEY)
  openai     — GPT-4o (OPENAI_API_KEY)
  gemini     — Gemini 1.5 Pro (GEMINI_API_KEY or GOOGLE_API_KEY)
  mistral    — Mistral Large (MISTRAL_API_KEY)
  ollama     — Local Ollama (no key, OLLAMA_URL or http://localhost:11434)

All providers expose a single function:
  complete(system, user, api_key, provider, model) -> str
"""
from __future__ import annotations

import os
from typing import Optional


# Default model for each provider
_DEFAULTS = {
    "anthropic": "claude-sonnet-4-6",
    "openai":    "gpt-4o",
    "gemini":    "gemini-1.5-pro",
    "mistral":   "mistral-large-latest",
    "ollama":    "llama3",
}


def detect(explicit_provider: str | None = None, explicit_key: str | None = None) -> tuple[str | None, str | None]:
    """Return (provider, api_key) by checking env vars in priority order.

    Priority:
      1. explicit_provider + explicit_key from CLI flags
      2. ANTHROPIC_API_KEY
      3. OPENAI_API_KEY
      4. GEMINI_API_KEY / GOOGLE_API_KEY
      5. MISTRAL_API_KEY
      6. Ollama running at OLLAMA_URL or localhost:11434 (no key needed)
      7. None, None — no AI available
    """
    if explicit_provider and explicit_key:
        return explicit_provider, explicit_key

    if explicit_key:
        # Key provided without provider — guess from prefix
        if explicit_key.startswith("sk-ant-"):
            return "anthropic", explicit_key
        if explicit_key.startswith("sk-"):
            return "openai", explicit_key
        # Default to anthropic for backwards compat
        return "anthropic", explicit_key

    if key := os.getenv("ANTHROPIC_API_KEY"):
        return "anthropic", key
    if key := os.getenv("OPENAI_API_KEY"):
        return "openai", key
    if key := os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"):
        return "gemini", key
    if key := os.getenv("MISTRAL_API_KEY"):
        return "mistral", key
    if _ollama_available():
        return "ollama", None

    return None, None


def complete(
    system: str,
    user: str,
    api_key: Optional[str],
    provider: str = "anthropic",
    model: Optional[str] = None,
) -> str:
    """Send a chat completion request to the selected provider and return the text response."""
    resolved_model = model or _DEFAULTS.get(provider, "")

    if provider == "anthropic":
        return _anthropic(system, user, api_key, resolved_model)
    if provider == "openai":
        return _openai(system, user, api_key, resolved_model)
    if provider == "gemini":
        return _gemini(system, user, api_key, resolved_model)
    if provider == "mistral":
        return _mistral(system, user, api_key, resolved_model)
    if provider == "ollama":
        return _ollama(system, user, resolved_model)

    raise ValueError(f"Unknown provider: {provider!r}. Choose: anthropic, openai, gemini, mistral, ollama")


def provider_label(provider: str, model: str | None = None) -> str:
    """Human-readable label for display in scan output."""
    m = model or _DEFAULTS.get(provider, "")
    names = {
        "anthropic": "Claude",
        "openai":    "OpenAI",
        "gemini":    "Gemini",
        "mistral":   "Mistral",
        "ollama":    "Ollama",
    }
    return f"{names.get(provider, provider)} ({m})"


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------

def _anthropic(system: str, user: str, api_key: str, model: str) -> str:
    try:
        import anthropic as _anthropic_sdk
    except ImportError:
        raise ImportError("pip install anthropic")

    client = _anthropic_sdk.Anthropic(api_key=api_key)
    resp = client.messages.create(
        model=model,
        max_tokens=4096,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return resp.content[0].text


def _openai(system: str, user: str, api_key: str, model: str) -> str:
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("pip install openai")

    client = OpenAI(api_key=api_key)
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    )
    return resp.choices[0].message.content


def _gemini(system: str, user: str, api_key: str, model: str) -> str:
    try:
        import google.generativeai as genai
    except ImportError:
        raise ImportError("pip install google-generativeai")

    genai.configure(api_key=api_key)
    m = genai.GenerativeModel(
        model_name=model,
        system_instruction=system,
    )
    resp = m.generate_content(user)
    return resp.text


def _mistral(system: str, user: str, api_key: str, model: str) -> str:
    try:
        from mistralai import Mistral
    except ImportError:
        raise ImportError("pip install mistralai")

    client = Mistral(api_key=api_key)
    resp = client.chat.complete(
        model=model,
        messages=[
            {"role": "system",  "content": system},
            {"role": "user",    "content": user},
        ],
    )
    return resp.choices[0].message.content


def _ollama(system: str, user: str, model: str) -> str:
    try:
        import httpx
    except ImportError:
        raise ImportError("pip install httpx")

    url = os.getenv("OLLAMA_URL", "http://localhost:11434") + "/api/chat"
    resp = httpx.post(url, json={
        "model":  model,
        "stream": False,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    }, timeout=120)
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def _ollama_available() -> bool:
    try:
        import httpx
        url = os.getenv("OLLAMA_URL", "http://localhost:11434") + "/api/tags"
        r = httpx.get(url, timeout=2)
        return r.status_code == 200
    except Exception:
        return False
