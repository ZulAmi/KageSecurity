"""
Payload loader — resolves named payload lists from YAML files.

Resolution order (first match wins):
  1. User overrides in ~/.kagesec/payloads/<name>.yaml
  2. Built-in payloads at scanner/payloads/<name>.yaml
  3. Hardcoded fallback in the calling module

Usage:
  from scanner.core.payload_loader import load

  XSS_PAYLOADS = load("xss", fallback=["<script>alert(1)</script>"])
  SQLI_PAYLOADS = load("sqli")

YAML format:
  payloads:
    - "<script>alert(1)</script>"
    - "' OR '1'='1"
    ...
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import List, Optional

_BUILTIN_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "payloads")
_USER_DIR    = os.path.expanduser("~/.kagesec/payloads")


@lru_cache(maxsize=128)
def load(name: str, section: Optional[str] = None, fallback: Optional[tuple] = None) -> List[str]:
    """
    Load payload list *name* (optionally a named *section* within the file).

    YAML formats supported:
      payloads: [...]          — top-level list under 'payloads' key
      [...]                    — bare list at root
      <section>: [...]         — named section (use section= param)

    Pass *fallback* as a tuple (hashable) for lru_cache compatibility.
    """
    for base_dir in (_USER_DIR, _BUILTIN_DIR):
        path = os.path.join(base_dir, f"{name}.yaml")
        if os.path.exists(path):
            try:
                import yaml  # type: ignore
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
                if isinstance(data, list):
                    return [str(p) for p in data if p is not None]
                if isinstance(data, dict):
                    if section and section in data:
                        raw = data[section]
                        if isinstance(raw, list):
                            return [str(p) for p in raw if p is not None]
                    if "payloads" in data:
                        raw = data["payloads"]
                        if isinstance(raw, list):
                            return [str(p) if not isinstance(p, (list, dict)) else p
                                    for p in raw if p is not None]
            except Exception:
                pass

    return list(fallback) if fallback else []


def load_raw(name: str) -> dict:
    """Return the full parsed YAML dict for *name* (all sections)."""
    for base_dir in (_USER_DIR, _BUILTIN_DIR):
        path = os.path.join(base_dir, f"{name}.yaml")
        if os.path.exists(path):
            try:
                import yaml  # type: ignore
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
    return {}


def reload(name: str) -> None:
    """Invalidate cache for *name* (e.g. after user edits a payload file)."""
    load.cache_clear()
