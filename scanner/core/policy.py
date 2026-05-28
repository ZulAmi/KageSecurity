"""
Persistent scan policy — loads ~/.kagesec/config.yaml and merges it with CLI args.

Priority (highest to lowest):
  1. CLI flags (explicit user input)
  2. Environment variables (KAGESEC_* / ANTHROPIC_API_KEY)
  3. ~/.kagesec/config.yaml  (persisted defaults)
  4. Hard-coded defaults in ScanConfig / argparse

YAML format example:
  depth: 5
  max_pages: 200
  concurrency: 12
  rate_limit: 20
  output: markdown
  no_ai: false
  browser: false
  proxy: http://127.0.0.1:8080
  modules:
    - xss
    - sqli
    - cors
  exclude:
    - "*/logout*"
    - "*.css"
  compliance:
    - gdpr
  template_dirs:
    - /home/user/my-templates
  profile: quick   # applies profile defaults first, then other keys override
"""
from __future__ import annotations

import os
from typing import Any

_CONFIG_PATH = os.path.expanduser("~/.kagesec/config.yaml")


def load() -> dict[str, Any]:
    """Return the persisted config as a dict, or {} if not present / unreadable."""
    if not os.path.exists(_CONFIG_PATH):
        return {}
    try:
        import yaml  # type: ignore
        with open(_CONFIG_PATH) as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        return {}


def save(data: dict[str, Any]) -> None:
    """Write *data* to ~/.kagesec/config.yaml (merge with existing keys)."""
    import yaml  # type: ignore
    os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
    existing = load()
    existing.update(data)
    with open(_CONFIG_PATH, "w") as f:
        yaml.safe_dump(existing, f, default_flow_style=False, sort_keys=True)


def apply_to_namespace(policy: dict[str, Any], args) -> None:
    """
    For each key in *policy*, set it on *args* ONLY if the arg is still at its
    default value (i.e. the user did not pass it explicitly on the CLI).

    Mapping from YAML keys → argparse attribute names:
    """
    _MAP = {
        "depth":         ("depth",          3),
        "max_pages":     ("max_pages",       100),
        "concurrency":   ("concurrency",     8),
        "rate_limit":    ("rate_limit",      10),
        "output":        ("output",          "json"),
        "no_ai":         ("no_ai",           False),
        "browser":       ("browser",         False),
        "proxy":         ("proxy",           None),
        "modules":       ("modules",         None),
        "exclude":       ("exclude",         None),
        "include":       ("include",         None),
        "compliance":    ("compliance",      None),
        "template_dirs": ("templates",       None),
        "parallel":      ("parallel",        1),
        "fail_on":       ("fail_on",         None),
        "nvd_api_key":   ("nvd_api_key",     None),
        "api_key":       ("api_key",         None),
    }

    for yaml_key, (attr, default) in _MAP.items():
        if yaml_key not in policy:
            continue
        yaml_val = policy[yaml_key]
        current = getattr(args, attr, default)
        # Apply only when still at default
        if current == default or current is None:
            setattr(args, attr, yaml_val)


def print_policy(policy: dict[str, Any]) -> None:
    if not policy:
        print(f"[*] No config file found at {_CONFIG_PATH}")
        return
    print(f"[*] Config: {_CONFIG_PATH}")
    for k, v in sorted(policy.items()):
        print(f"    {k:<20} {v}")
