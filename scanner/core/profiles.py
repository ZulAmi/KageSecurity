"""
Scan profiles — named presets for common use cases.

Built-in profiles:
  quick    — fast surface scan (depth 2, 50 pages, 16 threads, injection modules only)
  full     — thorough scan (depth 5, 500 pages, 8 threads, all modules)
  api      — REST/GraphQL API focused (depth 1, 200 pages, no browser, API modules)
  passive  -- read-only inspection (no injection, headers/cookies/content only)
  stealth  — slow, low-noise (depth 2, 30 pages, 2 threads, 2 RPS rate limit)

Custom profiles can be placed in ~/.kagesec/profiles/<name>.yaml and
referenced with --profile <name>.

Profile YAML format:
  depth: 3
  max_pages: 100
  concurrency: 8
  rate_limit: 10
  passive: false
  browser: false
  modules:
    - xss
    - sqli
"""
from __future__ import annotations

import os
from typing import Any

_PROFILES_DIR = os.path.expanduser("~/.kagesec/profiles")

_INJECTION_MODULES = [
    "sqli", "xss", "ssti", "cmd_injection", "path_traversal",
    "xxe", "ssrf", "open_redirect", "crlf", "http_param_pollution",
]

_API_MODULES = [
    "cors", "auth_bypass", "jwt_attacks", "idor", "rate_limit",
    "security_headers", "api_key_leak", "graphql", "ssrf",
    "open_redirect", "http_methods", "version_disclosure",
]

BUILT_IN: dict[str, dict[str, Any]] = {
    "quick": {
        "depth": 2,
        "max_pages": 50,
        "concurrency": 16,
        "rate_limit": 20,
        "passive": False,
        "browser": False,
        "modules": _INJECTION_MODULES,
    },
    "full": {
        "depth": 5,
        "max_pages": 500,
        "concurrency": 8,
        "rate_limit": 10,
        "passive": False,
        "browser": False,
        "modules": None,  # all modules
    },
    "api": {
        "depth": 1,
        "max_pages": 200,
        "concurrency": 12,
        "rate_limit": 15,
        "passive": False,
        "browser": False,
        "modules": _API_MODULES,
    },
    "passive": {
        "depth": 3,
        "max_pages": 100,
        "concurrency": 8,
        "rate_limit": 10,
        "passive": True,
        "browser": False,
        "modules": None,
    },
    "stealth": {
        "depth": 2,
        "max_pages": 30,
        "concurrency": 2,
        "rate_limit": 2,
        "passive": False,
        "browser": False,
        "modules": _INJECTION_MODULES,
    },
}


def load(name: str) -> dict[str, Any]:
    """Return profile dict for *name*. Raises ValueError if not found."""
    if name in BUILT_IN:
        return dict(BUILT_IN[name])

    # Try user-defined profile
    path = os.path.join(_PROFILES_DIR, f"{name}.yaml")
    if os.path.exists(path):
        try:
            import yaml  # type: ignore
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            if isinstance(data, dict):
                return data
        except Exception as e:
            raise ValueError(f"Could not load profile '{name}': {e}") from e

    available = list(BUILT_IN.keys())
    if os.path.isdir(_PROFILES_DIR):
        available += [
            f.removesuffix(".yaml")
            for f in os.listdir(_PROFILES_DIR)
            if f.endswith(".yaml")
        ]
    raise ValueError(
        f"Unknown profile '{name}'. Available: {', '.join(available)}"
    )


def apply_to_namespace(profile: dict[str, Any], args) -> None:
    """
    Apply profile settings to argparse namespace, but only for keys the user
    did NOT supply explicitly (i.e. still at argparse default).
    """
    _DEFAULTS = {
        "depth": 3, "max_pages": 100, "concurrency": 8,
        "rate_limit": 10, "passive": False, "browser": False,
        "modules": None,
    }
    _MAP = {
        "depth":       "depth",
        "max_pages":   "max_pages",
        "concurrency": "concurrency",
        "rate_limit":  "rate_limit",
        "passive":     "passive",
        "browser":     "browser",
        "modules":     "modules",
    }
    for prof_key, arg_attr in _MAP.items():
        if prof_key not in profile:
            continue
        default = _DEFAULTS.get(prof_key)
        current = getattr(args, arg_attr, default)
        if current == default or current is None:
            setattr(args, arg_attr, profile[prof_key])


def list_profiles() -> list[str]:
    names = list(BUILT_IN.keys())
    if os.path.isdir(_PROFILES_DIR):
        names += [
            f.removesuffix(".yaml")
            for f in sorted(os.listdir(_PROFILES_DIR))
            if f.endswith(".yaml")
        ]
    return names
