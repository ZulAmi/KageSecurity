"""
Per-Module Scan Policy Engine — Gap 25

Loaded from ~/.kagesec/policy.yaml or --policy FILE.
Controls per-module: enabled, strength (1–3), timeout_multiplier, max_payloads.

Policy YAML format:
  modules:
    sqli:
      enabled: true
      strength: 2          # 1=minimal, 2=normal, 3=aggressive
      timeout_multiplier: 1.5   # multiply default timeouts
      max_payloads: 10     # limit payload count (safety for prod servers)
    xss:
      enabled: true
      strength: 1
    time_based_sqli:
      enabled: false        # disable risky modules on prod
"""
from __future__ import annotations

import os
from typing import Optional

import yaml

_DEFAULT_POLICY_PATH = os.path.expanduser("~/.kagesec/policy.yaml")


class ModulePolicy:
    def __init__(self, data: dict):
        self.enabled: bool = bool(data.get("enabled", True))
        self.strength: int = max(1, min(3, int(data.get("strength", 2))))
        self.timeout_multiplier: float = float(data.get("timeout_multiplier", 1.0))
        self.max_payloads: Optional[int] = data.get("max_payloads")


class ScanPolicy:
    def __init__(self, data: dict):
        modules_raw = data.get("modules", {}) or {}
        self._modules: dict[str, ModulePolicy] = {
            name: ModulePolicy(cfg)
            for name, cfg in modules_raw.items()
            if isinstance(cfg, dict)
        }
        self._default = ModulePolicy({})

    @classmethod
    def load(cls, path: Optional[str] = None) -> "ScanPolicy":
        fpath = path or _DEFAULT_POLICY_PATH
        try:
            with open(fpath) as f:
                data = yaml.safe_load(f) or {}
            return cls(data)
        except FileNotFoundError:
            return cls({})
        except Exception:
            return cls({})

    def for_module(self, module_name: str) -> ModulePolicy:
        """Return the policy for a module. module_name = last part of module.__name__."""
        return self._modules.get(module_name, self._default)

    def is_enabled(self, module_name: str) -> bool:
        return self.for_module(module_name).enabled

    def max_payloads(self, module_name: str) -> Optional[int]:
        return self.for_module(module_name).max_payloads

    def timeout_multiplier(self, module_name: str) -> float:
        return self.for_module(module_name).timeout_multiplier
