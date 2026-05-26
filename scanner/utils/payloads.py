import os
from typing import Any

_PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "payloads")
_cache: dict[str, Any] = {}


def load_payloads(name: str) -> Any:
    """Load payload data from scanner/payloads/{name}.yaml.

    Returns the parsed YAML content (list or dict) on success,
    or None if the file is missing or pyyaml is not installed.
    Callers should fall back to hardcoded payloads when None is returned.
    Results are cached after first load.
    """
    if name in _cache:
        return _cache[name]

    path = os.path.normpath(os.path.join(_PAYLOADS_DIR, f"{name}.yaml"))
    if not os.path.exists(path):
        _cache[name] = None
        return None

    try:
        import yaml
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        _cache[name] = data
        return data
    except Exception:
        _cache[name] = None
        return None
