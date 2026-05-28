"""
Incremental / Delta Scanning — Gap 28

Saves a URL→content-hash map after each scan so subsequent scans can skip
pages that haven't changed. This dramatically speeds up CI/CD scans where
only a few endpoints change per commit.

State file: ~/.kagesec/crawl_state/{target_hash}.json
Override: --full flag forces a full re-scan ignoring the state file.

Format:
  {
    "target": "https://example.com",
    "scan_date": "2026-01-01T00:00:00",
    "pages": {
      "https://example.com/api/users": "sha256hex",
      ...
    }
  }
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from typing import Dict, Optional

_STATE_DIR = os.path.expanduser("~/.kagesec/crawl_state")


def _state_path(target: str) -> str:
    target_hash = hashlib.sha256(target.encode()).hexdigest()[:16]
    return os.path.join(_STATE_DIR, f"{target_hash}.json")


def load_state(target: str) -> Dict[str, str]:
    """Load saved URL→content-hash map for the target. Returns {} if none."""
    try:
        with open(_state_path(target)) as f:
            data = json.load(f)
        return data.get("pages", {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(target: str, pages: list):
    """Save current URL→content-hash map after a successful scan."""
    os.makedirs(_STATE_DIR, exist_ok=True)
    state = {
        "target": target,
        "scan_date": datetime.utcnow().isoformat(),
        "pages": {p.url: _page_hash(p) for p in pages},
    }
    try:
        with open(_state_path(target), "w") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


def filter_changed_pages(pages: list, saved_state: Dict[str, str]) -> tuple:
    """
    Split pages into (changed, unchanged).
    *changed* must be scanned; *unchanged* can be skipped.
    """
    if not saved_state:
        return pages, []

    changed = []
    unchanged = []
    for page in pages:
        current_hash = _page_hash(page)
        if saved_state.get(page.url) != current_hash:
            changed.append(page)
        else:
            unchanged.append(page)
    return changed, unchanged


def _page_hash(page) -> str:
    body = getattr(page, "body", "") or ""
    return hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()
