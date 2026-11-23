"""Path-safety helpers for anything that writes files named by untrusted input.

Zip archives (template bundles, exported scans) and API/MCP callers can supply
names like ``../../.bashrc``. Every write that derives a path from such input
must go through :func:`safe_join` so it cannot escape its base directory.
"""
from __future__ import annotations

import os
import re

_SCAN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def safe_join(base: str, *parts: str) -> str:
    """Join *parts* onto *base* and return the absolute path.

    Raises ``ValueError`` if the result would land outside *base* (via ``..``,
    an absolute component, or a symlinked parent that resolves elsewhere).
    """
    base_real = os.path.realpath(base)
    candidate = os.path.realpath(os.path.join(base_real, *parts))
    if os.path.commonpath([base_real, candidate]) != base_real:
        raise ValueError(f"path escapes base directory: {os.path.join(*parts)!r}")
    return candidate


def is_within(base: str, path: str) -> bool:
    """Return True if *path* resolves to a location inside *base*."""
    base_real = os.path.realpath(base)
    path_real = os.path.realpath(path)
    return os.path.commonpath([base_real, path_real]) == base_real


def validate_scan_id(scan_id: str) -> str:
    """Return *scan_id* unchanged if it is safe to embed in a filename."""
    if not isinstance(scan_id, str) or not _SCAN_ID_RE.match(scan_id):
        raise ValueError(f"invalid scan id: {scan_id!r}")
    return scan_id
