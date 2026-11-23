"""
Template auto-update check.

On each scan start, compares the locally saved template version stamp
(~/.kagesec/nuclei-templates/.version) against the latest GitHub release tag
for projectdiscovery/nuclei-templates.

The check is non-blocking: it runs in a background thread, prints a one-line
notice if a newer version is available, and exits. It never blocks the scan.

Modes:
  check_for_updates()  — background check, prints notice if outdated
  auto_update(dest_dir) — downloads and replaces templates silently
  get_local_version()  — reads ~/.kagesec/nuclei-templates/.version
  get_remote_version() — hits GitHub releases API (cached 1 h in stamp file)
"""
from __future__ import annotations

import os
import re
import json
import threading
import time
from typing import Optional

from scanner import __version__

_TEMPLATES_DIR = os.path.expanduser("~/.kagesec/nuclei-templates")
_VERSION_STAMP = os.path.join(_TEMPLATES_DIR, ".version")
_VERSION_CACHE  = os.path.join(_TEMPLATES_DIR, ".version_cache")
_CACHE_TTL      = 3600   # 1 hour — avoid hammering GitHub API on every scan

_RELEASES_API = "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest"


def get_local_version() -> Optional[str]:
    if not os.path.exists(_VERSION_STAMP):
        return None
    try:
        return open(_VERSION_STAMP).read().strip() or None
    except Exception:
        return None


def get_remote_version() -> Optional[str]:
    """Return latest GitHub release tag, using a 1-hour file cache."""
    # Check cache first
    if os.path.exists(_VERSION_CACHE):
        try:
            mtime = os.path.getmtime(_VERSION_CACHE)
            if time.time() - mtime < _CACHE_TTL:
                data = json.loads(open(_VERSION_CACHE).read())
                return data.get("tag_name")
        except Exception:
            pass

    try:
        import urllib.request
        req = urllib.request.Request(
            _RELEASES_API,
            headers={"User-Agent": f"KageSec/{__version__} template-updater"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310
            data = json.loads(resp.read())
        tag = data.get("tag_name")
        if tag:
            os.makedirs(os.path.dirname(_VERSION_CACHE), exist_ok=True)
            with open(_VERSION_CACHE, "w") as f:
                json.dump({"tag_name": tag}, f)
        return tag
    except Exception:
        return None


def save_local_version(version: str) -> None:
    os.makedirs(_TEMPLATES_DIR, exist_ok=True)
    with open(_VERSION_STAMP, "w") as f:
        f.write(version)


def bootstrap_if_needed(dest_dir: str = _TEMPLATES_DIR) -> None:
    """
    First-run bootstrap: if the templates directory does not exist, download
    Nuclei templates synchronously before the scan starts.
    Prints progress so the user knows why there's a delay.
    """
    if os.path.isdir(dest_dir):
        return  # already bootstrapped

    print("[*] First run: downloading Nuclei community templates (~30 MB) …")
    print("    This only happens once. Use --skip-templates to skip.\n")
    try:
        remote = get_remote_version() or "latest"
        _download_update(remote, dest_dir)
    except Exception as e:
        print(f"[!] Template bootstrap failed: {e}")
        print("    Run  kagesec update-templates  to retry, or use  --skip-templates  to scan without them.\n")


def check_for_updates(auto: bool = False, dest_dir: str = _TEMPLATES_DIR) -> None:
    """
    Non-blocking background check. Prints a notice if templates are outdated.
    If *auto* is True, downloads the update silently.
    """
    if not os.path.isdir(dest_dir):
        return   # no templates installed — skip silently

    def _check():
        local = get_local_version()
        remote = get_remote_version()
        if not remote:
            return
        if local == remote:
            return
        if auto:
            print(f"\n[*] Auto-updating templates {local or '(unknown)'} → {remote} …")
            _download_update(remote, dest_dir)
        else:
            print(
                f"\n[~] Template update available: {local or '(unknown)'} → {remote}\n"
                f"    Run: kagesec update-templates   or add  --auto-update  to update automatically.\n"
            )

    t = threading.Thread(target=_check, daemon=True)
    t.start()
    # Give it a moment but never block the scan
    t.join(timeout=6)


# Nuclei top-level protocol keys KageSec cannot run, or will not fetch by default.
# `code:` / `javascript:` templates execute scripts on the scanner host itself, so
# they are never downloaded unless the user passes --all (and even then they only
# run with --allow-code-templates).
UNSUPPORTED_KEYS = (
    "flow", "code", "javascript", "network", "dns", "headless", "ssl", "websocket", "whois",
)
_UNSUPPORTED_RE = re.compile(
    r"^(?:" + "|".join(re.escape(k) for k in UNSUPPORTED_KEYS) + r"):", re.MULTILINE
)

# Top-level directories in nuclei-templates that never contain runnable HTTP templates.
SKIP_DIRS = frozenset({
    "dns", "network", "headless", "ssl", "whois", "workflows", ".github",
    "helpers", "fuzzing", "code", "javascript",
})

_ARCHIVE_URL = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/{kind}/{ref}.zip"


def is_compatible(content: bytes) -> bool:
    """True if a template only uses top-level protocols KageSec supports."""
    try:
        return not _UNSUPPORTED_RE.search(content.decode("utf-8", errors="ignore"))
    except Exception:
        return False


def download_templates(
    dest_dir: str = _TEMPLATES_DIR,
    version: Optional[str] = None,
    keep_all: bool = False,
    verbose: bool = True,
) -> dict:
    """Download nuclei-templates and extract the compatible YAML files into *dest_dir*.

    The archive is pinned to *version* (a release tag) when known, so the
    contents always match the version stamp written afterwards. Every member
    path is checked so a malicious archive cannot write outside *dest_dir*.

    Returns counters: {"saved", "skipped_unsupported", "skipped_dir", "version"}.
    """
    import io
    import urllib.request
    import zipfile

    from scanner.utils.safe_paths import safe_join

    version = version or get_remote_version()
    url = (
        _ARCHIVE_URL.format(kind="tags", ref=version)
        if version else _ARCHIVE_URL.format(kind="heads", ref="main")
    )
    if verbose:
        print(f"[*] Fetching {url}")

    req = urllib.request.Request(url, headers={"User-Agent": "KageSec template-updater"})
    with urllib.request.urlopen(req, timeout=120) as resp:  # nosec B310 — fixed https URL
        data = resp.read()

    os.makedirs(dest_dir, exist_ok=True)
    stats = {"saved": 0, "skipped_unsupported": 0, "skipped_dir": 0, "version": version}

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for member in zf.namelist():
            if not member.endswith(".yaml"):
                continue
            # Strip the archive's top-level folder (nuclei-templates-<ref>/...)
            rel = member.split("/", 1)[1] if "/" in member else member
            if rel.split("/")[0].lower() in SKIP_DIRS:
                stats["skipped_dir"] += 1
                continue
            content = zf.read(member)
            if not keep_all and not is_compatible(content):
                stats["skipped_unsupported"] += 1
                continue
            try:
                out_path = safe_join(dest_dir, rel)
            except ValueError:
                stats["skipped_unsupported"] += 1
                continue
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(content)
            stats["saved"] += 1

    if version:
        save_local_version(version)
    return stats


def _download_update(version: str, dest_dir: str) -> None:
    """Background auto-update — never raises."""
    try:
        stats = download_templates(dest_dir, version=version, verbose=False)
        print(f"[+] Templates updated to {version} ({stats['saved']:,} files)")
    except Exception as e:
        print(f"[!] Auto-update failed: {e}")
