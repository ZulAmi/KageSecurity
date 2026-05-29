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
import json
import threading
import time
from typing import Optional

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
            headers={"User-Agent": "KageSec/1.0 template-updater"},
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
    print("    This only happens once. Use --no-templates to skip.\n")
    try:
        remote = get_remote_version() or "latest"
        _download_update(remote, dest_dir)
    except Exception as e:
        print(f"[!] Template bootstrap failed: {e}")
        print("    Run  kagesec update-templates  to retry, or use  --no-templates  to scan without them.\n")


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


def _download_update(version: str, dest_dir: str) -> None:
    """Download and replace templates (same logic as update-templates command)."""
    import urllib.request
    import zipfile
    import io

    _SKIP_DIRS = {"dns", "network", "headless", "ssl", "whois", "workflows", ".github", "helpers", "fuzzing"}
    _UNSUPPORTED = ("flow:", "network:", "dns:", "headless:", "ssl:", "websocket:", "whois:")

    NUCLEI_ZIP = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"
    try:
        req = urllib.request.Request(NUCLEI_ZIP, headers={"User-Agent": "KageSec/1.0 template-updater"})
        with urllib.request.urlopen(req, timeout=120) as resp:  # nosec B310
            data = resp.read()

        saved = 0
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for member in zf.namelist():
                if not member.endswith(".yaml"):
                    continue
                parts = member.split("/", 1)
                rel = parts[1] if len(parts) > 1 else member
                top = rel.split("/")[0].lower()
                if top in _SKIP_DIRS:
                    continue
                content = zf.read(member)
                text = content.decode("utf-8", errors="ignore")
                if any(k in text for k in _UNSUPPORTED):
                    continue
                out_path = os.path.join(dest_dir, rel)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as f:
                    f.write(content)
                saved += 1

        save_local_version(version)
        print(f"[+] Templates updated to {version} ({saved:,} files)")
    except Exception as e:
        print(f"[!] Auto-update failed: {e}")
