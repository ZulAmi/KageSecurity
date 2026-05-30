"""
Template-based scanning module.

Execution priority:
  1. kagesec-engine (Go binary) — 50 concurrent goroutines, fingerprint-aware
     template ordering, confidence scoring. Falls back to Python if unavailable.
  2. Python runner — sequential fallback, no concurrency.

With AI key:  Claude fingerprints the stack and selects 80-200 relevant templates
              before handing off to the engine (50-100x faster, higher signal).
Without AI:   engine runs all templates concurrently — no budget cap, no timeout.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from typing import List

from scanner.core.crawler import CrawlResult
from scanner.core.scan_result import Finding, Severity
from scanner.core.template_runner import load_templates, run_template
from scanner.core.fingerprinter import fingerprint_page

_NUCLEI_TEMPLATES_DIR = os.path.expanduser("~/.kagesec/nuclei-templates")
_BIN_NAME = "kagesec-engine.exe" if sys.platform == "win32" else "kagesec-engine"
# Bundled binary (pip install): scanner/_bin/kagesec-engine
_BUNDLED_BINARY = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "_bin", _BIN_NAME))
# Dev/cloned repo: engine/kagesec-engine
_ENGINE_BINARY = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "engine", _BIN_NAME))

_template_cache: dict[str, list] = {}
_state: dict[str, dict] = {}
_state_lock = threading.Lock()

# Go engine result cache — keyed by (base_url, templates_dir).
# The engine uses {{BaseURL}} (scheme+host) for all template paths, so every
# page on the same host produces identical results. Run once, return findings
# once, then return [] for all subsequent page calls so findings aren't
# added to the scan result multiple times.
_engine_cache: dict[tuple, list] = {}
_engine_consumed: set[tuple] = set()  # keys whose findings have already been returned
_engine_locks: dict[tuple, threading.Event] = {}
_engine_meta_lock = threading.Lock()

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
}


def _engine_binary() -> str | None:
    """Return path to kagesec-engine if available, else None."""
    # 1. Bundled binary (pip install) — scanner/_bin/kagesec-engine
    if os.path.isfile(_BUNDLED_BINARY):
        if not os.access(_BUNDLED_BINARY, os.X_OK):
            os.chmod(_BUNDLED_BINARY, 0o755)  # nosec B103 — executable bit required for bundled binary
        return _BUNDLED_BINARY
    # 2. Dev / cloned repo — engine/kagesec-engine
    if os.path.isfile(_ENGINE_BINARY) and os.access(_ENGINE_BINARY, os.X_OK):
        return _ENGINE_BINARY
    # 3. System PATH
    return shutil.which(_BIN_NAME)


def test(page: CrawlResult, client, config=None) -> List[Finding]:
    api_key    = getattr(config, "api_key",        None) if config else None
    target     = getattr(config, "target",         page.url) if config else page.url
    nuclei_opt = getattr(config, "nuclei_templates", False) if config else False
    oob_server = getattr(config, "oob_server",     "") if config else ""

    templates_dirs = _resolve_template_dirs(config, nuclei_opt)
    binary = _engine_binary()

    # --- AI template selection (with or without Go engine) ---
    selected_files: list[str] | None = None
    if api_key:
        state = _get_state(target)
        fingerprint_page(page, state["fingerprints"])
        selected_files = _ai_select(state, templates_dirs, api_key)

    # --- Go engine path ---
    if binary:
        findings = []
        base = _base_url(page.url)
        for tdir in templates_dirs:
            findings.extend(
                _engine_once(binary, base, tdir, config, oob_server, selected_files)
            )
        return findings

    # --- Python fallback ---
    all_templates = _get_all_templates(config, nuclei_opt)
    if not all_templates:
        return []
    if api_key and selected_files is not None:
        selected_ids = {os.path.abspath(f) for f in selected_files}
        run_set = [t for t in all_templates if os.path.abspath(t.source_file) in selected_ids] or all_templates
    else:
        run_set = all_templates
    return _run_python(run_set, page, client)


# ---------------------------------------------------------------------------
# Go engine
# ---------------------------------------------------------------------------

def _base_url(url: str) -> str:
    """Return scheme://host — the only part the Go engine actually uses."""
    from urllib.parse import urlparse
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _engine_once(
    binary: str,
    base: str,
    templates_dir: str,
    config,
    oob_server: str,
    selected_files: list[str] | None,
) -> list[Finding]:
    """Run the Go engine once per (base_url, templates_dir) and return findings once.

    - First thread: runs the engine, stores results, returns them.
    - All other threads: wait for the run to finish, then return [] so the same
      findings are never added to the scan result more than once.
    """
    key = (base, templates_dir)

    with _engine_meta_lock:
        # Already returned findings for this key — don't add them again
        if key in _engine_consumed:
            return []
        # Results ready but not yet returned — hand them off and mark consumed
        if key in _engine_cache:
            _engine_consumed.add(key)
            return _engine_cache[key]
        # First arrival: claim ownership of the engine run
        if key not in _engine_locks:
            _engine_locks[key] = threading.Event()
            owner = True
        else:
            owner = False
        event = _engine_locks[key]

    if not owner:
        # Wait for the owner to finish, then return nothing —
        # the owner already returned the findings.
        event.wait()
        return []

    # Owner: run the engine, store results, mark consumed, return once
    try:
        results = _run_engine(binary, base, templates_dir, config, oob_server, selected_files)
        _engine_cache[key] = results
    except Exception:
        _engine_cache[key] = []
    finally:
        with _engine_meta_lock:
            _engine_consumed.add(key)
        event.set()

    return _engine_cache[key]


def _run_engine(
    binary: str,
    target: str,
    templates_dir: str,
    config,
    oob_server: str,
    selected_files: list[str] | None,
) -> List[Finding]:
    if not os.path.isdir(templates_dir):
        return []

    fp = _build_fingerprint(config)
    auth_headers = _build_auth_headers(config)
    cookie = getattr(config, "auth_cookie", "") if config else ""
    # Go engine uses its own goroutine-level concurrency — no token-bucket needed.
    # Pass 0 to disable rate limiting; the concurrency flag is the real throttle.
    rate   = 0
    verify = not getattr(config, "no_verify", False) if config else True

    cmd = [
        binary,
        "-target",      target,
        "-templates",   templates_dir,
        "-fingerprint", json.dumps(fp),
        "-concurrency", "50",
        "-rate-limit",  str(rate),
        "-timeout",     "10",
        "-severity",    "info,low,medium,high,critical",
    ]
    if oob_server:
        cmd += ["-oob-url", oob_server]
    if cookie:
        cmd += ["-cookie", cookie]
    if not verify:
        cmd += ["-no-verify"]
    for k, v in auth_headers.items():
        cmd += ["-header", f"{k}: {v}"]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except OSError:
        return []

    findings: List[Finding] = []
    import time as _time

    last_output = [_time.monotonic()]

    def _watchdog(proc, silence_limit=120):
        """Kill the subprocess if it produces no output for silence_limit seconds.
        Handles goroutines stuck in network I/O that prevent the process from exiting."""
        while proc.poll() is None:
            _time.sleep(10)
            if _time.monotonic() - last_output[0] > silence_limit:
                proc.kill()
                return

    wd = threading.Thread(target=_watchdog, args=(proc,), daemon=True)
    wd.start()

    for line in proc.stdout:
        last_output[0] = _time.monotonic()
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("type") == "finding":
            f = _engine_finding_to_kagesec(msg)
            if f:
                findings.append(f)
        elif msg.get("type") == "progress":
            done  = msg.get("done", 0)
            total = msg.get("total", 0)
            found = msg.get("findings", 0)
            if total > 0 and done % 500 == 0:
                print(
                    f"[engine] {done}/{total} templates  |  {found} findings",
                    flush=True,
                )

    # Subprocess closed stdout — wait up to 30s for clean exit, then force kill.
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

    return findings


def _engine_finding_to_kagesec(msg: dict) -> Finding | None:
    sev_str  = str(msg.get("severity", "info")).lower()
    severity = _SEVERITY_MAP.get(sev_str, Severity.INFO)

    cve = msg.get("cve") or ""
    standards: list[str] = []
    if cve:
        standards.append(cve)
    if msg.get("owasp"):
        standards.append(msg["owasp"])

    return Finding(
        title       = msg.get("title", msg.get("template_id", "Unknown")),
        severity    = severity,
        url         = msg.get("url", ""),
        parameter   = None,
        payload     = None,
        evidence    = msg.get("evidence", ""),
        description = msg.get("description", ""),
        remediation = msg.get("remediation", ""),
        cwe         = msg.get("cwe") or None,
        cvss        = msg.get("cvss") or None,
        owasp_category = msg.get("owasp") or None,
        standards   = standards,
        confidence  = msg.get("confidence", 0.85),
        verified    = False,
        poc_curl    = msg.get("curl_command") or None,
    )


# ---------------------------------------------------------------------------
# AI template selection
# ---------------------------------------------------------------------------

def _get_state(target: str) -> dict:
    with _state_lock:
        if target not in _state:
            _state[target] = {
                "fingerprints": {},
                "selected":     None,
                "selecting":    False,
                "select_done":  threading.Event(),
            }
        return _state[target]


def _ai_select(state: dict, template_dirs: list[str], api_key: str) -> list[str] | None:
    if state["select_done"].is_set():
        return state["selected"]

    with _state_lock:
        already = state["selecting"]
        if not already:
            state["selecting"] = True

    if already:
        state["select_done"].wait(timeout=30)
        return state["selected"]

    try:
        all_templates = []
        for d in template_dirs:
            all_templates.extend(load_templates([d]))

        from scanner.ai.template_selector import select_templates, summarise_selection
        selected = select_templates(dict(state["fingerprints"]), all_templates, api_key)
        state["selected"] = [t.source_file for t in selected]
        print(f"\n{summarise_selection(state['fingerprints'], selected, len(all_templates))}")
    except Exception:
        state["selected"] = None
    finally:
        state["select_done"].set()

    return state["selected"]


# ---------------------------------------------------------------------------
# Python fallback
# ---------------------------------------------------------------------------

def _get_all_templates(config, nuclei_opt: bool) -> list:
    extra_dirs: list[str] = []
    if config:
        extra = getattr(config, "template_dirs", None)
        if extra:
            extra_dirs = list(extra) if isinstance(extra, (list, tuple)) else [extra]
    if nuclei_opt and os.path.isdir(_NUCLEI_TEMPLATES_DIR) and _NUCLEI_TEMPLATES_DIR not in extra_dirs:
        extra_dirs.append(_NUCLEI_TEMPLATES_DIR)

    cache_key = str(sorted(extra_dirs))
    if cache_key not in _template_cache:
        _template_cache[cache_key] = load_templates(extra_dirs if extra_dirs else None)
    return _template_cache[cache_key]


def _run_python(templates: list, page: CrawlResult, client) -> List[Finding]:
    findings: List[Finding] = []
    for t in templates:
        try:
            findings.extend(run_template(t, page.url, client))
        except Exception:
            pass
    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_template_dirs(config, nuclei_opt: bool) -> list[str]:
    dirs: list[str] = []
    if config:
        extra = getattr(config, "template_dirs", None)
        if extra:
            dirs = list(extra) if isinstance(extra, (list, tuple)) else [extra]
    if not dirs:
        # Built-in templates bundled with KageSec
        builtin = os.path.join(os.path.dirname(__file__), "..", "templates")
        dirs = [os.path.abspath(builtin)]
    if nuclei_opt and os.path.isdir(_NUCLEI_TEMPLATES_DIR) and _NUCLEI_TEMPLATES_DIR not in dirs:
        dirs.append(_NUCLEI_TEMPLATES_DIR)
    return dirs


def _build_fingerprint(config) -> dict:
    if not config:
        return {}
    return {
        "tech":     getattr(config, "detected_tech",     []),
        "cms":      getattr(config, "detected_cms",      ""),
        "language": getattr(config, "detected_language", ""),
        "server":   getattr(config, "detected_server",   ""),
    }


def _build_auth_headers(config) -> dict[str, str]:
    if not config:
        return {}
    headers: dict[str, str] = {}
    bearer = getattr(config, "auth_bearer", None)
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    extra = getattr(config, "extra_headers", None)
    if extra and isinstance(extra, dict):
        headers.update(extra)
    return headers
