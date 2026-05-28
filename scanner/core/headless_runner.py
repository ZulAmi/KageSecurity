"""
Headless template runner — executes Nuclei `headless:` template blocks
using Playwright.

Supports a subset of Nuclei headless actions sufficient for ~80% of community
headless templates:

  navigate    — go to a URL
  click       — click a CSS selector
  type        — fill an input field
  wait-for    — wait for selector / load / network-idle
  extract     — extract text/attribute from a selector
  screenshot  — capture a screenshot (saved to /tmp)
  sleep       — sleep N seconds
  evaluate    — run arbitrary JS in the page context
  assert      — assert page state (for matchers)

YAML headless block format (Nuclei-compatible):
---
id: csrf-header-check
headless:
  - action: navigate
    args:
      url: "{{BaseURL}}/dashboard"
  - action: click
    args:
      by: selector
      selector: "#submit-btn"
  - action: extract
    name: csrf_token
    args:
      by: selector
      selector: 'meta[name="csrf-token"]'
      attribute: content
  - action: assert
    args:
      by: status
      status: 200

Matchers on headless templates check the final page source / URL.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, List, Optional

_PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.sync_api import sync_playwright  # type: ignore
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass


@dataclass
class HeadlessAction:
    action: str
    args: dict = field(default_factory=dict)
    name: Optional[str] = None    # for extract → variable name


@dataclass
class HeadlessTemplate:
    id: str
    actions: List[HeadlessAction]
    matchers: List[dict] = field(default_factory=list)
    variables: dict = field(default_factory=dict)


def parse_headless(template_data: dict, variables: dict) -> Optional[HeadlessTemplate]:
    """Parse a raw template dict that has a 'headless:' key."""
    headless_block = template_data.get("headless")
    if not headless_block or not isinstance(headless_block, list):
        return None

    actions = []
    for item in headless_block:
        if not isinstance(item, dict):
            continue
        actions.append(HeadlessAction(
            action=item.get("action", ""),
            args=item.get("args", {}),
            name=item.get("name"),
        ))

    matchers = template_data.get("matchers", [])
    if isinstance(matchers, dict):
        matchers = [matchers]

    return HeadlessTemplate(
        id=template_data.get("id", "unknown"),
        actions=actions,
        matchers=matchers if isinstance(matchers, list) else [],
        variables={**variables},
    )


def run_headless(
    template: HeadlessTemplate,
    base_url: str,
    timeout_ms: int = 10_000,
) -> dict:
    """
    Execute a headless template against *base_url*.

    Returns a result dict:
      {
        "matched": bool,
        "url": str,
        "status": int,
        "body": str,
        "extracted": {name: value, ...},
        "screenshot": path_or_None,
        "error": str_or_None,
      }
    """
    if not _PLAYWRIGHT_AVAILABLE:
        return {
            "matched": False, "url": base_url, "status": 0,
            "body": "", "extracted": {}, "screenshot": None,
            "error": "playwright not installed — run: pip install playwright && playwright install chromium",
        }

    result: dict[str, Any] = {
        "matched": False, "url": base_url, "status": 0,
        "body": "", "extracted": {}, "screenshot": None, "error": None,
    }

    def _sub(text: str) -> str:
        """Variable substitution: {{BaseURL}} → base_url, {{varname}} → value."""
        text = text.replace("{{BaseURL}}", base_url)
        for k, v in template.variables.items():
            text = text.replace(f"{{{{{k}}}}}", str(v))
        return text

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_default_timeout(timeout_ms)

            for act in template.actions:
                action = act.action.lower()
                args = act.args

                if action == "navigate":
                    url = _sub(args.get("url", base_url))
                    resp = page.goto(url, wait_until="domcontentloaded")
                    if resp:
                        result["status"] = resp.status
                        result["url"] = page.url

                elif action == "click":
                    sel = _sub(args.get("selector", ""))
                    if sel:
                        page.click(sel)

                elif action == "type":
                    sel = _sub(args.get("selector", ""))
                    val = _sub(args.get("value", args.get("data", "")))
                    if sel:
                        page.fill(sel, val)

                elif action in ("wait-for", "waitfor", "wait_for"):
                    by = args.get("by", "selector")
                    if by == "selector":
                        sel = _sub(args.get("selector", ""))
                        if sel:
                            page.wait_for_selector(sel)
                    elif by == "load":
                        page.wait_for_load_state("load")
                    elif by == "network-idle":
                        page.wait_for_load_state("networkidle")

                elif action == "extract":
                    by = args.get("by", "selector")
                    var_name = act.name or args.get("name", "extracted")
                    if by == "selector":
                        sel = _sub(args.get("selector", ""))
                        attr = args.get("attribute")
                        if sel:
                            el = page.query_selector(sel)
                            if el:
                                val = el.get_attribute(attr) if attr else el.text_content()
                                result["extracted"][var_name] = val or ""
                                template.variables[var_name] = val or ""
                    elif by == "regex":
                        pattern = args.get("pattern", "")
                        body = page.content()
                        m = re.search(pattern, body)
                        if m:
                            val = m.group(1) if m.lastindex else m.group(0)
                            result["extracted"][var_name] = val
                            template.variables[var_name] = val

                elif action == "screenshot":
                    path = args.get("path", f"/tmp/kagesec_headless_{template.id}.png")
                    page.screenshot(path=path)
                    result["screenshot"] = path

                elif action == "sleep":
                    seconds = float(args.get("duration", args.get("seconds", 1)))
                    time.sleep(seconds)

                elif action == "evaluate":
                    js = _sub(args.get("js", args.get("code", "")))
                    if js:
                        page.evaluate(js)

                elif action in ("assert", "check"):
                    by = args.get("by", "")
                    if by == "status":
                        expected = int(args.get("status", 200))
                        if result["status"] != expected:
                            result["error"] = f"assert failed: status {result['status']} != {expected}"

            result["body"] = page.content()
            result["url"] = page.url

            # Run matchers
            if template.matchers:
                result["matched"] = _check_matchers(template.matchers, result)
            else:
                result["matched"] = result["status"] in range(200, 400)

            browser.close()

    except Exception as exc:
        result["error"] = str(exc)

    return result


def _check_matchers(matchers: list, result: dict) -> bool:
    """Check Nuclei-style matchers against headless result."""
    for m in matchers:
        mtype = m.get("type", "word")
        cond  = m.get("condition", "or")

        if mtype == "status":
            statuses = m.get("status", [])
            ok = result["status"] in statuses
        elif mtype == "word":
            words = m.get("words", [])
            body  = (result.get("body") or "").lower()
            if cond == "and":
                ok = all(w.lower() in body for w in words)
            else:
                ok = any(w.lower() in body for w in words)
        elif mtype == "regex":
            patterns = m.get("regex", [])
            body = result.get("body") or ""
            if cond == "and":
                ok = all(re.search(p, body) for p in patterns)
            else:
                ok = any(re.search(p, body) for p in patterns)
        else:
            ok = True

        negate = m.get("negative", False)
        if negate:
            ok = not ok
        if not ok:
            return False

    return True
