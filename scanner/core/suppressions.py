"""
Persistent False-Positive Suppression Rules — Gap 23

Stores suppression rules in ~/.kagesec/suppressions.yaml.
A matching finding is flagged as suppressed and excluded from output.

CLI:
  kagesec suppress add --title "XSS" --url-pattern "*/admin/*" --target https://example.com
  kagesec suppress list
  kagesec suppress remove <id>

Rule format (suppressions.yaml):
  suppressions:
    - id: 1
      title_contains: "XSS"
      url_pattern: "*/admin/*"
      target: "https://example.com"
      created: "2026-01-01T00:00:00"
      note: "Known false positive on admin XSS scan"
"""
from __future__ import annotations

import fnmatch
import os
import uuid
from datetime import datetime
from typing import List, Optional

import yaml

_SUPPRESSIONS_FILE = os.path.expanduser("~/.kagesec/suppressions.yaml")


def load_suppressions() -> List[dict]:
    try:
        with open(_SUPPRESSIONS_FILE) as f:
            data = yaml.safe_load(f) or {}
        return data.get("suppressions", [])
    except FileNotFoundError:
        return []
    except Exception:
        return []


def save_suppressions(rules: List[dict]):
    os.makedirs(os.path.dirname(_SUPPRESSIONS_FILE), exist_ok=True)
    with open(_SUPPRESSIONS_FILE, "w") as f:
        yaml.dump({"suppressions": rules}, f, default_flow_style=False)


def add_suppression(
    title_contains: str = "",
    url_pattern: str = "*",
    target: str = "",
    note: str = "",
) -> dict:
    rules = load_suppressions()
    rule = {
        "id": str(uuid.uuid4())[:8],
        "title_contains": title_contains,
        "url_pattern": url_pattern,
        "target": target,
        "note": note,
        "created": datetime.utcnow().isoformat(),
    }
    rules.append(rule)
    save_suppressions(rules)
    return rule


def remove_suppression(rule_id: str) -> bool:
    rules = load_suppressions()
    new_rules = [r for r in rules if r.get("id") != rule_id]
    if len(new_rules) == len(rules):
        return False
    save_suppressions(new_rules)
    return True


def is_suppressed(finding, rules: Optional[List[dict]] = None) -> bool:
    """Return True if the finding matches any suppression rule."""
    if rules is None:
        rules = load_suppressions()
    for rule in rules:
        if _matches(finding, rule):
            return True
    return False


def apply_suppressions(findings: list, rules: Optional[List[dict]] = None) -> list:
    """Mark suppressed findings and return filtered list."""
    if rules is None:
        rules = load_suppressions()
    if not rules:
        return findings
    for f in findings:
        if is_suppressed(f, rules):
            f.false_positive_suppressed = True
    return [f for f in findings if not f.false_positive_suppressed]


def _matches(finding, rule: dict) -> bool:
    title_contains = rule.get("title_contains", "")
    url_pattern = rule.get("url_pattern", "*")
    target = rule.get("target", "")

    if title_contains and title_contains.lower() not in (finding.title or "").lower():
        return False
    if url_pattern and url_pattern != "*":
        if not fnmatch.fnmatch(finding.url or "", url_pattern):
            return False
    if target and not (finding.url or "").startswith(target):
        return False
    return True


def print_suppressions():
    rules = load_suppressions()
    if not rules:
        print("No suppression rules configured.")
        return
    for r in rules:
        print(f"[{r.get('id')}] title_contains='{r.get('title_contains')}' "
              f"url_pattern='{r.get('url_pattern')}' target='{r.get('target')}' "
              f"note='{r.get('note', '')}'")
