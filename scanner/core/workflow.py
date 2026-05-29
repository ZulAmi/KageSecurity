"""
Workflow system — YAML-driven scan orchestration.

A workflow file chains multiple scan steps together, with optional conditions
that gate whether later steps run based on findings from earlier ones.

Workflow YAML format
--------------------
name: wordpress-full-scan
description: Fingerprint → if WordPress → run WP templates + targeted modules

steps:
  - id: fingerprint
    modules:
      - version_disclosure
      - waf_detect
    description: "Stack fingerprinting"

  - id: baseline
    modules:
      - security_headers
      - clickjacking
      - cors
    description: "Baseline security checks"

  - id: wordpress-check
    condition: "wordpress in fingerprints"
    modules:
      - sqli
      - xss
      - auth_bypass
    templates:
      - ~/.kagesec/nuclei-templates/wordpress/
    description: "WordPress-specific checks"

  - id: deep-sqli
    condition: "any_critical"    # run only if CRITICAL findings found so far
    modules:
      - sqli
    description: "Deep SQL injection after critical signal"

Built-in conditions
-------------------
  always                        — always run (default)
  any_finding                   — at least 1 finding so far
  any_high                      — at least 1 HIGH+ finding
  any_critical                  — at least 1 CRITICAL finding
  <tech> in fingerprints        — technology detected in fingerprints dict
  finding_title contains <str>  — any finding title contains string
  no_findings                   — zero findings so far

Custom condition eval: a single Python expression string evaluated with
  findings (list), fingerprints (dict), and step results available.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.scan_result import ScanResult
    from scanner.core.config import ScanConfig

_BUILTIN_WORKFLOWS_DIR = os.path.join(os.path.dirname(__file__), "..", "workflows")
_USER_WORKFLOWS_DIR    = os.path.expanduser("~/.kagesec/workflows")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class WorkflowStep:
    id: str
    modules: List[str] = field(default_factory=list)
    templates: List[str] = field(default_factory=list)
    condition: str = "always"
    description: str = ""
    max_pages: Optional[int] = None
    depth: Optional[int] = None


@dataclass
class Workflow:
    name: str
    description: str = ""
    steps: List[WorkflowStep] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load(name_or_path: str) -> Workflow:
    """Load a workflow by name (built-in/user) or file path."""
    if os.path.exists(name_or_path):
        return _parse_file(name_or_path)

    for base in (_USER_WORKFLOWS_DIR, _BUILTIN_WORKFLOWS_DIR):
        for ext in (".yaml", ".yml"):
            path = os.path.join(base, name_or_path + ext)
            if os.path.exists(path):
                return _parse_file(path)

    raise ValueError(f"Workflow not found: {name_or_path!r}")


def list_workflows() -> list[str]:
    """Return available workflow names."""
    names = []
    for base in (_BUILTIN_WORKFLOWS_DIR, _USER_WORKFLOWS_DIR):
        if not os.path.isdir(base):
            continue
        for fn in sorted(os.listdir(base)):
            if fn.endswith((".yaml", ".yml")):
                names.append(fn.rsplit(".", 1)[0])
    return names


def _parse_file(path: str) -> Workflow:
    import yaml  # type: ignore
    with open(path) as f:
        data = yaml.safe_load(f) or {}

    steps = []
    for s in data.get("steps", []):
        steps.append(WorkflowStep(
            id=s.get("id", "step"),
            modules=s.get("modules", []),
            templates=s.get("templates", []),
            condition=s.get("condition", "always"),
            description=s.get("description", ""),
            max_pages=s.get("max_pages"),
            depth=s.get("depth"),
        ))

    return Workflow(
        name=data.get("name", os.path.basename(path)),
        description=data.get("description", ""),
        steps=steps,
    )


# ---------------------------------------------------------------------------
# Condition evaluator
# ---------------------------------------------------------------------------

def evaluate_condition(
    condition: str,
    findings: list,
    fingerprints: dict,
) -> bool:
    """Return True if *condition* is satisfied given current state."""
    cond = condition.strip().lower()

    if cond in ("always", "true", ""):
        return True
    if cond == "never":
        return False
    if cond == "no_findings":
        return len(findings) == 0
    if cond == "any_finding":
        return len(findings) > 0
    if cond == "any_high":
        return any(f.severity.value in ("high", "critical") for f in findings)
    if cond == "any_critical":
        return any(f.severity.value == "critical" for f in findings)
    if cond == "any_medium":
        return any(f.severity.value in ("medium", "high", "critical") for f in findings)

    # "<tech> in fingerprints"
    if " in fingerprints" in cond:
        tech = cond.replace(" in fingerprints", "").strip().strip('"').strip("'")
        return tech in {k.lower() for k in fingerprints.keys()}

    # "finding_title contains <str>"
    if cond.startswith("finding_title contains "):
        substr = cond.removeprefix("finding_title contains ").strip().strip('"').strip("'")
        return any(substr.lower() in f.title.lower() for f in findings)

    # Arbitrary Python expression
    try:
        result = eval(  # noqa: S307  # nosec B307
            condition,
            {"__builtins__": {}},
            {"findings": findings, "fingerprints": fingerprints, "len": len},
        )
        return bool(result)
    except Exception:
        return True  # default: run the step


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_workflow(
    workflow: Workflow,
    config: "ScanConfig",
    api_key: Optional[str] = None,
    finding_callback=None,
    concurrency: int = 8,
) -> "ScanResult":
    """
    Execute *workflow* step by step, accumulating findings across all steps.
    Each step runs a partial scan (subset of modules / templates) against the
    same target. Fingerprints collected in step 1 are available for conditions
    in later steps.
    """
    import copy
    from scanner.core.engine import run_scan

    all_findings: list = []
    fingerprints: dict = {}
    final_result = None

    print(f"\n[workflow] Starting: {workflow.name}")
    if workflow.description:
        print(f"[workflow] {workflow.description}")
    print()

    for step in workflow.steps:
        if not evaluate_condition(step.condition, all_findings, fingerprints):
            print(f"[workflow] Step '{step.id}' — SKIPPED (condition: {step.condition})")
            continue

        desc = f" — {step.description}" if step.description else ""
        print(f"[workflow] Step '{step.id}'{desc}")

        step_config = copy.copy(config)
        if step.modules:
            step_config.modules = step.modules
        if step.templates:
            existing = list(step_config.template_dirs or [])
            step_config.template_dirs = existing + list(step.templates)
        if step.max_pages is not None:
            step_config.max_pages = step.max_pages
        if step.depth is not None:
            step_config.max_depth = step.depth

        result, _ = run_scan(
            config=step_config,
            api_key=api_key,
            finding_callback=finding_callback,
            concurrency=concurrency,
        )

        # Merge fingerprints from this step's pages (if fingerprinter ran)
        fp_attr = getattr(result, "_fingerprints", {})
        if isinstance(fp_attr, dict):
            fingerprints.update(fp_attr)

        new = [f for f in result.findings if f not in all_findings]
        all_findings.extend(new)
        final_result = result

        print(
            f"[workflow] Step '{step.id}' done — "
            f"{len(new)} new finding(s), {len(all_findings)} total"
        )

    if final_result is None:
        from scanner.core.scan_result import ScanResult as SR
        final_result = SR(target=config.target, findings=[], pages_crawled=0)

    final_result.findings = all_findings
    return final_result
