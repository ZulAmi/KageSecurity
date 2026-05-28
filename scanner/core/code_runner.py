"""
Nuclei `code:` Template Executor — Gap 15

Executes inline Python or shell code blocks defined in Nuclei-style `code:`
template sections. The code block receives the target URL and HTTP response
as environment variables and can emit findings via stdout JSON.

Security model:
  - Shell commands run in a subprocess with a 30-second timeout
  - Python code runs in a subprocess (NOT eval/exec in-process) to prevent
    accidental breakouts from the scanner process
  - No network access restrictions — the code block is trusted (user-supplied)
  - Output must be valid JSON on stdout; anything else is ignored

Template `code:` block format (Nuclei-compatible):
  code:
    - engine:
        - python3
      source: |
        import sys, json
        # target variable is passed as env var TARGET
        print(json.dumps({"matched": True, "output": "found something"}))

  or:

    - engine:
        - bash
      source: |
        echo '{"matched": true, "output": "'"$TARGET"'"}'
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CodeBlock:
    engine: str          # "python3", "bash", "sh", "python"
    source: str          # the code to execute
    args: List[str] = field(default_factory=list)   # extra CLI args


@dataclass
class CodeResult:
    matched: bool = False
    output: str = ""
    error: str = ""
    elapsed: float = 0.0
    raw_stdout: str = ""


_ALLOWED_ENGINES = {"python3", "python", "bash", "sh", "node", "nodejs"}
_DEFAULT_TIMEOUT = 30  # seconds


def run_code_block(
    block: CodeBlock,
    target_url: str,
    response_body: str = "",
    response_status: int = 0,
    response_headers: Optional[Dict[str, str]] = None,
    timeout: int = _DEFAULT_TIMEOUT,
) -> CodeResult:
    """
    Execute a code block in a sandboxed subprocess.

    Environment variables available to the script:
      TARGET          — full target URL
      RESPONSE_BODY   — HTTP response body (may be truncated to 64KB)
      RESPONSE_STATUS — HTTP status code as string
      RESPONSE_HEADERS — JSON-encoded response headers dict
    """
    engine = block.engine.lower()
    if engine not in _ALLOWED_ENGINES:
        return CodeResult(error=f"Unsupported engine: {block.engine}")

    env = {
        **os.environ,
        "TARGET": target_url,
        "RESPONSE_BODY": response_body[:65536],
        "RESPONSE_STATUS": str(response_status),
        "RESPONSE_HEADERS": json.dumps(response_headers or {}),
    }

    # Write source to a temp file so we don't need shell=True with untrusted content
    suffix = ".py" if engine.startswith("python") else (".js" if "node" in engine else ".sh")
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as tmp:
            tmp.write(block.source)
            tmp_path = tmp.name
    except Exception as e:
        return CodeResult(error=f"Failed to write temp file: {e}")

    try:
        cmd = [engine, tmp_path] + block.args
        start = time.time()
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        elapsed = time.time() - start
        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()

        return _parse_output(stdout, stderr, elapsed)
    except subprocess.TimeoutExpired:
        return CodeResult(error=f"Code block timed out after {timeout}s")
    except FileNotFoundError:
        return CodeResult(error=f"Engine '{engine}' not found in PATH")
    except Exception as e:
        return CodeResult(error=str(e))
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _parse_output(stdout: str, stderr: str, elapsed: float) -> CodeResult:
    """Parse subprocess output — expects JSON on stdout."""
    result = CodeResult(raw_stdout=stdout, elapsed=elapsed)
    if stderr:
        result.error = stderr[:500]

    if not stdout:
        return result

    # Try to extract JSON from stdout (may have debug output mixed in)
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                data = json.loads(line)
                result.matched = bool(data.get("matched", False))
                result.output = str(data.get("output", ""))
                return result
            except json.JSONDecodeError:
                continue

    # No JSON found — treat non-empty stdout as a match signal
    result.matched = bool(stdout)
    result.output = stdout[:500]
    return result


def parse_code_blocks(template_data: dict) -> List[CodeBlock]:
    """Parse `code:` section from a Nuclei template dict."""
    blocks = []
    code_section = template_data.get("code", [])
    if not isinstance(code_section, list):
        return blocks

    for entry in code_section:
        if not isinstance(entry, dict):
            continue
        engines = entry.get("engine", [])
        if isinstance(engines, str):
            engines = [engines]
        source = entry.get("source", "")
        args = entry.get("args", [])
        if not engines or not source:
            continue
        # Use the first available engine
        for eng in engines:
            if eng.lower() in _ALLOWED_ENGINES:
                blocks.append(CodeBlock(engine=eng, source=source, args=args))
                break

    return blocks
