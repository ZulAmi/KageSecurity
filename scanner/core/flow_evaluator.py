"""
Nuclei-compatible `flow:` template evaluator.

Nuclei uses a full JavaScript engine (goja) for flow:. KageSec implements the
practical subset that covers ~90% of real community templates:

Supported constructs
--------------------
  template.execute("request-id")          run a specific named request block
  template.execute("req-id", {key: val})  run with extra variable overrides
  iterate(list, fn)                       loop — iterate(results, r => ...)
  stop()                                  halt execution of remaining flow
  log(msg)                                debug print (goes to stderr)
  results                                 list of responses from executed requests
  out                                     shorthand for last result
  Variables set by extractors are available by name

Flow: is evaluated ONCE after all static requests in a template have run.
It can trigger additional requests by calling template.execute().

YAML usage
----------
requests:
  - id: check-version
    method: GET
    path: ["{{BaseURL}}/version"]
    extractors:
      - name: ver
        type: regex
        regex: ["version: ([0-9.]+)"]

flow: |
  if (out.status == 200) {
    template.execute("check-vuln");
  }

  - id: check-vuln
    method: GET
    path: ["{{BaseURL}}/exploit"]
    matchers: [...]
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scanner.core.template_runner import Template, TemplateRequest

# ---------------------------------------------------------------------------
# Mini JS-like expression evaluator
# ---------------------------------------------------------------------------

class FlowContext:
    """Execution context passed into the flow: script."""

    def __init__(self, template: "Template", variables: dict, client):
        self._template = template
        self._variables = variables
        self._client = client
        self._stopped = False
        self.results: list[dict] = []
        self.out: dict = {}

    def execute(self, request_id: str, overrides: dict | None = None) -> dict:
        """Execute a named request block; returns {status, body, headers}."""
        if self._stopped:
            return {}
        req = self._find_request(request_id)
        if req is None:
            return {}

        from scanner.core.template_runner import _execute_request, _substitute, _run_extractors
        vars_copy = {**self._variables, **(overrides or {})}

        for path_tpl in req.paths:
            url = _substitute(path_tpl, vars_copy)
            resp = _execute_request(req, url, vars_copy, self._client)
            if resp is None:
                continue
            status, body, headers = resp

            # Run extractors and merge into variables
            if req.extractors:
                extracted = _run_extractors(req.extractors, status, body, headers)
                self._variables.update(extracted)
                vars_copy.update(extracted)

            result = {"status": status, "body": body, "headers": headers, "url": url}
            self.results.append(result)
            self.out = result
            return result
        return {}

    def stop(self):
        self._stopped = True

    def log(self, msg: str):
        import sys
        print(f"[flow] {msg}", file=sys.stderr)

    def _find_request(self, request_id: str) -> "TemplateRequest | None":
        for req in self._template.requests:
            # Nuclei uses `id:` field on requests; we store it as req.id if present
            if getattr(req, "id", None) == request_id:
                return req
        return None


# ---------------------------------------------------------------------------
# Flow runner
# ---------------------------------------------------------------------------

def run_flow(
    flow_script: str,
    template: "Template",
    variables: dict,
    client,
) -> list[dict]:
    """
    Execute a flow: script and return list of result dicts from template.execute() calls.
    Each result dict: {status, body, headers, url}
    """
    ctx = FlowContext(template, variables, client)

    # Build a restricted globals dict — expose only safe names
    safe_globals: dict[str, Any] = {
        "__builtins__": {},
        "template": ctx,
        "results": _JSArray(ctx.results),
        "out": ctx.out,
        "stop": ctx.stop,
        "log": ctx.log,
        "iterate": _iterate,
        # Python built-ins
        "True": True, "False": False, "None": None,
        "len": len, "str": str, "int": int, "float": float,
        "list": list, "dict": dict, "range": range,
        "print": ctx.log,
        # JS helpers
        "_js_typeof": _js_typeof,
        "_js_parseInt": _js_parseInt,
        "_js_parseFloat": _js_parseFloat,
        "_js_regex_test": _js_regex_test,
        "_js_regex_match": _js_regex_match,
        "_JSRegex": _JSRegex,
        "_JSArray": _JSArray,
        "_JSString": _JSString,
        # JS array stand-ins
        "Array": _JSArray,
        "RegExp": _JSRegex,
        "parseInt": _js_parseInt,
        "parseFloat": _js_parseFloat,
        "typeof": _js_typeof,
    }

    # Expose extractor variables directly ({{varname}} → varname)
    for k, v in variables.items():
        clean_k = k[2:-2] if k.startswith("{{") and k.endswith("}}") else k
        if isinstance(v, str):
            safe_globals[clean_k] = _JSString(v)
        elif isinstance(v, list):
            safe_globals[clean_k] = _JSArray(v)
        else:
            safe_globals[clean_k] = v

    # Translate JS-isms to Python before eval
    py_script = _js_to_python(flow_script)

    try:
        exec(py_script, safe_globals)  # noqa: S102
    except _StopFlow:
        pass
    except Exception:
        pass

    return ctx.results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _StopFlow(Exception):
    pass


def _iterate(iterable, fn):
    for item in iterable:
        fn(item)


# ---------------------------------------------------------------------------
# JS built-ins exposed to the flow sandbox
# ---------------------------------------------------------------------------

def _js_includes(lst, item):
    return item in lst

def _js_filter(lst, fn):
    return [x for x in lst if fn(x)]

def _js_map(lst, fn):
    return [fn(x) for x in lst]

def _js_some(lst, fn):
    return any(fn(x) for x in lst)

def _js_every(lst, fn):
    return all(fn(x) for x in lst)

def _js_find(lst, fn):
    for x in lst:
        if fn(x):
            return x
    return None

def _js_index_of(lst, item):
    try:
        return lst.index(item)
    except ValueError:
        return -1

def _js_push(lst, item):
    lst.append(item)
    return len(lst)

def _js_pop(lst):
    return lst.pop() if lst else None


class _JSArray(list):
    """List subclass that exposes JS array methods as attributes."""
    def forEach(self, fn):
        for x in self:
            fn(x)
    def filter(self, fn):
        return _JSArray(_js_filter(self, fn))
    def map(self, fn):
        return _JSArray(_js_map(self, fn))
    def some(self, fn):
        return _js_some(self, fn)
    def every(self, fn):
        return _js_every(self, fn)
    def find(self, fn):
        return _js_find(self, fn)
    def includes(self, item):
        return item in self
    def indexOf(self, item):
        return _js_index_of(self, item)
    def push(self, item):
        return _js_push(self, item)
    def pop(self):
        return _JSArray.pop(self)
    def join(self, sep=""):
        return sep.join(str(x) for x in self)
    def reverse(self):
        super().reverse()
        return self
    def slice(self, start=0, end=None):
        return _JSArray(self[start:end])


class _JSString(str):
    """str subclass that exposes common JS string methods as attributes."""
    def includes(self, sub):
        return sub in self
    def startsWith(self, prefix):
        return self.startswith(prefix)
    def endsWith(self, suffix):
        return self.endswith(suffix)
    def toLowerCase(self):
        return _JSString(self.lower())
    def toUpperCase(self):
        return _JSString(self.upper())
    def trim(self):
        return _JSString(self.strip())
    def trimStart(self):
        return _JSString(self.lstrip())
    def trimEnd(self):
        return _JSString(self.rstrip())
    def split(self, sep=None, maxsplit=-1):
        return _JSArray(str.split(self, sep, maxsplit))
    def replace(self, old, new, count=-1):
        return _JSString(str.replace(self, old, new, count))
    def indexOf(self, sub):
        return str.find(self, sub)
    def charAt(self, idx):
        try:
            return self[idx]
        except IndexError:
            return ""
    def charCodeAt(self, idx):
        try:
            return ord(self[idx])
        except IndexError:
            return 0
    @property
    def length(self):
        return len(self)


def _js_regex_test(pattern: str, value: str, flags: str = "") -> bool:
    """Implements /regex/flags.test(value) semantics."""
    re_flags = 0
    if "i" in flags:
        re_flags |= re.IGNORECASE
    if "m" in flags:
        re_flags |= re.MULTILINE
    return bool(re.search(pattern, str(value), re_flags))


def _js_regex_match(pattern: str, value: str, flags: str = "") -> list:
    re_flags = 0
    if "i" in flags:
        re_flags |= re.IGNORECASE
    m = re.search(pattern, str(value), re_flags)
    if not m:
        return []
    return list(m.groups()) or [m.group(0)]


class _JSRegex:
    """Minimal regex object: new RegExp('pat','flags') or compiled from literal."""
    def __init__(self, pattern: str, flags: str = ""):
        self._pat = pattern
        self._flags = flags
    def test(self, value: str) -> bool:
        return _js_regex_test(self._pat, value, self._flags)
    def exec(self, value: str):
        return _js_regex_match(self._pat, value, self._flags) or None


def _js_typeof(val) -> str:
    if val is None:
        return "undefined"
    if isinstance(val, bool):
        return "boolean"
    if isinstance(val, int):
        return "number"
    if isinstance(val, float):
        return "number"
    if isinstance(val, str):
        return "string"
    if isinstance(val, (list, _JSArray)):
        return "object"
    if isinstance(val, dict):
        return "object"
    return "object"


def _js_parseInt(val, base=10):
    try:
        return int(str(val), base)
    except (ValueError, TypeError):
        return 0


def _js_parseFloat(val):
    try:
        return float(str(val))
    except (ValueError, TypeError):
        return 0.0


# ---------------------------------------------------------------------------
# JS→Python transpiler (improved)
# ---------------------------------------------------------------------------

# Ordered substitution rules — applied in sequence
_TRANSLATIONS: list[tuple] = [
    # 1. Single-line comments
    (re.compile(r'//([^\n]*)'), r'#\1'),

    # 2. Strict equality / inequality
    (re.compile(r'==='), '=='),
    (re.compile(r'!=='), '!='),

    # 3. Logical operators
    (re.compile(r'\&\&'), ' and '),
    (re.compile(r'\|\|'), ' or '),
    (re.compile(r'\bnull\b'), 'None'),
    (re.compile(r'\bundefined\b'), 'None'),
    (re.compile(r'\btrue\b'), 'True'),
    (re.compile(r'\bfalse\b'), 'False'),

    # 4. var/let/const declarations → plain assignment
    (re.compile(r'\b(?:var|let|const)\s+'), ''),

    # 5. Template literals: `hello ${expr}` → f"hello {expr}"
    (re.compile(r'`([^`]*)`'), lambda m: 'f"' + re.sub(r'\$\{([^}]+)\}', r'{\1}', m.group(1)) + '"'),

    # 6. Ternary: condition ? a : b  → (a if condition else b)
    #    Only single-level; nested ternaries are rare in Nuclei flows
    (re.compile(r'([^?:\n]+)\?([^?:\n]+):([^?:\n]+)'),
     lambda m: f'({m.group(2).strip()} if {m.group(1).strip()} else {m.group(3).strip()})'),

    # 7. typeof expr → _js_typeof(expr)
    (re.compile(r'\btypeof\s+(\w+)'), r'_js_typeof(\1)'),

    # 8. for (let x of arr) {  →  for x in arr:
    (re.compile(r'\bfor\s*\(\s*(?:var|let|const)?\s*(\w+)\s+of\s+(\w+)\s*\)\s*\{'), r'for \1 in \2:'),

    # 9. for (let i=0; i<N; i++) {  →  for i in range(0, N):  (simplified)
    (re.compile(r'\bfor\s*\(\s*(?:var|let|const)?\s*(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\w+)(?:\["\w+"\])?\s*;\s*\1\+\+\s*\)\s*\{'),
     r'for \1 in range(0, \2):'),

    # 10. while (...) {  →  while ...:
    (re.compile(r'\bwhile\s*\((.+?)\)\s*\{', re.DOTALL), r'while \1:'),

    # 11. if (...) {  →  if ...:
    (re.compile(r'\bif\s*\((.+?)\)\s*\{', re.DOTALL), r'if \1:'),

    # 12. } else if (...) {
    (re.compile(r'\}\s*else\s+if\s*\((.+?)\)\s*\{'), r'elif \1:'),

    # 13. } else {
    (re.compile(r'\}\s*else\s*\{'), 'else:'),

    # 14. Closing braces alone → blank (Python uses indentation)
    (re.compile(r'^\s*\}\s*$', re.MULTILINE), ''),

    # 15. Simple single-param arrow function: r => expr  →  lambda r: expr
    (re.compile(r'\b(\w+)\s*=>\s*'), r'lambda \1: '),

    # 16. Multi-param arrow: (a, b) => expr  →  lambda a, b: expr
    (re.compile(r'\((\w+(?:\s*,\s*\w+)*)\)\s*=>\s*'), r'lambda \1: '),

    # 17. .length  →  ["length_"]  workaround — handled by _JSString/Array
    #     We map this to a safe call on JS wrapper objects — skip direct translation

    # 18. parseInt/parseFloat
    (re.compile(r'\bparseInt\b'), '_js_parseInt'),
    (re.compile(r'\bparseFloat\b'), '_js_parseFloat'),

    # 19. Math.floor/ceil/abs/max/min/random
    (re.compile(r'\bMath\.floor\b'), 'int'),
    (re.compile(r'\bMath\.ceil\b'), '__import__("math").ceil'),
    (re.compile(r'\bMath\.abs\b'), 'abs'),
    (re.compile(r'\bMath\.max\b'), 'max'),
    (re.compile(r'\bMath\.min\b'), 'min'),
    (re.compile(r'\bMath\.random\b'), '__import__("random").random'),

    # 20. Object.keys / Object.values
    (re.compile(r'\bObject\.keys\s*\((\w+)\)'), r'list(\1.keys())'),
    (re.compile(r'\bObject\.values\s*\((\w+)\)'), r'list(\1.values())'),

    # 21. JSON.parse / JSON.stringify
    (re.compile(r'\bJSON\.parse\s*\('), '__import__("json").loads('),
    (re.compile(r'\bJSON\.stringify\s*\('), '__import__("json").dumps('),

    # 22. console.log → log (mapped to ctx.log in sandbox)
    (re.compile(r'\bconsole\.log\b'), 'log'),

    # 23. return statement — already valid Python

    # 24. Object property access on results: res.status, res.body, res.headers → dict access
    #     Only translate .status / .body / .headers / .url on known result vars,
    #     NOT on template/ctx/log/stop (those are real Python objects).
    #     We use a conservative regex that won't break method calls.
]

_SAFE_ATTRS = {"status", "body", "headers", "url", "text", "content"}
_NO_TRANSLATE = {"template", "ctx", "log", "stop", "iterate", "results",
                 "len", "str", "int", "float", "list", "dict", "range",
                 "_js_parseInt", "_js_parseFloat", "_js_typeof",
                 "True", "False", "None"}


def _translate_dot_access(script: str) -> str:
    """
    Translate `var.attr` → `var["attr"]` for known response attributes,
    but leave method calls (.execute, .filter, .forEach, etc.) untouched.
    """
    def _repl(m: re.Match) -> str:
        obj, attr = m.group(1), m.group(2)
        if obj in _NO_TRANSLATE:
            return m.group(0)
        if attr in _SAFE_ATTRS:
            return f'{obj}["{attr}"]'
        return m.group(0)

    return re.sub(r'\b(\w+)\.(\w+)\b(?!\s*\()', _repl, script)


def _handle_regex_literals(script: str) -> str:
    """
    Convert JS regex literal /pattern/flags to _JSRegex('pattern', 'flags').
    Handles .test() and .match() chained calls.
    """
    # /pattern/flags.test(value)  →  _js_regex_test('pattern', value, 'flags')
    script = re.sub(
        r'/([^/\n]+)/([gimsuy]*)\s*\.test\s*\(([^)]+)\)',
        lambda m: f"_js_regex_test({m.group(1)!r}, {m.group(3)}, {m.group(2)!r})",
        script,
    )
    # /pattern/flags.exec(value)  →  _js_regex_match('pattern', value, 'flags')
    script = re.sub(
        r'/([^/\n]+)/([gimsuy]*)\s*\.exec\s*\(([^)]+)\)',
        lambda m: f"_js_regex_match({m.group(1)!r}, {m.group(3)}, {m.group(2)!r})",
        script,
    )
    return script


def _js_to_python(script: str) -> str:
    """Transpile a Nuclei flow: JS snippet to executable Python."""
    script = _handle_regex_literals(script)
    for pattern, repl in _TRANSLATIONS:
        if callable(repl):
            script = pattern.sub(repl, script)
        else:
            script = pattern.sub(repl, script)
    script = _translate_dot_access(script)
    return script
