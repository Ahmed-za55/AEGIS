"""Static policy gate for LLM-generated Python code.

This is a policy layer, NOT an isolation boundary. Real isolation comes from
an IsolationBackend (e.g. Docker); the guard decides what may reach it.
"""
import ast
import re
from dataclasses import dataclass, field

ALLOWED_IMPORTS = frozenset({
    "math", "random", "json", "re", "statistics", "itertools",
    "collections", "datetime", "string", "decimal", "fractions",
    "functools", "heapq", "bisect", "typing", "dataclasses", "textwrap",
})
BLOCKED_CALLS = frozenset({
    "open", "eval", "exec", "compile", "__import__", "input", "breakpoint",
    "getattr", "setattr", "delattr", "globals", "locals", "vars",
})

_FORMAT_DUNDER = re.compile(r"\{[^{}]*__")


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)


def check_code(code: str) -> Verdict:
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return Verdict(False, (f"syntax error: {exc.msg}",))

    reasons: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root not in ALLOWED_IMPORTS:
                    reasons.append(f"import of '{root}' is not allowed")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if node.level or root not in ALLOWED_IMPORTS:
                reasons.append(f"import from '{node.module or '.'}' is not allowed")
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in BLOCKED_CALLS:
                reasons.append(f"call to '{func.id}()' is not allowed")
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("__"):
                reasons.append(f"access to '{node.attr}' is not allowed")
        elif isinstance(node, ast.Name):
            if node.id in {"__builtins__", "__import__"}:
                reasons.append(f"use of '{node.id}' is not allowed")
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and _FORMAT_DUNDER.search(node.value)):
            reasons.append("format-string access to dunder attributes is not allowed")

    unique = tuple(dict.fromkeys(reasons))
    return Verdict(not unique, unique)
