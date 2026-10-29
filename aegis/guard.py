"""Static policy gate for LLM-generated Python code.

This is a policy layer, NOT an isolation boundary. Real isolation comes from
an IsolationBackend (e.g. Docker); the guard decides what may reach it.
"""
import ast
import re
import string
from dataclasses import dataclass, field

ALLOWED_IMPORTS = frozenset({
    "math", "random", "json", "re", "statistics", "itertools",
    "collections", "datetime", "string", "decimal", "fractions",
    "functools", "heapq", "bisect", "typing", "dataclasses", "textwrap",
})
ALLOWED_MODULES = ALLOWED_IMPORTS | {"collections.abc"}

# Builtins that must not be used at all (calling OR merely referencing them:
# `f = open; f(...)` is the same capability).
BLOCKED_NAMES = frozenset({
    "open", "eval", "exec", "compile", "__import__", "__builtins__", "input",
    "breakpoint", "getattr", "setattr", "delattr", "globals", "locals", "vars",
    "help", "license", "copyright", "credits", "exit", "quit",
})

# Attributes that give access to other modules or to I/O even when reached
# through an allowed module (e.g. json.codecs.open, typing.sys.modules).
FORBIDDEN_ATTRS = frozenset({
    "sys", "os", "io", "codecs", "subprocess", "builtins", "importlib",
    "shutil", "socket", "pathlib", "ctypes", "enum", "modules", "system",
    "popen", "environ", "getenv", "open", "format_map", "vformat",
    "get_field", "get_value", "Formatter",
    # hidden eval: typing evaluates string annotations
    "get_type_hints", "ForwardRef", "singledispatch", "singledispatchmethod",
    # frame/code introspection (gen.gi_frame.f_builtins["open"] reaches builtins)
    "gi_frame", "cr_frame", "ag_frame", "gi_code", "cr_code", "ag_code",
    "f_globals", "f_builtins", "f_locals", "f_back", "f_code", "f_trace",
    "tb_frame", "tb_next", "with_traceback", "func_code",
})

_FORMAT_DUNDER = re.compile(r"\{[^{}]*__")


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)


def _private_or_forbidden(name: str) -> bool:
    return name.startswith("_") or name in FORBIDDEN_ATTRS


def _safe_format_receiver(node: ast.expr) -> bool:
    """str.format is only allowed on a literal whose fields are plain."""
    if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
        return False
    try:
        fields = [f for _, f, _, _ in string.Formatter().parse(node.value)
                  if f is not None]
    except ValueError:
        return False
    return not any("." in f or "[" in f for f in fields)


def check_code(code: str) -> Verdict:
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return Verdict(False, (f"syntax error: {exc.msg}",))

    reasons: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in ALLOWED_MODULES:
                    reasons.append(f"import of '{alias.name}' is not allowed")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or "."
            if node.level or module not in ALLOWED_MODULES:
                reasons.append(f"import from '{module}' is not allowed")
            else:
                for alias in node.names:
                    if _private_or_forbidden(alias.name):
                        reasons.append(f"import of '{alias.name}' is not allowed")
        elif isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load) and node.id in BLOCKED_NAMES:
                reasons.append(f"use of '{node.id}' is not allowed")
        elif isinstance(node, ast.Attribute):
            if _private_or_forbidden(node.attr):
                reasons.append(f"access to '{node.attr}' is not allowed")
            elif node.attr == "format" and not _safe_format_receiver(node.value):
                reasons.append("str.format is only allowed on a literal "
                               "with plain fields")
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and _FORMAT_DUNDER.search(node.value)):
            reasons.append("format-string access to dunder attributes "
                           "is not allowed")

    unique = tuple(dict.fromkeys(reasons))
    return Verdict(not unique, unique)
