"""Strip a UTF-8 BOM from the repository's text files.

Windows PowerShell 5.1 writes a BOM with `Set-Content -Encoding utf8`. Python
tolerates it in .py files, but pyproject.toml and ast.parse() reject it.

    python scripts/strip_bom.py
"""
import pathlib
import sys

BOM = b"\xef\xbb\xbf"
SUFFIXES = {".py", ".toml", ".yml", ".yaml", ".md", ".txt", ".cfg", ".ini", ".json"}
NAMES = {"LICENSE", ".gitattributes", ".gitignore"}
SKIP = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache",
        "node_modules", "build", "dist"}


def candidates(root: pathlib.Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        parts = path.relative_to(root).parts
        if set(parts) & SKIP or any(p.endswith(".egg-info") for p in parts):
            continue
        if path.suffix in SUFFIXES or path.name in NAMES:
            yield path


def main() -> int:
    root = pathlib.Path(".").resolve()
    fixed = []
    for path in candidates(root):
        data = path.read_bytes()
        if data.startswith(BOM):
            path.write_bytes(data[len(BOM):])
            fixed.append(path.relative_to(root).as_posix())
    for name in fixed:
        print("stripped BOM:", name)
    print(f"{len(fixed)} file(s) fixed")
    return 0


if __name__ == "__main__":
    sys.exit(main())