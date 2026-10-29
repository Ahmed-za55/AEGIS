"""Remove test functions that are shadowed by a later definition.

Python keeps only the LAST definition of a name at module level, so pytest
never ran the earlier copies: they are dead code. Only functions whose name
starts with "test_" are touched.

    python scripts/dedupe_tests.py            # dry run: prints what would go
    python scripts/dedupe_tests.py --write    # rewrites the files
"""
import ast
import pathlib
import re
import sys


def shadowed_ranges(source: str):
    tree = ast.parse(source)
    last = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            last[node.name] = node
    ranges = []
    for node in tree.body:
        if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name.startswith("test_") and last[node.name] is not node):
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            ranges.append((start, node.end_lineno, node.name))
    return ranges


def dedupe(source: str):
    ranges = shadowed_ranges(source)
    lines = source.split("\n")
    drop = set()
    for start, end, _ in ranges:
        drop.update(range(start - 1, end))
    kept = [ln for i, ln in enumerate(lines) if i not in drop]
    text = re.sub(r"\n{4,}", "\n\n\n", "\n".join(kept))
    return text, [name for _, _, name in ranges]


def main(argv) -> int:
    write = "--write" in argv
    total = 0
    for path in sorted(pathlib.Path("tests").glob("test_*.py")):
        source = path.read_text(encoding="utf-8")
        text, removed = dedupe(source)
        if removed:
            total += len(removed)
            print(f"{path}: {len(removed)} shadowed test(s)")
            if write:
                ast.parse(text)                      # never write broken Python
                path.write_text(text, encoding="utf-8")
    print(f"total shadowed definitions: {total}" + ("" if write else "  (dry run)"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
