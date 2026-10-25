"""python -m aegis <command>

  demo          run the scripted end-to-end demo (add --live for a real model)
  bench         run the red-team benchmark
  report        write docs/report.html
  verify-demo   show a lying isolation backend being caught
  audit-demo    show audit tampering being detected
  mcp           start the MCP server (--docker or --unsafe-local)
"""
import pathlib
import runpy
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = {
    "demo": ("demo.py", []),
    "bench": ("benchmark.py", []),
    "report": ("report.py", []),
    "verify-demo": ("verify_demo.py", []),
    "audit-demo": ("audit_tool.py", ["demo"]),
}


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    command, rest = argv[0], argv[1:]
    if command == "mcp":
        from aegis.mcp_server import main as mcp_main
        return mcp_main(rest)
    if command not in SCRIPTS:
        print(f"Unknown command: {command}\n{__doc__}", file=sys.stderr)
        return 2
    script, fixed = SCRIPTS[command]
    old_argv = sys.argv
    sys.argv = [script] + fixed + rest
    try:
        runpy.run_path(str(ROOT / "scripts" / script), run_name="__main__")
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0
    finally:
        sys.argv = old_argv
    return 0


if __name__ == "__main__":
    sys.exit(main())
