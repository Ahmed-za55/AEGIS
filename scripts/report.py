"""python scripts/report.py -> docs/report.html (self-contained)"""
import importlib.util
import pathlib

from aegis.pipeline import SecureCodeRunner
from aegis.html_report import render_html
from aegis.runtime.sandbox import RuntimeSandbox, SandboxSecurityPolicy

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_demo():
    spec = importlib.util.spec_from_file_location(
        "aegis_demo", ROOT / "scripts" / "demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    demo = _load_demo()
    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(allow_unsafe_local=True))
    runner = SecureCodeRunner(demo.ScriptedLLM(), sandbox, max_attempts=2)
    reports = [runner.run(task) for task in demo.SCENARIOS]

    bench_file = ROOT / "docs" / "benchmark.md"
    benchmark = (bench_file.read_text(encoding="utf-8-sig")
                 if bench_file.exists() else None)

    out = ROOT / "docs" / "report.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(render_html(reports, runner.log, benchmark_md=benchmark),
                   encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
