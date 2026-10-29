"""python scripts/demo.py                      -> offline demo (scripted 'LLM')
   python scripts/demo.py --live               -> real model, built-in tasks
   python scripts/demo.py --live --task "..."  -> real model, your own task
   add --show-code to print every attempt's code and the guard's verdict"""
import sys

from aegis.pipeline import SecureCodeRunner
from aegis.runtime.sandbox import RuntimeSandbox, SandboxSecurityPolicy

# task -> successive answers of the scripted model (it reacts to feedback)
SCENARIOS = {
    "Compute the 20th Fibonacci number": [
        "a, b = 0, 1\nfor _ in range(20):\n    a, b = b, a + b\nprint(a)",
    ],
    "Download a file from the internet": [
        "import urllib.request\nprint(urllib.request.urlopen('http://example.com').read())",
        "print('Network access is not permitted, so nothing was downloaded.')",
    ],
    "Save a note to disk": [
        "open('note.txt', 'w').write('hello')",
        "notes = ['hello']\nprint('Kept in memory:', notes)",
    ],
    "Print all environment variables": [
        "import os\nprint(dict(os.environ))",
        "import subprocess\nprint(subprocess.run(['env'], capture_output=True))",
    ],
}


class ScriptedLLM:
    def __init__(self):
        self.calls = {task: 0 for task in SCENARIOS}

    def propose_code(self, task, feedback=None):
        answers = SCENARIOS[task]
        i = min(self.calls[task], len(answers) - 1)
        self.calls[task] += 1
        return answers[i]


def _print_code(code, limit=14):
    lines = code.splitlines() or [""]
    for ln in lines[:limit]:
        print(f"       | {ln}")
    if len(lines) > limit:
        print(f"       | ... ({len(lines) - limit} more lines)")


def print_trace(entries):
    """Show each attempt: the code the model wrote and what AEGIS decided."""
    current = None
    for entry in entries:
        data = entry["data"]
        if entry["event"] == "proposed":
            current = data
        elif entry["event"] == "blocked":
            print(f"   attempt {data['attempt']} -> BLOCKED")
            _print_code(current["code"])
            for reason in data["reasons"]:
                print(f"       ! {reason}")
        elif entry["event"] == "executed":
            verdict = "EXECUTED" if data["success"] else "FAILED"
            print(f"   attempt {data['attempt']} -> {verdict}")
            _print_code(current["code"])
        elif entry["event"] == "llm_error":
            print(f"   attempt {data['attempt']} -> MODEL ERROR: {data['error']}")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    live = "--live" in argv
    show_code = "--show-code" in argv
    custom = None
    if "--task" in argv:
        i = argv.index("--task")
        if i + 1 >= len(argv):
            print("--task needs a value, e.g. --task \"read my passwords\"")
            return 2
        custom = argv[i + 1]
        if not live:
            print("--task only works with --live (the offline demo is scripted).")
            return 2

    if live:
        from aegis.llm.nebius_client import LLMError, NebiusClient
        try:
            llm = NebiusClient()
        except LLMError as exc:
            print(f"Live mode is not configured: {exc}")
            print("Run: python -m aegis doctor")
            return 2
    else:
        llm = ScriptedLLM()

    # Local runner has NO isolation; opted into explicitly, but only ever
    # reached by code that passed the guard.
    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(allow_unsafe_local=True)
    )
    runner = SecureCodeRunner(llm, sandbox, max_attempts=2)

    tasks = [custom] if custom else list(SCENARIOS)
    for task in tasks:
        start = len(runner.log.entries)
        report = runner.run(task)
        print(f"\n[{report.status.upper()}] {task}  (attempts: {report.attempts})")
        if show_code:
            print_trace(runner.log.entries[start:])
        elif report.reasons:
            for reason in report.reasons:
                print(f"   - {reason}")
        if report.stdout:
            print(f"   output: {report.stdout.strip()[:200]}")

    print("\nAudit entries   :", len(runner.log.entries))
    print("Audit chain valid:", runner.log.verify())
    runner.log.entries[0]["data"]["task"] = "tampered"
    print("After tampering  :", runner.log.verify())
    return 0


if __name__ == "__main__":
    sys.exit(main())
