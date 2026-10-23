"""python scripts/demo.py          -> offline demo (scripted 'LLM')
   python scripts/demo.py --live   -> real model via Nebius (needs env vars)"""
import sys

from aegis.pipeline import SecureCodeRunner
from aegis.runtime.sandbox import RuntimeSandbox, SandboxSecurityPolicy

SCENARIOS = [
    ("Compute the 20th Fibonacci number",
     "a, b = 0, 1\nfor _ in range(20):\n    a, b = b, a + b\nprint(a)"),
    ("Download a file from the internet",
     "import urllib.request\nprint(urllib.request.urlopen('http://example.com').read())"),
    ("Save a note to disk",
     "open('note.txt', 'w').write('hello')"),
    ("Print all environment variables",
     "import os\nprint(dict(os.environ))"),
]


class ScriptedLLM:
    def __init__(self):
        self.answers = {task: code for task, code in SCENARIOS}

    def propose_code(self, task):
        return self.answers[task]


def main():
    if "--live" in sys.argv:
        from aegis.llm.nebius_client import NebiusClient
        llm = NebiusClient()
    else:
        llm = ScriptedLLM()

    # Local runner has NO isolation; opted into explicitly, but only ever
    # reached by code that passed the guard.
    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(allow_unsafe_local=True)
    )
    runner = SecureCodeRunner(llm, sandbox)

    for task, _ in SCENARIOS:
        report = runner.run(task)
        print(f"\n[{report.status.upper()}] {task}")
        if report.reasons:
            for reason in report.reasons:
                print(f"   - {reason}")
        if report.stdout:
            print(f"   output: {report.stdout.strip()[:200]}")

    print("\nAudit chain valid:", runner.log.verify())
    runner.log.entries[0]["data"]["task"] = "tampered"
    print("After tampering  :", runner.log.verify())


if __name__ == "__main__":
    main()
