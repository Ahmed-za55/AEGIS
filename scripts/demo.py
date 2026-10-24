"""python scripts/demo.py          -> offline demo (scripted 'LLM')
   python scripts/demo.py --live   -> real model via Nebius (needs env vars)"""
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
    runner = SecureCodeRunner(llm, sandbox, max_attempts=2)

    for task in SCENARIOS:
        report = runner.run(task)
        print(f"\n[{report.status.upper()}] {task}  (attempts: {report.attempts})")
        for reason in report.reasons:
            print(f"   - {reason}")
        if report.stdout:
            print(f"   output: {report.stdout.strip()[:200]}")

    print("\nAudit entries   :", len(runner.log.entries))
    print("Audit chain valid:", runner.log.verify())
    runner.log.entries[0]["data"]["task"] = "tampered"
    print("After tampering  :", runner.log.verify())


if __name__ == "__main__":
    main()
