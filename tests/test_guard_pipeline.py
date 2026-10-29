import pytest

from aegis.guard import check_code
from aegis.pipeline import HashChainLog, SecureCodeRunner


@pytest.mark.parametrize("code", [
    "import math\nprint(math.sqrt(16))",
    "from collections import Counter\nprint(Counter('aab'))",
    "print(sum(range(10)))",
    "if __name__ == '__main__':\n    print('{}'.format(1))",
])
def test_guard_allows_safe_code(code):
    assert check_code(code).allowed


@pytest.mark.parametrize("code", [
    "import socket",
    "import os\nos.system('dir')",
    "import subprocess",
    "from os import environ",
    "open('x.txt','w').write('a')",
    "eval('1+1')",
    "__import__('os')",
    "().__class__.__bases__",
    "getattr(__builtins__, 'open')",
    "import urllib.request",
    "print('{0.__class__}'.format(1))",
    "def broken(:",
])
def test_guard_blocks_dangerous_code(code):
    verdict = check_code(code)
    assert not verdict.allowed and verdict.reasons


class FakeLLM:
    def __init__(self, code):
        self.code = code

    def propose_code(self, task):
        return self.code


class FakeResult:
    def __init__(self, success=True, stdout="ok", stderr="", exit_code=0):
        self.success, self.stdout = success, stdout
        self.stderr, self.exit_code = stderr, exit_code


class FakeSandbox:
    def __init__(self, result=None):
        self.calls = []
        self.result = result or FakeResult()

    def run(self, code):
        self.calls.append(code)
        return self.result


def test_blocked_code_never_reaches_sandbox():
    sandbox = FakeSandbox()
    runner = SecureCodeRunner(FakeLLM("import socket"), sandbox)
    report = runner.run("t")
    assert report.status == "blocked" and sandbox.calls == []


def test_safe_code_is_executed():
    sandbox = FakeSandbox()
    report = SecureCodeRunner(FakeLLM("print(1)"), sandbox).run("t")
    assert report.status == "executed" and report.stdout == "ok"
    assert sandbox.calls == ["print(1)"]


def test_failed_execution_is_reported():
    sandbox = FakeSandbox(FakeResult(False, "", "boom", 1))
    report = SecureCodeRunner(FakeLLM("print(1)"), sandbox).run("t")
    assert report.status == "failed" and report.stderr == "boom"


def test_log_chain_verifies_and_detects_tampering():
    runner = SecureCodeRunner(FakeLLM("print(1)"), FakeSandbox())
    runner.run("t")
    assert len(runner.log.entries) == 2 and runner.log.verify()
    runner.log.entries[0]["data"]["task"] = "tampered"
    assert not runner.log.verify()


def test_log_detects_removed_entry():
    log = HashChainLog()
    for i in range(3):
        log.append("e", {"i": i})
    del log.entries[1]
    assert not log.verify()
