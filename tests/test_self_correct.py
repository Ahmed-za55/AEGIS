import pytest

from aegis.llm.nebius_client import NebiusClient
from aegis.pipeline import SecureCodeRunner


class FeedbackLLM:
    def __init__(self, answers):
        self.answers, self.feedbacks = list(answers), []

    def propose_code(self, task, feedback=None):
        self.feedbacks.append(feedback)
        return self.answers[min(len(self.feedbacks) - 1, len(self.answers) - 1)]


class _Res:
    success, stdout, stderr, exit_code = True, "ok", "", 0


class _Sandbox:
    def __init__(self):
        self.calls = []

    def run(self, code):
        self.calls.append(code)
        return _Res()


def test_retry_succeeds_after_feedback():
    llm = FeedbackLLM(["import os", "print(1)"])
    sandbox = _Sandbox()
    runner = SecureCodeRunner(llm, sandbox, max_attempts=2)
    report = runner.run("t")
    assert report.status == "executed" and report.attempts == 2
    assert sandbox.calls == ["print(1)"]
    assert llm.feedbacks[0] is None and "os" in llm.feedbacks[1][0]
    events = [e["event"] for e in runner.log.entries]
    assert events == ["proposed", "blocked", "proposed", "executed"]
    assert runner.log.verify()


def test_persistent_attacker_stays_blocked():
    sandbox = _Sandbox()
    runner = SecureCodeRunner(FeedbackLLM(["import os", "import socket"]),
                              sandbox, max_attempts=2)
    report = runner.run("t")
    assert report.status == "blocked" and report.attempts == 2
    assert sandbox.calls == []


def test_default_is_single_attempt():
    runner = SecureCodeRunner(FeedbackLLM(["import os", "print(1)"]), _Sandbox())
    assert runner.run("t").status == "blocked"


def test_invalid_max_attempts():
    with pytest.raises(ValueError):
        SecureCodeRunner(FeedbackLLM(["x"]), _Sandbox(), max_attempts=0)


def test_client_includes_rejection_reasons_in_prompt():
    class Fake:
        def __init__(self):
            self.chat = self
            self.completions = self

        def create(self, **kw):
            self.messages = kw["messages"]

            class M:
                content = "```python\nprint(1)\n```"

            class C:
                message = M()

            class R:
                choices = [C()]

            return R()

    fake = Fake()
    code = NebiusClient(model="m", client=fake).propose_code(
        "task", feedback=["import of 'os' is not allowed"])
    assert code == "print(1)"
    assert "import of 'os' is not allowed" in fake.messages[1]["content"]
