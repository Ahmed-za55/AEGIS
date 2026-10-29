import importlib.util
import pathlib

from aegis.doctor import pick_model, run_doctor
from aegis.llm.nebius_client import LLMError
from aegis.pipeline import SecureCodeRunner

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_demo():
    spec = importlib.util.spec_from_file_location("demo_mod", ROOT / "scripts" / "demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Sandbox:
    def run(self, code):
        raise AssertionError("must not run")


class _DownLLM:
    def propose_code(self, task, feedback=None):
        raise LLMError("429 rate limited")


def test_runner_survives_llm_failure_and_logs_it():
    runner = SecureCodeRunner(_DownLLM(), _Sandbox())
    report = runner.run("t")
    assert report.status == "error" and "429" in report.reasons[0]
    assert [e["event"] for e in runner.log.entries] == ["llm_error"]
    assert runner.log.verify()


def test_runner_error_message_is_redacted(monkeypatch):
    monkeypatch.setenv("MY_API_KEY", "key-value-1234567890")

    class L:
        def propose_code(self, task, feedback=None):
            raise RuntimeError("bad key-value-1234567890")

    report = SecureCodeRunner(L(), _Sandbox()).run("t")
    assert "key-value-1234567890" not in report.reasons[0]


def test_pick_model_prefers_known_names_then_any_nemotron():
    assert pick_model(["a", "nvidia/nemotron-3-super-120b-a12b", "b"]) == \
        "nvidia/nemotron-3-super-120b-a12b"
    assert pick_model(["x/Nemotron-Custom", "y"]) == "x/Nemotron-Custom"
    assert pick_model(["llama", "gpt"]) is None


class _Model:
    def __init__(self, id):
        self.id = id


class _FakeOpenAI:
    def __init__(self, **kwargs):
        self.models = self

    def list(self):
        return [_Model("nvidia/llama-3.3-nemotron-super-49b-v1.5"), _Model("other")]


class _FakeClient:
    def __init__(self, model, api_key, base_url):
        self.model = model

    def propose_code(self, task):
        return "print(sum(range(1, 11)))"


def test_doctor_success_autoselects_model_and_never_prints_the_key():
    lines = []
    code = run_doctor({"NVIDIA_API_KEY": "nvapi-SECRET123"}, _FakeOpenAI, _FakeClient,
                      out=lines.append)
    text = "\n".join(lines)
    assert code == 0 and "READY" in text and "auto-selected" in text
    assert "nvapi-SECRET123" not in text


def test_doctor_without_key_returns_2():
    lines = []
    assert run_doctor({}, _FakeOpenAI, _FakeClient, out=lines.append) == 2
    assert any("MISSING" in ln for ln in lines)


def test_doctor_reports_llm_failure():
    class Broken(_FakeClient):
        def propose_code(self, task):
            raise LLMError("boom")

    lines = []
    assert run_doctor({"NVIDIA_API_KEY": "k"}, _FakeOpenAI, Broken, out=lines.append) == 1
    assert any("FAILED" in ln for ln in lines)


def test_demo_task_flag_validation(capsys):
    demo = _load_demo()
    assert demo.main(["--task", "x"]) == 2
    assert demo.main(["--live", "--task"]) == 2
    assert "needs" in capsys.readouterr().out


def test_demo_offline_runs_cleanly(capsys):
    assert _load_demo().main([]) == 0
    out = capsys.readouterr().out
    assert "[EXECUTED]" in out and "[BLOCKED]" in out and "Audit chain valid: True" in out
