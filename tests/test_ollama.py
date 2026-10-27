import pytest

from aegis.doctor import run_doctor
from aegis.llm.nebius_client import (
    OLLAMA_BASE_URL,
    LLMError,
    NebiusClient,
    resolve_settings,
)

_VARS = ("LLM_PROVIDER", "LLM_MODEL", "LLM_BASE_URL", "LLM_API_KEY", "LLM_TIMEOUT",
         "NVIDIA_API_KEY", "NVIDIA_MODEL", "NEBIUS_API_KEY", "NEBIUS_MODEL",
         "OLLAMA_MODEL", "OLLAMA_BASE_URL", "OLLAMA_API_KEY")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in _VARS:
        monkeypatch.delenv(name, raising=False)


def test_ollama_needs_no_key_and_defaults_to_nemotron_mini():
    provider, url, key, model = resolve_settings({"LLM_PROVIDER": "ollama"})
    assert (provider, url, model) == ("ollama", OLLAMA_BASE_URL, "nemotron-mini")
    assert key == "ollama"


def test_ollama_model_can_be_overridden():
    env = {"LLM_PROVIDER": "ollama", "OLLAMA_MODEL": "qwen2.5-coder:1.5b"}
    assert resolve_settings(env)[3] == "qwen2.5-coder:1.5b"


def test_custom_provider_requires_base_url():
    with pytest.raises(LLMError):
        resolve_settings({"LLM_PROVIDER": "custom"})
    _, url, key, model = resolve_settings(
        {"LLM_PROVIDER": "custom", "LLM_BASE_URL": "http://h/v1", "LLM_MODEL": "m"})
    assert (url, model) == ("http://h/v1", "m")


class _Msg:
    content = "```python\nprint(1)\n```"


class _Choice:
    message = _Msg()


class _Resp:
    choices = [_Choice()]


class _Spy:
    def __init__(self):
        self.chat = self
        self.completions = self

    def create(self, **kwargs):
        self.kwargs = kwargs
        return _Resp()


def test_ollama_caps_max_tokens_for_small_context(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    spy = _Spy()
    NebiusClient(client=spy).chat([{"role": "user", "content": "x"}], max_tokens=4096)
    assert spy.kwargs["max_tokens"] == 1024 and spy.kwargs["model"] == "nemotron-mini"


class _Model:
    def __init__(self, id):
        self.id = id


def _factory(ids=None, fail=False):
    class F:
        def __init__(self, **kwargs):
            self.models = self

        def list(self):
            if fail:
                raise ConnectionError("refused")
            return [_Model(i) for i in ids]
    return F


class _Client:
    def __init__(self, model, api_key, base_url):
        pass

    def propose_code(self, task):
        return "print(55)"


def test_doctor_with_ollama_accepts_name_without_tag():
    lines = []
    code = run_doctor({"LLM_PROVIDER": "ollama"}, _factory(["nemotron-mini:latest"]),
                      _Client, out=lines.append)
    text = "\n".join(lines)
    assert code == 0 and "READY" in text and "WARNING" not in text


def test_doctor_with_ollama_explains_missing_model_and_stopped_server():
    lines = []
    run_doctor({"LLM_PROVIDER": "ollama"}, _factory(["other:1b"]), _Client, out=lines.append)
    assert any("ollama pull nemotron-mini" in ln for ln in lines)
    lines.clear()
    run_doctor({"LLM_PROVIDER": "ollama"}, _factory(fail=True), _Client, out=lines.append)
    assert any("Is Ollama running" in ln or "is Ollama running" in ln for ln in lines)
