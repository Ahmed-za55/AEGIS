import pytest

from aegis.llm.nebius_client import (
    BASE_URL,
    NVIDIA_BASE_URL,
    LLMError,
    NebiusClient,
    extract_code,
    resolve_settings,
    strip_reasoning,
)

_ENV_VARS = ("LLM_PROVIDER", "LLM_MODEL", "NVIDIA_API_KEY", "NVIDIA_MODEL",
             "NVIDIA_BASE_URL", "NEBIUS_API_KEY", "NEBIUS_MODEL", "NEBIUS_BASE_URL")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)


class _Msg:
    def __init__(self, content):
        self.content = content


class _Choice:
    def __init__(self, content):
        self.message = _Msg(content)


class _Resp:
    def __init__(self, content):
        self.choices = [_Choice(content)]


class _FakeOpenAI:
    def __init__(self, content=None, errors=()):
        self._content, self._errors = content, list(errors)
        self.calls = 0
        self.chat = self
        self.completions = self

    def create(self, **kwargs):
        self.calls += 1
        if self._errors:
            raise self._errors.pop(0)
        self.kwargs = kwargs
        return _Resp(self._content)


class _HttpError(Exception):
    def __init__(self, status_code):
        super().__init__(f"http {status_code}")
        self.status_code = status_code


def test_strip_reasoning_removes_think_block():
    assert strip_reasoning("<think>hmm</think>answer") == "answer"


def test_extract_code_from_fence():
    assert extract_code("x\n```python\nprint(1)\n```\ny") == "print(1)"


def test_extract_code_without_fence_returns_text():
    assert extract_code("print(2)") == "print(2)"


def test_propose_code_uses_model_and_returns_code():
    fake = _FakeOpenAI("<think>t</think>```python\nprint(3)\n```")
    client = NebiusClient(model="m", client=fake)
    assert client.propose_code("task") == "print(3)"
    assert fake.kwargs["model"] == "m"


def test_missing_model_raises():
    with pytest.raises(LLMError):
        NebiusClient(client=_FakeOpenAI("x"))


def test_missing_api_key_raises():
    with pytest.raises(LLMError):
        NebiusClient(model="m")


def test_empty_answer_raises():
    client = NebiusClient(model="m", client=_FakeOpenAI("<think>x</think>"))
    with pytest.raises(LLMError):
        client.chat([{"role": "user", "content": "hi"}])


def test_api_error_is_wrapped_and_not_retried():
    fake = _FakeOpenAI(errors=[ValueError("boom")])
    client = NebiusClient(model="m", client=fake, sleep=lambda s: None)
    with pytest.raises(LLMError):
        client.chat([{"role": "user", "content": "hi"}])
    assert fake.calls == 1


def test_rate_limit_is_retried_with_backoff():
    sleeps = []
    fake = _FakeOpenAI("ok", errors=[_HttpError(429), _HttpError(429)])
    client = NebiusClient(model="m", client=fake, sleep=sleeps.append)
    assert client.chat([{"role": "user", "content": "hi"}]) == "ok"
    assert fake.calls == 3 and sleeps == [2, 4]


def test_rate_limit_gives_up_after_max_retries():
    fake = _FakeOpenAI("ok", errors=[_HttpError(429)] * 5)
    client = NebiusClient(model="m", client=fake, max_retries=3, sleep=lambda s: None)
    with pytest.raises(LLMError):
        client.chat([{"role": "user", "content": "hi"}])
    assert fake.calls == 3


def test_provider_defaults_to_nvidia_when_only_nvidia_key_is_set():
    provider, url, key, model = resolve_settings(
        {"NVIDIA_API_KEY": "nvapi-x", "NVIDIA_MODEL": "nvidia/m"})
    assert (provider, url, key, model) == ("nvidia", NVIDIA_BASE_URL, "nvapi-x", "nvidia/m")


def test_provider_defaults_to_nebius_otherwise():
    provider, url, key, model = resolve_settings(
        {"NEBIUS_API_KEY": "k", "NEBIUS_MODEL": "m"})
    assert (provider, url, key, model) == ("nebius", BASE_URL, "k", "m")


def test_explicit_provider_wins_when_both_keys_exist():
    env = {"LLM_PROVIDER": "nvidia", "NVIDIA_API_KEY": "a", "NEBIUS_API_KEY": "b"}
    assert resolve_settings(env)[0] == "nvidia"
    assert resolve_settings({"NVIDIA_API_KEY": "a", "NEBIUS_API_KEY": "b"})[0] == "nebius"


def test_unknown_provider_and_explicit_arguments():
    with pytest.raises(LLMError):
        resolve_settings({"LLM_PROVIDER": "other"})
    _, url, key, model = resolve_settings(
        {"NVIDIA_API_KEY": "a"}, model="m2", api_key="k2", base_url="http://x")
    assert (url, key, model) == ("http://x", "k2", "m2")
