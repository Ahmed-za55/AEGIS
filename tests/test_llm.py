import pytest

from aegis.llm.nebius_client import (
    LLMError,
    NebiusClient,
    extract_code,
    strip_reasoning,
)


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
    def __init__(self, content=None, error=None):
        self._content, self._error = content, error
        self.chat = self
        self.completions = self

    def create(self, **kwargs):
        if self._error:
            raise self._error
        self.kwargs = kwargs
        return _Resp(self._content)


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


def test_missing_model_raises(monkeypatch):
    monkeypatch.delenv("NEBIUS_MODEL", raising=False)
    with pytest.raises(LLMError):
        NebiusClient(client=_FakeOpenAI("x"))


def test_missing_api_key_raises(monkeypatch):
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    with pytest.raises(LLMError):
        NebiusClient(model="m")


def test_empty_answer_raises():
    client = NebiusClient(model="m", client=_FakeOpenAI("<think>x</think>"))
    with pytest.raises(LLMError):
        client.chat([{"role": "user", "content": "hi"}])


def test_api_error_is_wrapped():
    client = NebiusClient(model="m", client=_FakeOpenAI(error=ValueError("boom")))
    with pytest.raises(LLMError):
        client.chat([{"role": "user", "content": "hi"}])
