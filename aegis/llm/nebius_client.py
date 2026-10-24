"""Minimal Nebius Token Factory client (OpenAI-compatible API).

Nemotron models on Token Factory are reasoning models, so we do NOT use
native tool calling. The agent asks for plain text / a python code block and
AEGIS validates and executes it inside the sandbox.
"""
import os
import re

BASE_URL = "https://api.tokenfactory.nebius.com/v1/"

_THINK = re.compile(r"<think>.*?</think>", re.S)
_FENCE = re.compile(r"```(?:python)?[ \t]*\n(.*?)```", re.S)


class LLMError(RuntimeError):
    pass


def strip_reasoning(text: str) -> str:
    return _THINK.sub("", text).strip()


def extract_code(text: str) -> str:
    text = strip_reasoning(text)
    match = _FENCE.search(text)
    return (match.group(1) if match else text).strip()


class NebiusClient:
    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str = BASE_URL,
        timeout: float = 60.0,
        client=None,
    ):
        self.model = model or os.environ.get("NEBIUS_MODEL")
        if not self.model:
            raise LLMError("Set NEBIUS_MODEL (full model id, e.g. nvidia/...).")

        if client is None:
            key = api_key or os.environ.get("NEBIUS_API_KEY")
            if not key:
                raise LLMError("Set the NEBIUS_API_KEY environment variable.")
            from openai import OpenAI  # imported lazily

            client = OpenAI(api_key=key, base_url=base_url, timeout=timeout)

        self._client = client

    def chat(
        self,
        messages: list[dict],
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> str:
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except Exception as exc:
            raise LLMError(f"Nebius request failed: {exc}") from exc

        content = resp.choices[0].message.content
        if not content or not strip_reasoning(content):
            raise LLMError(
                "Empty answer. Reasoning models can spend all tokens "
                "thinking; try a larger max_tokens."
            )
        return strip_reasoning(content)

    def propose_code(self, task: str, feedback: list[str] | None = None) -> str:
        system = (
            "You write short, self-contained Python 3 scripts. "
            "Reply with ONE ```python code block and nothing else. "
            "Print the final result."
        )
        content = task
        if feedback:
            from aegis.guard import ALLOWED_IMPORTS

            content = (
                f"{task}\n\nYour previous code was rejected by the security "
                f"policy: {'; '.join(feedback)}. Rewrite it using only these "
                f"modules: {', '.join(sorted(ALLOWED_IMPORTS))}, with no file, "
                "network or process access. If the task cannot be done safely, "
                "print a short explanation instead."
            )
        answer = self.chat(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": content},
            ]
        )
        return extract_code(answer)
