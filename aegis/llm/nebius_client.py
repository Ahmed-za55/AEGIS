"""OpenAI-compatible LLM client: NVIDIA hosted API, Nebius, local Ollama, or any
other OpenAI-compatible endpoint.

Nemotron models are often reasoning models, so we do NOT use native tool
calling. The agent asks for a Python code block, strips <think> output and
extracts the code; AEGIS validates and executes it inside the sandbox.

Provider selection (environment):
  LLM_PROVIDER=nvidia|nebius|ollama|custom   explicit choice
  otherwise: nvidia if only NVIDIA_API_KEY is set, else nebius
  nvidia : NVIDIA_API_KEY, NVIDIA_MODEL, optional NVIDIA_BASE_URL
  nebius : NEBIUS_API_KEY, NEBIUS_MODEL, optional NEBIUS_BASE_URL
  ollama : local, no key. OLLAMA_MODEL (default nemotron-mini), OLLAMA_BASE_URL
  custom : LLM_BASE_URL, LLM_API_KEY, LLM_MODEL
  LLM_TIMEOUT overrides the request timeout in seconds.
"""
import os
import re
import time

BASE_URL = "https://api.tokenfactory.nebius.com/v1/"          # Nebius
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"       # NVIDIA hosted API
OLLAMA_BASE_URL = "http://localhost:11434/v1"                 # local Ollama
OLLAMA_DEFAULT_MODEL = "nemotron-mini"                        # NVIDIA Nemotron-Mini-4B

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


def resolve_settings(environ=None, model=None, api_key=None, base_url=None):
    """Return (provider, base_url, api_key, model) from arguments/environment."""
    env = os.environ if environ is None else environ
    provider = (env.get("LLM_PROVIDER") or "").strip().lower()
    if not provider:
        only_nvidia = env.get("NVIDIA_API_KEY") and not env.get("NEBIUS_API_KEY")
        provider = "nvidia" if only_nvidia else "nebius"
    if provider == "nvidia":
        url = base_url or env.get("NVIDIA_BASE_URL") or NVIDIA_BASE_URL
        key = api_key or env.get("NVIDIA_API_KEY")
        mdl = model or env.get("NVIDIA_MODEL") or env.get("LLM_MODEL")
    elif provider == "nebius":
        url = base_url or env.get("NEBIUS_BASE_URL") or BASE_URL
        key = api_key or env.get("NEBIUS_API_KEY")
        mdl = model or env.get("NEBIUS_MODEL") or env.get("LLM_MODEL")
    elif provider == "ollama":
        url = base_url or env.get("OLLAMA_BASE_URL") or OLLAMA_BASE_URL
        key = api_key or env.get("OLLAMA_API_KEY") or "ollama"   # Ollama ignores it
        mdl = (model or env.get("OLLAMA_MODEL") or env.get("LLM_MODEL")
               or OLLAMA_DEFAULT_MODEL)
    elif provider == "custom":
        url = base_url or env.get("LLM_BASE_URL")
        if not url:
            raise LLMError("Set LLM_BASE_URL for LLM_PROVIDER=custom.")
        key = api_key or env.get("LLM_API_KEY") or "none"
        mdl = model or env.get("LLM_MODEL")
    else:
        raise LLMError(
            f"Unknown LLM_PROVIDER '{provider}' (use nvidia, nebius, ollama or custom).")
    return provider, url, key, mdl


class NebiusClient:
    """Name kept for compatibility; works with every provider above."""

    def __init__(self, model=None, api_key=None, base_url=None,
                 timeout=None, client=None, max_retries: int = 3,
                 sleep=time.sleep):
        provider, url, key, mdl = resolve_settings(
            model=model, api_key=api_key, base_url=base_url)
        self.provider, self.model = provider, mdl
        if not self.model:
            raise LLMError("Set the model id (NVIDIA_MODEL, NEBIUS_MODEL or LLM_MODEL).")

        if client is None:
            if not key:
                raise LLMError("Set NVIDIA_API_KEY (or NEBIUS_API_KEY).")
            if timeout is None:
                default = 300.0 if provider == "ollama" else 60.0
                timeout = float(os.environ.get("LLM_TIMEOUT") or default)
            from openai import OpenAI  # imported lazily

            client = OpenAI(api_key=key, base_url=url, timeout=timeout)

        self._client = client
        self._max_retries = max(1, max_retries)
        self._sleep = sleep

    def _create(self, **kwargs):
        """Call the API; retry rate-limit (429) errors with exponential backoff."""
        for attempt in range(1, self._max_retries + 1):
            try:
                return self._client.chat.completions.create(**kwargs)
            except Exception as exc:
                rate_limited = getattr(exc, "status_code", None) == 429
                if rate_limited and attempt < self._max_retries:
                    self._sleep(2 ** attempt)
                    continue
                raise LLMError(f"{self.provider} request failed: {exc}") from exc

    def chat(self, messages: list[dict], temperature: float = 0.2,
             max_tokens: int = 4096) -> str:
        if self.provider == "ollama":      # small local models, 4k context
            max_tokens = min(max_tokens, 1024)
        resp = self._create(model=self.model, messages=messages,
                            temperature=temperature, max_tokens=max_tokens)
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
                f"policy: {'; '.join(feedback)}. Rewrite it so it still solves "
                "the task, using only built-in functions and, if really needed, "
                f"these standard modules: {', '.join(sorted(ALLOWED_IMPORTS))}. "
                "Import a module only if you use it. Do not use files, network, "
                "processes or environment variables. If the task cannot be done "
                "safely, print a one-line explanation instead."
            )
        answer = self.chat(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": content},
            ]
        )
        return extract_code(answer)


LLMClient = NebiusClient
