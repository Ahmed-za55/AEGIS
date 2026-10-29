"""`python -m aegis doctor`: check that the live LLM path works end to end.

Never prints the API key. Picks a Nemotron model automatically when possible.
"""
import os
import time

from aegis.guard import check_code
from aegis.llm.nebius_client import LLMError, NebiusClient, resolve_settings

PREFERRED = (
    "nvidia/llama-3.3-nemotron-super-49b-v1.5",
    "nvidia/nemotron-3-super-120b-a12b",
    "nvidia/nvidia-nemotron-nano-9b-v2",
)


def pick_model(ids):
    ids = list(ids)
    for name in PREFERRED:
        if name in ids:
            return name
    for name in ids:
        if "nemotron" in name.lower():
            return name
    return None


def _installed(model, ids):
    """Ollama lists 'name:tag'; accept the bare name too."""
    return model in ids or any(i.split(":")[0] == model for i in ids)


def run_doctor(env=None, openai_factory=None, client_factory=None, out=print) -> int:
    env = dict(os.environ) if env is None else dict(env)
    try:
        provider, url, key, model = resolve_settings(env)
    except LLMError as exc:
        out(f"config error: {exc}")
        return 2

    out(f"provider : {provider}")
    out(f"endpoint : {url}")
    out(f"api key  : {'set' if key else 'MISSING'}")
    if not key:
        out("-> set NVIDIA_API_KEY (or NEBIUS_API_KEY), or use a local model: "
            "LLM_PROVIDER=ollama")
        return 2

    if openai_factory is None:
        from openai import OpenAI as openai_factory
    ids, listed = [], False
    try:
        api = openai_factory(api_key=key, base_url=url)
        ids = [m.id for m in api.models.list()]
        listed = True
        out(f"models   : {len(ids)} available")
    except Exception as exc:
        out(f"models   : could not list ({type(exc).__name__}); continuing")
        if provider == "ollama":
            out("-> is Ollama running? Start it, then: ollama pull nemotron-mini")

    if not model:
        model = pick_model(ids)
        if not model and provider == "custom" and ids:
            model = ids[0]
        if not model:
            out("-> no Nemotron model found; set the model id manually.")
            return 2
        out(f"model    : {model}  (auto-selected)")
    else:
        warn = ""
        if listed and ids and not _installed(model, ids):
            warn = "  (WARNING: not in the model list)"
            if provider == "ollama":
                warn += f" -> run: ollama pull {model}"
        out(f"model    : {model}{warn}")

    make = client_factory or NebiusClient
    try:
        client = make(model=model, api_key=key, base_url=url)
        start = time.time()
        code = client.propose_code("Print the sum of the integers from 1 to 10.")
        elapsed = time.time() - start
    except LLMError as exc:
        out(f"llm call : FAILED: {exc}")
        return 1
    out(f"llm call : ok in {elapsed:.1f}s")
    out("proposed code:\n" + "\n".join("    " + ln for ln in code.splitlines()))

    verdict = check_code(code)
    if verdict.allowed:
        out("guard    : allowed")
    else:
        out("guard    : blocked: " + "; ".join(verdict.reasons))
    out("\nREADY. Next: python -m aegis demo --live")
    return 0


def main() -> int:
    return run_doctor()
