"""python scripts/nebius_check.py            -> list Nemotron model ids
   python scripts/nebius_check.py "prompt"   -> send a prompt to the model

Works with NVIDIA's hosted API (NVIDIA_API_KEY) or Nebius (NEBIUS_API_KEY)."""
import sys

from aegis.llm.nebius_client import NebiusClient, resolve_settings

if len(sys.argv) == 1:
    from openai import OpenAI

    provider, url, key, _ = resolve_settings()
    if not key:
        sys.exit("Set NVIDIA_API_KEY (or NEBIUS_API_KEY) first.")
    print(f"provider: {provider}")
    client = OpenAI(api_key=key, base_url=url)
    for m in client.models.list():
        if "nemotron" in m.id.lower():
            print(m.id)
else:
    client = NebiusClient()
    print(f"[{client.provider} / {client.model}]")
    print(client.chat([{"role": "user", "content": sys.argv[1]}]))
