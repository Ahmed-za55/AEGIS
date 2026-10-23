"""python scripts/nebius_check.py            -> list Nemotron model ids
   python scripts/nebius_check.py "prompt"   -> send a prompt to NEBIUS_MODEL"""
import os
import sys

from openai import OpenAI

from aegis.llm.nebius_client import BASE_URL, NebiusClient

if len(sys.argv) == 1:
    client = OpenAI(api_key=os.environ["NEBIUS_API_KEY"], base_url=BASE_URL)
    for m in client.models.list():
        if "nemotron" in m.id.lower():
            print(m.id)
else:
    print(NebiusClient().chat([{"role": "user", "content": sys.argv[1]}]))
