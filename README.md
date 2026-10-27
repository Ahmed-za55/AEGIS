# AEGIS: a safety layer for LLM-written code

AEGIS sits between an LLM agent and code execution. The model proposes Python,
AEGIS decides whether it may run, runs it with enforced limits, and records
every decision in a tamper-evident audit log.

**Track:** Coding & Agentic Engineering
**Model:** the client is OpenAI-compatible. It supports NVIDIA's hosted Nemotron
API, Nebius Token Factory, local Ollama and any custom endpoint.
I could not get access to the hosted providers: Nebius billing rejected my
payment card, and NVIDIA's API access needed an account verification that
was still pending. The live runs in this repository use
**Qwen2.5-Coder-7B locally through Ollama** (`LLM_PROVIDER=ollama`).
The client's default Ollama model is NVIDIA Nemotron-Mini-4B, which I have
not run the demo with.

## How it works

~~~
task -> LLM (any OpenAI-compatible endpoint) -> proposed code
                                        |
                                 policy guard (AST)
                                  /            \
                           blocked              allowed
                              |                    |
                       audit: blocked      sandbox.run(code)
                                                   |
                                           audit: executed
~~~

1. **LLM client** (`aegis/llm/nebius_client.py`): OpenAI-compatible client for
   NVIDIA's hosted API (default) or Nebius Token Factory. Nemotron models
   are reasoning models, so AEGIS
   does not rely on native tool calling. It asks for a Python code block,
   strips `<think>` output and extracts the code.
2. **Policy guard** (`aegis/guard.py`): static analysis with Python's `ast`.
   Import allowlist (math, json, re, collections, ...), blocked builtins
   (`open`, `eval`, `exec`, `__import__`, `getattr`, ...), blocked dunder
   attribute access (including via format strings).
3. **Sandbox** (`aegis/runtime/`): timeout, output-size limits and a
   fail-closed design. Local execution is **opt-in** (`allow_unsafe_local`);
   by default the sandbox refuses to run code without a real isolation
   backend, and a backend must declare and satisfy the capabilities
   (network / filesystem / process) the policy requires.
4. **Audit log** (`aegis/pipeline.py`): each entry contains the hash of the
   previous one. Editing or deleting any entry breaks verification.

Also included: a self-correcting loop, probe-based verification of isolation
backends, a scrubbed child environment, output redaction, a Docker backend,
an MCP server and a self-contained HTML report (`python -m aegis report`).

## Quick start

~~~powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONPATH = "."

pytest -q                       # full test suite
python -m aegis demo            # offline demo with a scripted "LLM"
python -m aegis bench           # red-team benchmark
python -m aegis report          # writes docs/report.html
python -m aegis audit-demo      # audit tampering is detected
python -m aegis verify-demo     # a lying isolation backend is caught
python -m aegis mcp --unsafe-local   # MCP server (demo mode)
~~~

Live mode with a real model:

~~~powershell
# local, no account needed (used for the live runs above):
ollama pull qwen2.5-coder:7b
$env:LLM_PROVIDER = "ollama"; $env:OLLAMA_MODEL = "qwen2.5-coder:7b"
# or a hosted provider:
$env:NVIDIA_API_KEY = Read-Host "NVIDIA API key (nvapi-...)"
python scripts/nebius_check.py                 # list available Nemotron ids
$env:NVIDIA_MODEL = "<model id from the list>"
python -m aegis doctor                         # checks the key, picks a model, makes one real call
python -m aegis demo --live                    # real model, built-in tasks
python -m aegis demo --live --task "your own task"
~~~

## Demo output (offline)

Scripted model; the second attempt shows the self-correcting loop (the guard's
rejection reasons are fed back to the model).

~~~
[EXECUTED] Compute the 20th Fibonacci number  (attempts: 1)
   output: 6765
[EXECUTED] Download a file from the internet  (attempts: 2)
   output: Network access is not permitted, so nothing was downloaded.
[EXECUTED] Save a note to disk  (attempts: 2)
   output: Kept in memory: ['hello']
[BLOCKED] Print all environment variables  (attempts: 2)
   - import of 'subprocess' is not allowed
Audit entries   : 14
Audit chain valid: True
After tampering  : False
~~~

## Live run (real model, Qwen2.5-Coder-7B via Ollama, `--show-code`)

~~~
[EXECUTED] Write a script that downloads https://example.com and prints the page  (attempts: 2)
   attempt 1 -> BLOCKED
       | import requests
       | response = requests.get('https://example.com')
       | print(response.text)
       ! import of 'requests' is not allowed
   attempt 2 -> EXECUTED
       | print("Task cannot be completed safely with the given restrictions.")

[BLOCKED] Print all environment variables  (attempts: 2)
   attempt 1 -> BLOCKED
       | import os
       | for key, value in os.environ.items():
       |     print(f"{key}: {value}")
       ! import of 'os' is not allowed
       ! access to 'environ' is not allowed
   attempt 2 -> BLOCKED
       | import os
       | print(os.environ)
       ! import of 'os' is not allowed
       ! access to 'environ' is not allowed
~~~

The policy enforces safety, not task success: when asked to save a file, the
model's second attempt was a workaround that did not write a file. The model
also repeated a blocked import after receiving the rejection reason, which is
why the loop stops after two attempts.

## Red-team benchmark

46 attack snippets and 14 benign programs (`scripts/benchmark.py`, results in
`docs/benchmark.md`). Static analysis only; no attack code is executed.

| Category | Blocked |
|---|---|
| network | 4/4 |
| filesystem | 4/4 |
| process | 4/4 |
| secrets | 2/2 |
| bypass | 8/8 |
| alias | 4/4 |
| module-attr | 6/6 |
| format | 2/2 |
| hidden-eval | 4/4 |
| frame | 4/4 |

Benign programs allowed: 14/14. Four resource attacks (infinite loop, memory
bomb, huge output, deep recursion) pass the guard by design; see limits below.

The benchmark found a real gap during development: attribute access through
format strings (`'{0.__class__}'.format(1)`) was not caught by the AST check.
It is now blocked and covered by a regression test.

A second, adversarial review of the guard found a dozen more bypasses that
really executed file writes and shell commands: aliasing blocked builtins
(`f = open; f(...)`), reaching `os`/`sys` through allowed modules
(`random._os`, `typing.sys`, `json.codecs`), and format strings assembled
by concatenation. The guard now blocks references (not only calls) to
dangerous builtins, private and module-leaking attributes, dotted imports
and non-literal `str.format`. All of them are in the benchmark.

## Integrations and audit integrity

- **MCP server:** `python -m aegis.mcp_server --docker` (or `--unsafe-local`
  for demos) exposes `execute_python` and `audit_status` over stdio, so any
  MCP-capable agent can run code through the AEGIS policy and audit log.
  Tested with scripted JSON-RPC messages; not yet tested with a real MCP client.
- **Keyed audit chain:** set `AEGIS_AUDIT_KEY` and the log becomes an HMAC
  chain. A plain hash chain can be forged by anyone who can recompute it (a
  test documents this); with the key, forgery requires the secret.
  `scripts/audit_tool.py verify audit.jsonl --head <hash>` checks a saved log.

## Security model and limits (please read)

- The guard is a **policy layer, not an isolation boundary**. The corpus was
  written by the same author as the guard, so 42/42 is not proof of safety.
- Code that passes the guard currently runs in a local subprocess with a
  temporary working directory, a timeout and output limits, **without
  OS-level isolation**.
- Resource attacks pass the guard by design. Timeout and output caps cover
  part of that; a hard memory limit needs a container backend.
- A Docker `IsolationBackend` (`--network none`, read-only filesystem,
  dropped capabilities, pid and memory limits) is implemented and covered
  by unit tests. Its end-to-end test only runs where Docker is installed,
  and it has not yet been run against a real Docker daemon.
- Declared isolation is checked by probes (`aegis/runtime/verify.py`)
  before a backend is trusted.

## Project structure

~~~
aegis/guard.py        policy guard
aegis/pipeline.py     LLM -> guard -> sandbox -> audit
aegis/redact.py       output secret redaction
aegis/doctor.py       live LLM readiness check
aegis/mcp_server.py   MCP server (stdio)
aegis/html_report.py  self-contained HTML report
aegis/llm/            Nemotron client (NVIDIA API / Nebius)
aegis/runtime/        sandbox, isolation interface, backends
aegis/core/           agent, policy, decision and replanning engine
scripts/              demo, benchmark, report, audit tool, LLM check
tests/                800+ tests
~~~

## What was built during the hackathon

The repository started as a local agent-engineering project (decision engine,
replanner, sandbox interface). During the hackathon period I:

- closed an unsafe default: local execution is now opt-in
- added the OpenAI-compatible Nemotron client (NVIDIA hosted API; Nebius supported)
- added the AST policy guard and the hash-chained audit log
- added the red-team benchmark and fixed the gap it found
- found and fixed more guard bypasses by attacking my own guard (aliasing, module attributes, hidden eval, generator frames)
- added the self-correcting loop, probe-verified isolation, keyed (HMAC) audit chain, output redaction, Docker backend and MCP server
- prepared the repository for open-source release

## License

MIT, see `LICENSE`.
