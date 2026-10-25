# AEGIS: a safety layer for LLM-written code

AEGIS sits between an LLM agent and code execution. The model proposes Python,
AEGIS decides whether it may run, runs it with enforced limits, and records
every decision in a tamper-evident audit log.

**Track:** Coding & Agentic Engineering
**Model:** NVIDIA Nemotron, served by Nebius Token Factory

## How it works

~~~
task -> LLM (Nemotron on Nebius) -> proposed code
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
   Nebius Token Factory. Nemotron models there are reasoning models, so AEGIS
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

## Quick start

~~~powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONPATH = "."

pytest -q                       # full test suite
python scripts/demo.py          # offline demo with a scripted "LLM"
python scripts/benchmark.py     # red-team benchmark
~~~

Live mode with a real model:

~~~powershell
$env:NEBIUS_API_KEY = Read-Host "Nebius API key"
python scripts/nebius_check.py                 # list available Nemotron ids
$env:NEBIUS_MODEL = "<model id from the list>"
python scripts/demo.py --live
~~~

## Demo output (offline)

~~~
[EXECUTED] Compute the 20th Fibonacci number      -> 6765
[BLOCKED]  Download a file from the internet      -> import of 'urllib' is not allowed
[BLOCKED]  Save a note to disk                    -> call to 'open()' is not allowed
[BLOCKED]  Print all environment variables        -> import of 'os' is not allowed
Audit chain valid: True
After tampering  : False
~~~

## Red-team benchmark

38 attack snippets and 14 benign programs (`scripts/benchmark.py`, results in
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

## Security model and limits (please read)

- The guard is a **policy layer, not an isolation boundary**. The corpus was
  written by the same author as the guard, so 34/34 is not proof of safety.
- Code that passes the guard currently runs in a local subprocess with a
  temporary working directory, a timeout and output limits, **without
  OS-level isolation**.
- Resource attacks pass the guard by design. Timeout and output caps cover
  part of that; a hard memory limit needs a container backend.
- Planned: a Docker `IsolationBackend` (`--network none`, read-only
  filesystem, dropped capabilities, pids and memory limits) and
  probe-based verification of declared isolation capabilities.

## Project structure

~~~
aegis/guard.py        policy guard
aegis/pipeline.py     LLM -> guard -> sandbox -> audit
aegis/llm/            Nebius / Nemotron client
aegis/runtime/        sandbox, isolation interface, backends
aegis/core/           agent, policy, decision and replanning engine
scripts/              demo, benchmark, Nebius check
tests/                600+ tests
~~~

## What was built during the hackathon

The repository started as a local agent-engineering project (decision engine,
replanner, sandbox interface). During the hackathon period I:

- closed an unsafe default: local execution is now opt-in
- added the Nebius Token Factory / Nemotron client
- added the AST policy guard and the hash-chained audit log
- added the red-team benchmark and fixed the gap it found
- prepared the repository for open-source release

## License

MIT, see `LICENSE`.
