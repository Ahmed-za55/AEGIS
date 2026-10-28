"""AEGIS Playground: a local web UI (standard library only).

    python -m aegis ui --unsafe-local     # local runner, no isolation (demo)
    python -m aegis ui --docker           # Docker backend verified by probes

The server listens on 127.0.0.1 only. Every POST needs a random per-run token
and a localhost Host header, so another website cannot drive it. Code always
passes the policy guard before it can reach the sandbox.
"""
import contextlib
import importlib.util
import io
import json
import pathlib
import runpy
import secrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aegis.guard import check_code
from aegis.pipeline import HashChainLog, SecureCodeRunner, env_audit_key
from aegis.redact import redact

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAX_BODY = 100_000

PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>AEGIS Playground</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--card:#f5f5f7;--line:#ddd;--ok:#1a7f37;--bad:#cf222e;--warn:#9a6700;--acc:#3b5bdb}
@media (prefers-color-scheme:dark){:root{--bg:#111318;--fg:#e8e8ea;--mut:#9a9aa3;--card:#1b1e26;--line:#2d313c;--ok:#3fb950;--bad:#f85149;--warn:#d29922;--acc:#748ffc}:root .b{color:#0b0d12}}
*{box-sizing:border-box}body{font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:1000px;margin:0 auto;padding:1rem}
h1{margin:.2rem 0}h2{margin:0 0 .5rem;font-size:1.05rem}.mut{color:var(--mut)}
.card{background:var(--card);border:1px solid var(--line);border-radius:.6rem;padding:1rem;margin:1rem 0}
textarea,input{width:100%;font:13px ui-monospace,Consolas,monospace;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:.4rem;padding:.5rem}
textarea{height:9rem}button{font:inherit;padding:.4rem .8rem;border:1px solid var(--line);border-radius:.4rem;background:var(--bg);color:var(--fg);cursor:pointer;margin:.3rem .3rem 0 0}
button.p{background:#3b5bdb;color:#fff;border-color:#3b5bdb}
.b{display:inline-block;padding:.05rem .5rem;border-radius:.6rem;font-size:.8rem;font-weight:600;color:#fff}
.EXECUTED,.ALLOWED,.VALID{background:var(--ok)}.BLOCKED,.BROKEN{background:var(--bad)}.FAILED,.ERROR{background:var(--warn)}
pre{background:var(--bg);border:1px solid var(--line);padding:.5rem;border-radius:.4rem;overflow-x:auto;font-size:12.5px;margin:.3rem 0}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:.25rem .4rem;border-bottom:1px solid var(--line)}
.step{border-left:3px solid var(--line);padding-left:.7rem;margin:.6rem 0}.reason{color:var(--bad)}
</style></head><body>
<h1>AEGIS Playground</h1>
<p class="mut">A safety layer between LLM-written code and execution. Everything runs on this machine.</p>

<div class="card"><h2>1. Try some code</h2>
<textarea id="code" spellcheck="false">print(sum(range(1, 11)))</textarea>
<div><button class="p" onclick="runCode()">Run through AEGIS</button>
<button onclick="ex(0)">Safe</button><button onclick="ex(1)">Attack: shell</button>
<button onclick="ex(2)">Attack: write file</button><button onclick="ex(3)">Attack: generator frame</button>
<button onclick="ex(4)">Attack: alias open</button></div><div id="codeOut"></div></div>

<div class="card"><h2>2. Ask a model</h2>
<input id="task" value="Write a script that downloads https://example.com and prints the page">
<div><button class="p" onclick="runTask('live')">Run with the configured model</button>
<button onclick="runTask('scripted')">Scripted demo task</button></div>
<p class="mut">Scripted tasks: Compute the 20th Fibonacci number / Download a file from the internet / Save a note to disk / Print all environment variables</p>
<div id="taskOut"></div></div>

<div class="card"><h2>3. Audit log</h2><div id="auditHead"></div>
<div><button onclick="loadAudit()">Refresh</button><button onclick="post('/api/tamper').then(loadAudit)">Tamper with entry 0</button>
<button onclick="post('/api/reset').then(loadAudit)">Reset log</button></div><div id="auditOut"></div></div>

<div class="card"><h2>4. Red-team benchmark</h2><button onclick="bench()">Run benchmark</button><pre id="benchOut" hidden></pre></div>
<script>
const TOKEN="__TOKEN__";
const EX=["print(sum(range(1, 11)))","import os\nos.system('whoami')","f = open\nf('x.txt', 'w').write('pwned')",
"g = (1 for _ in [0])\nprint(g.gi_frame.f_builtins['open'])","import random\nrandom._os.system('whoami')"];
function ex(i){document.getElementById('code').value=EX[i];runCode();}
async function post(path,body){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-AEGIS-Token':TOKEN},body:JSON.stringify(body||{})});return r.json();}
function el(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
function badge(s){return el('span',s,'b '+s);}
function clear(id){const n=document.getElementById(id);n.replaceChildren();return n;}
function codeBlock(c){return el('pre',c);}
function reasons(list){const d=el('div');(list||[]).forEach(r=>d.appendChild(el('div','! '+r,'reason')));return d;}
async function runCode(){const o=clear('codeOut');const r=await post('/api/run-code',{code:document.getElementById('code').value});
 if(r.error){o.appendChild(el('p',r.error,'reason'));return;}
 o.appendChild(badge(r.status.toUpperCase()));o.appendChild(reasons(r.reasons));
 if(r.stdout)o.appendChild(codeBlock(r.stdout));if(r.stderr)o.appendChild(codeBlock(r.stderr));loadAudit();}
async function runTask(mode){const o=clear('taskOut');o.appendChild(el('p','Working... (a local model can take a minute)','mut'));
 const r=await post('/api/run-task',{task:document.getElementById('task').value,mode});o.replaceChildren();
 if(r.error){o.appendChild(el('p',r.error,'reason'));return;}
 o.appendChild(badge(r.status.toUpperCase()));o.appendChild(el('span','  attempts: '+r.attempts,'mut'));
 r.trace.forEach(t=>{const s=el('div',undefined,'step');s.appendChild(el('strong','attempt '+t.attempt+' '));s.appendChild(badge(t.verdict));
  if(t.code)s.appendChild(codeBlock(t.code));s.appendChild(reasons(t.reasons));o.appendChild(s);});
 if(r.stdout)o.appendChild(codeBlock(r.stdout));loadAudit();}
async function loadAudit(){const r=await post('/api/audit');const h=clear('auditHead');
 h.appendChild(badge(r.valid?'VALID':'BROKEN'));h.appendChild(el('span','  '+r.entries.length+' entries, head '+r.head.slice(0,16),'mut'));
 const o=clear('auditOut');const t=el('table');const hr=el('tr');['#','event','attempt','hash'].forEach(x=>hr.appendChild(el('th',x)));t.appendChild(hr);
 r.entries.forEach(e=>{const tr=el('tr');[e.index,e.event,e.attempt,e.hash].forEach(x=>tr.appendChild(el('td',String(x))));t.appendChild(tr);});o.appendChild(t);}
async function bench(){const p=document.getElementById('benchOut');p.hidden=false;p.textContent='Running...';const r=await post('/api/benchmark');p.textContent=r.text||r.error;}
loadAudit();
</script></body></html>"""


def _load_demo():
    path = ROOT / "scripts" / "demo.py"
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location("aegis_ui_demo", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _default_llm():
    from aegis.llm.nebius_client import NebiusClient
    return NebiusClient()


class AppState:
    def __init__(self, sandbox, llm_factory=None, token=None):
        self.sandbox = sandbox
        self.llm_factory = llm_factory or _default_llm
        self.token = token or secrets.token_urlsafe(16)
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        self.log = HashChainLog(key=env_audit_key())


def _trace(entries):
    out, current = [], None
    for e in entries:
        d = e["data"]
        if e["event"] == "proposed":
            current = d
        elif e["event"] == "blocked":
            out.append({"attempt": d["attempt"], "verdict": "BLOCKED",
                        "code": current["code"] if current else "",
                        "reasons": d["reasons"]})
        elif e["event"] == "executed":
            out.append({"attempt": d["attempt"],
                        "verdict": "EXECUTED" if d["success"] else "FAILED",
                        "code": current["code"] if current else "", "reasons": []})
        elif e["event"] == "llm_error":
            out.append({"attempt": d["attempt"], "verdict": "ERROR", "code": "",
                        "reasons": [d["error"]]})
    return out


def _json(status, payload):
    return status, "application/json", json.dumps(payload).encode("utf-8")


def _run_code(state, code):
    if not isinstance(code, str) or not code.strip():
        return {"error": "Enter some Python code."}
    state.log.append("proposed", {"code": code, "attempt": 1})
    verdict = check_code(code)
    if not verdict.allowed:
        state.log.append("blocked", {"reasons": list(verdict.reasons), "attempt": 1})
        return {"status": "blocked", "reasons": list(verdict.reasons),
                "stdout": "", "stderr": ""}
    result = state.sandbox.run(code)
    state.log.append("executed", {"success": result.success,
                                  "exit_code": result.exit_code, "attempt": 1})
    return {"status": "executed" if result.success else "failed", "reasons": [],
            "stdout": redact(result.stdout), "stderr": redact(result.stderr)}


def _run_task(state, task, mode):
    if not isinstance(task, str) or not task.strip():
        return {"error": "Enter a task."}
    if mode == "scripted":
        demo = _load_demo()
        if demo is None or task not in demo.SCENARIOS:
            return {"error": "Scripted mode only knows the four built-in tasks."}
        llm = demo.ScriptedLLM()
    else:
        try:
            llm = state.llm_factory()
        except Exception as exc:
            return {"error": f"Model not configured: {exc}. "
                             "Set LLM_PROVIDER (ollama, nvidia, nebius) and try 'python -m aegis doctor'."}
    start = len(state.log.entries)
    runner = SecureCodeRunner(llm, state.sandbox, log=state.log, max_attempts=2)
    report = runner.run(task)
    return {"status": report.status, "attempts": report.attempts,
            "trace": _trace(state.log.entries[start:]),
            "stdout": report.stdout, "reasons": list(report.reasons)}


def _benchmark():
    path = ROOT / "scripts" / "benchmark.py"
    if not path.exists():
        return {"error": "benchmark script not found"}
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        runpy.run_path(str(path), run_name="__main__")
    return {"text": buffer.getvalue()}


def handle(state, method, path, headers, body):
    """Return (status, content_type, bytes). Pure function: easy to test."""
    host = (headers.get("Host") or "").split(":")[0]
    if host not in ("127.0.0.1", "localhost"):
        return _json(403, {"error": "forbidden host"})
    if method == "GET":
        if path in ("/", "/index.html"):
            page = PAGE.replace("__TOKEN__", state.token)
            return 200, "text/html; charset=utf-8", page.encode("utf-8")
        return _json(404, {"error": "not found"})
    if method != "POST":
        return _json(405, {"error": "method not allowed"})
    if not secrets.compare_digest(headers.get("X-AEGIS-Token") or "", state.token):
        return _json(403, {"error": "bad token"})
    if "application/json" not in (headers.get("Content-Type") or ""):
        return _json(415, {"error": "JSON required"})
    if len(body) > MAX_BODY:
        return _json(413, {"error": "request too large"})
    try:
        data = json.loads(body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _json(400, {"error": "invalid JSON"})
    if not isinstance(data, dict):
        return _json(400, {"error": "JSON object required"})

    with state.lock:
        if path == "/api/run-code":
            return _json(200, _run_code(state, data.get("code")))
        if path == "/api/run-task":
            return _json(200, _run_task(state, data.get("task"), data.get("mode")))
        if path == "/api/audit":
            return _json(200, {
                "valid": state.log.verify(), "head": state.log.head(),
                "entries": [{"index": e["index"], "event": e["event"],
                             "attempt": e["data"].get("attempt", ""),
                             "hash": e["hash"][:16]} for e in state.log.entries]})
        if path == "/api/tamper":
            if state.log.entries:
                state.log.entries[0]["data"]["tampered"] = True
            return _json(200, {"ok": True})
        if path == "/api/reset":
            state.reset()
            return _json(200, {"ok": True})
        if path == "/api/benchmark":
            return _json(200, _benchmark())
    return _json(404, {"error": "not found"})


def make_server(state, host="127.0.0.1", port=8765):
    class Handler(BaseHTTPRequestHandler):
        def _reply(self, method):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(min(length, MAX_BODY + 1)) if length else b""
            status, ctype, data = handle(state, method, self.path.split("?")[0],
                                         self.headers, body)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._reply("GET")

        def do_POST(self):
            self._reply("POST")

        def log_message(self, *args):
            pass

    return ThreadingHTTPServer((host, port), Handler)


def main(argv=None) -> int:
    from aegis.mcp_server import build_sandbox

    argv = sys.argv[1:] if argv is None else argv
    modes = [a for a in argv if a in ("--docker", "--unsafe-local")]
    if len(modes) != 1:
        print("Choose exactly one of --docker or --unsafe-local.", file=sys.stderr)
        return 2
    port = 8765
    if "--port" in argv:
        port = int(argv[argv.index("--port") + 1])
    state = AppState(build_sandbox(modes[0]))
    server = make_server(state, port=port)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"AEGIS Playground at {url}   (Ctrl+C to stop)")
    if "--no-browser" not in argv:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
