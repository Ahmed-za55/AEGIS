"""AEGIS as a Model Context Protocol (MCP) server over stdio.

Any MCP-capable agent can call `execute_python`; the code goes through the
AEGIS policy guard, a sandbox and the tamper-evident audit log.

    python -m aegis.mcp_server --docker         # verified Docker isolation
    python -m aegis.mcp_server --unsafe-local   # NO isolation (demo only)
"""
import json
import sys

from aegis.guard import check_code
from aegis.pipeline import HashChainLog, env_audit_key
from aegis.redact import redact

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "execute_python",
        "description": ("Run Python code under AEGIS policy and isolation. "
                        "Only a small safe subset of the standard library is "
                        "allowed; file, network and process access are blocked."),
        "inputSchema": {
            "type": "object",
            "properties": {"code": {"type": "string",
                                    "description": "Python source to run"}},
            "required": ["code"],
        },
    },
    {
        "name": "audit_status",
        "description": "Verify the audit log chain and return its head hash.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class AegisMcpServer:
    def __init__(self, sandbox, guard=check_code, log=None):
        self.sandbox, self.guard = sandbox, guard
        self.log = log if log is not None else HashChainLog(key=env_audit_key())

    # -- tools ---------------------------------------------------------
    def _execute(self, code):
        if not isinstance(code, str):
            return "Argument 'code' must be a string.", True
        self.log.append("proposed", {"code": code})
        verdict = self.guard(code)
        if not verdict.allowed:
            self.log.append("blocked", {"reasons": list(verdict.reasons)})
            return ("BLOCKED by AEGIS policy: " + "; ".join(verdict.reasons)), True
        result = self.sandbox.run(code)
        self.log.append("executed", {"success": result.success,
                                     "exit_code": result.exit_code})
        text = redact(result.stdout)
        if result.stderr:
            text += ("\n" if text else "") + "[stderr] " + redact(result.stderr)
        return (text or "(no output)"), not result.success

    def _audit_status(self):
        ok = self.log.verify()
        return (f"chain_valid={ok} entries={len(self.log.entries)} "
                f"head={self.log.head()}"), not ok

    def _call_tool(self, params):
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "execute_python":
            text, is_error = self._execute(args.get("code"))
        elif name == "audit_status":
            text, is_error = self._audit_status()
        else:
            return None
        return {"content": [{"type": "text", "text": text}], "isError": is_error}

    # -- JSON-RPC ------------------------------------------------------
    def handle(self, message: dict):
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}

        def ok(result):
            return {"jsonrpc": "2.0", "id": msg_id, "result": result}

        def err(code, text):
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": code, "message": text}}

        if msg_id is None:                      # notification: no reply
            return None
        if method == "initialize":
            return ok({
                "protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "aegis", "version": "0.1.0"},
            })
        if method == "ping":
            return ok({})
        if method == "tools/list":
            return ok({"tools": TOOLS})
        if method == "tools/call":
            result = self._call_tool(params)
            return err(-32602, f"Unknown tool: {params.get('name')}") if result is None else ok(result)
        return err(-32601, f"Method not found: {method}")


def serve(server: AegisMcpServer, stdin, stdout) -> None:
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            reply = {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32700, "message": "Parse error"}}
        else:
            reply = server.handle(message) if isinstance(message, dict) else None
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()


def build_sandbox(mode: str):
    from aegis.runtime.sandbox import RuntimeSandbox, SandboxSecurityPolicy

    if mode == "--docker":
        from aegis.runtime.docker_backend import DockerIsolationBackend
        from aegis.runtime.verify import VerifiedBackend

        return RuntimeSandbox(
            security_policy=SandboxSecurityPolicy(
                require_network_isolation=True,
                require_filesystem_isolation=True,
                require_process_isolation=True,
            ),
            isolation_backend=VerifiedBackend(DockerIsolationBackend()),
        )
    return RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(allow_unsafe_local=True))


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    modes = [a for a in argv if a in ("--docker", "--unsafe-local")]
    if len(modes) != 1:
        print("Choose exactly one of --docker or --unsafe-local.", file=sys.stderr)
        return 2
    serve(AegisMcpServer(build_sandbox(modes[0])), sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
