import io
import json

from aegis.mcp_server import AegisMcpServer, main, serve


class _Res:
    def __init__(self, success=True, stdout="42\n", stderr=""):
        self.success, self.stdout, self.stderr, self.exit_code = success, stdout, stderr, 0 if success else 1


class _Sandbox:
    def __init__(self, result=None):
        self.calls, self.result = [], result or _Res()

    def run(self, code):
        self.calls.append(code)
        return self.result


def _call(server, name, arguments=None, msg_id=1):
    return server.handle({"jsonrpc": "2.0", "id": msg_id, "method": "tools/call",
                          "params": {"name": name, "arguments": arguments or {}}})


def test_initialize_and_tools_list():
    server = AegisMcpServer(_Sandbox())
    init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                          "params": {"protocolVersion": "2025-03-26"}})
    assert init["result"]["protocolVersion"] == "2025-03-26"
    assert "tools" in init["result"]["capabilities"]
    tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert {t["name"] for t in tools["result"]["tools"]} == {"execute_python", "audit_status"}


def test_notifications_get_no_reply():
    server = AegisMcpServer(_Sandbox())
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_safe_code_runs():
    sandbox = _Sandbox()
    reply = _call(AegisMcpServer(sandbox), "execute_python", {"code": "print(42)"})
    assert reply["result"]["isError"] is False
    assert reply["result"]["content"][0]["text"] == "42\n"
    assert sandbox.calls == ["print(42)"]


def test_dangerous_code_is_blocked_and_never_runs():
    sandbox = _Sandbox()
    reply = _call(AegisMcpServer(sandbox), "execute_python", {"code": "import os"})
    assert reply["result"]["isError"] is True
    assert "BLOCKED" in reply["result"]["content"][0]["text"]
    assert sandbox.calls == []


def test_failed_execution_is_an_error_result():
    reply = _call(AegisMcpServer(_Sandbox(_Res(False, "", "boom"))),
                  "execute_python", {"code": "print(1)"})
    assert reply["result"]["isError"] is True
    assert "boom" in reply["result"]["content"][0]["text"]


def test_bad_arguments_and_unknown_things():
    server = AegisMcpServer(_Sandbox())
    assert _call(server, "execute_python", {"code": 5})["result"]["isError"] is True
    assert _call(server, "nope")["error"]["code"] == -32602
    assert server.handle({"jsonrpc": "2.0", "id": 9, "method": "x"})["error"]["code"] == -32601


def test_audit_status_reports_valid_chain_after_calls():
    server = AegisMcpServer(_Sandbox())
    _call(server, "execute_python", {"code": "print(1)"})
    _call(server, "execute_python", {"code": "import os"})
    text = _call(server, "audit_status")["result"]["content"][0]["text"]
    assert "chain_valid=True" in text and "entries=4" in text


def test_stdio_loop_round_trip():
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        "not json",
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    ]
    out = io.StringIO()
    serve(AegisMcpServer(_Sandbox()), io.StringIO("\n".join(lines) + "\n"), out)
    replies = [json.loads(l) for l in out.getvalue().splitlines()]
    assert replies[0]["result"] == {} and replies[1]["error"]["code"] == -32700
    assert len(replies) == 2


def test_server_refuses_to_start_without_an_explicit_mode():
    assert main([]) == 2 and main(["--docker", "--unsafe-local"]) == 2
