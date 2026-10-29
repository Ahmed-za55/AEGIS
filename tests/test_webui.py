import json
import threading
import urllib.error
import urllib.request

from aegis.webui import AppState, handle, make_server


class _Res:
    def __init__(self, ok=True, out="55\n"):
        self.success, self.stdout, self.stderr = ok, out, ""
        self.exit_code = 0 if ok else 1


class _Sandbox:
    def __init__(self):
        self.calls = []

    def run(self, code):
        self.calls.append(code)
        return _Res()


def _state(**kw):
    return AppState(_Sandbox(), token="tok", **kw)


GOOD = {"Host": "127.0.0.1:8765", "X-AEGIS-Token": "tok",
        "Content-Type": "application/json"}


def _post(state, path, payload=None, headers=None):
    status, ctype, data = handle(state, "POST", path, headers or GOOD,
                                 json.dumps(payload or {}).encode())
    return status, json.loads(data)


def test_page_is_served_with_the_token_and_only_to_localhost():
    state = _state()
    status, ctype, data = handle(state, "GET", "/", {"Host": "localhost:8765"}, b"")
    assert status == 200 and "text/html" in ctype and b"tok" in data
    assert handle(state, "GET", "/", {"Host": "evil.example"}, b"")[0] == 403
    assert handle(state, "GET", "/nope", {"Host": "127.0.0.1"}, b"")[0] == 404


def test_posts_need_token_json_and_localhost_host():
    state = _state()
    assert _post(state, "/api/audit", headers={**GOOD, "X-AEGIS-Token": "bad"})[0] == 403
    assert _post(state, "/api/audit", headers={**GOOD, "Host": "evil.com"})[0] == 403
    assert _post(state, "/api/audit", headers={**GOOD, "Content-Type": "text/plain"})[0] == 415
    status, _, _ = handle(state, "POST", "/api/audit", GOOD, b"x" * 200_000)
    assert status == 413
    assert handle(state, "POST", "/api/audit", GOOD, b"not json")[0] == 400
    assert handle(state, "PUT", "/", GOOD, b"")[0] == 405


def test_dangerous_code_is_blocked_and_never_reaches_the_sandbox():
    state = _state()
    status, body = _post(state, "/api/run-code", {"code": "import os\nos.system('x')"})
    assert status == 200 and body["status"] == "blocked" and body["reasons"]
    assert state.sandbox.calls == []


def test_safe_code_runs_and_empty_code_is_rejected():
    state = _state()
    _, body = _post(state, "/api/run-code", {"code": "print(55)"})
    assert body["status"] == "executed" and body["stdout"] == "55\n"
    assert "error" in _post(state, "/api/run-code", {"code": "  "})[1]


def test_scripted_task_shows_the_attempt_trace():
    state = _state()
    _, body = _post(state, "/api/run-task",
                    {"task": "Download a file from the internet", "mode": "scripted"})
    assert body["attempts"] == 2 and body["status"] == "executed"
    assert [t["verdict"] for t in body["trace"]] == ["BLOCKED", "EXECUTED"]
    assert "error" in _post(state, "/api/run-task", {"task": "other", "mode": "scripted"})[1]


def test_live_mode_reports_missing_configuration():
    def broken():
        raise RuntimeError("no model")

    state = _state(llm_factory=broken)
    _, body = _post(state, "/api/run-task", {"task": "x", "mode": "live"})
    assert "Model not configured" in body["error"]


def test_audit_tamper_and_reset():
    state = _state()
    _post(state, "/api/run-code", {"code": "print(1)"})
    assert _post(state, "/api/audit")[1]["valid"] is True
    _post(state, "/api/tamper")
    assert _post(state, "/api/audit")[1]["valid"] is False
    _post(state, "/api/reset")
    audit = _post(state, "/api/audit")[1]
    assert audit["valid"] is True and audit["entries"] == []


def test_real_server_round_trip():
    state = _state()
    server = make_server(state, port=0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{port}"
        assert b"AEGIS Playground" in urllib.request.urlopen(base + "/").read()
        req = urllib.request.Request(
            base + "/api/run-code", data=json.dumps({"code": "import socket"}).encode(),
            headers={"Content-Type": "application/json", "X-AEGIS-Token": "tok"})
        assert json.loads(urllib.request.urlopen(req).read())["status"] == "blocked"
        bad = urllib.request.Request(base + "/api/audit", data=b"{}",
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(bad)
            raise AssertionError("expected 403")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
    finally:
        server.shutdown()
        server.server_close()
