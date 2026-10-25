from aegis.pipeline import HashChainLog


def _forge(original, key=None):
    forged = HashChainLog(key=key)
    for e in original.entries:
        event, data = e["event"], dict(e["data"])
        if event == "blocked":
            event, data = "executed", {"ok": True}
        forged.append(event, data)
    return forged


def _log(key=None):
    log = HashChainLog(key=key)
    log.append("proposed", {"task": "t"})
    log.append("blocked", {"reasons": ["x"]})
    log.append("executed", {"ok": True})
    return log


def test_unkeyed_chain_can_be_forged_by_recomputing():
    assert _forge(_log()).verify()          # documents the weakness


def test_keyed_chain_rejects_forgery_without_the_key():
    original = _log(key=b"secret")
    forged = _forge(original, key=None)     # attacker has no key
    forged_with_key_check = HashChainLog(key=b"secret")
    forged_with_key_check.entries = forged.entries
    assert not forged_with_key_check.verify()


def test_keyed_chain_verifies_with_the_right_key_only(tmp_path):
    path = tmp_path / "a.jsonl"
    _log(key=b"secret").save(path)
    assert HashChainLog.load(path, key=b"secret").verify()
    assert not HashChainLog.load(path, key=b"wrong").verify()
    assert not HashChainLog.load(path).verify()


def test_runner_uses_env_key(monkeypatch):
    from aegis.pipeline import SecureCodeRunner

    class L:
        def propose_code(self, task, feedback=None):
            return "print(1)"

    class R:
        success, stdout, stderr, exit_code = True, "1", "", 0

    class S:
        def run(self, code):
            return R()

    monkeypatch.setenv("AEGIS_AUDIT_KEY", "k")
    runner = SecureCodeRunner(L(), S())
    runner.run("t")
    assert runner.log.verify()
    other = HashChainLog(key=b"other")
    other.entries = runner.log.entries
    assert not other.verify()
