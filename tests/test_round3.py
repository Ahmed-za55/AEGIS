import os

import pytest

from aegis.guard import check_code
from aegis.pipeline import HashChainLog
from tests.helpers import unsafe_sandbox


@pytest.mark.parametrize("code", [
    "import typing\ndef f(x: \"__import__('os').system('echo hi')\"):\n    pass\ntyping.get_type_hints(f)",
    "from typing import get_type_hints",
    "from typing import ForwardRef",
    "import functools\n@functools.singledispatch\ndef g(a):\n    pass",
    "help('modules')",
    "license()",
    "exit()",
])
def test_hidden_eval_and_site_builtins_are_blocked(code):
    assert not check_code(code).allowed


def test_child_process_does_not_inherit_secrets(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_CANARY", "topsecret")
    monkeypatch.setenv("NEBIUS_API_KEY", "nb-canary")
    result = unsafe_sandbox().run(
        "import os\n"
        "print(os.environ.get('AEGIS_SECRET_CANARY'), "
        "os.environ.get('NEBIUS_API_KEY'))")
    assert result.success and result.stdout.strip() == "None None"


def test_isolated_mode_ignores_pythonpath(monkeypatch, tmp_path):
    (tmp_path / "evilmod.py").write_text("print('LOADED')")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    result = unsafe_sandbox().run("import evilmod")
    assert result.success is False


def _sample_log():
    log = HashChainLog()
    log.append("proposed", {"task": "t", "attempt": 1})
    log.append("blocked", {"reasons": ["x"], "attempt": 1})
    log.append("executed", {"success": True, "attempt": 2})
    return log


def test_log_round_trip_and_first_invalid(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = _sample_log()
    log.save(path)
    loaded = HashChainLog.load(path)
    assert loaded.verify() and loaded.head() == log.head()
    loaded.entries[1]["data"]["reasons"] = ["edited"]
    assert loaded.first_invalid() == 1


def test_truncation_is_detected_with_head_hash(tmp_path):
    log = _sample_log()
    head = log.head()
    del log.entries[-1]
    assert log.verify()            # a bare chain cannot see tail truncation
    assert log.head() != head      # an externally stored head can


def test_malformed_entry_counts_as_invalid():
    log = _sample_log()
    del log.entries[2]["hash"]
    assert log.first_invalid() == 2
