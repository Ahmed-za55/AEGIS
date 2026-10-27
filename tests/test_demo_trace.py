import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _demo():
    spec = importlib.util.spec_from_file_location("demo_trace", ROOT / "scripts" / "demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_show_code_prints_each_attempt_and_the_verdict(capsys):
    assert _demo().main(["--show-code"]) == 0
    out = capsys.readouterr().out
    assert "attempt 1 -> BLOCKED" in out and "attempt 2 -> EXECUTED" in out
    assert "| import urllib.request" in out
    assert "! import of 'urllib.request' is not allowed" in out


def test_default_output_has_no_code_listing(capsys):
    assert _demo().main([]) == 0
    assert "|" not in capsys.readouterr().out
