from aegis.__main__ import main
from aegis.pipeline import HashChainLog, RunReport
from aegis.html_report import render_html


def _log():
    log = HashChainLog()
    log.append("proposed", {"attempt": 1})
    log.append("blocked", {"attempt": 1})
    return log


def test_report_escapes_attacker_controlled_text():
    evil = "<script>alert(1)</script>"
    report = RunReport(task=evil, status="blocked", code=evil,
                       reasons=(evil,), stdout=evil)
    page = render_html([report], _log(), benchmark_md=evil)
    assert "<script>" not in page
    assert page.count("&lt;script&gt;") >= 4


def test_report_shows_status_counts_and_chain_state():
    reports = [RunReport("a", "executed", "print(1)", stdout="1"),
               RunReport("b", "blocked", "import os", reasons=("no",))]
    page = render_html(reports, _log())
    assert "1 executed, 1 blocked, 0 failed" in page and "CHAIN VALID" in page
    broken = _log()
    broken.entries[0]["event"] = "tampered"
    assert "CHAIN BROKEN" in render_html(reports, broken)


def test_cli_usage_and_unknown_command(capsys):
    assert main([]) == 2
    assert main(["--help"]) == 0
    assert main(["bogus"]) == 2
    assert "Unknown command" in capsys.readouterr().err


def test_cli_runs_the_benchmark(capsys):
    assert main(["bench"]) == 0
    assert "Total" in capsys.readouterr().out
