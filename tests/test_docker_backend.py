import subprocess

import pytest

from aegis.runtime.docker_backend import DockerIsolationBackend
from aegis.runtime.isolation import IsolationCapabilities
from aegis.runtime.verify import verify_backend


class FakeRunner:
    def __init__(self, returncode=0, stdout="", stderr="", raises=None):
        self.calls, self.returncode = [], returncode
        self.stdout, self.stderr, self.raises = stdout, stderr, raises

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if self.raises and cmd[1] == "run":
            raise self.raises
        return subprocess.CompletedProcess(cmd, self.returncode,
                                           self.stdout, self.stderr)


def _flag_value(cmd, flag):
    return cmd[cmd.index(flag) + 1]


def test_command_enforces_isolation_flags():
    cmd = DockerIsolationBackend().build_command("n")
    assert _flag_value(cmd, "--network") == "none"
    assert _flag_value(cmd, "--cap-drop") == "ALL"
    assert _flag_value(cmd, "--user") == "65534:65534"
    assert _flag_value(cmd, "--security-opt") == "no-new-privileges"
    assert "--read-only" in cmd and "--rm" in cmd
    assert _flag_value(cmd, "--pids-limit") == "64"
    assert _flag_value(cmd, "--memory") == _flag_value(cmd, "--memory-swap")
    assert cmd[-3:] == ["python", "-I", "-"]


def test_code_is_sent_over_stdin_not_argv():
    runner = FakeRunner(stdout="hi\n")
    result = DockerIsolationBackend(runner=runner).run("print('hi')", 5)
    cmd, kwargs = runner.calls[0]
    assert kwargs["input"] == "print('hi')" and "print('hi')" not in cmd
    assert result.success and result.stdout == "hi\n"


def test_nonzero_exit_is_failure():
    result = DockerIsolationBackend(
        runner=FakeRunner(returncode=1, stderr="boom")).run("x", 5)
    assert result.success is False and result.exit_code == 1


def test_timeout_kills_the_container():
    runner = FakeRunner(raises=subprocess.TimeoutExpired("docker", 1))
    result = DockerIsolationBackend(runner=runner).run("while True: pass", 1)
    assert result.success is False and "timed out" in result.stderr
    assert runner.calls[-1][0][1] == "kill"


def test_output_cap():
    runner = FakeRunner(stdout="x" * 50)
    result = DockerIsolationBackend(runner=runner, max_output_size=10).run("x", 5)
    assert result.success is False and len(result.stdout) == 10


def test_unavailable_when_docker_missing():
    def missing(cmd, **kwargs):
        raise FileNotFoundError("docker")

    assert DockerIsolationBackend(runner=missing).is_available() is False
    assert DockerIsolationBackend(runner=FakeRunner(returncode=1)).is_available() is False


_real = DockerIsolationBackend()


@pytest.mark.skipif(not _real.is_available(), reason="Docker not available")
def test_real_docker_passes_all_probes():
    report = verify_backend(_real, timeout=60)
    assert report.verified == IsolationCapabilities(True, True, True), report.details
