import subprocess
import sys

from aegis.core.models import SandboxResult
from aegis.runtime.isolation import IsolationBackend, IsolationCapabilities
from aegis.runtime.sandbox import RuntimeSandbox, SandboxSecurityPolicy
from aegis.runtime.verify import VerifiedBackend, verify_backend

ALL = IsolationCapabilities(True, True, True)
NONE = IsolationCapabilities(False, False, False)


class LyingBackend(IsolationBackend):
    """Claims full isolation but runs code in a plain local subprocess."""

    def __init__(self):
        self.calls = 0

    def is_available(self):
        return True

    def capabilities(self):
        return ALL

    def run(self, code, timeout):
        self.calls += 1
        p = subprocess.run([sys.executable, "-c", code], capture_output=True,
                           text=True, timeout=timeout)
        return SandboxResult(p.returncode == 0, p.stdout, p.stderr, p.returncode)


class ContainedBackend(LyingBackend):
    """Simulates real isolation: nothing is reachable, nothing is shared."""

    def run(self, code, timeout):
        self.calls += 1
        return SandboxResult(True, "CONTAINED\n", "", 0)


class CrashingBackend(LyingBackend):
    def run(self, code, timeout):
        raise RuntimeError("boom")


def test_lying_backend_is_caught_on_all_capabilities():
    report = verify_backend(LyingBackend())
    assert report.declared == ALL
    assert report.verified == NONE
    assert set(report.lies()) == {
        "network_isolation", "filesystem_isolation", "process_isolation"}


def test_contained_backend_is_verified():
    report = verify_backend(ContainedBackend())
    assert report.verified == ALL and report.lies() == []


def test_undeclared_capabilities_are_not_probed():
    class Honest(LyingBackend):
        def capabilities(self):
            return NONE

    backend = Honest()
    report = verify_backend(backend)
    assert backend.calls == 0 and report.verified == NONE


def test_crashing_backend_fails_closed():
    assert verify_backend(CrashingBackend()).verified == NONE


def test_verified_backend_exposes_only_proven_capabilities():
    wrapped = VerifiedBackend(LyingBackend())
    assert wrapped.capabilities() == NONE and wrapped.is_available() is True


def test_sandbox_refuses_to_run_on_a_lying_backend():
    policy = SandboxSecurityPolicy(require_network_isolation=True)
    sandbox = RuntimeSandbox(security_policy=policy,
                             isolation_backend=VerifiedBackend(LyingBackend()))
    result = sandbox.run("print('should not run')")
    assert result.success is False
    assert "network isolation capability" in result.stderr
