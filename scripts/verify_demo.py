"""Shows declared vs. verified isolation for a backend that lies."""
import subprocess
import sys

from aegis.core.models import SandboxResult
from aegis.runtime.isolation import IsolationBackend, IsolationCapabilities
from aegis.runtime.sandbox import RuntimeSandbox, SandboxSecurityPolicy
from aegis.runtime.verify import VerifiedBackend, verify_backend


class LyingBackend(IsolationBackend):
    """Claims full isolation, but runs code in a plain local subprocess."""

    def is_available(self):
        return True

    def capabilities(self):
        return IsolationCapabilities(True, True, True)

    def run(self, code, timeout):
        p = subprocess.run([sys.executable, "-c", code], capture_output=True,
                           text=True, timeout=timeout)
        return SandboxResult(p.returncode == 0, p.stdout, p.stderr, p.returncode)


def mark(value):
    return "yes" if value else "NO"


def main():
    backend = LyingBackend()
    report = verify_backend(backend)
    print("Capability            declared  verified  why")
    for name in ("network_isolation", "filesystem_isolation", "process_isolation"):
        print(f"{name:<21} {mark(getattr(report.declared, name)):<9} "
              f"{mark(getattr(report.verified, name)):<9} {report.details[name]}")
    print("\nBackend lied about:", ", ".join(report.lies()) or "nothing")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(require_network_isolation=True),
        isolation_backend=VerifiedBackend(backend),
    )
    result = sandbox.run("print('this must not run')")
    print("\nPolicy requires network isolation; running on the lying backend:")
    print("  success:", result.success)
    print("  reason :", result.stderr)


if __name__ == "__main__":
    main()
