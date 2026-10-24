"""Verified capabilities: don't trust declared isolation, prove it.

For every capability a backend DECLARES, run a harmless probe through the
backend's own run(). If the probe shows the program can still reach the
resource, the capability is downgraded to False. Fail-closed: a probe that
cannot run counts as not verified.
"""
import os
import socket
import tempfile
from dataclasses import dataclass, field

from aegis.runtime.isolation import IsolationBackend, IsolationCapabilities


@dataclass(frozen=True)
class VerificationReport:
    declared: IsolationCapabilities
    verified: IsolationCapabilities
    details: dict = field(default_factory=dict)

    def lies(self) -> list[str]:
        out = []
        for name in ("network_isolation", "filesystem_isolation",
                     "process_isolation"):
            if getattr(self.declared, name) and not getattr(self.verified, name):
                out.append(name)
        return out


def _run(backend, code, timeout):
    try:
        return backend.run(code, timeout)
    except Exception as exc:  # backend crashed: not verified
        return exc


def _probe_network(backend, timeout):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    code = (
        "import socket\n"
        "try:\n"
        f"    socket.create_connection(('127.0.0.1', {port}), timeout=1).close()\n"
        "    print('ESCAPED')\n"
        "except Exception:\n"
        "    print('CONTAINED')\n"
    )
    try:
        result = _run(backend, code, timeout)
    finally:
        listener.close()
    if isinstance(result, Exception) or not result.success:
        return False, "probe could not run"
    if "ESCAPED" in result.stdout:
        return False, "program reached a host TCP port"
    return "CONTAINED" in result.stdout, "contained"


def _probe_filesystem(backend, timeout):
    with tempfile.TemporaryDirectory() as host_dir:
        target = os.path.join(host_dir, "aegis_probe.txt")
        code = (
            "try:\n"
            f"    open({target!r}, 'w').write('x')\n"
            "except Exception:\n"
            "    pass\n"
            "print('DONE')\n"
        )
        result = _run(backend, code, timeout)
        if isinstance(result, Exception) or not result.success:
            return False, "probe could not run"
        if os.path.exists(target):
            return False, "program wrote to a host path"
        return True, "contained"


_PROCESS_PROBE = """
import os, sys
pid = __PID__
if sys.platform == "win32":
    import ctypes
    k = ctypes.windll.kernel32
    k.OpenProcess.restype = ctypes.c_void_p
    k.CloseHandle.argtypes = [ctypes.c_void_p]
    h = k.OpenProcess(0x1000, False, pid)
    visible = bool(h)
    if h:
        k.CloseHandle(h)
else:
    try:
        os.kill(pid, 0)
        visible = True
    except ProcessLookupError:
        visible = False
    except PermissionError:
        visible = True
print("ESCAPED" if visible else "CONTAINED")
"""


def _probe_process(backend, timeout):
    """Can the program see the runner's own process (host PID namespace)?"""
    code = _PROCESS_PROBE.replace("__PID__", str(os.getpid()))
    result = _run(backend, code, timeout)
    if isinstance(result, Exception) or not result.success:
        return False, "probe could not run"
    if "ESCAPED" in result.stdout:
        return False, "program can see the runner's process"
    return "CONTAINED" in result.stdout, "contained"


_PROBES = {
    "network_isolation": _probe_network,
    "filesystem_isolation": _probe_filesystem,
    "process_isolation": _probe_process,
}


def verify_backend(backend: IsolationBackend,
                   timeout: float = 10.0) -> VerificationReport:
    declared = backend.capabilities()
    verified, details = {}, {}
    for name, probe in _PROBES.items():
        if not getattr(declared, name):
            verified[name], details[name] = False, "not declared"
            continue
        ok, why = probe(backend, timeout)
        verified[name], details[name] = ok, why
    return VerificationReport(declared, IsolationCapabilities(**verified), details)


class VerifiedBackend(IsolationBackend):
    """Wraps a backend and exposes only the capabilities that were proven."""

    def __init__(self, backend: IsolationBackend, timeout: float = 10.0):
        self._backend = backend
        self._timeout = timeout
        self._report = None

    @property
    def report(self) -> VerificationReport:
        if self._report is None:
            self._report = verify_backend(self._backend, self._timeout)
        return self._report

    def is_available(self) -> bool:
        return self._backend.is_available()

    def capabilities(self) -> IsolationCapabilities:
        return self.report.verified

    def run(self, code: str, timeout: float):
        return self._backend.run(code, timeout)
