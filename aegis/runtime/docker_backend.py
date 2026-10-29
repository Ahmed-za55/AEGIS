"""Docker isolation backend.

Runs untrusted Python in a throw-away container: no network, read-only root
filesystem, no capabilities, memory/CPU/pid limits, unprivileged user.
Wrap it in VerifiedBackend so the claimed isolation is proven by probes
before the sandbox relies on it.
"""
import subprocess
import uuid

from aegis.core.models import SandboxResult
from aegis.runtime.isolation import IsolationBackend, IsolationCapabilities


class DockerIsolationBackend(IsolationBackend):
    def __init__(self, image: str = "python:3.12-slim", memory: str = "256m",
                 cpus: str = "1", pids_limit: int = 64,
                 max_output_size: int = 1_000_000,
                 docker: str = "docker", runner=subprocess.run):
        self.image, self.memory, self.cpus = image, memory, cpus
        self.pids_limit, self.max_output_size = pids_limit, max_output_size
        self.docker, self._run = docker, runner

    def is_available(self) -> bool:
        try:
            result = self._run([self.docker, "info"], capture_output=True,
                               timeout=5)
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def capabilities(self) -> IsolationCapabilities:
        # Declared. VerifiedBackend proves them with probes.
        return IsolationCapabilities(True, True, True)

    def build_command(self, name: str) -> list[str]:
        return [
            self.docker, "run", "--rm", "-i", "--name", name,
            "--network", "none",
            "--ipc", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--memory", self.memory,
            "--memory-swap", self.memory,
            "--cpus", self.cpus,
            "--pids-limit", str(self.pids_limit),
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", "65534:65534",
            self.image, "python", "-I", "-",
        ]

    def run(self, code: str, timeout: float) -> SandboxResult:
        name = f"aegis-{uuid.uuid4().hex[:12]}"
        try:
            proc = self._run(
                self.build_command(name), input=code, capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            self._run([self.docker, "kill", name], capture_output=True)
            return SandboxResult(False, "", "Execution timed out.", -1)

        stdout, stderr = proc.stdout or "", proc.stderr or ""
        cap = self.max_output_size
        if len(stdout) > cap:
            return SandboxResult(False, stdout[:cap],
                                 "Output exceeded the maximum allowed size.", -1)
        if len(stderr) > cap:
            return SandboxResult(
                False, stdout,
                stderr[:cap] + "\nError output exceeded the maximum allowed size.",
                -1)
        return SandboxResult(proc.returncode == 0, stdout, stderr,
                             proc.returncode)
