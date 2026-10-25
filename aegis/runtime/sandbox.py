import math
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass

from aegis.core.models import SandboxResult
from aegis.runtime.backends import NoIsolationBackend
from aegis.runtime.isolation import (
    IsolationBackend,
    IsolationCapabilities,
)


# Only these variables reach untrusted code. API keys and other secrets
# in the parent environment are NOT inherited.
_SAFE_ENV_KEYS = frozenset({
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "TEMP", "TMP", "PATH",
    "PATHEXT", "COMSPEC", "LANG", "LC_ALL",
})


def _clean_env() -> dict:
    return {k: v for k, v in os.environ.items() if k.upper() in _SAFE_ENV_KEYS}


@dataclass(frozen=True)
class SandboxSecurityPolicy:
    allow_network: bool = False
    require_network_isolation: bool = False
    require_filesystem_isolation: bool = False
    require_process_isolation: bool = False
    # Local execution has NO real isolation (network, filesystem and
    # environment variables are all accessible). It must be opted into.
    allow_unsafe_local: bool = False

    def network_allowed(self) -> bool:
        return self.allow_network

    def requires_network_isolation(self) -> bool:
        return self.require_network_isolation

    def requires_filesystem_isolation(self) -> bool:
        return self.require_filesystem_isolation

    def requires_process_isolation(self) -> bool:
        return self.require_process_isolation

    def unsafe_local_allowed(self) -> bool:
        return self.allow_unsafe_local


class RuntimeSandbox:
    def __init__(
        self,
        timeout: float = 10.0,
        max_output_size: int = 1_000_000,
        allow_network: bool = False,
        security_policy: SandboxSecurityPolicy | None = None,
        isolation_backend: IsolationBackend | None = None,
    ):
        if isinstance(timeout, bool) or not isinstance(
            timeout, (int, float)
        ):
            raise TypeError("Timeout must be a number.")

        if not math.isfinite(timeout):
            raise ValueError("Timeout must be finite.")

        if timeout <= 0:
            raise ValueError("Timeout must be greater than zero.")

        if isinstance(max_output_size, bool):
            raise TypeError("Max output size must be an integer.")

        if isinstance(max_output_size, float):
            if max_output_size == 0:
                raise ValueError(
                    "Max output size must be greater than zero."
                )
            raise TypeError("Max output size must be an integer.")

        if not isinstance(max_output_size, int):
            raise TypeError("Max output size must be an integer.")

        if max_output_size <= 0:
            raise ValueError(
                "Max output size must be greater than zero."
            )

        self.timeout = float(timeout)
        self.max_output_size = max_output_size

        self._explicit_security_policy = security_policy is not None
        self._explicit_isolation_backend = isolation_backend is not None

        self.security_policy = (
            security_policy
            if security_policy is not None
            else SandboxSecurityPolicy(allow_network=allow_network)
        )

        self.isolation_backend = (
            isolation_backend
            if isolation_backend is not None
            else NoIsolationBackend()
        )

        if not isinstance(self.isolation_backend, IsolationBackend):
            raise TypeError("Invalid isolation backend.")

        if not isinstance(self.security_policy, SandboxSecurityPolicy):
            raise TypeError("Invalid security policy.")

        self.allow_network = self.security_policy.allow_network

    def isolation_capabilities(self):
        return self.isolation_backend.capabilities()

    def _failure(self, message: str) -> SandboxResult:
        return SandboxResult(
            success=False,
            stdout="",
            stderr=message,
            exit_code=-1,
        )

    def _validate_backend_result(self, result) -> SandboxResult:
        if not isinstance(result, SandboxResult):
            return self._failure(
                "Isolation backend returned an invalid result."
            )

        if (
            type(result.success) is not bool
            or type(result.exit_code) is not int
            or not isinstance(result.stdout, str)
            or not isinstance(result.stderr, str)
        ):
            return self._failure(
                "Isolation backend returned an invalid result."
            )

        # Preserve valid backend results exactly as returned.
        return result

    def _validate_capabilities(
        self,
        capabilities,
        requires_network: bool,
        requires_filesystem: bool,
        requires_process: bool,
    ) -> SandboxResult | None:
        if not isinstance(capabilities, IsolationCapabilities):
            return self._failure(
                "Isolation backend returned invalid capabilities."
            )

        values = (
            capabilities.network_isolation,
            capabilities.filesystem_isolation,
            capabilities.process_isolation,
        )

        if not all(type(value) is bool for value in values):
            return self._failure(
                "Isolation backend returned invalid capability types."
            )

        if requires_network and not capabilities.network_isolation:
            return self._failure(
                "Required network isolation capability "
                "is unavailable on this backend."
            )

        if (
            requires_filesystem
            and not capabilities.filesystem_isolation
        ):
            return self._failure(
                "Required filesystem isolation capability "
                "is unavailable on this backend."
            )

        if requires_process and not capabilities.process_isolation:
            return self._failure(
                "Required process isolation capability "
                "is unavailable on this backend."
            )

        return None

    def _run_local(self, code: str) -> SandboxResult:
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                process = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-u",
                        "-X",
                        "utf8",
                        "-c",
                        code,
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.timeout,
                    cwd=temp_dir,
                    env=_clean_env(),
                )

            stdout = process.stdout
            stderr = process.stderr

            if len(stdout) > self.max_output_size:
                return SandboxResult(
                    success=False,
                    stdout=stdout[:self.max_output_size],
                    stderr="Output exceeded the maximum allowed size.",
                    exit_code=-1,
                )

            if len(stderr) > self.max_output_size:
                return SandboxResult(
                    success=False,
                    stdout=stdout,
                    stderr=(
                        stderr[:self.max_output_size]
                        + "\nError output exceeded the maximum allowed size."
                    ),
                    exit_code=-1,
                )

            return SandboxResult(
                success=process.returncode == 0,
                stdout=stdout,
                stderr=stderr,
                exit_code=process.returncode,
            )

        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""

            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")

            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")

            return SandboxResult(
                success=False,
                stdout=stdout[:self.max_output_size],
                stderr=(
                    stderr[:self.max_output_size]
                    + "\nExecution timed out."
                ),
                exit_code=-1,
            )

        except Exception as exc:
            return self._failure(
                f"Local execution failed: {exc}"
            )

    def run(self, code: str) -> SandboxResult:
        if not isinstance(code, str):
            return self._failure("Code must be a string.")

        if not code.strip():
            return self._failure("Code cannot be empty.")

        requires_network = (
            self.security_policy.requires_network_isolation()
        )
        requires_filesystem = (
            self.security_policy.requires_filesystem_isolation()
        )
        requires_process = (
            self.security_policy.requires_process_isolation()
        )

        requires_backend = (
            requires_network
            or requires_filesystem
            or requires_process
        )

        # When network access is allowed, secure network isolation
        # must be explicitly required.
        if self.allow_network and not requires_network:
            if requires_backend:
                # Continue to validate the requested backend and its
                # capabilities before refusing execution.
                pass
            else:
                return self._failure(
                    "Network access requires secure network isolation; "
                    "a network isolation backend is required."
                )

        # No isolation requested: local execution is NOT isolated,
        # so it only runs when explicitly allowed by the policy.
        if not requires_backend:
            if not self.security_policy.unsafe_local_allowed():
                return self._failure(
                    "Local execution is NOT isolated. "
                    "Set allow_unsafe_local=True to run it explicitly."
                )
            return self._run_local(code)

        try:
            availability = self.isolation_backend.is_available()
        except Exception as exc:
            return self._failure(
                f"Isolation backend availability check failed: {exc}"
            )

        if type(availability) is not bool:
            return self._failure(
                "Isolation backend returned invalid availability."
            )

        if not availability:
            required = []

            if requires_network:
                required.append("network")
            if requires_filesystem:
                required.append("filesystem")
            if requires_process:
                required.append("process")

            isolation_name = "/".join(required)
            if requires_network and not self.allow_network:
                message = (
                    "Network access is disabled by security policy; "
                    "Secure network isolation is unavailable."
                )
            elif requires_network:
                message = (
                    "Secure network isolation is unavailable on this "
                    "runtime; network isolation backend is unavailable."
                )
            else:
                message = (
                    f"Required {isolation_name} isolation backend "
                    "is unavailable on this runtime."
                )

            return self._failure(message)

        try:
            capabilities = self.isolation_backend.capabilities()
        except Exception as exc:
            return self._failure(
                f"Isolation backend capability check failed: {exc}"
            )

        capability_error = self._validate_capabilities(
            capabilities,
            requires_network,
            requires_filesystem,
            requires_process,
        )

        if capability_error is not None:
            return capability_error

        # If network use is allowed, network isolation must be explicitly
        # required before this backend can execute code.
        if self.allow_network and not requires_network:
            return self._failure(
                "Network access requires secure network isolation; "
                "a network isolation backend is required."
            )

        try:
            result = self.isolation_backend.run(
                code,
                timeout=self.timeout,
            )
        except Exception as exc:
            return self._failure(str(exc))

        return self._validate_backend_result(result)