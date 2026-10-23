from aegis.core.models import SandboxResult
from aegis.runtime.isolation import IsolationBackend, IsolationCapabilities


class NoIsolationBackend(IsolationBackend):

    def is_available(self) -> bool:
        return False

    def capabilities(self) -> IsolationCapabilities:
        return IsolationCapabilities(
            network_isolation=False,
            filesystem_isolation=False,
            process_isolation=False,
        )

    def run(self, code: str, timeout: float) -> SandboxResult:
        raise RuntimeError("No real isolation backend is available.")