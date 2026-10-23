from aegis.runtime.backends import NoIsolationBackend
from aegis.runtime.isolation import IsolationCapabilities


class WindowsIsolationBackend(NoIsolationBackend):
    """
    Placeholder for a future Windows OS-level isolation backend.

    This backend is intentionally unavailable until real OS-level
    isolation is implemented.
    """

    def is_available(self) -> bool:
        return False

    def capabilities(self) -> IsolationCapabilities:
        return IsolationCapabilities(
            network_isolation=False,
            filesystem_isolation=False,
            process_isolation=False,
        )