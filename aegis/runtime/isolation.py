from abc import ABC, abstractmethod
from dataclasses import dataclass

from aegis.core.models import SandboxResult


@dataclass(frozen=True)
class IsolationCapabilities:
    network_isolation: bool
    filesystem_isolation: bool
    process_isolation: bool


class IsolationBackend(ABC):
    @abstractmethod
    def is_available(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def capabilities(self) -> IsolationCapabilities:
        raise NotImplementedError

    @abstractmethod
    def run(self, code: str, timeout: float) -> SandboxResult:
        raise NotImplementedError