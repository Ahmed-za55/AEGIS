from abc import ABC, abstractmethod
from typing import Any

from .policy import PermissionLevel


class Tool(ABC):

    name: str
    description: str
    permission_level: PermissionLevel = PermissionLevel.SAFE

    @abstractmethod
    def execute(self, **kwargs: Any) -> Any:
        """Execute the tool."""
        raise NotImplementedError