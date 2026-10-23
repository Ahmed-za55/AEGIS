from abc import ABC, abstractmethod

from .models import Plan, Task


class Agent(ABC):

    @abstractmethod
    def plan(self, task: Task) -> Plan:
        """Create an execution plan for a task."""
        raise NotImplementedError