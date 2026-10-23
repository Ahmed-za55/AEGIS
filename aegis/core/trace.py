from dataclasses import dataclass

from .audit import AuditEvent


@dataclass
class ExecutionTrace:

    task_id: str
    events: list[AuditEvent]

    @property
    def total_events(self) -> int:
        return len(self.events)

    @property
    def successful_events(self) -> int:
        return sum(
            event.success
            for event in self.events
        )

    @property
    def failed_events(self) -> int:
        return sum(
            not event.success
            for event in self.events
        )

    @property
    def denied_events(self) -> int:
        return sum(
            not event.policy_allowed
            for event in self.events
        )