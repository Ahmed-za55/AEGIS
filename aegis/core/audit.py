from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


@dataclass
class AuditEvent:

    event_id: str = field(
        default_factory=lambda: str(uuid4())
    )

    task_id: str = ""

    tool_name: str = ""

    arguments: dict[str, Any] = field(
        default_factory=dict
    )

    policy_allowed: bool = False

    success: bool = False

    output: Any = None

    error: str | None = None

    timestamp: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )


class AuditLogger:

    def __init__(self):
        self._events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self._events.append(event)

    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def get_by_task(
        self,
        task_id: str,
    ) -> list[AuditEvent]:

        return [
            event
            for event in self._events
            if event.task_id == task_id
        ]

    def get_by_tool(
        self,
        tool_name: str,
    ) -> list[AuditEvent]:

        return [
            event
            for event in self._events
            if event.tool_name == tool_name
        ]

    def successful_events(self) -> list[AuditEvent]:

        return [
            event
            for event in self._events
            if event.success
        ]

    def failed_events(self) -> list[AuditEvent]:

        return [
            event
            for event in self._events
            if not event.success
        ]

    def denied_events(self) -> list[AuditEvent]:

        return [
            event
            for event in self._events
            if not event.policy_allowed
        ]

    def clear(self) -> None:
        self._events.clear()