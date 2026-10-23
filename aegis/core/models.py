from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .trace import ExecutionTrace
from uuid import uuid4
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .trace import ExecutionTrace

class TaskStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

@dataclass
class Task:
    description: str
    requirements: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    expected_outcome: str | None = None
    id: str = field(default_factory=lambda: str(uuid4()))
    status: TaskStatus = TaskStatus.PENDING

@dataclass
class ToolCall:
    tool_name: str
    arguments: dict[str, Any]
    call_id: str = field(default_factory=lambda: str(uuid4()))


@dataclass
class PlanStep:
    id: str
    description: str
    tool_call: ToolCall | None = None


@dataclass
class Plan:
    task_id: str
    steps: list[PlanStep]
    strategy: str | None = None
    expected_result: str | None = None
    requirements: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)
    
@dataclass
class Observation:
    step_id: str
    success: bool
    output: Any = None
    error: str | None = None


@dataclass
class ExecutionContext:
    task_id: str
    variables: dict[str, Any] = field(default_factory=dict)

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .trace import ExecutionTrace
    
@dataclass
class ExecutionResult:
    task_id: str
    status: TaskStatus
    observations: list[Observation]
    trace: "ExecutionTrace | None" = None
    summary: ExecutionSummary | None = None
    
@dataclass
class ExecutionSummary:

    task_id: str
    status: TaskStatus
    total_events: int
    successful_events: int
    failed_events: int
    denied_events: int
    
@dataclass
class SandboxResult:
    success: bool
    stdout: str
    stderr: str
    exit_code: int