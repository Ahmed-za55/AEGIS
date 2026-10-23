from .models import ExecutionSummary, TaskStatus
from .trace import ExecutionTrace


def create_execution_summary(
    trace: ExecutionTrace,
    status: TaskStatus,
) -> ExecutionSummary:

    return ExecutionSummary(
        task_id=trace.task_id,
        status=status,
        total_events=trace.total_events,
        successful_events=trace.successful_events,
        failed_events=trace.failed_events,
        denied_events=trace.denied_events,
    )