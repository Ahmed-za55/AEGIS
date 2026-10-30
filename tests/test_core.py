from tests.helpers import unsafe_sandbox
from aegis.core.agent import Agent
from aegis.core.engine import ExecutionEngine
from aegis.core.models import (
    Plan,
    PlanStep,
    Task,
    TaskStatus,
    ToolCall,
)
from aegis.core.policy import (
    PermissionLevel,
    PolicyEngine,
)
from aegis.core.registry import ToolRegistry
from aegis.tools.calculator import CalculatorTool
from aegis.core.audit import (
    AuditEvent,
    AuditLogger,
)
from aegis.core.trace import ExecutionTrace
from aegis.core.models import (
    ExecutionContext,
    ExecutionResult,
    ExecutionSummary,
    Observation,
)
from aegis.core.evaluator import PlanEvaluator, EvaluationResult
from dataclasses import FrozenInstanceError
from aegis.runtime.isolation import IsolationBackend, IsolationCapabilities
from aegis.runtime.sandbox import RuntimeSandbox
from aegis.core.summary import create_execution_summary
from aegis.core.engineering_agent import EngineeringAgent
from aegis.core.validator import PlanValidator
from aegis.core.decision import (
    PlanDecision,
    PlanDecisionEngine,
)
import subprocess
import pytest
from aegis.runtime.windows_backend import WindowsIsolationBackend
from aegis.runtime.backends import NoIsolationBackend
from aegis.runtime.sandbox import SandboxSecurityPolicy
from aegis.tools.sandbox import SandboxTool 
from pathlib import Path
from aegis.core.replanner import Replanner
from aegis.core.tool import Tool
from aegis.core.models import (
    SandboxResult,
)
class TestAgent(Agent):
    def plan(self, task):
        return Plan(
            task_id=task.id,
            steps=[
                PlanStep(
                    id="step1",
                    description="Analyze task",
                ),
                PlanStep(
                    id="step2",
                    description="Build API",
                ),
            ],
        )

def plan(self, task: Task) -> Plan:
        return Plan(
            task_id=task.id,
            steps=[
                PlanStep(
                    id="step-1",
                    description="Analyze task",
                ),
                PlanStep(
                    id="step-2",
                    description="Execute solution",
                ),
            ],
        )


def test_agent_execution():

    task = Task(
        description="Build a simple API"
    )

    agent = TestAgent()

    registry = ToolRegistry()

    engine = ExecutionEngine(
        agent=agent,
        tool_registry=registry,
        policy_engine=PolicyEngine(),
    )

    result = engine.run(task)

    assert result.status == TaskStatus.COMPLETED

    assert len(result.observations) == 2

    assert all(
        observation.success
        for observation in result.observations
    )


def test_calculator_tool():

    registry = ToolRegistry()

    calculator = CalculatorTool()

    registry.register(calculator)

    tool = registry.get("calculator")

    result = tool.execute(
        operation="multiply",
        a=12,
        b=5,
    )

    assert result == 60


def test_tool_registry():

    registry = ToolRegistry()

    registry.register(CalculatorTool())

    assert "calculator" in registry.list_tools()


def test_engine_executes_tool():

    registry = ToolRegistry()

    registry.register(CalculatorTool())

    class CalculatorAgent(Agent):

        def plan(self, task: Task) -> Plan:

            return Plan(
                task_id=task.id,
                steps=[
                    PlanStep(
                        id="calculate",
                        description="Multiply numbers",
                        tool_call=ToolCall(
                            tool_name="calculator",
                            arguments={
                                "operation": "multiply",
                                "a": 12,
                                "b": 5,
                            },
                        ),
                    )
                ],
            )

    agent = CalculatorAgent()

    engine = ExecutionEngine(
        agent=agent,
        tool_registry=registry,
        policy_engine=PolicyEngine(),
    )

    task = Task(
        description="Calculate 12 × 5"
    )

    result = engine.run(task)

    assert result.status == TaskStatus.COMPLETED

    assert len(result.observations) == 1

    assert result.observations[0].success is True

    assert result.observations[0].output == 60


def test_safe_tool_is_allowed():

    policy = PolicyEngine(
        max_allowed_level=PermissionLevel.SAFE
    )

    decision = policy.authorize(
        PermissionLevel.SAFE
    )

    assert decision.allowed is True


def test_restricted_tool_is_denied():

    policy = PolicyEngine(
        max_allowed_level=PermissionLevel.SAFE
    )

    decision = policy.authorize(
        PermissionLevel.RESTRICTED
    )

    assert decision.allowed is False


def test_dangerous_tool_is_denied():

    policy = PolicyEngine(
        max_allowed_level=PermissionLevel.SAFE
    )

    decision = policy.authorize(
        PermissionLevel.DANGEROUS
    )

    assert decision.allowed is False


def test_engine_blocks_unauthorized_tool():

    registry = ToolRegistry()

    registry.register(CalculatorTool())

    class CalculatorAgent(Agent):

        def plan(self, task: Task) -> Plan:

            return Plan(
                task_id=task.id,
                steps=[
                    PlanStep(
                        id="calculate",
                        description="Calculate",
                        tool_call=ToolCall(
                            tool_name="calculator",
                            arguments={
                                "operation": "add",
                                "a": 10,
                                "b": 20,
                            },
                        ),
                    )
                ],
            )

    policy = PolicyEngine(
        max_allowed_level=PermissionLevel.SAFE
    )

    engine = ExecutionEngine(
        agent=CalculatorAgent(),
        tool_registry=registry,
        policy_engine=policy,
    )

    task = Task(
        description="Calculate 10 + 20"
    )

    result = engine.run(task)

    assert result.status == TaskStatus.COMPLETED

    assert result.observations[0].success is True


def test_audit_logger_records_event():

    logger = AuditLogger()

    event = AuditEvent(
        task_id="task-1",
        tool_name="calculator",
        arguments={
            "operation": "add",
            "a": 10,
            "b": 20,
        },
        policy_allowed=True,
        success=True,
        output=30,
    )

    logger.record(event)

    events = logger.events()

    assert len(events) == 1
    assert events[0].tool_name == "calculator"
    assert events[0].policy_allowed is True
    assert events[0].success is True
    assert events[0].output == 30


def test_audit_logger_records_denied_event():

    logger = AuditLogger()

    event = AuditEvent(
        task_id="task-2",
        tool_name="shell",
        arguments={
            "command": "rm -rf"
        },
        policy_allowed=False,
        success=False,
        error="POLICY DENIED",
    )

    logger.record(event)

    events = logger.events()

    assert len(events) == 1
    assert events[0].policy_allowed is False
    assert events[0].success is False
    assert events[0].error == "POLICY DENIED"


def test_audit_logger_clear():

    logger = AuditLogger()

    logger.record(
        AuditEvent(
            task_id="task-1",
            tool_name="calculator",
        )
    )

    assert len(logger.events()) == 1

    logger.clear()

    assert len(logger.events()) == 0
    
    
def test_engine_creates_audit_event():

    registry = ToolRegistry()

    registry.register(CalculatorTool())

    audit_logger = AuditLogger()

    class CalculatorAgent(Agent):

        def plan(self, task: Task) -> Plan:

            return Plan(
                task_id=task.id,
                steps=[
                    PlanStep(
                        id="calculate",
                        description="Calculate",
                        tool_call=ToolCall(
                            tool_name="calculator",
                            arguments={
                                "operation": "multiply",
                                "a": 6,
                                "b": 7,
                            },
                        ),
                    )
                ],
            )

    engine = ExecutionEngine(
        agent=CalculatorAgent(),
        tool_registry=registry,
        policy_engine=PolicyEngine(),
        audit_logger=audit_logger,
    )

    task = Task(
        description="Calculate 6 × 7"
    )

    result = engine.run(task)

    assert result.status == TaskStatus.COMPLETED

    events = audit_logger.events()

    assert len(events) == 1

    event = events[0]

    assert event.task_id == task.id
    assert event.tool_name == "calculator"
    assert event.policy_allowed is True
    assert event.success is True
    assert event.output == 42   
    
def test_audit_get_by_task():

    logger = AuditLogger()

    logger.record(
        AuditEvent(
            task_id="task-1",
            tool_name="calculator",
            success=True,
        )
    )

    logger.record(
        AuditEvent(
            task_id="task-2",
            tool_name="calculator",
            success=True,
        )
    )

    logger.record(
        AuditEvent(
            task_id="task-1",
            tool_name="calculator",
            success=False,
        )
    )

    events = logger.get_by_task("task-1")

    assert len(events) == 2

    assert all(
        event.task_id == "task-1"
        for event in events
    )


def test_audit_get_by_tool():

    logger = AuditLogger()

    logger.record(
        AuditEvent(
            task_id="task-1",
            tool_name="calculator",
            success=True,
        )
    )

    logger.record(
        AuditEvent(
            task_id="task-2",
            tool_name="shell",
            success=True,
        )
    )

    logger.record(
        AuditEvent(
            task_id="task-3",
            tool_name="calculator",
            success=False,
        )
    )

    events = logger.get_by_tool("calculator")

    assert len(events) == 2

    assert all(
        event.tool_name == "calculator"
        for event in events
    )


def test_audit_event_categories():

    logger = AuditLogger()

    logger.record(
        AuditEvent(
            task_id="task-1",
            tool_name="calculator",
            policy_allowed=True,
            success=True,
        )
    )

    logger.record(
        AuditEvent(
            task_id="task-2",
            tool_name="calculator",
            policy_allowed=True,
            success=False,
            error="Execution failed",
        )
    )

    logger.record(
        AuditEvent(
            task_id="task-3",
            tool_name="shell",
            policy_allowed=False,
            success=False,
            error="POLICY DENIED",
        )
    )

    assert len(logger.successful_events()) == 1
    assert len(logger.failed_events()) == 2
    assert len(logger.denied_events()) == 1
    
def test_execution_trace():

    events = [
        AuditEvent(
            task_id="task-1",
            tool_name="calculator",
            policy_allowed=True,
            success=True,
            output=42,
        ),
        AuditEvent(
            task_id="task-1",
            tool_name="calculator",
            policy_allowed=True,
            success=False,
            error="Execution failed",
        ),
    ]

    trace = ExecutionTrace(
        task_id="task-1",
        events=events,
    )

    assert trace.task_id == "task-1"

    assert trace.total_events == 2

    assert trace.successful_events == 1

    assert trace.failed_events == 1

    assert trace.denied_events == 0
    
def test_execution_trace_denied_event():

    event = AuditEvent(
        task_id="task-2",
        tool_name="shell",
        policy_allowed=False,
        success=False,
        error="POLICY DENIED",
    )

    trace = ExecutionTrace(
        task_id="task-2",
        events=[event],
    )

    assert trace.total_events == 1

    assert trace.successful_events == 0

    assert trace.failed_events == 1

    assert trace.denied_events == 1
    
def test_engine_returns_execution_trace():

    registry = ToolRegistry()

    registry.register(CalculatorTool())

    audit_logger = AuditLogger()

    class CalculatorAgent(Agent):

        def plan(self, task: Task) -> Plan:

            return Plan(
                task_id=task.id,
                steps=[
                    PlanStep(
                        id="calculate",
                        description="Calculate",
                        tool_call=ToolCall(
                            tool_name="calculator",
                            arguments={
                                "operation": "multiply",
                                "a": 6,
                                "b": 7,
                            },
                        ),
                    )
                ],
            )

    engine = ExecutionEngine(
        agent=CalculatorAgent(),
        tool_registry=registry,
        policy_engine=PolicyEngine(),
        audit_logger=audit_logger,
    )

    task = Task(
        description="Calculate 6 × 7"
    )

    result = engine.run(task)

    assert result.status == TaskStatus.COMPLETED
    assert result.trace is not None
    assert result.trace.task_id == task.id
    assert result.trace.total_events == 1
    assert result.trace.successful_events == 1
    assert result.trace.failed_events == 0
    assert result.trace.denied_events == 0
    assert result.trace.events[0].output == 42
    
def test_execution_summary():

    summary = ExecutionSummary(
        task_id="task-1",
        status=TaskStatus.COMPLETED,
        total_events=3,
        successful_events=2,
        failed_events=1,
        denied_events=0,
    )

    assert summary.task_id == "task-1"

    assert summary.status == TaskStatus.COMPLETED

    assert summary.total_events == 3

    assert summary.successful_events == 2

    assert summary.failed_events == 1

    assert summary.denied_events == 0
    
def test_failed_execution_summary():

    summary = ExecutionSummary(
        task_id="task-2",
        status=TaskStatus.FAILED,
        total_events=4,
        successful_events=1,
        failed_events=2,
        denied_events=1,
    )

    assert summary.status == TaskStatus.FAILED

    assert summary.total_events == 4

    assert summary.successful_events == 1

    assert summary.failed_events == 2

    assert summary.denied_events == 1
    
def test_create_execution_summary_from_trace():

    events = [
        AuditEvent(
            task_id="task-1",
            tool_name="calculator",
            policy_allowed=True,
            success=True,
            output=42,
        ),
        AuditEvent(
            task_id="task-1",
            tool_name="calculator",
            policy_allowed=True,
            success=False,
            error="Execution failed",
        ),
        AuditEvent(
            task_id="task-1",
            tool_name="shell",
            policy_allowed=False,
            success=False,
            error="POLICY DENIED",
        ),
    ]

    trace = ExecutionTrace(
        task_id="task-1",
        events=events,
    )

    summary = create_execution_summary(
        trace=trace,
        status=TaskStatus.FAILED,
    )

    assert summary.task_id == "task-1"
    assert summary.status == TaskStatus.FAILED
    assert summary.total_events == 3
    assert summary.successful_events == 1
    assert summary.failed_events == 2
    assert summary.denied_events == 1
    
def test_engine_returns_execution_summary():

    registry = ToolRegistry()

    registry.register(CalculatorTool())

    class CalculatorAgent(Agent):

        def plan(self, task: Task) -> Plan:

            return Plan(
                task_id=task.id,
                steps=[
                    PlanStep(
                        id="calculate",
                        description="Calculate",
                        tool_call=ToolCall(
                            tool_name="calculator",
                            arguments={
                                "operation": "multiply",
                                "a": 8,
                                "b": 5,
                            },
                        ),
                    )
                ],
            )

    engine = ExecutionEngine(
        agent=CalculatorAgent(),
        tool_registry=registry,
        policy_engine=PolicyEngine(),
    )

    task = Task(
        description="Calculate 8 × 5"
    )

    result = engine.run(task)

    assert result.status == TaskStatus.COMPLETED

    assert result.summary is not None

    assert result.summary.task_id == task.id

    assert result.summary.status == TaskStatus.COMPLETED

    assert result.summary.total_events == 1

    assert result.summary.successful_events == 1

    assert result.summary.failed_events == 0

    assert result.summary.denied_events == 0 
    
def test_engineering_task_model():

    task = Task(
        description="Build a secure calculator",
        requirements=[
            "Support arithmetic operations",
            "Handle invalid input",
        ],
        constraints=[
            "Do not use eval()",
            "Handle division by zero",
        ],
        expected_outcome="All tests pass",
    )

    assert task.description == "Build a secure calculator"

    assert len(task.requirements) == 2

    assert "Support arithmetic operations" in task.requirements

    assert len(task.constraints) == 2

    assert "Do not use eval()" in task.constraints

    assert task.expected_outcome == "All tests pass"

    assert task.status == TaskStatus.PENDING
    
def test_engineering_plan():

    task = Task(
        description="Build a secure calculator",
        expected_outcome="All tests pass",
    )

    plan = Plan(
        task_id=task.id,
        strategy="Implement and verify",
        expected_result="All tests pass",
        steps=[
            PlanStep(
                id="step-1",
                description="Implement calculator",
            ),
            PlanStep(
                id="step-2",
                description="Run tests",
            ),
        ],
    )

    assert plan.task_id == task.id

    assert plan.strategy == "Implement and verify"

    assert plan.expected_result == "All tests pass"

    assert len(plan.steps) == 2

    assert plan.steps[0].description == "Implement calculator"
    
def test_engineering_agent_creates_plan():

    task = Task(
        description="Build a secure calculator",
        requirements=[
            "Support arithmetic operations",
        ],
        constraints=[
            "Do not use eval()",
        ],
        expected_outcome="All tests pass",
    )

    agent = EngineeringAgent()

    plan = agent.plan(task)

    assert plan.task_id == task.id

    assert plan.strategy == "Analyze, implement, and verify"

    assert plan.expected_result == "All tests pass"

    assert len(plan.steps) == 3

    assert plan.steps[0].id == "analyze"

    assert plan.steps[1].id == "implement"

    assert plan.steps[2].id == "verify"
    
def test_engineering_agent_preserves_task_requirements():

    task = Task(
        description="Build a secure calculator",
        requirements=[
            "Support arithmetic operations",
            "Handle invalid input",
        ],
        constraints=[
            "Do not use eval()",
            "Handle division by zero",
        ],
        expected_outcome="All tests pass",
    )

    agent = EngineeringAgent()

    plan = agent.plan(task)

    assert plan.requirements == task.requirements

    assert plan.constraints == task.constraints

    assert plan.expected_result == task.expected_outcome

    assert "requirements" in plan.steps[0].description.lower()

    assert "constraints" in plan.steps[0].description.lower() 
    
    
def test_plan_validator_accepts_valid_plan():
    registry = ToolRegistry()

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="analyze",
                description="Analyze the task",
            )
        ],
    )

    result = PlanValidator().validate(plan, registry)

    assert result.valid is True
    assert result.errors == []


def test_plan_validator_rejects_empty_task_id():
    registry = ToolRegistry()

    plan = Plan(
        task_id="",
        steps=[
            PlanStep(
                id="analyze",
                description="Analyze the task",
            )
        ],
    )

    result = PlanValidator().validate(plan, registry)

    assert result.valid is False
    assert "Plan task_id is required." in result.errors


def test_plan_validator_rejects_empty_steps():
    registry = ToolRegistry()

    plan = Plan(
        task_id="task-1",
        steps=[],
    )

    result = PlanValidator().validate(plan, registry)

    assert result.valid is False
    assert "Plan must contain at least one step." in result.errors


def test_plan_validator_rejects_duplicate_step_ids():
    registry = ToolRegistry()

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="analyze",
                description="Analyze",
            ),
            PlanStep(
                id="analyze",
                description="Analyze again",
            ),
        ],
    )

    result = PlanValidator().validate(plan, registry)

    assert result.valid is False
    assert "Duplicate plan step id: analyze" in result.errors


def test_plan_validator_rejects_unknown_tool():
    registry = ToolRegistry()

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="calculate",
                description="Calculate",
                tool_call=ToolCall(
                    tool_name="unknown_tool",
                    arguments={},
                ),
            )
        ],
    )

    result = PlanValidator().validate(plan, registry)

    assert result.valid is False
    assert "Tool not found: unknown_tool" in result.errors


def test_plan_validator_accepts_registered_tool():
    from aegis.tools.calculator import CalculatorTool

    registry = ToolRegistry()
    registry.register(CalculatorTool())

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="calculate",
                description="Calculate",
                tool_call=ToolCall(
                    tool_name="calculator",
                    arguments={
                        "operation": "add",
                        "a": 2,
                        "b": 3,
                    },
                ),
            )
        ],
    )

    result = PlanValidator().validate(plan, registry)

    assert result.valid is True
    assert result.errors == []
    
def test_engine_rejects_invalid_plan_before_tool_execution():

    class InvalidPlanAgent(Agent):

        def plan(self, task: Task) -> Plan:
            return Plan(
                task_id=task.id,
                steps=[
                    PlanStep(
                        id="invalid",
                        description="Use missing tool",
                        tool_call=ToolCall(
                            tool_name="missing_tool",
                            arguments={},
                        ),
                    )
                ],
            )

    registry = ToolRegistry()

    engine = ExecutionEngine(
        agent=InvalidPlanAgent(),
        tool_registry=registry,
        policy_engine=PolicyEngine(),
    )

    task = Task(
        description="Test invalid plan",
    )

    result = engine.run(task)

    assert result.status == TaskStatus.FAILED
    assert len(result.observations) == 1
    assert result.observations[0].step_id == "plan_validation"
    assert result.observations[0].success is False
    assert "PLAN VALIDATION FAILED" in result.observations[0].error
    assert result.trace.total_events == 0 
    
def test_plan_validator_rejects_empty_step_id():

    registry = ToolRegistry()

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="",
                description="Analyze the task",
            )
        ],
    )

    result = PlanValidator().validate(
        plan=plan,
        tool_registry=registry,
    )

    assert result.valid is False
    assert "Every plan step must have an id." in result.errors


def test_plan_validator_rejects_empty_step_description():

    registry = ToolRegistry()

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="analyze",
                description="",
            )
        ],
    )

    result = PlanValidator().validate(
        plan=plan,
        tool_registry=registry,
    )

    assert result.valid is False
    assert "Every plan step must have a description." in result.errors


def test_plan_validator_rejects_task_id_mismatch():

    registry = ToolRegistry()

    plan = Plan(
        task_id="different-task",
        steps=[
            PlanStep(
                id="analyze",
                description="Analyze the task",
            )
        ],
    )

    result = PlanValidator().validate(
        plan=plan,
        tool_registry=registry,
        task_id="task-1",
    )

    assert result.valid is False
    assert "Plan task_id does not match the requested task." in result.errors


def test_plan_validator_preserves_requirements_and_constraints():

    registry = ToolRegistry()

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="analyze",
                description="Analyze the task",
            )
        ],
        requirements=[
            "Support arithmetic operations",
            "Handle invalid input",
        ],
        constraints=[
            "Do not use eval()",
            "Handle division by zero",
        ],
    )

    result = PlanValidator().validate(
        plan=plan,
        tool_registry=registry,
    )

    assert result.valid is True
    assert result.errors == []


def test_plan_validator_rejects_duplicate_requirements():

    registry = ToolRegistry()

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="analyze",
                description="Analyze the task",
            )
        ],
        requirements=[
            "Support arithmetic operations",
            "Support arithmetic operations",
        ],
    )

    result = PlanValidator().validate(
        plan=plan,
        tool_registry=registry,
    )

    assert result.valid is False
    assert "Duplicate plan requirement" in result.errors[0]
    
def test_plan_evaluator_accepts_plan_with_full_requirement_coverage():

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="implement",
                description=(
                    "Implement arithmetic operations "
                    "and handle division by zero"
                ),
            ),
            PlanStep(
                id="verify",
                description=(
                    "Verify arithmetic operations "
                    "and division by zero handling"
                ),
            ),
        ],
        requirements=[
            "Support arithmetic operations",
            "Handle division by zero",
        ],
    )

    result = PlanEvaluator().evaluate(plan)

    assert result.valid is True
    assert result.coverage == 1.0
    assert result.missing_requirements == []


def test_plan_evaluator_detects_missing_requirements():

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="implement",
                description="Implement arithmetic operations",
            ),
        ],
        requirements=[
            "Support arithmetic operations",
            "Handle division by zero",
        ],
    )

    result = PlanEvaluator().evaluate(plan)

    assert result.valid is False
    assert result.coverage == 0.5
    assert result.missing_requirements == [
        "Handle division by zero"
    ]


def test_plan_evaluator_accepts_plan_without_requirements():

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="implement",
                description="Implement the solution",
            ),
        ],
    )

    result = PlanEvaluator().evaluate(plan)

    assert result.valid is True
    assert result.coverage == 1.0
    assert result.missing_requirements == []


def test_plan_evaluator_is_case_insensitive():

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="implement",
                description="IMPLEMENT ARITHMETIC OPERATIONS",
            ),
        ],
        requirements=[
            "support arithmetic operations",
        ],
    )

    result = PlanEvaluator().evaluate(plan)

    assert result.valid is True
    assert result.coverage == 1.0
    
def test_plan_evaluator_accepts_full_constraint_coverage():

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="implement",
                description=(
                    "Implement arithmetic operations "
                    "without using eval and handle division by zero"
                ),
            ),
        ],
        requirements=[
            "Support arithmetic operations",
        ],
        constraints=[
            "Do not use eval()",
            "Handle division by zero",
        ],
    )

    result = PlanEvaluator().evaluate(plan)

    assert result.valid is True
    assert result.constraint_coverage == 1.0
    assert result.violated_constraints == []


def test_plan_evaluator_detects_violated_constraints():

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="implement",
                description="Implement arithmetic operations",
            ),
        ],
        requirements=[
            "Support arithmetic operations",
        ],
        constraints=[
            "Do not use eval()",
            "Handle division by zero",
        ],
    )

    result = PlanEvaluator().evaluate(plan)

    assert result.valid is False
    assert result.constraint_coverage == 0.0
    assert result.violated_constraints == [
        "Do not use eval()",
        "Handle division by zero",
    ]


def test_plan_evaluator_calculates_partial_constraint_coverage():

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="implement",
                description=(
                    "Implement arithmetic operations "
                    "without using eval"
                ),
            ),
        ],
        requirements=[
            "Support arithmetic operations",
        ],
        constraints=[
            "Do not use eval()",
            "Handle division by zero",
        ],
    )

    result = PlanEvaluator().evaluate(plan)

    assert result.valid is False
    assert result.constraint_coverage == 0.5
    assert result.violated_constraints == [
        "Handle division by zero"
    ]


def test_plan_evaluator_accepts_plan_without_constraints():

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="implement",
                description="Implement the solution",
            ),
        ],
    )

    result = PlanEvaluator().evaluate(plan)

    assert result.valid is True
    assert result.constraint_coverage == 1.0
    assert result.violated_constraints == []
    
    
def test_plan_decision_accepts_fully_valid_plan():
    engine = PlanDecisionEngine()

    result = engine.decide(
        coverage=1.0,
        constraint_coverage=1.0,
    )

    assert result.decision == PlanDecision.ACCEPT
    assert result.reason
    assert result.requirement_coverage == 1.0
    assert result.constraint_coverage == 1.0


def test_plan_decision_replans_when_requirements_are_missing():
    engine = PlanDecisionEngine()

    result = engine.decide(
        coverage=0.5,
        constraint_coverage=1.0,
    )

    assert result.decision == PlanDecision.REPLAN
    assert result.requirement_coverage == 0.5
    assert result.constraint_coverage == 1.0


def test_plan_decision_rejects_when_constraints_are_violated():
    engine = PlanDecisionEngine()

    result = engine.decide(
        coverage=1.0,
        constraint_coverage=0.0,
    )

    assert result.decision == PlanDecision.REJECT
    assert result.requirement_coverage == 1.0
    assert result.constraint_coverage == 0.0
    
    
def test_engine_does_not_execute_tool_when_plan_requires_replan():
    class ReplanAgent(Agent):
        def plan(self, task: Task) -> Plan:
            return Plan(
                task_id=task.id,
                steps=[
                    PlanStep(
                        id="calculate",
                        description="Perform calculation",
                        tool_call=ToolCall(
                            tool_name="calculator",
                            arguments={
                                "operation": "add",
                                "a": 10,
                                "b": 20,
                            },
                        ),
                    )
                ],
                requirements=[
                    "perform calculation",
                    "missing requirement",
                ],
            )

    class BlockingReplanner(Replanner):
     def replan(
            self,
            plan: Plan,
         evaluation: EvaluationResult,
        ) -> Plan:
            return Plan(
                task_id=plan.task_id,
                steps=[
                    PlanStep(
                        id="replanned",
                        description="Replanned solution",
                    )
                ],
                requirements=[
                    "perform calculation",
                    "missing requirement",
                ],
            )

    registry = ToolRegistry()
    registry.register(CalculatorTool())

    replanner = BlockingReplanner()

    engine = ExecutionEngine(
        agent=ReplanAgent(),
        tool_registry=registry,
        policy_engine=PolicyEngine(),
        replanner=replanner,
    )

    task = Task(
        description="Test replanning guard",
    )

    result = engine.run(task)

    assert result.status == TaskStatus.FAILED

    # No tool was executed because the replanned
    # plan still did not satisfy the requirements.
    assert len(engine.audit_logger.events()) == 0
    
def test_engine_does_not_execute_unknown_tool():
    class UnknownToolAgent(Agent):
        def plan(self, task):
            return Plan(
                task_id=task.id,
                steps=[
                    PlanStep(
                        id="unknown_tool",
                        description="Use an unknown tool",
                        tool_call=ToolCall(
                            tool_name="does_not_exist",
                            arguments={},
                        ),
                    )
                ],
            )

    task = Task(description="Test unknown tool")

    engine = ExecutionEngine(
        agent=UnknownToolAgent(),
        tool_registry=ToolRegistry(),
        policy_engine=PolicyEngine(),
    )

    result = engine.run(task)

    assert result.status == TaskStatus.FAILED
    assert len(engine.audit_logger.events()) == 0


def test_engine_records_tool_exception_as_failure():
    class FailingTool(Tool):
        name = "failing_tool"
        description = "A tool that always fails."
        permission_level = PermissionLevel.SAFE

        def execute(self, **kwargs):
            raise RuntimeError("intentional failure")

    class FailingToolAgent(Agent):
        def plan(self, task):
            return Plan(
                task_id=task.id,
                steps=[
                    PlanStep(
                        id="fail",
                        description="Execute failing tool",
                        tool_call=ToolCall(
                            tool_name="failing_tool",
                            arguments={},
                        ),
                    )
                ],
            )

    registry = ToolRegistry()
    registry.register(FailingTool())

    task = Task(description="Test tool failure")

    engine = ExecutionEngine(
        agent=FailingToolAgent(),
        tool_registry=registry,
        policy_engine=PolicyEngine(),
    )

    result = engine.run(task)

    assert result.status == TaskStatus.FAILED

    events = engine.audit_logger.events()

    assert len(events) == 1
    assert events[0].tool_name == "failing_tool"
    assert events[0].policy_allowed is True
    assert events[0].success is False
    assert events[0].error == "intentional failure"


def test_engine_records_successful_tool_output():
    class SuccessfulTool(Tool):
        name = "successful_tool"
        description = "A tool that succeeds."
        permission_level = PermissionLevel.SAFE

        def execute(self, **kwargs):
            return 42

    class SuccessfulToolAgent(Agent):
        def plan(self, task):
            return Plan(
                task_id=task.id,
                steps=[
                    PlanStep(
                        id="success",
                        description="Execute successful tool",
                        tool_call=ToolCall(
                            tool_name="successful_tool",
                            arguments={},
                        ),
                    )
                ],
            )

    registry = ToolRegistry()
    registry.register(SuccessfulTool())

    task = Task(description="Test successful tool")

    engine = ExecutionEngine(
        agent=SuccessfulToolAgent(),
        tool_registry=registry,
        policy_engine=PolicyEngine(),
    )

    result = engine.run(task)

    assert result.status == TaskStatus.COMPLETED

    events = engine.audit_logger.events()

    assert len(events) == 1
    assert events[0].tool_name == "successful_tool"
    assert events[0].policy_allowed is True
    assert events[0].success is True
    assert events[0].output == 42
    
def test_sandbox_result_represents_successful_execution():
    result = SandboxResult(
        success=True,
        stdout="Hello AEGIS",
        stderr="",
        exit_code=0,
    )

    assert result.success is True
    assert result.stdout == "Hello AEGIS"
    assert result.stderr == ""
    assert result.exit_code == 0


def test_sandbox_result_represents_failed_execution():
    result = SandboxResult(
        success=False,
        stdout="",
        stderr="Something went wrong",
        exit_code=1,
    )

    assert result.success is False
    assert result.stdout == ""
    assert result.stderr == "Something went wrong"
    assert result.exit_code == 1
    
def test_runtime_sandbox_captures_stdout():
    sandbox = unsafe_sandbox()

    result = sandbox.run('print("Hello AEGIS")')

    assert isinstance(result, SandboxResult)
    assert result.success is True
    assert result.stdout.strip() == "Hello AEGIS"
    assert result.stderr == ""
    assert result.exit_code == 0


def test_runtime_sandbox_captures_python_error():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        'raise RuntimeError("intentional sandbox failure")'
    )

    assert isinstance(result, SandboxResult)
    assert result.success is False
    assert "intentional sandbox failure" in result.stderr
    assert result.exit_code != 0


def test_runtime_sandbox_handles_multiline_code():
    sandbox = unsafe_sandbox()

    code = """
value = 21
result = value * 2
print(result)
"""

    result = sandbox.run(code)

    assert result.success is True
    assert result.stdout.strip() == "42"
    assert result.stderr == ""
    assert result.exit_code == 0
    
    


    
def test_runtime_sandbox_isolates_working_directory():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        """
with open("sandbox_test.txt", "w") as file:
    file.write("sandbox only")

print("created")
"""
    )

    assert isinstance(result, SandboxResult)
    assert result.success is True
    assert result.stdout.strip() == "created"
    assert result.stderr == ""
    assert result.exit_code == 0
    
def test_runtime_sandbox_cleans_up_workspace():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        """
from pathlib import Path

path = Path("cleanup_test.txt")
path.write_text("temporary")
print(path.resolve())
"""
    )

    assert isinstance(result, SandboxResult)
    assert result.success is True

    created_path = Path(result.stdout.strip())

    assert created_path.name == "cleanup_test.txt"
    assert not created_path.exists() 
    
def test_runtime_sandbox_timeout_is_configurable():
    sandbox = unsafe_sandbox(timeout=0.5)

    result = sandbox.run(
        """
while True:
    pass
"""
    )

    assert isinstance(result, SandboxResult)
    assert result.success is False
    assert result.exit_code != 0
    assert "timed out" in result.stderr.lower()
    
def test_runtime_sandbox_limits_output():
    sandbox = unsafe_sandbox(max_output_size=100)

    result = sandbox.run(
        """
print("A" * 10000)
"""
    )

    assert isinstance(result, SandboxResult)
    assert result.success is False
    assert "output" in result.stderr.lower()
    
def test_runtime_sandbox_runs_in_isolated_process():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        """
import os

print(os.getpid())
"""
    )

    assert isinstance(result, SandboxResult)
    assert result.success is True

    pid = int(result.stdout.strip())

    assert pid > 0
    
    
def test_sandbox_tool_is_registered():
    sandbox_tool = SandboxTool()

    registry = ToolRegistry()
    registry.register(sandbox_tool)

    assert "sandbox" in registry.list_tools()
    assert registry.get("sandbox") is sandbox_tool
    
def test_sandbox_tool_executes_code():
    sandbox = unsafe_sandbox()
    sandbox_tool = SandboxTool(sandbox=sandbox)

    result = sandbox_tool.execute('print("AEGIS")')

    assert isinstance(result, SandboxResult)
    assert result.success is True
    assert result.stdout.strip() == "AEGIS"
    assert result.stderr == ""
    assert result.exit_code == 0
    
def test_engine_executes_sandbox_tool_when_policy_allows():
    task = Task(
        description="Run code in sandbox",
        expected_outcome="AEGIS",
    )

    sandbox_tool = SandboxTool()

    registry = ToolRegistry()
    registry.register(sandbox_tool)

    policy = PolicyEngine(
        max_allowed_level=PermissionLevel.RESTRICTED
    )

    agent = EngineeringAgent()

    plan = Plan(
        task_id=task.id,
        steps=[
            PlanStep(
                id="run_code",
                description="Run code in sandbox",
                tool_call=ToolCall(
                    tool_name="sandbox",
                    arguments={
                        "code": 'print("AEGIS")',
                    },
                ),
            )
        ],
    )

    class SandboxAgent(Agent):
        def plan(self, task):
            return plan

    engine = ExecutionEngine(
        agent=SandboxAgent(),
        tool_registry=registry,
        policy_engine=policy,
    )

    result = engine.run(task)

    assert result.status == TaskStatus.COMPLETED

    assert len(result.observations) >= 1
    assert any(
        observation.success
        for observation in result.observations
    )

def test_engine_denies_sandbox_when_policy_disallows_it():
    task = Task(
        description="Run restricted sandbox code",
        expected_outcome="Should not execute",
    )

    sandbox = RuntimeSandbox()
    sandbox_tool = SandboxTool(sandbox=sandbox)

    registry = ToolRegistry()
    registry.register(sandbox_tool)

    policy = PolicyEngine(
        max_allowed_level=PermissionLevel.SAFE
    )

    class DenyAgent(Agent):
        def plan(self, task):
            return Plan(
                task_id=task.id,
                steps=[
                    PlanStep(
                        id="run_code",
                        description="Run code in sandbox",
                        tool_call=ToolCall(
                            tool_name="sandbox",
                            arguments={
                                "code": 'print("SHOULD_NOT_RUN")',
                            },
                        ),
                    )
                ],
            )

    audit_logger = AuditLogger()

    engine = ExecutionEngine(
        agent=DenyAgent(),
        tool_registry=registry,
        policy_engine=policy,
        audit_logger=audit_logger,
    )

    result = engine.run(task)

    assert result.status == TaskStatus.FAILED

    events = audit_logger.get_by_tool("sandbox")

    assert len(events) == 1

    event = events[0]

    assert event.policy_allowed is False
    assert event.success is False
    assert event.error is not None
    
def test_engine_does_not_execute_denied_sandbox_code():
    task = Task(
        description="Attempt denied sandbox execution",
        expected_outcome="Code must not execute",
    )

    sandbox = RuntimeSandbox()
    sandbox_tool = SandboxTool(sandbox=sandbox)

    registry = ToolRegistry()
    registry.register(sandbox_tool)

    policy = PolicyEngine(
        max_allowed_level=PermissionLevel.SAFE
    )

    class DenyAgent(Agent):
        def plan(self, task):
            return Plan(
                task_id=task.id,
                steps=[
                    PlanStep(
                        id="run_code",
                        description="Run code in sandbox",
                        tool_call=ToolCall(
                            tool_name="sandbox",
                            arguments={
                                "code": 'raise RuntimeError("EXECUTED")',
                            },
                        ),
                    )
                ],
            )

    audit_logger = AuditLogger()

    engine = ExecutionEngine(
        agent=DenyAgent(),
        tool_registry=registry,
        policy_engine=policy,
        audit_logger=audit_logger,
    )

    result = engine.run(task)

    assert result.status == TaskStatus.FAILED

    events = audit_logger.get_by_tool("sandbox")

    assert len(events) == 1

    event = events[0]

    assert event.policy_allowed is False
    assert event.success is False
    assert event.error is not None

    assert "EXECUTED" not in (event.error or "")  
    
def test_runtime_sandbox_network_policy_defaults_to_disabled():
    sandbox = RuntimeSandbox()

    assert sandbox.allow_network is False


def test_runtime_sandbox_can_explicitly_allow_network():
    sandbox = RuntimeSandbox(allow_network=True)

    assert sandbox.allow_network is True
    
def test_runtime_sandbox_network_policy_is_exposed():
    sandbox = RuntimeSandbox()

    assert sandbox.allow_network is False

    network_enabled_sandbox = RuntimeSandbox(
        allow_network=True
    )

    assert network_enabled_sandbox.allow_network is True
    
def test_runtime_sandbox_defaults_to_network_isolation_requirement():
    sandbox = RuntimeSandbox()

    assert sandbox.allow_network is False
    
def test_sandbox_security_policy_defaults_to_network_disabled():
    policy = SandboxSecurityPolicy()

    assert policy.allow_network is False


def test_sandbox_security_policy_can_allow_network():
    policy = SandboxSecurityPolicy(
        allow_network=True
    )

    assert policy.allow_network is True   
    
def test_runtime_sandbox_uses_security_policy():
    policy = SandboxSecurityPolicy(
        allow_network=False
    )

    sandbox = RuntimeSandbox(
        security_policy=policy
    )

    assert sandbox.security_policy is policy
    assert sandbox.security_policy.allow_network is False
    
def test_sandbox_security_policy_reports_network_permission():
    disabled_policy = SandboxSecurityPolicy(
        allow_network=False
    )

    enabled_policy = SandboxSecurityPolicy(
        allow_network=True
    )

    assert disabled_policy.network_allowed() is False
    assert enabled_policy.network_allowed() is True
  
def test_runtime_sandbox_rejects_execution_without_network_isolation():
    policy = SandboxSecurityPolicy(
        allow_network=False,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(security_policy=policy)

    result = sandbox.run("""
import urllib.request

urllib.request.urlopen(
    "http://example.com",
    timeout=2,
)
""")

    assert isinstance(result, SandboxResult)
    assert result.success is False
    assert result.exit_code != 0
    assert "network isolation" in result.stderr.lower()  
    
def test_isolation_backend_is_abstract():
    assert hasattr(IsolationBackend, "is_available")
    assert hasattr(IsolationBackend, "run")


def test_isolation_backend_requires_is_available_implementation():
    class IncompleteBackend(IsolationBackend):
        def run(self, code: str, timeout: float):
            return None

    try:
        IncompleteBackend()
        assert False, "Incomplete backend should not be instantiable."
    except TypeError:
        pass
    
    
def test_no_isolation_backend_reports_unavailable():
    backend = NoIsolationBackend()

    assert backend.is_available() is False


def test_no_isolation_backend_refuses_execution():
    backend = NoIsolationBackend()

    try:
        backend.run("print('hello')", timeout=1)
        assert False, "Backend must refuse execution."
    except RuntimeError as exc:
        assert "no real isolation backend" in str(exc).lower()

def test_runtime_sandbox_exposes_isolation_backend():
    sandbox = RuntimeSandbox()

    assert isinstance(sandbox.isolation_backend, NoIsolationBackend)
    assert sandbox.isolation_backend.is_available() is False


    
def test_runtime_sandbox_uses_backend_availability_for_strict_mode():
    backend = NoIsolationBackend()

    policy = SandboxSecurityPolicy(
        allow_network=False,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    assert sandbox.isolation_backend is backend
    assert sandbox.isolation_backend.is_available() is False 
    
def test_runtime_sandbox_calls_isolation_backend():
    class SpyBackend(IsolationBackend):
        def __init__(self):
            self.called = False
            self.received_code = None
            self.received_timeout = None

        def is_available(self) -> bool:
            return True
        def capabilities(self) -> IsolationCapabilities:
         return IsolationCapabilities(
            network_isolation=True,
            filesystem_isolation=True,
            process_isolation=True,
        )
        def run(self, code: str, timeout: float):
            self.called = True
            self.received_code = code
            self.received_timeout = timeout
            

            return SandboxResult(
                success=True,
                stdout="BACKEND_EXECUTED",
                stderr="",
                exit_code=0,
            )

    backend = SpyBackend()

    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        timeout=5,
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert backend.called is True
    assert backend.received_code == "print('hello')"
    assert backend.received_timeout == 5

    assert result.success is True
    assert result.stdout == "BACKEND_EXECUTED"
    
def test_isolation_backend_contract_returns_sandbox_result():
    class TestBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True
        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
            network_isolation=True,
            filesystem_isolation=True,
            process_isolation=True,
        )
        def run(self, code: str, timeout: float) -> SandboxResult:
            return SandboxResult(
                success=True,
                stdout="isolated",
                stderr="",
                exit_code=0,
            )

    backend = TestBackend()

    assert backend.is_available() is True

    result = backend.run(
        "print('hello')",
        timeout=5,
    )

    assert isinstance(result, SandboxResult)
    assert result.success is True
    assert result.stdout == "isolated"
    assert result.stderr == ""
    assert result.exit_code == 0
    
    

def test_windows_isolation_backend_is_explicitly_unavailable():
    backend = WindowsIsolationBackend()

    assert backend.is_available() is False
    
    
    
def test_runtime_sandbox_rejects_when_required_network_isolation_is_unavailable():
    backend = NoIsolationBackend()

    policy = SandboxSecurityPolicy(
        allow_network=False,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run('print("should not run")')

    assert result.success is False
    assert "network isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_when_backend_lacks_network_capability():
    class LimitedBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Backend must not execute the code.")

    backend = LimitedBackend()

    policy = SandboxSecurityPolicy(
        allow_network=False,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run('print("should not run")')

    assert result.success is False
    assert "network isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_exposes_filesystem_isolation_capability():
    sandbox = RuntimeSandbox()

    capabilities = sandbox.isolation_capabilities()

    assert capabilities.filesystem_isolation is False
    
def test_runtime_sandbox_rejects_when_required_filesystem_isolation_is_unavailable():
    backend = NoIsolationBackend()

    policy = SandboxSecurityPolicy(
        allow_network=False,
        require_network_isolation=False,
        require_filesystem_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run('print("should not run")')

    assert result.success is False
    assert "filesystem isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_when_required_process_isolation_is_unavailable():
    backend = NoIsolationBackend()

    policy = SandboxSecurityPolicy(
        allow_network=False,
        require_network_isolation=False,
        require_filesystem_isolation=False,
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run('print("should not run")')

    assert result.success is False
    assert "process isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_when_required_isolation_capabilities_are_incomplete():
    class IncompleteBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Backend must not execute the code.")

    backend = IncompleteBackend()

    policy = SandboxSecurityPolicy(
        allow_network=False,
        require_network_isolation=True,
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run('print("should not run")')

    assert result.success is False
    assert "process isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_runs_with_complete_isolation_backend():
    class CompleteBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            return SandboxResult(
                success=True,
                stdout="isolated execution",
                stderr="",
                exit_code=0,
            )

    backend = CompleteBackend()

    policy = SandboxSecurityPolicy(
        allow_network=False,
        require_network_isolation=True,
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run('print("hello")')

    assert result.success is True
    assert result.stdout == "isolated execution"
    assert result.stderr == ""
    assert result.exit_code == 0
    
def test_no_isolation_backend_reports_all_isolation_capabilities_as_unavailable():
    backend = NoIsolationBackend()

    capabilities = backend.capabilities()

    assert capabilities.network_isolation is False
    assert capabilities.filesystem_isolation is False
    assert capabilities.process_isolation is False
    
def test_windows_isolation_backend_reports_unavailable_capabilities():
    backend = WindowsIsolationBackend()

    assert backend.is_available() is False

    capabilities = backend.capabilities()

    assert capabilities.network_isolation is False
    assert capabilities.filesystem_isolation is False
    assert capabilities.process_isolation is False
    
        
        
        
    
    
    
def test_runtime_sandbox_uses_custom_backend():
    class CustomBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            return SandboxResult(
                success=True,
                stdout="custom backend",
                stderr="",
                exit_code=0,
            )

    backend = CustomBackend()
    sandbox = RuntimeSandbox(isolation_backend=backend)

    assert sandbox.isolation_backend is backend
    assert not isinstance(sandbox.isolation_backend, NoIsolationBackend)
    
    
    
    
def test_runtime_sandbox_does_not_call_unavailable_isolation_backend():
    class UnavailableBackend(IsolationBackend):
        def is_available(self) -> bool:
            return False

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Unavailable backend must not execute.")

    backend = UnavailableBackend()

    policy = SandboxSecurityPolicy(
        require_network_isolation=True,
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "unavailable" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_checks_capabilities_before_backend_execution():
    class UnsafeBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Backend must not execute.")

    backend = UnsafeBackend()

    policy = SandboxSecurityPolicy(
        require_filesystem_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "filesystem isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_handles_isolation_backend_exception():
    class FailingBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise RuntimeError("Backend execution failed.")

    backend = FailingBackend()

    policy = SandboxSecurityPolicy(
        require_network_isolation=True,
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert "Backend execution failed." in result.stderr
    assert result.exit_code == -1
    
        
        
def test_runtime_sandbox_rejects_when_network_isolation_is_missing_from_complete_policy():
    class MissingNetworkBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Backend must not execute.")

    backend = MissingNetworkBackend()

    policy = SandboxSecurityPolicy(
        require_network_isolation=True,
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "network isolation" in result.stderr.lower()
    assert result.exit_code == -1 
    
def test_runtime_sandbox_rejects_filesystem_isolation_when_backend_unavailable():
    class UnavailableBackend(IsolationBackend):
        def is_available(self) -> bool:
            return False

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Backend must not execute.")

    backend = UnavailableBackend()

    policy = SandboxSecurityPolicy(
        require_filesystem_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "filesystem isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_process_isolation_when_backend_unavailable():
    class UnavailableBackend(IsolationBackend):
        def is_available(self) -> bool:
            return False

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Backend must not execute.")

    backend = UnavailableBackend()

    policy = SandboxSecurityPolicy(
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "process isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_when_process_isolation_capability_is_missing():
    class MissingProcessBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Backend must not execute.")

    backend = MissingProcessBackend()

    policy = SandboxSecurityPolicy(
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "process isolation capability" in result.stderr.lower()
    assert result.exit_code == -1
    
    
def test_runtime_sandbox_executes_with_complete_isolation_backend():
    class CompleteBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            assert code == "print('backend execution')"
            assert timeout == 10.0

            return SandboxResult(
                success=True,
                stdout="backend execution\n",
                stderr="",
                exit_code=0,
            )

    backend = CompleteBackend()

    policy = SandboxSecurityPolicy(
        require_network_isolation=True,
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('backend execution')")

    assert result.success is True
    assert result.stdout == "backend execution\n"
    assert result.stderr == ""
    assert result.exit_code == 0  
    
def test_runtime_sandbox_does_not_treat_allow_network_as_network_isolation():
    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "network isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_does_not_execute_unavailable_network_backend():
    class UnavailableNetworkBackend(IsolationBackend):
        def is_available(self) -> bool:
            return False

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Unavailable backend must not execute.")

    backend = UnavailableNetworkBackend()

    policy = SandboxSecurityPolicy(
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "network isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
    
def test_runtime_sandbox_checks_backend_availability_before_process_capabilities():
    class UnavailableProcessBackend(IsolationBackend):
        def is_available(self) -> bool:
            return False

        def capabilities(self) -> IsolationCapabilities:
            raise AssertionError(
                "Capabilities must not be checked when backend is unavailable."
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Backend must not execute.")

    backend = UnavailableProcessBackend()

    policy = SandboxSecurityPolicy(
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "process isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_combined_isolation_when_one_capability_is_missing():
    class MissingProcessBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Backend must not execute.")

    backend = MissingProcessBackend()

    policy = SandboxSecurityPolicy(
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "process isolation capability" in result.stderr.lower()
    assert result.exit_code == -1 
    
def test_runtime_sandbox_checks_backend_availability_before_combined_capabilities():
    class UnavailableBackend(IsolationBackend):
        def is_available(self) -> bool:
            return False

        def capabilities(self) -> IsolationCapabilities:
            raise AssertionError(
                "Capabilities must not be checked when backend is unavailable."
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Backend must not execute.")

    backend = UnavailableBackend()

    policy = SandboxSecurityPolicy(
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "filesystem/process isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
        
        
    
    
    
    
    
    
def test_runtime_sandbox_allows_stderr_on_successful_execution():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys; print('AEGIS_OK'); sys.stderr.write('warning')"
    )

    assert result.success is True
    assert result.stdout.strip() == "AEGIS_OK"
    assert result.stderr == "warning"
    assert result.exit_code == 0  
    
def test_runtime_sandbox_reports_python_error():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "raise ValueError('AEGIS_TEST_ERROR')"
    )

    assert result.success is False
    assert "AEGIS_TEST_ERROR" in result.stderr
    assert result.exit_code != 0
    
    


    
def test_runtime_sandbox_allow_network_requires_isolation_for_strict_network_policy():
    sandbox = RuntimeSandbox(
        allow_network=True,
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "network isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_uses_custom_backend_for_required_network_isolation():
    class CustomBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            return SandboxResult(
                success=True,
                stdout="CUSTOM_BACKEND_OK",
                stderr="",
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=CustomBackend(),
    )

    result = sandbox.run("print('ignored')")

    assert result.success is True
    assert result.stdout == "CUSTOM_BACKEND_OK"
    assert result.stderr == ""
    assert result.exit_code == 0
    
    
def test_runtime_sandbox_passes_configured_timeout_to_custom_backend():
    class TimeoutBackend(IsolationBackend):
        def __init__(self):
            self.received_timeout = None

        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            self.received_timeout = timeout
            return SandboxResult(
                success=True,
                stdout="TIMEOUT_OK",
                stderr="",
                exit_code=0,
            )

    backend = TimeoutBackend()

    sandbox = RuntimeSandbox(
        timeout=3.5,
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('ignored')")

    assert result.success is True
    assert result.stdout == "TIMEOUT_OK"
    assert backend.received_timeout == 3.5 
    
    
    
    
    
def test_runtime_sandbox_returns_backend_isolation_capabilities():
    class CustomBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Backend must not execute.")

    backend = CustomBackend()

    sandbox = RuntimeSandbox(
        isolation_backend=backend,
    )

    capabilities = sandbox.isolation_capabilities()

    assert capabilities.network_isolation is True
    assert capabilities.filesystem_isolation is True
    assert capabilities.process_isolation is False
    
def test_runtime_sandbox_reads_current_isolation_capabilities():
    class DynamicBackend(IsolationBackend):
        def __init__(self):
            self.network_enabled = False

        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=self.network_enabled,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError("Backend must not execute.")

    backend = DynamicBackend()
    sandbox = RuntimeSandbox(isolation_backend=backend)

    first = sandbox.isolation_capabilities()

    assert first.network_isolation is False

    backend.network_enabled = True

    second = sandbox.isolation_capabilities()

    assert second.network_isolation is True
    
    
def test_sandbox_security_policy_fields_are_immutable():
    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    with pytest.raises(AttributeError):
        policy.allow_network = False

    with pytest.raises(AttributeError):
        policy.require_network_isolation = False

    with pytest.raises(AttributeError):
        policy.require_filesystem_isolation = False

    with pytest.raises(AttributeError):
        policy.require_process_isolation = False
        
        
def test_runtime_sandbox_does_not_execute_backend_when_capability_is_missing():
    class MissingFilesystemBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError(
                "Backend must not execute when required capability is missing."
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_filesystem_isolation=True,
        ),
        isolation_backend=MissingFilesystemBackend(),
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "filesystem isolation capability" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_does_not_execute_backend_when_process_capability_is_missing():
    class MissingProcessBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError(
                "Backend must not execute when required capability is missing."
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_process_isolation=True,
        ),
        isolation_backend=MissingProcessBackend(),
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "process isolation capability" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_does_not_execute_backend_when_network_capability_is_missing():
    class MissingNetworkBackend(IsolationBackend):
        def is_available(self) -> bool:
            return True

        def capabilities(self) -> IsolationCapabilities:
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code: str, timeout: float) -> SandboxResult:
            raise AssertionError(
                "Backend must not execute when required capability is missing."
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=MissingNetworkBackend(),
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "network isolation capability" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_filesystem_root_is_temporary():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "from pathlib import Path; print(Path.cwd().name)"
    )

    assert result.success is True
    assert result.stdout.strip()
    assert result.stdout.strip().lower() != "aegis"
    
def test_runtime_sandbox_removes_temporary_files_after_execution():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "from pathlib import Path; "
        "Path('temporary_marker.txt').write_text('AEGIS'); "
        "print(Path.cwd())"
    )

    assert result.success is True

    temporary_path = Path(result.stdout.strip())
    marker_path = temporary_path / "temporary_marker.txt"

    assert not marker_path.exists()
    assert not temporary_path.exists()
    
def test_runtime_sandbox_reports_non_zero_exit_code():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys; print('FAILED'); sys.exit(7)"
    )

    assert result.success is False
    assert result.stdout.strip() == "FAILED"
    assert result.stderr == ""
    assert result.exit_code == 7
    
def test_runtime_sandbox_handles_unicode_stdout():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "print('AEGIS اختبار ✓')"
    )

    assert result.success is True
    assert result.stdout.strip() == "AEGIS اختبار ✓"
    assert result.stderr == ""
    assert result.exit_code == 0
    
    
    
def test_runtime_sandbox_handles_unicode_python_error():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "raise ValueError('حدث خطأ ✓')"
    )

    assert result.success is False
    assert "حدث خطأ ✓" in result.stderr
    assert result.exit_code != 0
    
def test_runtime_sandbox_unicode_output_respects_max_size():
    sandbox = unsafe_sandbox(max_output_size=20)

    result = sandbox.run(
        "print('اختبار Unicode طويل جدًا ✓')"
    )

    assert result.success is False
    assert "maximum allowed size" in result.stderr
    assert len(result.stdout) <= 20
    
def test_runtime_sandbox_unicode_timeout():
    sandbox = unsafe_sandbox(timeout=0.2)

    result = sandbox.run(
        "import time; print('بدأ التنفيذ ✓'); time.sleep(2)"
    )

    assert result.success is False
    assert "Execution timed out." in result.stderr
    assert result.exit_code == -1
    
def test_runtime_sandbox_unicode_stderr_respects_max_size():
    sandbox = unsafe_sandbox(max_output_size=20)

    result = sandbox.run(
        "import sys; sys.stderr.write('خطأ Unicode طويل جدًا ✓')"
    )

    assert result.success is False
    assert "maximum allowed size" in result.stderr
    assert len(result.stderr) <= 20 + len(
        "\nError output exceeded the maximum allowed size."
    )
    
def test_runtime_sandbox_custom_backend_preserves_unicode():
    class UnicodeBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="AEGIS اختبار ✓",
                stderr="",
                exit_code=0,
            )

    backend = UnicodeBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=False,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('ignored')")

    assert result.success is True
    assert result.stdout == "AEGIS اختبار ✓"
    assert result.stderr == ""
    assert result.exit_code == 0
    
    
    
    
    
    
    
    
    
def test_runtime_sandbox_executes_backend_when_all_isolation_capabilities_exist():
    class SpyBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            return SandboxResult(
                success=True,
                stdout="AEGIS isolated execution ✓",
                stderr="",
                exit_code=0,
            )

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert result.stdout == "AEGIS isolated execution ✓"
    assert result.stderr == ""
    assert result.exit_code == 0
    assert backend.run_called is True
    
    
    
    
    
    
def test_runtime_sandbox_writes_only_inside_temp_directory():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "from pathlib import Path; "
        "Path('sandbox_test.txt').write_text('AEGIS', encoding='utf-8'); "
        "print(Path('sandbox_test.txt').exists())"
    )

    assert result.success is True
    assert result.stdout.strip() == "True"
    
    
def test_runtime_sandbox_cleans_up_temp_directory():
    from pathlib import Path

    captured_path = None

    original_run = subprocess.run

    def spy_run(*args, **kwargs):
        nonlocal captured_path

        captured_path = Path(kwargs["cwd"])

        return original_run(*args, **kwargs)

    subprocess.run = spy_run

    try:
        sandbox = unsafe_sandbox()

        result = sandbox.run(
            "from pathlib import Path; "
            "Path('temporary.txt').write_text('AEGIS', encoding='utf-8')"
        )
    finally:
        subprocess.run = original_run

    assert result.success is True
    assert captured_path is not None
    assert not captured_path.exists()
    
    
    
    
    
def test_runtime_sandbox_handles_large_stdout_and_stderr():
    sandbox = unsafe_sandbox(max_output_size=100)

    result = sandbox.run(
        "import sys; "
        "print('O' * 1000); "
        "sys.stderr.write('E' * 1000)"
    )

    assert result.success is False
    assert "maximum allowed size" in result.stderr
    assert len(result.stdout) <= 100
    assert len(result.stderr) <= 100 + len(
        "\nError output exceeded the maximum allowed size."
    )
    assert result.exit_code == -1
    
def test_runtime_sandbox_allows_stdout_exactly_at_max_size():
    sandbox = unsafe_sandbox(max_output_size=100)

    result = sandbox.run(
        "print('A' * 99, end='')"
    )

    assert result.success is True
    assert len(result.stdout) == 99
    assert result.stderr == ""
    assert result.exit_code == 0
    
def test_runtime_sandbox_allows_stderr_exactly_at_max_size():
    sandbox = unsafe_sandbox(max_output_size=100)

    result = sandbox.run(
        "import sys; sys.stderr.write('E' * 100)"
    )

    assert result.success is True
    assert result.stdout == ""
    assert len(result.stderr) == 100
    assert result.exit_code == 0
    
    
    
def test_runtime_sandbox_supports_minimum_output_size():
    sandbox = unsafe_sandbox(max_output_size=1)

    result = sandbox.run(
        "print('AB', end='')"
    )

    assert result.success is False
    assert result.stdout == "A"
    assert "maximum allowed size" in result.stderr
    assert result.exit_code == -1
    
    
    
    
    
def test_runtime_sandbox_returns_failure_for_python_error():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "raise ValueError('AEGIS test error')"
    )

    assert result.success is False
    assert "ValueError" in result.stderr
    assert "AEGIS test error" in result.stderr
    assert result.exit_code != 0
    
    
    
    
    
    
    
    
    
    
    
    
    
def test_runtime_sandbox_combined_isolation_missing_capability_prevents_execution():
    class SpyBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend must not execute.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "process isolation capability" in result.stderr
    assert result.exit_code == -1
    assert backend.run_called is False
    
    
def test_runtime_sandbox_output_exactly_at_limit_succeeds():
    sandbox = unsafe_sandbox(max_output_size=3)

    result = sandbox.run("print('ABC', end='')")

    assert result.success is True
    assert result.stdout == "ABC"
    assert result.stderr == ""
    assert result.exit_code == 0
    
def test_runtime_sandbox_stderr_exactly_at_limit_succeeds():
    sandbox = unsafe_sandbox(max_output_size=3)

    result = sandbox.run(
        "import sys; sys.stderr.write('ABC')"
    )

    assert result.success is True
    assert result.stderr == "ABC"
    assert result.stdout == ""
    assert result.exit_code == 0
    
    
    
    
def test_runtime_sandbox_preserves_unicode_stderr_before_timeout():
    sandbox = unsafe_sandbox(timeout=0.1)

    result = sandbox.run(
        "import sys, time; "
        "sys.stderr.write('خطأ قبل انتهاء الوقت'); "
        "sys.stderr.flush(); "
        "time.sleep(1)"
    )

    assert result.success is False
    assert "خطأ قبل انتهاء الوقت" in result.stderr
    assert "Execution timed out." in result.stderr
    assert result.exit_code == -1
    
def test_runtime_sandbox_preserves_unicode_stdout_before_timeout():
    sandbox = unsafe_sandbox(timeout=0.1)

    result = sandbox.run(
        "import time; "
        "print('مرحبا من AEGIS', flush=True); "
        "time.sleep(1)"
    )

    assert result.success is False
    assert "مرحبا من AEGIS" in result.stdout
    assert "Execution timed out." in result.stderr
    assert result.exit_code == -1
    
    
def test_runtime_sandbox_unicode_stdout_exactly_at_limit_succeeds():
    sandbox = unsafe_sandbox(max_output_size=4)

    result = sandbox.run(
        "print('أ', end='')"
    )

    assert result.success is True
    assert result.stdout == "أ"
    assert result.stderr == ""
    assert result.exit_code == 0
    
def test_runtime_sandbox_unicode_stderr_exactly_at_limit_succeeds():
    sandbox = unsafe_sandbox(max_output_size=4)

    result = sandbox.run(
        "import sys; sys.stderr.write('أ')"
    )

    assert result.success is True
    assert result.stdout == ""
    assert result.stderr == "أ"
    assert result.exit_code == 0
    
    
    
def test_runtime_sandbox_temp_directory_is_removed_after_success():
    import os

    captured_cwd = None

    original_run = subprocess.run

    def spy_run(*args, **kwargs):
        nonlocal captured_cwd
        captured_cwd = kwargs["cwd"]
        return original_run(*args, **kwargs)

    try:
        subprocess.run = spy_run

        sandbox = unsafe_sandbox()

        result = sandbox.run("print('AEGIS')")

    finally:
        subprocess.run = original_run

    assert result.success is True
    assert captured_cwd is not None
    assert os.path.exists(captured_cwd) is False
    
def test_runtime_sandbox_temp_directory_is_removed_after_failure():
    import os

    captured_cwd = None

    original_run = subprocess.run

    def spy_run(*args, **kwargs):
        nonlocal captured_cwd
        captured_cwd = kwargs["cwd"]
        return original_run(*args, **kwargs)

    try:
        subprocess.run = spy_run

        sandbox = unsafe_sandbox()

        result = sandbox.run(
            "raise RuntimeError('AEGIS failure')"
        )

    finally:
        subprocess.run = original_run

    assert result.success is False
    assert result.exit_code != 0
    assert captured_cwd is not None
    assert os.path.exists(captured_cwd) is False
    
def test_runtime_sandbox_temp_directory_is_removed_after_timeout():
    import os

    captured_cwd = None

    original_run = subprocess.run

    def spy_run(*args, **kwargs):
        nonlocal captured_cwd
        captured_cwd = kwargs["cwd"]
        return original_run(*args, **kwargs)

    try:
        subprocess.run = spy_run

        sandbox = unsafe_sandbox(timeout=0.1)

        result = sandbox.run(
            "import time; time.sleep(1)"
        )

    finally:
        subprocess.run = original_run

    assert result.success is False
    assert "Execution timed out." in result.stderr
    assert captured_cwd is not None
    assert os.path.exists(captured_cwd) is False
    
    
def test_runtime_sandbox_preserves_stdout_on_nonzero_exit():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "print('before-failure', flush=True); raise SystemExit(7)"
    )

    assert result.success is False
    assert result.stdout == "before-failure\n"
    assert result.exit_code == 7
    
def test_runtime_sandbox_preserves_stderr_on_nonzero_exit():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys; "
        "sys.stderr.write('before-failure'); "
        "raise SystemExit(7)"
    )

    assert result.success is False
    assert result.stderr == "before-failure"
    assert result.exit_code == 7
    
def test_runtime_sandbox_preserves_unicode_on_nonzero_exit():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys; "
        "print('نجاح جزئي', flush=True); "
        "sys.stderr.write('خطأ جزئي'); "
        "raise SystemExit(7)"
    )

    assert result.success is False
    assert result.stdout == "نجاح جزئي\n"
    assert result.stderr == "خطأ جزئي"
    assert result.exit_code == 7
    
def test_runtime_sandbox_limits_stdout_and_stderr_together():
    sandbox = unsafe_sandbox(max_output_size=3)

    result = sandbox.run(
        "import sys; "
        "print('ABCD', end=''); "
        "sys.stderr.write('WXYZ')"
    )

    assert result.success is False
    assert result.stdout == "ABC"
    assert "maximum allowed size" in result.stderr
    assert result.exit_code == -1
    
    
def test_runtime_sandbox_stdout_and_stderr_exactly_at_limits_succeed():
    sandbox = unsafe_sandbox(max_output_size=3)

    result = sandbox.run(
        "import sys; "
        "print('ABC', end=''); "
        "sys.stderr.write('XYZ')"
    )

    assert result.success is True
    assert result.stdout == "ABC"
    assert result.stderr == "XYZ"
    assert result.exit_code == 0
    
def test_runtime_sandbox_successful_execution_returns_zero_exit_code():
    sandbox = unsafe_sandbox()

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert result.exit_code == 0
    
    
def test_runtime_sandbox_successful_execution_without_output():
    sandbox = unsafe_sandbox()

    result = sandbox.run("x = 42")

    assert result.success is True
    assert result.stdout == ""
    assert result.stderr == ""
    assert result.exit_code == 0
    
def test_runtime_sandbox_rejects_none_code():
    sandbox = RuntimeSandbox()

    result = sandbox.run(None)

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert result.stderr == "Code must be a string."
    
    
def test_runtime_sandbox_rejects_integer_code():
    sandbox = RuntimeSandbox()

    result = sandbox.run(123)

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert result.stderr == "Code must be a string."  
    
def test_runtime_sandbox_rejects_empty_string_code():
    sandbox = RuntimeSandbox()

    result = sandbox.run("")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert result.stderr == "Code cannot be empty."
    
    
def test_runtime_sandbox_handles_python_syntax_error():
    sandbox = RuntimeSandbox()

    result = sandbox.run(
        "if True print('AEGIS')"
    )

    assert result.success is False
    assert result.exit_code != 0
    assert result.stderr != ""
    
def test_runtime_sandbox_handles_runtime_error():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "1 / 0"
    )

    assert result.success is False
    assert result.exit_code != 0
    assert "ZeroDivisionError" in result.stderr 
    
def test_runtime_sandbox_preserves_stdout_on_runtime_error():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "print('before-error', flush=True); 1 / 0"
    )

    assert result.success is False
    assert result.stdout == "before-error\n"
    assert "ZeroDivisionError" in result.stderr
    assert result.exit_code != 0 
    
def test_runtime_sandbox_preserves_stderr_on_runtime_error():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys; "
        "sys.stderr.write('before-error'); "
        "sys.stderr.flush(); "
        "1 / 0"
    )

    assert result.success is False
    assert result.stderr.startswith("before-error")
    assert "ZeroDivisionError" in result.stderr
    assert result.exit_code != 0
    
def test_runtime_sandbox_preserves_unicode_on_runtime_error():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys; "
        "print('قبل الخطأ', flush=True); "
        "sys.stderr.write('رسالة خطأ'); "
        "sys.stderr.flush(); "
        "1 / 0"
    )

    assert result.success is False
    assert "قبل الخطأ" in result.stdout
    assert "رسالة خطأ" in result.stderr
    assert "ZeroDivisionError" in result.stderr
    assert result.exit_code != 0
    
def test_runtime_sandbox_successful_unicode_execution():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "print('أهلاً من AEGIS')"
    )

    assert result.success is True
    assert result.stdout == "أهلاً من AEGIS\n"
    assert result.stderr == ""
    assert result.exit_code == 0
    
def test_runtime_sandbox_does_not_write_outside_temp_directory():
    from pathlib import Path

    marker = Path("aegis_sandbox_security_test.txt")

    if marker.exists():
        marker.unlink()

    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "from pathlib import Path; "
        "Path('aegis_sandbox_security_test.txt').write_text('blocked')"
    )

    assert result.success is True
    assert marker.exists() is False
    
def test_runtime_sandbox_temp_directory_exists_during_execution():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import os; "
        "print(os.path.isdir(os.getcwd()))"
    )

    assert result.success is True
    assert result.stdout.strip() == "True"
    
    
    
    
    
def test_runtime_sandbox_allow_network_false_does_not_claim_isolation():
    sandbox = RuntimeSandbox(allow_network=False)

    assert sandbox.allow_network is False
    assert sandbox.security_policy.allow_network is False
    assert sandbox.isolation_capabilities().network_isolation is False
    
def test_runtime_sandbox_allow_network_true_does_not_create_isolation():
    sandbox = RuntimeSandbox(allow_network=True)

    assert sandbox.allow_network is True
    assert sandbox.security_policy.allow_network is True
    assert sandbox.isolation_capabilities().network_isolation is False
    
def test_runtime_sandbox_uses_custom_backend_capabilities():
    class CustomBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="custom backend",
                stderr="",
                exit_code=0,
            )

    backend = CustomBackend()

    sandbox = RuntimeSandbox(
        isolation_backend=backend
    )

    capabilities = sandbox.isolation_capabilities()

    assert capabilities.network_isolation is True
    assert capabilities.filesystem_isolation is False
    assert capabilities.process_isolation is True
    
    
    
    
def test_runtime_sandbox_handles_custom_backend_exception():
    class FailingBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise RuntimeError("Backend execution failed")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=FailingBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.stdout == ""
    assert "Backend execution failed" in result.stderr
    assert result.exit_code == -1
    
    
    
    
    
    
def test_runtime_sandbox_executes_backend_when_all_required_capabilities_exist():
    class TestBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False
            self.received_code = None
            self.received_timeout = None

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            self.received_code = code
            self.received_timeout = timeout

            return SandboxResult(
                success=True,
                stdout="backend-success",
                stderr="",
                exit_code=0,
            )

    backend = TestBackend()

    sandbox = RuntimeSandbox(
        timeout=3.0,
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert result.stdout == "backend-success"
    assert result.stderr == ""
    assert result.exit_code == 0

    assert backend.run_called is True
    assert backend.received_code == "print('AEGIS')"
    assert backend.received_timeout == 3.0
    
def test_runtime_sandbox_default_security_policy():
    sandbox = RuntimeSandbox()

    policy = sandbox.security_policy

    assert policy.allow_network is False
    assert policy.require_network_isolation is False
    assert policy.require_filesystem_isolation is False
    assert policy.require_process_isolation is False
    
    
    
    
def test_security_policy_is_immutable():
    policy = SandboxSecurityPolicy(
        allow_network=False,
        require_network_isolation=True,
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    try:
        policy.allow_network = True
        changed = True
    except Exception:
        changed = False

    assert changed is False
    assert policy.allow_network is False
    
def test_custom_security_policy_preserves_all_values():
    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
        require_filesystem_isolation=False,
        require_process_isolation=True,
    )

    assert policy.allow_network is True
    assert policy.requires_network_isolation() is True
    assert policy.requires_filesystem_isolation() is False
    assert policy.requires_process_isolation() is True
    
    
    
def test_custom_isolation_backend_replaces_default():
    backend = NoIsolationBackend()
    sandbox = RuntimeSandbox(isolation_backend=backend)

    assert sandbox.isolation_backend is backend
    
    
def test_backend_is_not_used_without_required_isolation():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            return SandboxResult(
                success=True,
                stdout="backend",
                stderr="",
                exit_code=0,
            )

    backend = SpyBackend()

    sandbox = unsafe_sandbox(
        isolation_backend=backend,
        security_policy=SandboxSecurityPolicy(allow_unsafe_local=True, 
            allow_network=False,
            require_network_isolation=False,
            require_filesystem_isolation=False,
            require_process_isolation=False,
        ),
    )

    result = sandbox.run("print('normal')")

    assert result.success is True
    assert "normal" in result.stdout
    assert backend.called is False
    
def test_unavailable_backend_does_not_execute():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False

        def is_available(self):
            return False

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            raise AssertionError("Backend must not execute.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert result.exit_code == -1
    assert backend.called is False
    assert "unavailable" in result.stderr.lower()
    
    
def test_backend_exception_is_handled():
    class FailingBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise RuntimeError("Backend crashed")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=FailingBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "Backend crashed" in result.stderr
    
def test_missing_filesystem_capability_prevents_execution():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            raise AssertionError("Backend must not execute.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_filesystem_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert result.exit_code == -1
    assert backend.called is False
    assert "filesystem isolation" in result.stderr.lower()
    
def test_missing_process_capability_prevents_execution():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code, timeout):
            self.called = True
            raise AssertionError("Backend must not execute.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_process_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert result.exit_code == -1
    assert backend.called is False
    assert "process isolation" in result.stderr.lower()  
    
def test_complete_isolation_backend_executes_code():
    class TestBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="executed",
                stderr="",
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=TestBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is True
    assert result.stdout == "executed"
    assert result.stderr == ""
    assert result.exit_code == 0
    
def test_no_isolation_backend_has_no_isolation_capabilities():
    backend = NoIsolationBackend()

    capabilities = backend.capabilities()

    assert capabilities.network_isolation is False
    assert capabilities.filesystem_isolation is False
    assert capabilities.process_isolation is False
    
def test_windows_backend_has_no_isolation_capabilities():
    backend = WindowsIsolationBackend()

    capabilities = backend.capabilities()

    assert capabilities.network_isolation is False
    assert capabilities.filesystem_isolation is False
    assert capabilities.process_isolation is False
    assert backend.is_available() is False
    
def test_default_security_policy_requires_no_isolation():
    policy = SandboxSecurityPolicy()

    assert policy.allow_network is False
    assert policy.requires_network_isolation() is False
    assert policy.requires_filesystem_isolation() is False
    assert policy.requires_process_isolation() is False
    
def test_allow_network_does_not_imply_network_isolation():
    policy = SandboxSecurityPolicy(
        allow_network=True,
    )

    assert policy.allow_network is True
    assert policy.requires_network_isolation() is False
    
    
def test_runtime_sandbox_returns_backend_capabilities():
    backend = NoIsolationBackend()
    sandbox = RuntimeSandbox(isolation_backend=backend)

    capabilities = sandbox.isolation_capabilities()
    expected = backend.capabilities()

    assert capabilities == expected
    
def test_isolation_capabilities_are_read_dynamically():
    class DynamicBackend(NoIsolationBackend):
        def __init__(self):
            self.network = False

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=self.network,
                filesystem_isolation=False,
                process_isolation=False,
            )

    backend = DynamicBackend()
    sandbox = RuntimeSandbox(isolation_backend=backend)

    first = sandbox.isolation_capabilities()
    assert first.network_isolation is False

    backend.network = True

    second = sandbox.isolation_capabilities()
    assert second.network_isolation is True  
    
def test_missing_network_capability_prevents_execution():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            raise AssertionError("Backend must not execute.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert result.exit_code == -1
    assert backend.called is False
    assert "network isolation" in result.stderr.lower()
    
def test_missing_process_capability_prevents_execution_directly():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code, timeout):
            self.called = True
            raise AssertionError("Backend must not execute.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_process_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert result.exit_code == -1
    assert backend.called is False
    assert "process isolation" in result.stderr.lower()
    
def test_missing_filesystem_capability_prevents_execution_directly():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            raise AssertionError("Backend must not execute.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_filesystem_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert result.exit_code == -1
    assert backend.called is False
    assert "filesystem isolation" in result.stderr.lower()
    
def test_all_required_isolation_capabilities_allow_execution():
    class TestBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            return SandboxResult(
                success=True,
                stdout="allowed",
                stderr="",
                exit_code=0,
            )

    backend = TestBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is True
    assert result.stdout == "allowed"
    assert backend.called is True
    
def test_all_required_isolation_rejects_unavailable_backend():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False

        def is_available(self):
            return False

        def capabilities(self):
            raise AssertionError("Capabilities must not be checked.")

        def run(self, code, timeout):
            self.called = True
            raise AssertionError("Backend must not execute.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert result.exit_code == -1
    assert backend.called is False
    assert "isolation" in result.stderr.lower()
    assert "unavailable" in result.stderr.lower()
    
    
    
def test_stdout_exceeding_limit_is_rejected():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run("print('12345678901')")

    assert result.success is False
    assert len(result.stdout) == 10
    assert "maximum allowed size" in result.stderr.lower()
    
def test_stderr_exceeding_limit_is_rejected():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('12345678901')"
    )

    assert result.success is False
    assert len(result.stderr) > 10
    assert "error output exceeded the maximum allowed size" in result.stderr.lower()
    
def test_stdout_exactly_at_limit_is_allowed():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run("print('123456789', end='')")

    assert result.success is True
    assert result.stdout == "123456789"
    assert len(result.stdout) == 9
    
def test_stderr_exactly_at_limit_is_allowed():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('123456789')"
    )

    assert result.success is True
    assert result.stderr == "123456789"
    assert len(result.stderr) == 9
    
def test_stdout_one_byte_over_limit_is_rejected():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run("print('12345678901', end='')")

    assert result.success is False
    assert len(result.stdout) == 10
    assert result.stdout == "1234567890"
    assert "maximum allowed size" in result.stderr.lower()
    
def test_stderr_one_byte_over_limit_is_rejected():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('12345678901')"
    )

    assert result.success is False
    assert result.stderr.startswith("1234567890")
    assert "error output exceeded the maximum allowed size" in result.stderr.lower()
    
    
    
    
    
    
    
    
def test_runtime_sandbox_preserves_nonzero_exit_code():
    sandbox = unsafe_sandbox()

    result = sandbox.run("raise SystemExit(7)")

    assert result.success is False
    assert result.exit_code == 7
    
def test_runtime_sandbox_preserves_stdout_on_failure():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "print('before failure'); raise ValueError('boom')"
    )

    assert result.success is False
    assert result.exit_code != 0
    assert result.stdout == "before failure\n"
    assert "ValueError" in result.stderr
def test_runtime_sandbox_preserves_unicode_on_failure():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "print('مرحبا بالعالم'); raise SystemExit(5)"
    )

    assert result.success is False
    assert result.exit_code == 5
    assert result.stdout == "مرحبا بالعالم\n"
    
def test_runtime_sandbox_preserves_stdout_before_timeout():
    sandbox = unsafe_sandbox(timeout=0.1)

    result = sandbox.run(
        "import time; print('before timeout', flush=True); time.sleep(1)"
    )

    assert result.success is False
    assert "before timeout" in result.stdout
    assert "timed out" in result.stderr.lower()
    
def test_runtime_sandbox_preserves_stderr_before_timeout():
    sandbox = unsafe_sandbox(timeout=0.1)

    result = sandbox.run(
        "import sys, time; sys.stderr.write('before timeout'); sys.stderr.flush(); time.sleep(1)"
    )

    assert result.success is False
    assert "before timeout" in result.stderr
    assert "timed out" in result.stderr.lower()
    
    
def test_runtime_sandbox_accepts_small_positive_timeout():
    sandbox = RuntimeSandbox(timeout=0.01)

    result = sandbox.run("print('hello')")

    assert result.exit_code in (0, -1)
    
    
    
def test_runtime_sandbox_does_not_write_to_project_directory():
    from pathlib import Path

    project_dir = Path.cwd()
    target = project_dir / "aegis_sandbox_escape_test.txt"

    if target.exists():
        target.unlink()

    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "from pathlib import Path; Path('aegis_sandbox_escape_test.txt').write_text('blocked')"
    )

    assert result.success is True
    assert not target.exists()
    
def test_runtime_sandbox_cleans_up_temp_directory_after_success():
    import os

    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import os; print(os.getcwd())"
    )

    temp_dir = result.stdout.strip()

    assert result.success is True
    assert temp_dir != ""
    assert not os.path.exists(temp_dir)
    
def test_runtime_sandbox_cleans_up_temp_directory_after_failure():
    import os

    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import os; print(os.getcwd()); raise ValueError('boom')"
    )

    temp_dir = result.stdout.strip()

    assert result.success is False
    assert temp_dir != ""
    assert not os.path.exists(temp_dir)
    
def test_runtime_sandbox_cleans_up_temp_directory_after_timeout():
    import os

    sandbox = unsafe_sandbox(timeout=0.1)

    result = sandbox.run(
        "import os, time; print(os.getcwd(), flush=True); time.sleep(1)"
    )

    temp_dir = result.stdout.strip()

    assert result.success is False
    assert temp_dir != ""
    assert not os.path.exists(temp_dir)
    
def test_runtime_sandbox_allows_writing_inside_temp_directory():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "from pathlib import Path; "
        "Path('test.txt').write_text('hello'); "
        "print(Path('test.txt').read_text())"
    )

    assert result.success is True
    assert result.stdout == "hello\n"
    
def test_runtime_sandbox_can_read_file_inside_temp_directory():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "from pathlib import Path; "
        "Path('data.txt').write_text('AEGIS'); "
        "print(Path('data.txt').read_text())"
    )

    assert result.success is True
    assert result.stdout == "AEGIS\n"
    
    
def test_allow_network_true_does_not_create_isolation():
    sandbox = RuntimeSandbox(allow_network=True)

    capabilities = sandbox.isolation_capabilities()

    assert sandbox.allow_network is True
    assert capabilities.network_isolation is False
    
def test_runtime_sandbox_uses_no_isolation_backend_by_default():
    sandbox = RuntimeSandbox()

    assert isinstance(sandbox.isolation_backend, NoIsolationBackend)
    
    
def test_runtime_sandbox_passes_timeout_to_custom_backend():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.received_timeout = None

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.received_timeout = timeout
            return SandboxResult(True, "ok", "", 0)

    backend = SpyBackend()
    sandbox = RuntimeSandbox(
        timeout=7.5,
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is True
    assert backend.received_timeout == 7.5
    
    
def test_runtime_sandbox_unavailable_backend_does_not_execute():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False

        def is_available(self):
            return False

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            return SandboxResult(True, "backend", "", 0)

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "isolation is unavailable" in result.stderr
    assert backend.called is False
    
def test_runtime_sandbox_checks_backend_availability_before_capabilities():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.capabilities_called = False

        def is_available(self):
            return False

        def capabilities(self):
            self.capabilities_called = True
            raise AssertionError("Capabilities should not be checked.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('blocked')")

    assert result.success is False
    assert backend.capabilities_called is False
    
def test_runtime_sandbox_missing_filesystem_capability_prevents_execution():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            return SandboxResult(True, "backend", "", 0)

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_filesystem_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "filesystem isolation capability is unavailable" in result.stderr
    assert backend.called is False
    
def test_runtime_sandbox_missing_process_capability_prevents_execution():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code, timeout):
            self.called = True
            return SandboxResult(True, "backend", "", 0)

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_process_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "process isolation capability is unavailable" in result.stderr
    assert backend.called is False
    
def test_runtime_sandbox_missing_network_capability_prevents_execution():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            return SandboxResult(True, "backend", "", 0)

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert "network isolation capability is unavailable" in result.stderr
    assert backend.called is False
    
def test_runtime_sandbox_complete_isolation_backend_executes():
    class TestBackend(NoIsolationBackend):
        def __init__(self):
            self.called = False
            self.received_code = None
            self.received_timeout = None

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            self.received_code = code
            self.received_timeout = timeout
            return SandboxResult(True, "backend-output", "", 0)

    backend = TestBackend()

    sandbox = RuntimeSandbox(
        timeout=5.0,
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is True
    assert result.stdout == "backend-output"
    assert result.exit_code == 0
    assert backend.called is True
    assert backend.received_code == "print('hello')"
    assert backend.received_timeout == 5.0
def test_no_isolation_backend_reports_all_capabilities_as_false():
    backend = NoIsolationBackend()

    capabilities = backend.capabilities()

    assert capabilities.network_isolation is False
    assert capabilities.filesystem_isolation is False
    assert capabilities.process_isolation is False
    
def test_windows_isolation_backend_reports_all_capabilities_as_false():
    backend = WindowsIsolationBackend()

    capabilities = backend.capabilities()

    assert capabilities.network_isolation is False
    assert capabilities.filesystem_isolation is False
    assert capabilities.process_isolation is False
    
    
def test_sandbox_security_policy_defaults():
    policy = SandboxSecurityPolicy()

    assert policy.allow_network is False
    assert policy.requires_network_isolation() is False
    assert policy.requires_filesystem_isolation() is False
    assert policy.requires_process_isolation() is False
    
def test_allow_network_true_does_not_imply_network_isolation():
    sandbox = RuntimeSandbox(allow_network=True)

    assert sandbox.allow_network is True
    assert sandbox.isolation_capabilities().network_isolation is False
    
def test_runtime_sandbox_preserves_custom_security_policy():
    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
        require_filesystem_isolation=True,
        require_process_isolation=False,
    )

    sandbox = RuntimeSandbox(security_policy=policy)

    assert sandbox.security_policy is policy
    assert sandbox.allow_network is True
    assert sandbox.security_policy.requires_network_isolation() is True
    assert sandbox.security_policy.requires_filesystem_isolation() is True
    assert sandbox.security_policy.requires_process_isolation() is False
    
def test_runtime_sandbox_default_backend_is_no_isolation():
    sandbox = RuntimeSandbox()

    assert isinstance(sandbox.isolation_backend, NoIsolationBackend)
    assert sandbox.isolation_backend.is_available() is False
    
def test_runtime_sandbox_custom_backend_replaces_default():
    backend = WindowsIsolationBackend()

    sandbox = RuntimeSandbox(isolation_backend=backend)

    assert sandbox.isolation_backend is backend
    assert type(sandbox.isolation_backend) is WindowsIsolationBackend
    
def test_runtime_sandbox_rejects_non_positive_timeout():
    import pytest

    with pytest.raises(ValueError, match="Timeout must be greater than zero"):
        RuntimeSandbox(timeout=0)

    with pytest.raises(ValueError, match="Timeout must be greater than zero"):
        RuntimeSandbox(timeout=-1)
        
        
def test_runtime_sandbox_rejects_stdout_over_max_output_size():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run("print('12345678901')")

    assert result.success is False
    assert "maximum allowed size" in result.stderr
    
def test_runtime_sandbox_rejects_stderr_over_max_output_size():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('12345678901')"
    )

    assert result.success is False
    assert "Error output exceeded the maximum allowed size." in result.stderr
    
def test_runtime_sandbox_allows_stdout_at_max_output_size():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run("print('123456789')")

    assert result.success is True
    assert result.stdout == "123456789\n"
    
def test_runtime_sandbox_allows_stderr_at_max_output_size():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('1234567890')"
    )

    assert result.success is True
    assert result.stderr == "1234567890"
    
    
    
    
    
def test_runtime_sandbox_successful_execution():
    sandbox = unsafe_sandbox()

    result = sandbox.run("print('hello')")

    assert result.success is True
    assert result.stdout == "hello\n"
    assert result.stderr == ""
    assert result.exit_code == 0
    
def test_runtime_sandbox_successful_execution_with_stderr():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys; print('out'); print('err', file=sys.stderr)"
    )

    assert result.success is True
    assert result.stdout == "out\n"
    assert result.stderr == "err\n"
    assert result.exit_code == 0
    
def test_runtime_sandbox_python_error():
    sandbox = unsafe_sandbox()

    result = sandbox.run("raise ValueError('boom')")

    assert result.success is False
    assert result.exit_code != 0
    assert "ValueError: boom" in result.stderr
def test_runtime_sandbox_nonzero_exit_code_is_failure():
    sandbox = unsafe_sandbox()

    result = sandbox.run("raise SystemExit(3)")

    assert result.success is False
    assert result.exit_code == 3
    
def test_runtime_sandbox_handles_unicode_output_on_failure():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys; "
        "print('مرحبا AEGIS'); "
        "print('خطأ', file=sys.stderr); "
        "raise RuntimeError('فشل')"
    )

    assert result.success is False
    assert "مرحبا AEGIS" in result.stdout
    assert "خطأ" in result.stderr
    assert "RuntimeError" in result.stderr
    
def test_runtime_sandbox_timeout_stops_execution():
    sandbox = unsafe_sandbox(timeout=0.2)

    result = sandbox.run(
        "import time; time.sleep(2); print('finished')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert "Execution timed out." in result.stderr
    
def test_runtime_sandbox_timeout_without_output():
    sandbox = unsafe_sandbox(timeout=0.2)

    result = sandbox.run(
        "import time; time.sleep(2)"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert "Execution timed out." in result.stderr
    
def test_runtime_sandbox_preserves_parent_working_directory():
    import os

    original_cwd = os.getcwd()
    sandbox = unsafe_sandbox()

    result = sandbox.run("import os; print(os.getcwd())")

    assert result.success is True
    assert os.getcwd() == original_cwd
    
    
def test_runtime_sandbox_does_not_change_project_working_directory():
    import os

    original_cwd = os.getcwd()
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "from pathlib import Path; "
        "Path('sandbox_file.txt').write_text('hello')"
    )

    assert result.success is True
    assert os.getcwd() == original_cwd
    
    
def test_runtime_sandbox_cleans_up_temporary_directory_after_failure():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "from pathlib import Path; "
        "Path('temporary_file.txt').write_text('hello'); "
        "print(Path.cwd()); "
        "raise RuntimeError('boom')"
    )

    assert result.success is False

    temp_directory = result.stdout.strip()

    from pathlib import Path

    assert not Path(temp_directory).exists()
    
def test_runtime_sandbox_cleans_up_temporary_directory_after_timeout():
    sandbox = unsafe_sandbox(timeout=0.2)

    result = sandbox.run(
        "from pathlib import Path; "
        "Path('temporary_file.txt').write_text('hello'); "
        "print(Path.cwd(), flush=True); "
        "import time; "
        "time.sleep(2)"
    )

    assert result.success is False
    assert "Execution timed out." in result.stderr

    temp_directory = result.stdout.strip()

    from pathlib import Path

    assert temp_directory
    assert not Path(temp_directory).exists()
    
def test_runtime_sandbox_allows_file_operations_inside_temp_directory():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "from pathlib import Path; "
        "p = Path('test.txt'); "
        "p.write_text('AEGIS'); "
        "print(p.read_text())"
    )

    assert result.success is True
    assert result.stdout == "AEGIS\n"
    assert result.stderr == ""
    
    
def test_runtime_sandbox_preserves_parent_cwd_after_timeout():
    import os

    original_cwd = os.getcwd()
    sandbox = unsafe_sandbox(timeout=0.2)

    result = sandbox.run(
        "import os, time; "
        "os.chdir('..'); "
        "time.sleep(2)"
    )

    assert result.success is False
    assert "Execution timed out." in result.stderr
    assert os.getcwd() == original_cwd
    
def test_allow_network_false_does_not_claim_network_isolation():
    sandbox = RuntimeSandbox(allow_network=False)

    assert sandbox.allow_network is False
    assert sandbox.isolation_capabilities().network_isolation is False
    
def test_runtime_sandbox_preserves_custom_backend_identity():
    backend = NoIsolationBackend()

    sandbox = RuntimeSandbox(isolation_backend=backend)

    assert sandbox.isolation_backend is backend
    
    
    
def test_runtime_sandbox_checks_filesystem_capability_before_execution():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend run() must not be called.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_filesystem_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('blocked')")

    assert result.success is False
    assert backend.run_called is False
    assert "filesystem isolation capability is unavailable" in result.stderr
    
def test_runtime_sandbox_checks_process_capability_before_execution():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend run() must not be called.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_process_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('blocked')")

    assert result.success is False
    assert backend.run_called is False
    assert "process isolation capability is unavailable" in result.stderr
    
def test_runtime_sandbox_checks_network_capability_before_execution():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend run() must not be called.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('blocked')")

    assert result.success is False
    assert backend.run_called is False
    assert "network isolation capability is unavailable" in result.stderr
    
def test_runtime_sandbox_rejects_backend_with_all_required_capabilities_missing():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend run() must not be called.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('blocked')")

    assert result.success is False
    assert backend.run_called is False
    assert "network isolation capability is unavailable" in result.stderr
    
    
def test_runtime_sandbox_passes_timeout_to_isolation_backend():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.received_timeout = None

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.received_timeout = timeout
            return SandboxResult(True, "ok", "", 0)

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        timeout=7.5,
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is True
    assert result.stdout == "ok"
    assert backend.received_timeout == 7.5
    
def test_runtime_sandbox_passes_code_unchanged_to_isolation_backend():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.received_code = None

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.received_code = code
            return SandboxResult(True, "ok", "", 0)

    backend = SpyBackend()

    code = "print('AEGIS isolation test')"

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run(code)

    assert result.success is True
    assert backend.received_code == code
    
def test_runtime_sandbox_returns_isolation_backend_result_unchanged():
    class SpyBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=False,
                stdout="backend-output",
                stderr="backend-error",
                exit_code=42,
            )

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert result.stdout == "backend-output"
    assert result.stderr == "backend-error"
    assert result.exit_code == 42
    
    
def test_runtime_sandbox_does_not_call_backend_without_isolation_requirement():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend must not be called.")

    backend = SpyBackend()

    sandbox = unsafe_sandbox(
        security_policy=SandboxSecurityPolicy(allow_unsafe_local=True, 
            allow_network=False
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('normal execution')")

    assert result.success is True
    assert result.stdout.strip() == "normal execution"
    assert backend.run_called is False
def test_runtime_sandbox_allow_network_true_does_not_require_isolation_backend():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend must not be called.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        allow_network=True,
        isolation_backend=backend,
    )

    result = sandbox.run("print('network-enabled mode')")

    assert result.success is False
    assert result.exit_code == -1
    assert "network isolation" in result.stderr.lower()
    assert backend.run_called is False


    
def test_runtime_sandbox_network_policy_overrides_allow_network_flag():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend run() must not be called.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        allow_network=True,
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('blocked')")

    assert result.success is False
    assert backend.run_called is False
    assert "network isolation capability is unavailable" in result.stderr
    
def test_runtime_sandbox_does_not_execute_code_when_isolation_backend_unavailable():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return False

        def capabilities(self):
            self.run_called = True
            raise AssertionError("capabilities() must not be called.")

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("run() must not be called.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('must not execute')")

    assert result.success is False
    assert backend.run_called is False
    assert "Secure network isolation is unavailable" in result.stderr
    
def test_runtime_sandbox_rejects_non_string_code_before_backend_execution():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            self.run_called = True
            return True

        def capabilities(self):
            self.run_called = True
            raise AssertionError("Backend must not be inspected.")

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend must not be executed.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run(123)

    assert result.success is False
    assert result.stderr == "Code must be a string."
    assert result.exit_code == -1
    assert backend.run_called is False
    
def test_runtime_sandbox_rejects_empty_code_before_backend_execution():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            self.run_called = True
            return True

        def capabilities(self):
            self.run_called = True
            raise AssertionError("Backend must not be inspected.")

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend must not be executed.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("")

    assert result.success is False
    assert result.stderr == "Code cannot be empty."
    assert result.exit_code == -1
    assert backend.run_called is False
    
def test_runtime_sandbox_rejects_whitespace_code_before_backend_execution():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            self.run_called = True
            return True

        def capabilities(self):
            self.run_called = True
            raise AssertionError("Backend must not be inspected.")

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend must not be executed.")

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("   \n\t  ")

    assert result.success is False
    assert result.stderr == "Code cannot be empty."
    assert result.exit_code == -1
    assert backend.run_called is False
    
    
def test_runtime_sandbox_normalizes_timeout_to_float_for_backend():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.received_timeout = None

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.received_timeout = timeout
            return SandboxResult(True, "ok", "", 0)

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        timeout=5,
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is True
    assert backend.received_timeout == 5
    assert isinstance(backend.received_timeout, float)
    
def test_runtime_sandbox_preserves_max_output_size_as_integer():
    sandbox = RuntimeSandbox(max_output_size=12345)

    assert sandbox.max_output_size == 12345
    assert isinstance(sandbox.max_output_size, int)
    
def test_runtime_sandbox_rejects_timeout_that_becomes_non_positive():
    with pytest.raises(ValueError, match="Timeout must be greater than zero."):
        RuntimeSandbox(timeout=0)
        
def test_runtime_sandbox_accepts_fractional_timeout():
    sandbox = RuntimeSandbox(timeout=0.25)

    assert sandbox.timeout == 0.25
    assert isinstance(sandbox.timeout, float)
    
def test_runtime_sandbox_does_not_modify_isolation_backend_output():
    class CustomBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="x" * 100,
                stderr="y" * 100,
                exit_code=0,
            )

    backend = CustomBackend()

    sandbox = RuntimeSandbox(
        max_output_size=10,
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is True
    assert result.stdout == "x" * 100
    assert result.stderr == "y" * 100
    assert result.exit_code == 0
    
def test_runtime_sandbox_uses_isolation_backend_run_contract():
    class ContractBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            assert isinstance(code, str)
            assert isinstance(timeout, float)
            assert code == "print('contract')"
            assert timeout == 3.0
            return SandboxResult(True, "ok", "", 0)

    backend = ContractBackend()

    sandbox = RuntimeSandbox(
        timeout=3,
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('contract')")

    assert result.success is True
    assert result.stdout == "ok"
    
def test_runtime_sandbox_preserves_custom_isolation_backend_identity():
    class CustomBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(True, "ok", "", 0)

    backend = CustomBackend()

    sandbox = RuntimeSandbox(
        isolation_backend=backend
    )

    assert sandbox.isolation_backend is backend
    
def test_runtime_sandbox_creates_independent_default_backends():
    sandbox_one = RuntimeSandbox()
    sandbox_two = RuntimeSandbox()

    assert sandbox_one.isolation_backend is not sandbox_two.isolation_backend
    assert type(sandbox_one.isolation_backend) is NoIsolationBackend
    assert type(sandbox_two.isolation_backend) is NoIsolationBackend
    
def test_runtime_sandbox_uses_default_backend_when_none_is_provided():
    sandbox = RuntimeSandbox(isolation_backend=None)

    assert type(sandbox.isolation_backend) is NoIsolationBackend
    assert sandbox.isolation_backend.is_available() is False
    
    
def test_runtime_sandbox_preserves_security_policy_identity():
    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    assert sandbox.security_policy is policy
    
def test_runtime_sandbox_exposes_custom_backend_capabilities():
    class CustomBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(True, "ok", "", 0)

    backend = CustomBackend()

    sandbox = RuntimeSandbox(
        isolation_backend=backend
    )

    capabilities = sandbox.isolation_capabilities()

    assert capabilities.network_isolation is True
    assert capabilities.filesystem_isolation is False
    assert capabilities.process_isolation is True
    
def test_runtime_sandbox_cannot_mutate_isolation_capabilities():
    sandbox = RuntimeSandbox()

    capabilities = sandbox.isolation_capabilities()

    with pytest.raises(AttributeError):
        capabilities.network_isolation = True
        
def test_runtime_sandbox_reads_capabilities_before_backend_execution():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.capabilities_called = False
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            self.capabilities_called = True
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            assert self.capabilities_called is True
            self.run_called = True
            return SandboxResult(True, "ok", "", 0)

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is True
    assert backend.capabilities_called is True
    assert backend.run_called is True
    
def test_runtime_sandbox_checks_capabilities_before_passing_timeout():
    class SpyBackend(NoIsolationBackend):
        def __init__(self):
            self.capabilities_checked = False
            self.received_timeout = None

        def is_available(self):
            return True

        def capabilities(self):
            self.capabilities_checked = True
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            assert self.capabilities_checked is True
            self.received_timeout = timeout
            return SandboxResult(True, "ok", "", 0)

    backend = SpyBackend()

    sandbox = RuntimeSandbox(
        timeout=4,
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is True
    assert backend.received_timeout == 4.0
    
def test_runtime_sandbox_rejects_none_from_isolation_backend():
    class BrokenBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return None

    backend = BrokenBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert "invalid" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_invalid_isolation_backend_result():
    class BrokenBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return "not a sandbox result"

    backend = BrokenBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert "invalid" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_malformed_isolation_backend_result():
    class BrokenBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success="yes",
                stdout="",
                stderr="",
                exit_code=0,
            )

    backend = BrokenBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert "invalid" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_malformed_isolation_backend_exit_code():
    class BrokenBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=False,
                stdout="",
                stderr="error",
                exit_code="zero",
            )

    backend = BrokenBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert "invalid" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_malformed_isolation_backend_stdout():
    class BrokenBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout=123,
                stderr="",
                exit_code=0,
            )

    backend = BrokenBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert "invalid" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_malformed_isolation_backend_stderr():
    class BrokenBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=False,
                stdout="",
                stderr=123,
                exit_code=1,
            )

    backend = BrokenBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert "invalid" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_preserves_valid_isolation_backend_result():
    expected = SandboxResult(
        success=True,
        stdout="hello",
        stderr="warning",
        exit_code=0,
    )

    class ValidBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return expected

    backend = ValidBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result is expected
    
    
    
    
    
def test_runtime_sandbox_checks_backend_availability():
    class TrackingBackend(NoIsolationBackend):
        def __init__(self):
            self.checked = False

        def is_available(self):
            self.checked = True
            return False

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=False,
                process_isolation=False,
            )

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert backend.checked is True
    assert result.success is False
    
    
def test_runtime_sandbox_checks_capabilities_before_execution():
    class InvalidCapabilitiesBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend should not execute.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=InvalidCapabilitiesBackend(),
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert "network isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_executes_backend_with_complete_capabilities():
    class CompleteBackend(NoIsolationBackend):
        def __init__(self):
            self.executed = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.executed = True
            return SandboxResult(
                success=True,
                stdout="backend executed",
                stderr="",
                exit_code=0,
            )

    backend = CompleteBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert backend.executed is True
    assert result.success is True
    assert result.stdout == "backend executed"
    assert result.exit_code == 0
    
    
    
    
    
    
    
    
    
def test_runtime_sandbox_rejects_none_isolation_capabilities():
    class BrokenCapabilitiesBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return None

        def run(self, code, timeout):
            raise AssertionError("Backend should not execute.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=BrokenCapabilitiesBackend(),
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert "capabilities" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_invalid_isolation_capabilities_type():
    class BrokenCapabilitiesBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return "invalid capabilities"

        def run(self, code, timeout):
            raise AssertionError("Backend should not execute.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=BrokenCapabilitiesBackend(),
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert "capabilities" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_invalid_backend_availability_before_capabilities():
    class BrokenBackend(NoIsolationBackend):
        def is_available(self):
            return "yes"

        def capabilities(self):
            raise AssertionError(
                "Capabilities should not be checked."
            )

        def run(self, code, timeout):
            raise AssertionError(
                "Backend should not execute."
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=BrokenBackend(),
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert "availability" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_incomplete_capabilities():
    class IncompleteBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend should not execute.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_filesystem_isolation=True
        ),
        isolation_backend=IncompleteBackend(),
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert "filesystem isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_missing_process_isolation():
    class IncompleteProcessBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend should not execute.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_process_isolation=True
        ),
        isolation_backend=IncompleteProcessBackend(),
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert "process isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_combined_incomplete_capabilities():
    class IncompleteCombinedBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend should not execute.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
            require_filesystem_isolation=True,
        ),
        isolation_backend=IncompleteCombinedBackend(),
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert "filesystem isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_no_isolation_backend_reports_no_capabilities():
    backend = NoIsolationBackend()

    assert backend.is_available() is False

    capabilities = backend.capabilities()

    assert capabilities.network_isolation is False
    assert capabilities.filesystem_isolation is False
    assert capabilities.process_isolation is False
    
def test_windows_isolation_backend_reports_no_capabilities():
    backend = WindowsIsolationBackend()

    assert backend.is_available() is False

    capabilities = backend.capabilities()

    assert capabilities.network_isolation is False
    assert capabilities.filesystem_isolation is False
    assert capabilities.process_isolation is False
    
        
def test_sandbox_security_policy_is_immutable():
    policy = SandboxSecurityPolicy(
        allow_network=False,
        require_network_isolation=True,
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    try:
        policy.allow_network = True
    except (AttributeError, TypeError):
        pass
    else:
        raise AssertionError(
            "SandboxSecurityPolicy should be immutable."
        )
        
        
    
    
    
    
    
    
    
def test_runtime_sandbox_rejects_missing_network_capability_before_run():
    class TrackingBackend(NoIsolationBackend):
        def __init__(self):
            self.executed = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.executed = True
            raise AssertionError("Backend should not execute.")

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert backend.executed is False
    assert "network isolation" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_missing_filesystem_capability_before_run():
    class TrackingBackend(NoIsolationBackend):
        def __init__(self):
            self.executed = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.executed = True
            raise AssertionError("Backend should not execute.")

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_filesystem_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert backend.executed is False
    assert "filesystem isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_missing_process_capability_before_run():
    class TrackingBackend(NoIsolationBackend):
        def __init__(self):
            self.executed = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code, timeout):
            self.executed = True
            raise AssertionError("Backend should not execute.")

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_process_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert backend.executed is False
    assert "process isolation" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_combined_incomplete_capabilities_before_run():
    class TrackingBackend(NoIsolationBackend):
        def __init__(self):
            self.executed = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code, timeout):
            self.executed = True
            raise AssertionError("Backend should not execute.")

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert backend.executed is False
    assert result.exit_code == -1
    assert (
        "filesystem isolation" in result.stderr.lower()
        or "process isolation" in result.stderr.lower()
    )
    
def test_runtime_sandbox_does_not_execute_unavailable_backend():
    class TrackingBackend(NoIsolationBackend):
        def __init__(self):
            self.executed = False

        def is_available(self):
            return False

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.executed = True
            raise AssertionError("Unavailable backend should not execute.")

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert backend.executed is False
    assert result.exit_code == -1
    assert "unavailable" in result.stderr.lower()
    
    
def test_runtime_sandbox_rejects_none_from_backend():
    class NoneBackend(NoIsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return None

    backend = NoneBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('test')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid" in result.stderr.lower()
    
    
    
    
    
def test_runtime_sandbox_does_not_use_backend_without_required_isolation():
    class TrackingBackend(NoIsolationBackend):
        def __init__(self):
            self.executed = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.executed = True
            raise AssertionError("Backend should not execute.")

    backend = TrackingBackend()

    sandbox = unsafe_sandbox(
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is True
    assert result.stdout.strip() == "hello"
    assert backend.executed is False
    
def test_isolation_capabilities_are_immutable():
    capabilities = IsolationCapabilities(
        network_isolation=True,
        filesystem_isolation=False,
        process_isolation=True,
    )

    try:
        capabilities.network_isolation = False
        raise AssertionError("IsolationCapabilities should be immutable.")
    except AttributeError:
        pass

    assert capabilities.network_isolation is True
    
def test_sandbox_security_policy_defaults_are_safe():
    policy = SandboxSecurityPolicy()

    assert policy.allow_network is False
    assert policy.require_network_isolation is False
    assert policy.require_filesystem_isolation is False
    assert policy.require_process_isolation is False

    assert policy.network_allowed() is False
    assert policy.requires_network_isolation() is False
    assert policy.requires_filesystem_isolation() is False
    assert policy.requires_process_isolation() is False
def test_allow_network_does_not_claim_network_isolation():
    policy = SandboxSecurityPolicy(
        allow_network=True
    )

    assert policy.allow_network is True
    assert policy.network_allowed() is True
    assert policy.requires_network_isolation() is False
    
def test_runtime_sandbox_uses_custom_security_policy():
    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    assert sandbox.security_policy is policy
    assert sandbox.allow_network is True
    assert sandbox.security_policy.requires_network_isolation() is True
    
def test_runtime_sandbox_allow_network_creates_policy():
    sandbox = RuntimeSandbox(
        allow_network=True,
    )

    assert sandbox.security_policy.allow_network is True
    assert sandbox.allow_network is True
    assert sandbox.security_policy.requires_network_isolation() is False
    
def test_runtime_sandbox_uses_custom_isolation_backend():
    class CustomBackend(NoIsolationBackend):
        pass

    backend = CustomBackend()

    sandbox = RuntimeSandbox(
        isolation_backend=backend,
    )

    assert sandbox.isolation_backend is backend
    
def test_runtime_sandbox_preserves_timeout_value():
    sandbox = RuntimeSandbox(timeout=5)

    assert sandbox.timeout == 5.0
    assert isinstance(sandbox.timeout, float)
def test_runtime_sandbox_preserves_max_output_size():
    sandbox = RuntimeSandbox(max_output_size=5000)

    assert sandbox.max_output_size == 5000
        
    
def test_runtime_sandbox_executes_python_successfully():
    sandbox = unsafe_sandbox()

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout.strip() == "AEGIS"
    assert result.stderr == ""
def test_runtime_sandbox_captures_stderr():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys; print('warning', file=sys.stderr)"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stderr.strip() == "warning"
def test_runtime_sandbox_handles_python_error():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "raise RuntimeError('AEGIS test error')"
    )

    assert result.success is False
    assert result.exit_code != 0
    assert "AEGIS test error" in result.stderr
def test_runtime_sandbox_handles_nonzero_exit_code():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys; sys.exit(3)"
    )

    assert result.success is False
    assert result.exit_code == 3
def test_runtime_sandbox_preserves_output_on_failure():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys; print('before failure'); "
        "print('error message', file=sys.stderr); "
        "sys.exit(2)"
    )

    assert result.success is False
    assert result.exit_code == 2
    assert result.stdout.strip() == "before failure"
    assert result.stderr.strip() == "error message"
def test_runtime_sandbox_handles_unicode_output():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "print('AEGIS — اختبار عربي 🚀')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout.strip() == "AEGIS — اختبار عربي 🚀"
def test_runtime_sandbox_supports_file_operations():
    sandbox = unsafe_sandbox()

    code = """
from pathlib import Path

path = Path("test.txt")
path.write_text("AEGIS")
print(path.read_text())
"""

    result = sandbox.run(code)

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout.strip() == "AEGIS"
    assert result.stderr == ""
def test_runtime_sandbox_defaults_to_network_disabled():
    sandbox = RuntimeSandbox()

    assert sandbox.allow_network is False
    assert sandbox.security_policy.allow_network is False
    assert sandbox.security_policy.requires_network_isolation() is False
def test_runtime_sandbox_rejects_non_string_code_before_backend():
    class TrackingBackend(NoIsolationBackend):
        def __init__(self):
            self.executed = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.executed = True
            raise AssertionError("Backend should not execute.")

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run(123)

    assert result.success is False
    assert backend.executed is False
    assert result.exit_code == -1
    assert "code must be a string" in result.stderr.lower()
def test_runtime_sandbox_rejects_empty_code_before_backend():
    class TrackingBackend(NoIsolationBackend):
        def __init__(self):
            self.executed = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.executed = True
            raise AssertionError("Backend should not execute.")

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("")

    assert result.success is False
    assert backend.executed is False
    assert result.exit_code == -1
    assert "code cannot be empty" in result.stderr.lower()
def test_runtime_sandbox_handles_timeout():
    sandbox = unsafe_sandbox(timeout=0.1)

    result = sandbox.run(
        "import time; time.sleep(1)"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert "timed out" in result.stderr.lower()
def test_runtime_sandbox_limits_stdout_size():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "print('A' * 100)"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert len(result.stdout) <= 10
    assert "output exceeded" in result.stderr.lower()
def test_runtime_sandbox_limits_stderr_size():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('E' * 100)"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert len(result.stderr) <= 10 + len(
        "\nError output exceeded the maximum allowed size."
    )
    assert "Error output exceeded" in result.stderr
def test_runtime_sandbox_allows_output_within_limit():
    sandbox = unsafe_sandbox(max_output_size=100)

    result = sandbox.run(
        "import sys; "
        "print('normal output'); "
        "print('normal error', file=sys.stderr)"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout.strip() == "normal output"
    assert result.stderr.strip() == "normal error"
def test_runtime_sandbox_uses_fresh_temporary_directory_each_run():
    sandbox = unsafe_sandbox()

    first = sandbox.run(
        "import os; print(os.getcwd())"
    )

    second = sandbox.run(
        "import os; print(os.getcwd())"
    )

    assert first.success is True
    assert second.success is True

    first_dir = first.stdout.strip()
    second_dir = second.stdout.strip()

    assert first_dir
    assert second_dir
    assert first_dir != second_dir
def test_runtime_sandbox_returns_empty_stderr_on_success():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "print('success')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout.strip() == "success"
    assert result.stderr == ""
def test_runtime_sandbox_handles_unicode_stderr():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys; "
        "print('تحذير ⚠️', file=sys.stderr)"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stderr.strip() == "تحذير ⚠️"
def test_runtime_sandbox_allows_stdout_at_exact_limit():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "print('123456789', end='')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == "123456789"
    assert len(result.stdout) == 9
def test_runtime_sandbox_allows_stderr_at_exact_limit():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('123456789')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stderr == "123456789"
    assert len(result.stderr) == 9
def test_runtime_sandbox_rejects_stdout_one_byte_over_limit():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "print('12345678901', end='')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert len(result.stdout) == 10
    assert "output exceeded" in result.stderr.lower()
    
def test_runtime_sandbox_rejects_stderr_one_byte_over_limit():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('12345678901')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert len(result.stderr) == 10 + len(
        "\nError output exceeded the maximum allowed size."
    )
def test_runtime_sandbox_accepts_stdout_at_exact_limit():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "print('1234567890', end='')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == "1234567890"
    assert result.stderr == ""
def test_runtime_sandbox_accepts_stderr_at_exact_limit():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('1234567890')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == ""
    assert result.stderr == "1234567890"
def test_runtime_sandbox_truncates_stdout_to_limit():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "print('123456789012345', end='')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stdout == "1234567890"
    assert "output exceeded" in result.stderr.lower()
def test_runtime_sandbox_truncates_stderr_to_limit():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('123456789012345')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stderr.startswith("1234567890")
    assert "Error output exceeded the maximum allowed size." in result.stderr
def test_runtime_sandbox_stdout_overflow_has_expected_error():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "print('123456789012345', end=''); "
        "import sys; sys.stderr.write('abcdefghijklmno')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stdout == "1234567890"
    assert result.stderr == "Output exceeded the maximum allowed size."
def test_runtime_sandbox_rejects_stderr_overflow_when_stdout_is_valid():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; "
        "print('1234567890', end=''); "
        "sys.stderr.write('abcdefghijklmno')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stdout == "1234567890"
    assert result.stderr.startswith("abcdefghij")
    assert "Error output exceeded the maximum allowed size." in result.stderr
def test_runtime_sandbox_accepts_stderr_at_exact_limit_with_empty_stdout():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('abcdefghij')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == ""
    assert result.stderr == "abcdefghij"
def test_runtime_sandbox_accepts_stdout_and_stderr_within_limits():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; "
        "print('12345', end=''); "
        "sys.stderr.write('abcde')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == "12345"
    assert result.stderr == "abcde"
def test_runtime_sandbox_rejects_stderr_overflow_with_empty_stdout():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('abcdefghijk')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stdout == ""
    assert result.stderr.startswith("abcdefghij")
    assert "Error output exceeded the maximum allowed size." in result.stderr
def test_runtime_sandbox_preserves_stdout_prefix_when_truncated():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "print('ABCDEFGHIJKLMNO', end='')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stdout == "ABCDEFGHIJ"
    assert result.stderr == "Output exceeded the maximum allowed size."
def test_runtime_sandbox_preserves_stderr_prefix_when_truncated():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('ABCDEFGHIJKLMNO')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stdout == ""
    assert result.stderr.startswith("ABCDEFGHIJ")
    assert "Error output exceeded the maximum allowed size." in result.stderr
def test_runtime_sandbox_supports_one_byte_output_limit():
    sandbox = unsafe_sandbox(max_output_size=1)

    result = sandbox.run(
        "print('AB', end='')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stdout == "A"
    assert "output exceeded" in result.stderr.lower()
def test_runtime_sandbox_supports_one_byte_stderr_limit():
    sandbox = unsafe_sandbox(max_output_size=1)

    result = sandbox.run(
        "import sys; sys.stderr.write('AB')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stdout == ""
    assert result.stderr.startswith("A")
    assert "Error output exceeded the maximum allowed size." in result.stderr
    
def test_runtime_sandbox_accepts_one_byte_outputs():
    sandbox = unsafe_sandbox(max_output_size=1)

    result = sandbox.run(
        "import sys; "
        "print('A', end=''); "
        "sys.stderr.write('B')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == "A"
    assert result.stderr == "B"
def test_runtime_sandbox_limits_unicode_stdout_by_characters():
    sandbox = unsafe_sandbox(max_output_size=5)

    result = sandbox.run(
        "print('أهلاًوسهلاً', end='')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert len(result.stdout) == 5
    assert "output exceeded" in result.stderr.lower()
def test_runtime_sandbox_limits_unicode_stderr_by_characters():
    sandbox = unsafe_sandbox(max_output_size=5)

    result = sandbox.run(
        "import sys; sys.stderr.write('أهلاًوسهلاً')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stderr.startswith("أهلاً")
    assert "Error output exceeded the maximum allowed size." in result.stderr
def test_runtime_sandbox_accepts_float_timeout():
    sandbox = RuntimeSandbox(timeout=0.5)

    assert sandbox.timeout == 0.5
def test_runtime_sandbox_rejects_zero_float_timeout():
    with pytest.raises(ValueError):
        RuntimeSandbox(timeout=0.0)
def test_runtime_sandbox_rejects_zero_float_max_output_size():
    with pytest.raises(ValueError):
        RuntimeSandbox(max_output_size=0.0)
def test_runtime_sandbox_rejects_negative_float_max_output_size():
    with pytest.raises(TypeError):
        RuntimeSandbox(max_output_size=-1.5)
def test_runtime_sandbox_rejects_negative_float_timeout():
    with pytest.raises(ValueError):
        RuntimeSandbox(timeout=-1.5)
def test_runtime_sandbox_accepts_integer_timeout():
    sandbox = RuntimeSandbox(timeout=5)

    assert sandbox.timeout == 5.0
def test_runtime_sandbox_accepts_integer_max_output_size():
    sandbox = RuntimeSandbox(max_output_size=100)

    assert sandbox.max_output_size == 100
def test_runtime_sandbox_rejects_nan_timeout():
    with pytest.raises(ValueError):
        RuntimeSandbox(timeout=float("nan"))
def test_runtime_sandbox_rejects_infinite_timeout():
    with pytest.raises(ValueError):
        RuntimeSandbox(timeout=float("inf"))
def test_runtime_sandbox_rejects_negative_infinite_timeout():
    with pytest.raises(ValueError):
        RuntimeSandbox(timeout=float("-inf"))
def test_runtime_sandbox_rejects_infinite_max_output_size():
    with pytest.raises(TypeError):
        RuntimeSandbox(max_output_size=float("inf"))
def test_runtime_sandbox_rejects_nan_max_output_size():
    with pytest.raises(TypeError):
        RuntimeSandbox(max_output_size=float("nan"))
def test_runtime_sandbox_accepts_tiny_positive_timeout():
    sandbox = RuntimeSandbox(timeout=0.001)

    assert sandbox.timeout == 0.001
def test_runtime_sandbox_accepts_minimum_output_size():
    sandbox = RuntimeSandbox(max_output_size=1)

    assert sandbox.max_output_size == 1
def test_runtime_sandbox_accepts_output_exactly_at_limit_two():
    sandbox = unsafe_sandbox(max_output_size=2)

    result = sandbox.run(
        "print('AB', end='')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == "AB"
def test_runtime_sandbox_rejects_output_one_over_limit_two():
    sandbox = unsafe_sandbox(max_output_size=2)

    result = sandbox.run(
        "print('ABC', end='')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stdout == "AB"
    assert "output exceeded" in result.stderr.lower()
def test_runtime_sandbox_accepts_large_output_limit():
    sandbox = unsafe_sandbox(max_output_size=1_000_000)

    result = sandbox.run(
        "print('AEGIS', end='')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == "AEGIS"
    assert result.stderr == ""
def test_runtime_sandbox_accepts_large_timeout():
    sandbox = RuntimeSandbox(timeout=3600)

    assert sandbox.timeout == 3600.0
def test_runtime_sandbox_accepts_tiny_positive_float_timeout():
    sandbox = RuntimeSandbox(timeout=1e-9)

    assert sandbox.timeout == 1e-9
def test_runtime_sandbox_accepts_stderr_exactly_at_limit_two():
    sandbox = unsafe_sandbox(max_output_size=2)

    result = sandbox.run(
        "import sys; sys.stderr.write('AB')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == ""
    assert result.stderr == "AB"
def test_runtime_sandbox_rejects_stderr_one_over_limit_two():
    sandbox = unsafe_sandbox(max_output_size=2)

    result = sandbox.run(
        "import sys; sys.stderr.write('ABC')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stdout == ""
    assert result.stderr.startswith("AB")
    assert "Error output exceeded the maximum allowed size." in result.stderr
def test_runtime_sandbox_preserves_both_outputs_when_within_limits():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; "
        "print('HELLO', end=''); "
        "sys.stderr.write('WORLD')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == "HELLO"
    assert result.stderr == "WORLD"
def test_runtime_sandbox_handles_empty_outputs():
    sandbox = unsafe_sandbox()

    result = sandbox.run("pass")

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == ""
    assert result.stderr == ""
def test_runtime_sandbox_truncates_multiline_stdout():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "print('12345'); print('67890'); print('ABCDE')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stdout == "12345\n6789"
    assert "output exceeded" in result.stderr.lower()
def test_runtime_sandbox_truncates_multiline_stderr():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; "
        "sys.stderr.write('12345\\n67890\\nABCDE')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert result.stdout == ""
    assert result.stderr.startswith("12345\n6789")
    assert "Error output exceeded the maximum allowed size." in result.stderr
def test_runtime_sandbox_does_not_modify_successful_output():
    sandbox = unsafe_sandbox(max_output_size=100)

    result = sandbox.run(
        "print('AEGIS-OK', end='')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == "AEGIS-OK"
    assert result.stderr == ""
def test_runtime_sandbox_preserves_stdout_on_python_error():
    sandbox = unsafe_sandbox(max_output_size=1000)

    result = sandbox.run(
        "print('BEFORE-ERROR', end=''); raise RuntimeError('boom')"
    )

    assert result.success is False
    assert result.exit_code != 0
    assert result.stdout == "BEFORE-ERROR"
    assert "RuntimeError" in result.stderr
def test_runtime_sandbox_preserves_stderr_on_python_error():
    sandbox = unsafe_sandbox(max_output_size=1000)

    result = sandbox.run(
        "raise RuntimeError('AEGIS-ERROR')"
    )

    assert result.success is False
    assert result.exit_code != 0
    assert "RuntimeError" in result.stderr
    assert "AEGIS-ERROR" in result.stderr
def test_runtime_sandbox_does_not_modify_successful_stderr():
    sandbox = unsafe_sandbox(max_output_size=1000)

    result = sandbox.run(
        "import sys; print('AEGIS-WARNING', file=sys.stderr, end='')"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == ""
    assert result.stderr == "AEGIS-WARNING"
def test_runtime_sandbox_runs_are_independent():
    sandbox = unsafe_sandbox(max_output_size=1000)

    first = sandbox.run("print('FIRST', end='')")
    second = sandbox.run("print('SECOND', end='')")

    assert first.success is True
    assert first.stdout == "FIRST"
    assert first.stderr == ""

    assert second.success is True
    assert second.stdout == "SECOND"
    assert second.stderr == ""
def test_runtime_sandbox_does_not_reuse_previous_working_directory():
    sandbox = unsafe_sandbox()

    first = sandbox.run(
        "from pathlib import Path; Path('aegis_temp.txt').write_text('SECRET')"
    )

    second = sandbox.run(
        "from pathlib import Path; print(Path('aegis_temp.txt').exists(), end='')"
    )

    assert first.success is True
    assert second.success is True
    assert second.stdout == "False"
def test_runtime_sandbox_cleans_working_directory_after_failure():
    sandbox = RuntimeSandbox()

    result = sandbox.run(
        "from pathlib import Path; "
        "Path('failure_temp.txt').write_text('SECRET'); "
        "raise RuntimeError('boom')"
    )

    assert result.success is False
    assert result.exit_code != 0
def test_runtime_sandbox_uses_isolated_working_directory():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import os; print(os.getcwd(), end='')"
    )

    assert result.success is True
    assert result.stdout.strip() != ""
    assert result.stdout.strip() != "E:\\AEGIS"
def test_runtime_sandbox_uses_fresh_working_directory_each_run():
    sandbox = unsafe_sandbox()

    first = sandbox.run("import os; print(os.getcwd(), end='')")
    second = sandbox.run("import os; print(os.getcwd(), end='')")

    assert first.success is True
    assert second.success is True
    assert first.stdout != second.stdout
def test_runtime_sandbox_removes_temporary_directory():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import os; print(os.getcwd(), end='')"
    )

    assert result.success is True

    working_directory = result.stdout

    import os

    assert os.path.exists(working_directory) is False
def test_runtime_sandbox_accepts_custom_isolation_backend():
    class CustomBackend(IsolationBackend):
        def is_available(self):
            return False

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code, timeout):
            raise RuntimeError("Should not execute.")

    backend = CustomBackend()
    sandbox = RuntimeSandbox(isolation_backend=backend)

    assert sandbox.isolation_backend is backend
def test_runtime_sandbox_checks_backend_capabilities_before_run():
    class TrackingBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend run() must not be called.")

    backend = TrackingBackend()

    policy = SandboxSecurityPolicy(
        allow_network=False,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )
    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert "network isolation" in result.stderr.lower()
    assert backend.run_called is False
def test_runtime_sandbox_does_not_run_backend_without_required_capability():
    class TrackingBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend run() must not be called.")

    backend = TrackingBackend()

    policy = SandboxSecurityPolicy(
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "capability" in result.stderr.lower()
    assert backend.run_called is False
def test_runtime_sandbox_passes_timeout_to_backend():
    class TrackingBackend(IsolationBackend):
        def __init__(self):
            self.received_timeout = None

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.received_timeout = timeout
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        timeout=7.5,
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert result.stdout == "AEGIS"
    assert backend.received_timeout == 7.5
def test_runtime_sandbox_preserves_valid_backend_result():
    class ValidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=False,
                stdout="BACKEND-OUTPUT",
                stderr="BACKEND-ERROR",
                exit_code=23,
            )

    backend = ValidBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.stdout == "BACKEND-OUTPUT"
    assert result.stderr == "BACKEND-ERROR"
    assert result.exit_code == 23
def test_runtime_sandbox_handles_backend_exception():
    class FailingBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise RuntimeError("BACKEND-FAILED")

    backend = FailingBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.stdout == ""
    assert "BACKEND-FAILED" in result.stderr
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_invalid_backend_success_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success="true",
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    backend = InvalidBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "invalid result" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_invalid_backend_stderr_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr=123,
                exit_code=0,
            )

    backend = InvalidBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "invalid result" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_invalid_backend_stdout_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout=123,
                stderr="",
                exit_code=0,
            )

    backend = InvalidBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "invalid result" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_invalid_backend_exit_code_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code="0",
            )

    backend = InvalidBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "invalid result" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_invalid_backend_capabilities_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return "invalid"

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    backend = InvalidBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "invalid capabilities" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_invalid_backend_availability_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return "yes"

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    backend = InvalidBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "invalid availability" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_unavailable_network_backend():
    class UnavailableBackend(IsolationBackend):
        def is_available(self):
            return False

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code, timeout):
            raise AssertionError("Unavailable backend must not run.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=UnavailableBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "secure network isolation is unavailable" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_unavailable_filesystem_backend():
    class UnavailableBackend(IsolationBackend):
        def is_available(self):
            return False

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code, timeout):
            raise AssertionError("Unavailable backend must not run.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_filesystem_isolation=True,
        ),
        isolation_backend=UnavailableBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "filesystem isolation backend is unavailable" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_unavailable_process_backend():
    class UnavailableBackend(IsolationBackend):
        def is_available(self):
            return False

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code, timeout):
            raise AssertionError("Unavailable backend must not run.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_process_isolation=True,
        ),
        isolation_backend=UnavailableBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "process isolation backend is unavailable" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_backend_without_network_capability():
    class LimitedBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=LimitedBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "network isolation capability" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_backend_without_filesystem_capability():
    class LimitedBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_filesystem_isolation=True,
        ),
        isolation_backend=LimitedBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "filesystem isolation capability" in result.stderr.lower()
    assert result.exit_code == -1
    
def test_runtime_sandbox_rejects_backend_without_process_capability():
    class LimitedBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_process_isolation=True,
        ),
        isolation_backend=LimitedBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "process isolation capability" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_accepts_backend_with_all_required_capabilities():
    class FullIsolationBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=FullIsolationBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert result.stdout == "AEGIS"
    assert result.stderr == ""
    assert result.exit_code == 0
def test_runtime_sandbox_checks_all_required_capabilities_before_run():
    class LimitedBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=False,
            )

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend must not run.")

    backend = LimitedBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert backend.run_called is False
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_missing_capability_before_backend_execution():
    class LimitedBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Backend must not run.")

    backend = LimitedBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_filesystem_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert backend.run_called is False
    assert "filesystem isolation capability" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_preserves_backend_code_exactly():
    class RecordingBackend(IsolationBackend):
        def __init__(self):
            self.received_code = None

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.received_code = code
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    backend = RecordingBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    code = "  print('AEGIS')\n\n"
    result = sandbox.run(code)

    assert result.success is True
    assert backend.received_code == code
def test_runtime_sandbox_does_not_bypass_required_network_isolation_with_allow_network():
    sandbox = RuntimeSandbox(
        allow_network=True,
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=NoIsolationBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert "secure network isolation is unavailable" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_allow_network_does_not_enable_network_without_isolation_backend():
    sandbox = RuntimeSandbox(
        allow_network=True,
    )

    result = sandbox.run(
        "import urllib.request\n"
        "urllib.request.urlopen('https://example.com', timeout=2)"
    )

    assert result.success is False
    assert result.exit_code != 0
def test_runtime_sandbox_does_not_use_network_backend_when_network_is_not_required():
    class NetworkBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            return SandboxResult(
                success=True,
                stdout="backend",
                stderr="",
                exit_code=0,
            )

    backend = NetworkBackend()

    sandbox = unsafe_sandbox(
        allow_network=False,
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert result.stdout == "AEGIS\n"
    assert backend.run_called is False
def test_runtime_sandbox_does_not_run_network_backend_when_unavailable():
    class UnavailableNetworkBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return False

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            raise AssertionError("Unavailable network backend must not run.")

    backend = UnavailableNetworkBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert backend.run_called is False
    assert result.exit_code == -1
def test_runtime_sandbox_checks_availability_before_capabilities():
    class OrderedBackend(IsolationBackend):
        def __init__(self):
            self.events = []

        def is_available(self):
            self.events.append("availability")
            return False

        def capabilities(self):
            self.events.append("capabilities")
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.events.append("run")
            raise AssertionError("Backend must not run.")

    backend = OrderedBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert backend.events == ["availability"]
    assert result.exit_code == -1
def test_runtime_sandbox_checks_capabilities_before_backend_run():
    class OrderedBackend(IsolationBackend):
        def __init__(self):
            self.events = []

        def is_available(self):
            self.events.append("availability")
            return True

        def capabilities(self):
            self.events.append("capabilities")
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.events.append("run")
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    backend = OrderedBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert backend.events == ["availability", "capabilities", "run"]
def test_runtime_sandbox_checks_network_filesystem_and_process_requirements():
    class FullBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    backend = FullBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert backend.run_called is True
def test_runtime_sandbox_uses_security_policy_network_setting():
    policy = SandboxSecurityPolicy(
        allow_network=False,
        require_network_isolation=False,
    )

    sandbox = RuntimeSandbox(
        allow_network=True,
        security_policy=policy,
    )

    assert sandbox.allow_network is False
    assert sandbox.security_policy is policy
def test_runtime_sandbox_builds_default_security_policy_from_allow_network():
    sandbox = RuntimeSandbox(allow_network=True)

    assert sandbox.security_policy.allow_network is True
    assert sandbox.allow_network is True
def test_runtime_sandbox_default_security_policy_disables_network():
    sandbox = RuntimeSandbox()

    assert sandbox.security_policy.allow_network is False
    assert sandbox.allow_network is False
    assert sandbox.security_policy.requires_network_isolation() is False
def test_runtime_sandbox_security_policy_is_immutable():
    policy = SandboxSecurityPolicy()

    try:
        policy.allow_network = True
    except Exception:
        pass
    else:
        raise AssertionError("Security policy must be immutable.")

    assert policy.allow_network is False
def test_runtime_sandbox_exposes_backend_capabilities():
    class CustomBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    backend = CustomBackend()
    sandbox = RuntimeSandbox(isolation_backend=backend)

    capabilities = sandbox.isolation_capabilities()

    assert capabilities == IsolationCapabilities(
        network_isolation=True,
        filesystem_isolation=False,
        process_isolation=True,
    )
def test_runtime_sandbox_isolation_capabilities_are_read_only():
    class CustomBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    sandbox = RuntimeSandbox(isolation_backend=CustomBackend())

    capabilities = sandbox.isolation_capabilities()

    assert capabilities.network_isolation is True
    assert capabilities.filesystem_isolation is False
    assert capabilities.process_isolation is True

    try:
        capabilities.network_isolation = False
    except Exception:
        pass
    else:
        raise AssertionError("Isolation capabilities must be immutable.")
def test_runtime_sandbox_uses_default_backend_when_isolation_backend_is_none():
    sandbox = RuntimeSandbox(isolation_backend=None)

    assert isinstance(sandbox.isolation_backend, NoIsolationBackend)
    assert sandbox.isolation_capabilities() == IsolationCapabilities(
        network_isolation=False,
        filesystem_isolation=False,
        process_isolation=False,
    )
def test_runtime_sandbox_default_backend_reports_no_isolation():
    sandbox = RuntimeSandbox()

    capabilities = sandbox.isolation_capabilities()

    assert capabilities.network_isolation is False
    assert capabilities.filesystem_isolation is False
    assert capabilities.process_isolation is False
    assert sandbox.isolation_backend.is_available() is False
def test_runtime_sandbox_preserves_custom_backend_instance():
    class CustomBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    backend = CustomBackend()
    sandbox = RuntimeSandbox(isolation_backend=backend)

    assert sandbox.isolation_backend is backend
def test_runtime_sandbox_allow_network_does_not_modify_backend():
    class CustomBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    backend = CustomBackend()
    sandbox = RuntimeSandbox(
        allow_network=True,
        isolation_backend=backend,
    )

    assert sandbox.isolation_backend is backend
    assert backend.run_called is False
def test_runtime_sandbox_preserves_custom_security_policy_instance():
    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    assert sandbox.security_policy is policy
    assert sandbox.allow_network is True
def test_runtime_sandbox_policy_can_disable_network_access():
    class NetworkIsolationBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            # This fake backend represents code executed in an isolated
            # environment where network access is denied by the backend.
            return SandboxResult(
                success=True,
                stdout="isolated execution",
                stderr="",
                exit_code=0,
            )

    backend = NetworkIsolationBackend()
    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=False,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert result.stdout == "isolated execution"
    assert result.exit_code == 0
    assert backend.run_called is True

def test_runtime_sandbox_allows_network_when_policy_and_isolation_are_enabled():
    class NetworkBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="network-ok",
                stderr="",
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=NetworkBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert result.stdout == "network-ok"
    assert result.exit_code == 0
def test_runtime_sandbox_rejects_network_when_isolation_is_not_required():
    class NetworkBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            return SandboxResult(
                success=True,
                stdout="network-ok",
                stderr="",
                exit_code=0,
            )

    backend = NetworkBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=False,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert backend.run_called is False
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_network_when_policy_disables_it():
    # A local subprocess is not a network-isolation boundary. Requiring
    # network isolation ensures the sandbox fails closed when no isolation
    # backend is available.
    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=False,
            require_network_isolation=True,
        )
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert "network access is disabled" in result.stderr.lower() or \
        "network isolation" in result.stderr.lower()

def test_runtime_sandbox_rejects_when_filesystem_isolation_is_required_but_unavailable():
    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_filesystem_isolation=True,
        ),
        isolation_backend=NoIsolationBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert "filesystem isolation" in result.stderr.lower()
def test_runtime_sandbox_rejects_when_process_isolation_is_required_but_unavailable():
    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_process_isolation=True,
        ),
        isolation_backend=NoIsolationBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert "process isolation" in result.stderr.lower()
def test_runtime_sandbox_rejects_when_all_isolation_requirements_are_unavailable():
    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
            allow_network=True,
        ),
        isolation_backend=NoIsolationBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert "network isolation" in result.stderr.lower()
def test_runtime_sandbox_does_not_run_backend_when_process_isolation_is_missing():
    class PartialBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code, timeout):
            self.run_called = True
            return SandboxResult(
                success=True,
                stdout="should-not-run",
                stderr="",
                exit_code=0,
            )

    backend = PartialBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_process_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert backend.run_called is False
    assert result.exit_code == -1
    assert "process isolation" in result.stderr.lower()
def test_runtime_sandbox_does_not_run_backend_when_filesystem_isolation_is_missing():
    class PartialBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            return SandboxResult(
                success=True,
                stdout="should-not-run",
                stderr="",
                exit_code=0,
            )

    backend = PartialBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            require_filesystem_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert backend.run_called is False
    assert result.exit_code == -1
    assert "filesystem isolation" in result.stderr.lower()
def test_runtime_sandbox_does_not_run_backend_when_network_isolation_is_missing():
    class PartialBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            return SandboxResult(
                success=True,
                stdout="should-not-run",
                stderr="",
                exit_code=0,
            )

    backend = PartialBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert backend.run_called is False
    assert result.exit_code == -1
    assert "network isolation" in result.stderr.lower()
def test_runtime_sandbox_runs_backend_when_all_required_capabilities_are_available():
    class FullIsolationBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False
            self.received_code = None
            self.received_timeout = None

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            self.received_code = code
            self.received_timeout = timeout
            return SandboxResult(
                success=True,
                stdout="isolated-ok",
                stderr="",
                exit_code=0,
            )

    backend = FullIsolationBackend()

    sandbox = RuntimeSandbox(
        timeout=7,
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert result.stdout == "isolated-ok"
    assert result.exit_code == 0
    assert backend.run_called is True
    assert backend.received_code == "print('AEGIS')"
    assert backend.received_timeout == 7.0
def test_runtime_sandbox_rejects_invalid_backend_result_type():
    class BadBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return "invalid-result"

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=BadBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid result" in result.stderr.lower()
def test_runtime_sandbox_converts_backend_exception_to_failure():
    class FailingBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise RuntimeError("backend failure")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=FailingBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert result.stderr == "backend failure"
def test_runtime_sandbox_preserves_backend_result_fields():
    class CustomBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=False,
                stdout="custom stdout",
                stderr="custom stderr",
                exit_code=42,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=CustomBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.stdout == "custom stdout"
    assert result.stderr == "custom stderr"
    assert result.exit_code == 42
def test_runtime_sandbox_rejects_backend_result_with_invalid_stdout_type():
    class BadBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout=123,
                stderr="",
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=BadBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid result" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_result_with_invalid_stderr_type():
    class BadBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr=123,
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=BadBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid result" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_result_with_invalid_exit_code_type():
    class BadBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code="0",
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=BadBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid result" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_result_with_invalid_capability_type():
    class BadBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation="yes",
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=BadBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_result_with_invalid_success_type():
    class BadBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success="yes",
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=BadBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid result" in result.stderr.lower()    
def test_runtime_sandbox_rejects_backend_result_with_invalid_result_type():
    class BadBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return {
                "success": True,
                "stdout": "AEGIS",
                "stderr": "",
                "exit_code": 0,
            }

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=BadBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid result" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_result_with_invalid_capabilities_object():
    class BadBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=BadBackend(),
    )

    sandbox.isolation_backend.capabilities = lambda: "invalid"

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid capabilities" in result.stderr.lower()
def test_runtime_sandbox_preserves_backend_result_when_all_fields_are_valid():
    class GoodBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=False,
                stdout="partial output",
                stderr="tool failed",
                exit_code=7,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=GoodBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.stdout == "partial output"
    assert result.stderr == "tool failed"
    assert result.exit_code == 7
def test_runtime_sandbox_rejects_backend_result_with_invalid_result_object_fields():
    class BadBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=BadBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert result.stdout == "AEGIS"
    assert result.stderr == ""
    assert result.exit_code == 0
def test_runtime_sandbox_does_not_run_backend_when_required_capability_is_missing():
    class TrackingBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            return SandboxResult(
                success=True,
                stdout="SHOULD NOT RUN",
                stderr="",
                exit_code=0,
            )

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
            require_filesystem_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert backend.run_called is False
    assert "filesystem isolation" in result.stderr.lower()
def test_runtime_sandbox_passes_code_exactly_to_backend():
    class TrackingBackend(IsolationBackend):
        def __init__(self):
            self.received_code = None

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.received_code = code
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    backend = TrackingBackend()

    code = "print('AEGIS Ω 🚀')\nvalue = 42"

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run(code)

    assert result.success is True
    assert backend.received_code == code
def test_runtime_sandbox_passes_timeout_as_float_to_backend():
    class TrackingBackend(IsolationBackend):
        def __init__(self):
            self.received_timeout = None

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.received_timeout = timeout
            return SandboxResult(
                success=True,
                stdout="AEGIS",
                stderr="",
                exit_code=0,
            )

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        timeout=5,
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert backend.received_timeout == 5.0
    assert isinstance(backend.received_timeout, float)
def test_runtime_sandbox_does_not_run_unavailable_backend():
    class UnavailableBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return False

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.run_called = True
            return SandboxResult(
                success=True,
                stdout="SHOULD NOT RUN",
                stderr="",
                exit_code=0,
            )

    backend = UnavailableBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert backend.run_called is False
    assert "unavailable" in result.stderr.lower()
def test_runtime_sandbox_does_not_run_backend_with_invalid_capabilities():
    class BadCapabilitiesBackend(IsolationBackend):
        def __init__(self):
            self.run_called = False

        def is_available(self):
            return True

        def capabilities(self):
            return "invalid capabilities"

        def run(self, code, timeout):
            self.run_called = True
            return SandboxResult(
                success=True,
                stdout="SHOULD NOT RUN",
                stderr="",
                exit_code=0,
            )

    backend = BadCapabilitiesBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.exit_code == -1
    assert backend.run_called is False
    assert "invalid capabilities" in result.stderr.lower()
def test_runtime_sandbox_preserves_backend_failure_result():
    class FailingBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=False,
                stdout="partial",
                stderr="execution failed",
                exit_code=42,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=FailingBackend(),
    )

    result = sandbox.run("print('AEGIS')")

    assert result.success is False
    assert result.stdout == "partial"
    assert result.stderr == "execution failed"
    assert result.exit_code == 42
def test_runtime_sandbox_rejects_invalid_isolation_backend():
    try:
        RuntimeSandbox(
            isolation_backend="not-a-backend",
        )
    except TypeError as exc:
        assert "invalid isolation backend" in str(exc).lower()
    else:
        assert False, "RuntimeSandbox should reject an invalid isolation backend"
def test_runtime_sandbox_rejects_non_numeric_timeout():
    try:
        RuntimeSandbox(timeout="10")
    except TypeError as exc:
        assert "timeout must be a number" in str(exc).lower()
    else:
        assert False, "RuntimeSandbox should reject a non-numeric timeout"
def test_runtime_sandbox_rejects_non_integer_max_output_size():
    try:
        RuntimeSandbox(max_output_size=100.5)
    except TypeError as exc:
        assert "max output size must be an integer" in str(exc).lower()
    else:
        assert False, "RuntimeSandbox should reject a non-integer max_output_size"
def test_runtime_sandbox_rejects_non_positive_max_output_size():
    for size in (0, -1):
        try:
            RuntimeSandbox(max_output_size=size)
        except ValueError as exc:
            assert "greater than zero" in str(exc).lower()
        else:
            assert False, "RuntimeSandbox should reject a non-positive max_output_size"
def test_runtime_sandbox_rejects_non_string_code():
    sandbox = RuntimeSandbox()

    result = sandbox.run(123)

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert "code must be a string" in result.stderr.lower()
def test_runtime_sandbox_rejects_empty_code():
    sandbox = RuntimeSandbox()

    result = sandbox.run("   ")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert "code cannot be empty" in result.stderr.lower()
def test_runtime_sandbox_executes_valid_python_code():
    sandbox = unsafe_sandbox()

    result = sandbox.run("print('AEGIS')")

    assert result.success is True
    assert result.stdout.strip() == "AEGIS"
    assert result.stderr == ""
    assert result.exit_code == 0
def test_runtime_sandbox_rejects_stdout_exceeding_max_output_size():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run("print('A' * 100)")

    assert result.success is False
    assert len(result.stdout) <= 10
    assert "output exceeded" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_stderr_exceeding_max_output_size():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('E' * 100)"
    )

    assert result.success is False
    assert len(result.stderr) > 10
    assert "exceeded" in result.stderr.lower()
def test_runtime_sandbox_preserves_normal_output():
    sandbox = unsafe_sandbox(max_output_size=100)

    result = sandbox.run(
        "print('AEGIS OUT'); import sys; sys.stderr.write('AEGIS ERR')"
    )

    assert result.success is True
    assert result.stdout.strip() == "AEGIS OUT"
    assert result.stderr == "AEGIS ERR"
    assert result.exit_code == 0
def test_runtime_sandbox_reports_python_execution_failure():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "raise RuntimeError('AEGIS failure')"
    )

    assert result.success is False
    assert result.exit_code != 0
    assert "aegis failure" in result.stderr.lower()
def test_runtime_sandbox_times_out_long_running_code():
    sandbox = unsafe_sandbox(timeout=0.2)

    result = sandbox.run(
        "import time; time.sleep(2)"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert "timed out" in result.stderr.lower()
def test_runtime_sandbox_uses_temporary_working_directory():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import os; print(os.getcwd())"
    )

    assert result.success is True
    assert result.stdout.strip()
    assert result.stdout.strip() != r"E:\AEGIS"
def test_runtime_sandbox_writes_files_inside_temporary_directory():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "from pathlib import Path; Path('aegis_test.txt').write_text('AEGIS'); print(Path('aegis_test.txt').exists())"
    )

    assert result.success is True
    assert result.stdout.strip() == "True"
def test_runtime_sandbox_cleans_up_temporary_directory():
    from pathlib import Path

    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "from pathlib import Path; "
        "Path('aegis_test.txt').write_text('AEGIS'); "
        "print(Path.cwd())"
    )

    assert result.success is True

    temp_path = Path(result.stdout.strip())

    assert temp_path.exists() is False
    
def test_runtime_sandbox_failure_is_not_reported_as_success():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "print('before'); raise ValueError('AEGIS failure')"
    )

    assert result.success is False
    assert result.exit_code != 0
    assert "aegis failure" in result.stderr.lower()
    assert "before" in result.stdout
def test_runtime_sandbox_truncates_stdout_exactly_to_max_output_size():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "print('A' * 100, end='')"
    )

    assert result.success is False
    assert len(result.stdout) == 10
    assert result.stdout == "A" * 10
    assert "output exceeded" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_truncates_stderr_exactly_to_max_output_size():
    sandbox = unsafe_sandbox(max_output_size=10)

    result = sandbox.run(
        "import sys; sys.stderr.write('E' * 100)"
    )

    assert result.success is False
    assert result.stderr.startswith("E" * 10)
    assert "error output exceeded" in result.stderr.lower()
    assert result.exit_code == -1
def test_runtime_sandbox_preserves_unicode_output():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "print('AEGIS Ω 🚀 مصر')"
    )

    assert result.success is True
    assert result.stdout.strip() == "AEGIS Ω 🚀 مصر"
    assert result.stderr == ""
    assert result.exit_code == 0
def test_runtime_sandbox_handles_timeout_with_output():
    sandbox = unsafe_sandbox(timeout=0.2)

    result = sandbox.run(
        "import time; print('before', flush=True); "
        "import sys; sys.stderr.write('warning\\n'); "
        "time.sleep(2)"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert "timed out" in result.stderr.lower()
    assert "before" in result.stdout
def test_runtime_sandbox_decodes_timeout_bytes_output():
    sandbox = unsafe_sandbox(timeout=0.2)

    result = sandbox.run(
        "import time; print('AEGIS', flush=True); time.sleep(2)"
    )

    assert result.success is False
    assert isinstance(result.stdout, str)
    assert isinstance(result.stderr, str)
    assert result.exit_code == -1
    assert "timed out" in result.stderr.lower()
def test_runtime_sandbox_stores_timeout_as_float():
    sandbox = RuntimeSandbox(timeout=5)

    assert sandbox.timeout == 5.0
    assert isinstance(sandbox.timeout, float)
def test_runtime_sandbox_stores_network_policy():
    sandbox = RuntimeSandbox(allow_network=False)

    assert sandbox.allow_network is False
def test_runtime_sandbox_stores_enabled_network_policy():
    sandbox = RuntimeSandbox(allow_network=True)

    assert sandbox.allow_network is True
def test_runtime_sandbox_preserves_security_policy():
    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    assert sandbox.security_policy is policy
def test_runtime_sandbox_defaults_to_no_isolation_backend():
    sandbox = RuntimeSandbox()

    assert isinstance(sandbox.isolation_backend, NoIsolationBackend)
def test_runtime_sandbox_uses_explicit_isolation_backend():
    backend = NoIsolationBackend()

    sandbox = RuntimeSandbox(
        isolation_backend=backend,
    )

    assert sandbox.isolation_backend is backend
def test_runtime_sandbox_exposes_isolation_capabilities():
    sandbox = RuntimeSandbox()

    capabilities = sandbox.isolation_capabilities()

    assert isinstance(capabilities, IsolationCapabilities)
    assert capabilities.network_isolation is False
    assert capabilities.filesystem_isolation is False
    assert capabilities.process_isolation is False
def test_runtime_sandbox_security_policy_defaults_to_safe_values():
    sandbox = RuntimeSandbox()

    assert sandbox.security_policy.allow_network is False
    assert sandbox.security_policy.require_network_isolation is False
    assert sandbox.security_policy.require_filesystem_isolation is False
    assert sandbox.security_policy.require_process_isolation is False
def test_runtime_sandbox_security_policy_can_require_filesystem_isolation():
    policy = SandboxSecurityPolicy(
        require_filesystem_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    assert sandbox.security_policy.requires_filesystem_isolation() is True
def test_runtime_sandbox_security_policy_can_require_process_isolation():
    policy = SandboxSecurityPolicy(
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    assert sandbox.security_policy.requires_process_isolation() is True
def test_runtime_sandbox_security_policy_can_require_network_isolation():
    policy = SandboxSecurityPolicy(
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    assert sandbox.security_policy.requires_network_isolation() is True
def test_runtime_sandbox_security_policy_helpers_match_configuration():
    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    assert policy.network_allowed() is True
    assert policy.requires_network_isolation() is True
    assert policy.requires_filesystem_isolation() is True
    assert policy.requires_process_isolation() is True
def test_runtime_sandbox_rejects_required_network_isolation_when_backend_unavailable():
    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "isolation" in result.stderr.lower()
def test_runtime_sandbox_rejects_required_filesystem_isolation_when_backend_unavailable():
    policy = SandboxSecurityPolicy(
        require_filesystem_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "filesystem isolation" in result.stderr.lower()
def test_runtime_sandbox_rejects_required_process_isolation_when_backend_unavailable():
    policy = SandboxSecurityPolicy(
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "process isolation" in result.stderr.lower()
def test_runtime_sandbox_rejects_required_filesystem_and_process_isolation_when_backend_unavailable():
    policy = SandboxSecurityPolicy(
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "filesystem/process isolation" in result.stderr.lower()
def test_runtime_sandbox_blocks_network_when_network_isolation_is_required_but_not_allowed():
    policy = SandboxSecurityPolicy(
        allow_network=False,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "network access is disabled" in result.stderr.lower()
def test_runtime_sandbox_rejects_network_access_without_isolation_backend():
    sandbox = RuntimeSandbox(
        allow_network=True,
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "network isolation backend" in result.stderr.lower()
def test_runtime_sandbox_preserves_custom_timeout():
    sandbox = RuntimeSandbox(timeout=3.5)

    assert sandbox.timeout == 3.5
    assert isinstance(sandbox.timeout, float)
def test_runtime_sandbox_preserves_custom_max_output_size():
    sandbox = RuntimeSandbox(max_output_size=500)

    assert sandbox.max_output_size == 500
    assert isinstance(sandbox.max_output_size, int)
def test_runtime_sandbox_allow_network_matches_security_policy():
    policy = SandboxSecurityPolicy(
        allow_network=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    assert sandbox.allow_network is True
    assert sandbox.security_policy.allow_network is True
def test_runtime_sandbox_default_policy_is_independent_per_instance():
    sandbox_a = RuntimeSandbox()
    sandbox_b = RuntimeSandbox()

    assert sandbox_a.security_policy is not sandbox_b.security_policy
    assert sandbox_a.security_policy.allow_network is False
    assert sandbox_b.security_policy.allow_network is False
def test_runtime_sandbox_allow_network_argument_creates_policy():
    sandbox = RuntimeSandbox(
        allow_network=True,
    )

    assert sandbox.security_policy.allow_network is True
    assert sandbox.allow_network is True
def test_runtime_sandbox_explicit_policy_takes_precedence_over_allow_network_argument():
    policy = SandboxSecurityPolicy(
        allow_network=False,
    )

    sandbox = RuntimeSandbox(
        allow_network=True,
        security_policy=policy,
    )

    assert sandbox.security_policy is policy
    assert sandbox.allow_network is False
def test_runtime_sandbox_rejects_non_finite_timeout():
    with pytest.raises(ValueError, match="finite"):
        RuntimeSandbox(timeout=float("inf"))
def test_runtime_sandbox_rejects_zero_timeout():
    with pytest.raises(ValueError, match="greater than zero"):
        RuntimeSandbox(timeout=0)
def test_runtime_sandbox_rejects_negative_timeout():
    with pytest.raises(ValueError, match="greater than zero"):
        RuntimeSandbox(timeout=-1)
def test_runtime_sandbox_rejects_boolean_timeout():
    with pytest.raises(TypeError, match="number"):
        RuntimeSandbox(timeout=True)
def test_runtime_sandbox_rejects_boolean_max_output_size():
    with pytest.raises(TypeError, match="integer"):
        RuntimeSandbox(max_output_size=True)
def test_runtime_sandbox_rejects_zero_max_output_size():
    with pytest.raises(ValueError, match="greater than zero"):
        RuntimeSandbox(max_output_size=0)
def test_runtime_sandbox_rejects_negative_max_output_size():
    with pytest.raises(ValueError, match="greater than zero"):
        RuntimeSandbox(max_output_size=-1)
def test_runtime_sandbox_rejects_float_max_output_size():
    with pytest.raises(TypeError, match="integer"):
        RuntimeSandbox(max_output_size=100.5)
def test_runtime_sandbox_rejects_string_max_output_size():
    with pytest.raises(TypeError, match="integer"):
        RuntimeSandbox(max_output_size="1000")
def test_runtime_sandbox_rejects_none_max_output_size():
    with pytest.raises(TypeError, match="integer"):
        RuntimeSandbox(max_output_size=None)
def test_runtime_sandbox_rejects_string_timeout():
    with pytest.raises(TypeError, match="number"):
        RuntimeSandbox(timeout="10")
def test_runtime_sandbox_rejects_none_timeout():
    with pytest.raises(TypeError, match="number"):
        RuntimeSandbox(timeout=None)
def test_runtime_sandbox_preserves_integer_timeout_as_float():
    sandbox = RuntimeSandbox(timeout=5)

    assert sandbox.timeout == 5.0
    assert isinstance(sandbox.timeout, float)
def test_runtime_sandbox_default_max_output_size_is_positive():
    sandbox = RuntimeSandbox()

    assert sandbox.max_output_size > 0
    assert isinstance(sandbox.max_output_size, int)
def test_runtime_sandbox_default_timeout_is_positive():
    sandbox = RuntimeSandbox()

    assert sandbox.timeout > 0
    assert isinstance(sandbox.timeout, float)
def test_runtime_sandbox_policy_helpers_return_booleans():
    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
        require_filesystem_isolation=True,
        require_process_isolation=True,
    )

    assert isinstance(policy.network_allowed(), bool)
    assert isinstance(policy.requires_network_isolation(), bool)
    assert isinstance(policy.requires_filesystem_isolation(), bool)
    assert isinstance(policy.requires_process_isolation(), bool)
def test_runtime_sandbox_preserves_zero_output_on_empty_code():
    sandbox = RuntimeSandbox()

    result = sandbox.run("")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
def test_runtime_sandbox_rejects_whitespace_only_code():
    sandbox = RuntimeSandbox()

    result = sandbox.run("   \n\t  ")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert "empty" in result.stderr.lower()
def test_runtime_sandbox_preserves_multiline_stdout():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "print('line 1')\n"
        "print('line 2')"
    )

    assert result.success is True
    assert result.stdout == "line 1\nline 2\n"
def test_runtime_sandbox_preserves_stderr_on_success():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys\n"
        "print('warning', file=sys.stderr)"
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout == ""
    assert result.stderr == "warning\n"
def test_runtime_sandbox_returns_nonzero_exit_code_on_failure():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "raise SystemExit(7)"
    )

    assert result.success is False
    assert result.exit_code == 7
def test_runtime_sandbox_captures_python_exception_stderr():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "raise ValueError('boom')"
    )

    assert result.success is False
    assert result.exit_code != 0
    assert "ValueError" in result.stderr
    assert "boom" in result.stderr
def test_runtime_sandbox_handles_large_stderr_without_exceeding_limit():
    sandbox = RuntimeSandbox(max_output_size=100)

    result = sandbox.run(
        "import sys\n"
        "sys.stderr.write('x' * 1000)"
    )

    assert result.success is False
    assert len(result.stderr) <= 100 + len(
        "\nError output exceeded the maximum allowed output size."
    )
def test_runtime_sandbox_handles_large_stdout_without_exceeding_limit():
    sandbox = unsafe_sandbox(max_output_size=100)

    result = sandbox.run(
        "print('x' * 1000, end='')"
    )

    assert result.success is False
    assert len(result.stdout) == 100
    assert "maximum allowed size" in result.stderr.lower()
def test_runtime_sandbox_uses_utf8_encoding_for_unicode_source():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "print('أحمد 🚀')"
    )

    assert result.success is True
    assert result.stdout == "أحمد 🚀\n"
def test_runtime_sandbox_does_not_modify_parent_working_directory():
    import os

    sandbox = unsafe_sandbox()
    original_cwd = os.getcwd()

    result = sandbox.run(
        "import os\n"
        "print(os.getcwd())"
    )

    assert result.success is True
    assert os.getcwd() == original_cwd
def test_runtime_sandbox_uses_unique_temporary_directories():
    sandbox = unsafe_sandbox()

    result_a = sandbox.run(
        "import os\n"
        "print(os.getcwd())"
    )

    result_b = sandbox.run(
        "import os\n"
        "print(os.getcwd())"
    )

    assert result_a.success is True
    assert result_b.success is True
    assert result_a.stdout != result_b.stdout
def test_runtime_sandbox_does_not_leave_created_files_behind():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "from pathlib import Path\n"
        "Path('temporary.txt').write_text('secret')\n"
        "print(Path('temporary.txt').exists())"
    )

    assert result.success is True
    assert result.stdout.strip() == "True"
def test_runtime_sandbox_returns_empty_stdout_when_code_only_writes_stderr():
    sandbox = unsafe_sandbox()

    result = sandbox.run(
        "import sys\n"
        "sys.stderr.write('error')"
    )

    assert result.success is True
    assert result.stdout == ""
    assert result.stderr == "error"
    assert result.exit_code == 0
def test_runtime_sandbox_preserves_empty_successful_result():
    sandbox = unsafe_sandbox()

    result = sandbox.run("pass")

    assert result.success is True
    assert result.stdout == ""
    assert result.stderr == ""
    assert result.exit_code == 0
def test_runtime_sandbox_preserves_exit_code_zero_on_success():
    sandbox = unsafe_sandbox()

    result = sandbox.run("print('ok')")

    assert result.success is True
    assert result.exit_code == 0
def test_runtime_sandbox_preserves_boolean_success_flag():
    sandbox = RuntimeSandbox()

    result = sandbox.run("pass")

    assert isinstance(result.success, bool)
def test_runtime_sandbox_result_fields_have_expected_types_on_success():
    sandbox = RuntimeSandbox()

    result = sandbox.run("print('ok')")

    assert isinstance(result.success, bool)
    assert isinstance(result.stdout, str)
    assert isinstance(result.stderr, str)
    assert isinstance(result.exit_code, int)
def test_runtime_sandbox_result_fields_have_expected_types_on_failure():
    sandbox = RuntimeSandbox()

    result = sandbox.run("raise ValueError('boom')")

    assert isinstance(result.success, bool)
    assert isinstance(result.stdout, str)
    assert isinstance(result.stderr, str)
    assert isinstance(result.exit_code, int)
def test_runtime_sandbox_result_fields_have_expected_types_on_timeout():
    sandbox = RuntimeSandbox(timeout=0.1)

    result = sandbox.run(
        "import time\n"
        "time.sleep(1)"
    )

    assert isinstance(result.success, bool)
    assert isinstance(result.stdout, str)
    assert isinstance(result.stderr, str)
    assert isinstance(result.exit_code, int)
def test_runtime_sandbox_timeout_result_is_failure():
    sandbox = unsafe_sandbox(timeout=0.1)

    result = sandbox.run(
        "import time\n"
        "time.sleep(1)"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert "timed out" in result.stderr.lower()
def test_runtime_sandbox_timeout_preserves_partial_stdout():
    sandbox = unsafe_sandbox(timeout=0.2)

    result = sandbox.run(
        "import time\n"
        "print('before timeout', flush=True)\n"
        "time.sleep(1)"
    )

    assert result.success is False
    assert "before timeout" in result.stdout
    assert "timed out" in result.stderr.lower()
def test_runtime_sandbox_timeout_preserves_partial_stderr():
    sandbox = unsafe_sandbox(timeout=0.2)

    result = sandbox.run(
        "import sys, time\n"
        "print('warning before timeout', file=sys.stderr, flush=True)\n"
        "time.sleep(1)"
    )

    assert result.success is False
    assert "warning before timeout" in result.stderr
    assert "timed out" in result.stderr.lower()
def test_runtime_sandbox_uses_isolated_working_directory_for_each_run():
    sandbox = unsafe_sandbox()

    result_a = sandbox.run(
        "from pathlib import Path\n"
        "Path('marker.txt').write_text('A')\n"
        "print(Path('marker.txt').read_text())"
    )

    result_b = sandbox.run(
        "from pathlib import Path\n"
        "print(Path('marker.txt').exists())"
    )

    assert result_a.success is True
    assert result_a.stdout.strip() == "A"
    assert result_b.success is True
    assert result_b.stdout.strip() == "False"
def test_runtime_sandbox_does_not_execute_code_when_isolation_requirement_is_unavailable():
    policy = SandboxSecurityPolicy(
        require_filesystem_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    result = sandbox.run(
        "from pathlib import Path\n"
        "Path('should_not_run.txt').write_text('executed')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert "filesystem isolation" in result.stderr.lower()
def test_runtime_sandbox_does_not_execute_code_when_process_isolation_is_unavailable():
    policy = SandboxSecurityPolicy(
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    result = sandbox.run(
        "from pathlib import Path\n"
        "Path('should_not_run.txt').write_text('executed')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert "process isolation" in result.stderr.lower()
def test_runtime_sandbox_does_not_execute_code_when_network_isolation_is_unavailable():
    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
    )

    result = sandbox.run(
        "from pathlib import Path\n"
        "Path('should_not_run.txt').write_text('executed')"
    )

    assert result.success is False
    assert result.exit_code == -1
    assert "network isolation" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_missing_required_network_capability():
    class PartialBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not execute code.")

    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=PartialBackend(),
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert result.exit_code == -1
    assert "network isolation" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_missing_required_filesystem_capability():
    class PartialBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not execute code.")

    policy = SandboxSecurityPolicy(
        require_filesystem_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=PartialBackend(),
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert result.exit_code == -1
    assert "filesystem isolation" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_missing_required_process_capability():
    class PartialBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=False,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not execute code.")

    policy = SandboxSecurityPolicy(
        require_process_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=PartialBackend(),
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert result.exit_code == -1
    assert "process isolation" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_missing_multiple_required_capabilities():
    class PartialBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=False,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not execute code.")

    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
        require_filesystem_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=PartialBackend(),
    )

    result = sandbox.run("print('should not run')")

    assert result.success is False
    assert result.exit_code == -1
    assert "network isolation" in result.stderr.lower()
def test_runtime_sandbox_preserves_backend_success_result_exactly():
    class SuccessBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="custom stdout",
                stderr="custom stderr",
                exit_code=0,
            )

    backend = SuccessBackend()

    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result == SandboxResult(
        success=True,
        stdout="custom stdout",
        stderr="custom stderr",
        exit_code=0,
    )
def test_runtime_sandbox_preserves_backend_failure_result_exactly():
    class FailureBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=False,
                stdout="partial output",
                stderr="backend failure",
                exit_code=17,
            )

    policy = SandboxSecurityPolicy(
        allow_network=True,
        require_network_isolation=True,
    )

    sandbox = RuntimeSandbox(
        security_policy=policy,
        isolation_backend=FailureBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result == SandboxResult(
        success=False,
        stdout="partial output",
        stderr="backend failure",
        exit_code=17,
    )
def test_runtime_sandbox_does_not_call_backend_when_network_is_disabled():
    class TrackingBackend(IsolationBackend):
        called = False

        def is_available(self):
            self.called = True
            return True

        def capabilities(self):
            self.called = True
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            return SandboxResult(
                success=True,
                stdout="should not run",
                stderr="",
                exit_code=0,
            )

    backend = TrackingBackend()

    sandbox = unsafe_sandbox(
        allow_network=False,
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is True
    assert result.stdout == "hello\n"
    assert backend.called is False
def test_runtime_sandbox_rejects_backend_with_invalid_success_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success="yes",
                stdout="output",
                stderr="",
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=InvalidBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert "invalid result" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_with_invalid_stdout_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout=123,
                stderr="",
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=InvalidBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert "invalid result" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_with_invalid_stderr_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="output",
                stderr=123,
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=InvalidBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert "invalid result" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_with_invalid_exit_code_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="output",
                stderr="",
                exit_code="0",
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=InvalidBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert "invalid result" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_with_invalid_capabilities_object():
    class InvalidBackend(IsolationBackend):
        called = False

        def is_available(self):
            return True

        def capabilities(self):
            return "invalid capabilities"

        def run(self, code, timeout):
            self.called = True
            return SandboxResult(
                success=True,
                stdout="should not run",
                stderr="",
                exit_code=0,
            )

    backend = InvalidBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid capabilities" in result.stderr.lower()
    assert backend.called is False
def test_runtime_sandbox_rejects_backend_with_invalid_availability_type():
    class InvalidBackend(IsolationBackend):
        called = False

        def is_available(self):
            return "yes"

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            return SandboxResult(
                success=True,
                stdout="should not run",
                stderr="",
                exit_code=0,
            )

    backend = InvalidBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid availability" in result.stderr.lower()
    assert backend.called is False
def test_runtime_sandbox_passes_code_and_timeout_to_backend():
    class TrackingBackend(IsolationBackend):
        received_code = None
        received_timeout = None

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.received_code = code
            self.received_timeout = timeout

            return SandboxResult(
                success=True,
                stdout="ok",
                stderr="",
                exit_code=0,
            )

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        timeout=7,
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    code = "print('AEGIS')"
    result = sandbox.run(code)

    assert result.success is True
    assert backend.received_code == code
    assert backend.received_timeout == 7.0
def test_runtime_sandbox_does_not_run_backend_when_backend_is_unavailable():
    class UnavailableBackend(IsolationBackend):
        called = False

        def is_available(self):
            return False

        def capabilities(self):
            self.called = True
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            raise AssertionError("Backend must not run.")

    backend = UnavailableBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "unavailable" in result.stderr.lower()
    assert backend.called is False
def test_runtime_sandbox_converts_backend_exception_to_failure_result():
    class FailingBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise RuntimeError("backend crashed")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=FailingBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.stdout == ""
    assert result.stderr == "backend crashed"
    assert result.exit_code == -1
def test_runtime_sandbox_does_not_call_backend_when_capabilities_are_insufficient():
    class TrackingBackend(IsolationBackend):
        called = False

        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=False,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.called = True
            raise AssertionError("Backend must not run.")

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "network isolation" in result.stderr.lower()
    assert backend.called is False
def test_runtime_sandbox_preserves_backend_result_when_network_is_enabled():
    class NetworkBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            assert code == "network_task()"
            assert timeout == 5.0

            return SandboxResult(
                success=True,
                stdout="network success",
                stderr="",
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        timeout=5,
        allow_network=True,
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=NetworkBackend(),
    )

    result = sandbox.run("network_task()")

    assert result == SandboxResult(
        success=True,
        stdout="network success",
        stderr="",
        exit_code=0,
    )
def test_runtime_sandbox_rejects_backend_with_invalid_result_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return "not a sandbox result"

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=InvalidBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert "invalid result" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_with_invalid_network_capability_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation="yes",
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    backend = InvalidBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid capability types" in result.stderr.lower()
    assert backend.called if hasattr(backend, "called") else True
def test_runtime_sandbox_rejects_backend_with_invalid_filesystem_capability_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation="yes",
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    backend = InvalidBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
            require_filesystem_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid capability types" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_with_invalid_process_capability_type():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation="yes",
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=InvalidBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid capability types" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_with_invalid_multiple_capability_types():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation="yes",
                filesystem_isolation=1,
                process_isolation=None,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=InvalidBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert "invalid capability types" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_with_non_boolean_capabilities_even_when_not_required():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation="yes",
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=InvalidBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.exit_code == -1
    assert "invalid capability types" in result.stderr.lower()
def test_runtime_sandbox_rejects_non_boolean_capabilities_when_required():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation="yes",
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=InvalidBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert "invalid capability types" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_with_invalid_filesystem_and_process_capability_types():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation="yes",
                process_isolation=1,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=InvalidBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert "invalid capability types" in result.stderr.lower()
def test_runtime_sandbox_accepts_valid_boolean_capabilities():
    class ValidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            return SandboxResult(
                success=True,
                stdout="valid",
                stderr="",
                exit_code=0,
            )

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
            require_filesystem_isolation=True,
            require_process_isolation=True,
        ),
        isolation_backend=ValidBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is True
    assert result.stdout == "valid"
    assert result.stderr == ""
    assert result.exit_code == 0
def test_runtime_sandbox_rejects_backend_with_invalid_filesystem_capability_when_required():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation="invalid",
                process_isolation=True,
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_filesystem_isolation=True,
        ),
        isolation_backend=InvalidBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert "invalid capability types" in result.stderr.lower()
def test_runtime_sandbox_rejects_backend_with_invalid_process_capability_when_required():
    class InvalidBackend(IsolationBackend):
        def is_available(self):
            return True

        def capabilities(self):
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation="invalid",
            )

        def run(self, code, timeout):
            raise AssertionError("Backend must not run.")

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_process_isolation=True,
        ),
        isolation_backend=InvalidBackend(),
    )

    result = sandbox.run("print('hello')")

    assert result.success is False
    assert result.stdout == ""
    assert result.exit_code == -1
    assert "invalid capability types" in result.stderr.lower()
def test_runtime_sandbox_calls_backend_only_after_valid_capabilities():
    class TrackingBackend(IsolationBackend):
        calls = []

        def is_available(self):
            self.calls.append("available")
            return True

        def capabilities(self):
            self.calls.append("capabilities")
            return IsolationCapabilities(
                network_isolation=True,
                filesystem_isolation=True,
                process_isolation=True,
            )

        def run(self, code, timeout):
            self.calls.append("run")
            return SandboxResult(
                success=True,
                stdout="ok",
                stderr="",
                exit_code=0,
            )

    backend = TrackingBackend()

    sandbox = RuntimeSandbox(
        security_policy=SandboxSecurityPolicy(
            allow_network=True,
            require_network_isolation=True,
        ),
        isolation_backend=backend,
    )

    result = sandbox.run("print('hello')")

    assert result.success is True
    assert backend.calls == [
        "available",
        "capabilities",
        "run",
    ]