from .agent import Agent
from .audit import AuditEvent, AuditLogger
from .models import (
    ExecutionContext,
    ExecutionResult,
    Observation,
    Task,
    TaskStatus,
)
from .policy import PolicyEngine
from .registry import ToolRegistry
from .trace import ExecutionTrace
from .summary import create_execution_summary
from .validator import PlanValidator
from .decision import PlanDecision, PlanDecisionEngine
from .evaluator import PlanEvaluator
from .replanner import Replanner


class ExecutionEngine:

    def __init__(
        self,
        agent: Agent,
        tool_registry: ToolRegistry,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger | None = None,
        plan_validator: PlanValidator | None = None,
        plan_evaluator: PlanEvaluator | None = None,
        decision_engine: PlanDecisionEngine | None = None,
        replanner: Replanner | None = None,
        max_replans: int = 3,
    ):
        
        self.agent = agent
        self.tool_registry = tool_registry
        self.policy_engine = policy_engine

        self.audit_logger = (
            audit_logger
            if audit_logger is not None
            else AuditLogger()
        )

        self.plan_validator = (
            plan_validator
            if plan_validator is not None
            else PlanValidator()
        )

        self.plan_evaluator = (
            plan_evaluator
            if plan_evaluator is not None
            else PlanEvaluator()
        )

        self.decision_engine = (
            decision_engine
            if decision_engine is not None
            else PlanDecisionEngine()
        )

        self.replanner = (
            replanner
            if replanner is not None
            else Replanner()
        )

        self.max_replans = max_replans

    def run(self, task: Task) -> ExecutionResult:

        task.status = TaskStatus.RUNNING

        context = ExecutionContext(
            task_id=task.id
        )

        observations: list[Observation] = []

        # --------------------------------
        # Helpers
        # --------------------------------

        def build_trace() -> ExecutionTrace:
            return ExecutionTrace(
                task_id=task.id,
                events=self.audit_logger.get_by_task(task.id),
            )

        def build_result() -> ExecutionResult:
            trace = build_trace()

            summary = create_execution_summary(
                trace=trace,
                status=task.status,
            )

            return ExecutionResult(
                task_id=task.id,
                status=task.status,
                observations=observations,
                trace=trace,
                summary=summary,
            )

        # --------------------------------
        # Initial Plan
        # --------------------------------

        plan = self.agent.plan(task)

        replan_count = 0

        # --------------------------------
        # Planning / Validation /
        # Evaluation / Decision Loop
        # --------------------------------

        while True:

            # --------------------------------
            # Plan Validation
            # --------------------------------

            validation = self.plan_validator.validate(
                plan=plan,
                tool_registry=self.tool_registry,
                task_id=task.id,
            )

            if not validation.valid:

                task.status = TaskStatus.FAILED

                observations.append(
                    Observation(
                        step_id="plan_validation",
                        success=False,
                        error=(
                            "PLAN VALIDATION FAILED: "
                            + "; ".join(validation.errors)
                        ),
                    )
                )

                return build_result()

            # --------------------------------
            # Plan Evaluation
            # --------------------------------

            evaluation = self.plan_evaluator.evaluate(plan)

            # --------------------------------
            # Plan Decision
            # --------------------------------

            decision = self.decision_engine.decide(
                coverage=evaluation.coverage,
                constraint_coverage=evaluation.constraint_coverage,
            )

            # --------------------------------
            # ACCEPT
            # --------------------------------
            if decision.decision == PlanDecision.ACCEPT:
             break

            # --------------------------------
            # REJECT
            # --------------------------------

            if decision.decision == PlanDecision.REJECT:

                task.status = TaskStatus.FAILED

                observations.append(
                    Observation(
                        step_id="plan_decision",
                        success=False,
                        error=(
                            f"PLAN REJECTED: "
                            f"{decision.reason}"
                        ),
                    )
                )

                return build_result()

            # --------------------------------
            # REPLAN
            # --------------------------------

            if decision.decision == PlanDecision.REPLAN:

                if replan_count >= self.max_replans:

                    task.status = TaskStatus.FAILED

                    observations.append(
                        Observation(
                            step_id="replan_limit",
                            success=False,
                            error=(
                                "REPLAN LIMIT REACHED: "
                                f"Maximum of {self.max_replans} "
                                "replans exceeded."
                            ),
                        )
                    )

                    return build_result()

                replan_count += 1

                observations.append(
                    Observation(
                        step_id=f"replan_{replan_count}",
                        success=True,
                        output=(
                            "REPLANNING: "
                            f"{decision.reason}"
                        ),
                    )
                )

                plan = self.replanner.replan(
                    plan=plan,
                    evaluation=evaluation,
                )

                continue

        # --------------------------------
        # Execute Accepted Plan
        # --------------------------------

        for step in plan.steps:

            try:

                # --------------------------------
                # Non-tool step
                # --------------------------------

                if step.tool_call is None:

                    observation = Observation(
                        step_id=step.id,
                        success=True,
                        output=(
                            f"Completed: "
                            f"{step.description}"
                        ),
                    )

                # --------------------------------
                # Tool step
                # --------------------------------

                else:

                    tool = self.tool_registry.get(
                        step.tool_call.tool_name
                    )

                    policy_decision = (
                        self.policy_engine.authorize(
                            tool.permission_level
                        )
                    )

                    # --------------------------------
                    # Policy Denied
                    # --------------------------------

                    if not policy_decision.allowed:

                        observation = Observation(
                            step_id=step.id,
                            success=False,
                            error=(
                                "POLICY DENIED: "
                                f"{policy_decision.reason}"
                            ),
                        )

                        self.audit_logger.record(
                            AuditEvent(
                                task_id=task.id,
                                tool_name=(
                                    step.tool_call.tool_name
                                ),
                                arguments=(
                                    step.tool_call.arguments
                                ),
                                policy_allowed=False,
                                success=False,
                                error=(
                                    "POLICY DENIED: "
                                    f"{policy_decision.reason}"
                                ),
                            )
                        )

                        observations.append(observation)

                        task.status = TaskStatus.FAILED

                        return build_result()

                    # --------------------------------
                    # Execute Tool
                    # --------------------------------

                    output = tool.execute(
                        **step.tool_call.arguments
                    )

                    observation = Observation(
                        step_id=step.id,
                        success=True,
                        output=output,
                    )

                    self.audit_logger.record(
                        AuditEvent(
                            task_id=task.id,
                            tool_name=(
                                step.tool_call.tool_name
                            ),
                            arguments=(
                                step.tool_call.arguments
                            ),
                            policy_allowed=True,
                            success=True,
                            output=output,
                        )
                    )

                    context.variables[
                        step.id
                    ] = output

            except Exception as exc:

                observation = Observation(
                    step_id=step.id,
                    success=False,
                    error=str(exc),
                )

                if step.tool_call is not None:

                    self.audit_logger.record(
                        AuditEvent(
                            task_id=task.id,
                            tool_name=(
                                step.tool_call.tool_name
                            ),
                            arguments=(
                                step.tool_call.arguments
                            ),
                            policy_allowed=True,
                            success=False,
                            error=str(exc),
                        )
                    )

                observations.append(observation)

                task.status = TaskStatus.FAILED

                return build_result()

            observations.append(observation)

        # --------------------------------
        # Completed
        # --------------------------------

        task.status = TaskStatus.COMPLETED

        return build_result()