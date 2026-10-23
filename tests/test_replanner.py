from aegis.core.models import Plan, PlanStep, Task, TaskStatus
from aegis.core.evaluator import EvaluationResult
from aegis.core.replanner import Replanner

from aegis.core.engine import ExecutionEngine
from aegis.core.agent import Agent
from aegis.core.engineering_agent import EngineeringAgent
from aegis.core.policy import PolicyEngine
from aegis.core.registry import ToolRegistry

def test_replanner_adds_missing_requirements_to_plan():
    replanner = Replanner()

    plan = Plan(
        task_id="task-1",
        steps=[
            PlanStep(
                id="analyze",
                description="Analyze the task requirements",
            )
        ],
        requirements=[
            "perform calculation",
            "handle division by zero",
        ],
    )

    evaluation = EvaluationResult(
        valid=False,
        coverage=0.5,
        missing_requirements=[
            "handle division by zero",
        ],
        constraint_coverage=1.0,
        violated_constraints=[],
    )

    new_plan = replanner.replan(
        plan=plan,
        evaluation=evaluation,
    )

    assert new_plan.task_id == plan.task_id
    assert len(new_plan.steps) > len(plan.steps)
    assert any(
        "division by zero" in step.description.lower()
        for step in new_plan.steps
    )


def test_replanner_preserves_original_requirements():
    replanner = Replanner()

    plan = Plan(
        task_id="task-2",
        steps=[
            PlanStep(
                id="analyze",
                description="Analyze the task",
            )
        ],
        requirements=[
            "perform calculation",
            "handle errors",
        ],
    )

    evaluation = EvaluationResult(
        valid=False,
        coverage=0.5,
        missing_requirements=["handle errors"],
        constraint_coverage=1.0,
        violated_constraints=[],
    )

    new_plan = replanner.replan(
        plan=plan,
        evaluation=evaluation,
    )

    assert new_plan.requirements == plan.requirements


def test_replanner_preserves_constraints():
    replanner = Replanner()

    plan = Plan(
        task_id="task-3",
        steps=[
            PlanStep(
                id="analyze",
                description="Analyze the task",
            )
        ],
        constraints=[
            "Do not use eval()",
        ],
    )

    evaluation = EvaluationResult(
        valid=False,
        coverage=1.0,
        missing_requirements=[],
        constraint_coverage=0.5,
        violated_constraints=[
            "Do not use eval()",
        ],
    )

    new_plan = replanner.replan(
        plan=plan,
        evaluation=evaluation,
    )

    assert new_plan.constraints == plan.constraints
    
def test_replanner_improves_requirement_coverage():
    from aegis.core.evaluator import PlanEvaluator

    replanner = Replanner()
    evaluator = PlanEvaluator()

    plan = Plan(
        task_id="task-improvement",
        steps=[
            PlanStep(
                id="analyze",
                description="Analyze the task",
            )
        ],
        requirements=[
            "perform calculation",
            "handle division by zero",
        ],
    )

    initial_evaluation = evaluator.evaluate(plan)

    assert initial_evaluation.coverage == 0.0

    new_plan = replanner.replan(
        plan=plan,
        evaluation=initial_evaluation,
    )

    improved_evaluation = evaluator.evaluate(new_plan)

    assert improved_evaluation.coverage > initial_evaluation.coverage
    
def test_replanner_can_produce_an_acceptable_plan():
    from aegis.core.evaluator import PlanEvaluator
    from aegis.core.decision import (
        PlanDecision,
        PlanDecisionEngine,
    )

    replanner = Replanner()
    evaluator = PlanEvaluator()
    decision_engine = PlanDecisionEngine()

    plan = Plan(
        task_id="task-loop",
        steps=[
            PlanStep(
                id="analyze",
                description="Analyze the task",
            )
        ],
        requirements=[
            "perform calculation",
        ],
    )

    initial_evaluation = evaluator.evaluate(plan)

    initial_decision = decision_engine.decide(
        coverage=initial_evaluation.coverage,
        constraint_coverage=initial_evaluation.constraint_coverage,
    )

    assert initial_decision.decision == PlanDecision.REPLAN

    new_plan = replanner.replan(
        plan=plan,
        evaluation=initial_evaluation,
    )

    new_evaluation = evaluator.evaluate(new_plan)

    new_decision = decision_engine.decide(
        coverage=new_evaluation.coverage,
        constraint_coverage=new_evaluation.constraint_coverage,
    )

    assert new_decision.decision == PlanDecision.ACCEPT
    
def test_execution_engine_accepts_replanner():
    from aegis.core.engine import ExecutionEngine

    replanner = Replanner()

    engine = ExecutionEngine(
        agent=EngineeringAgent(),
        tool_registry=ToolRegistry(),
        policy_engine=PolicyEngine(),
        replanner=replanner,
    )

    assert engine.replanner is replanner
    
def test_execution_engine_replans_before_execution():
    from aegis.core.engine import ExecutionEngine
    from aegis.core.models import ToolCall
    from aegis.tools.calculator import CalculatorTool

    class ReplanAgent(Agent):

        def __init__(self):
            self.calls = 0

        def plan(self, task: Task) -> Plan:
            self.calls += 1

            if self.calls == 1:
                return Plan(
                    task_id=task.id,
                    steps=[
                        PlanStep(
                            id="initial",
                            description="Analyze the task",
                        )
                    ],
                    requirements=[
                        "perform calculation",
                    ],
                )

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
                ],
            )

    class TrackingReplanner(Replanner):

        def __init__(self):
            self.calls = 0

        def replan(
            self,
            plan: Plan,
            evaluation: EvaluationResult,
        ) -> Plan:
            self.calls += 1

            return Plan(
                task_id=plan.task_id,
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
                requirements=plan.requirements.copy(),
                constraints=plan.constraints.copy(),
            )

    agent = ReplanAgent()
    replanner = TrackingReplanner()

    registry = ToolRegistry()
    registry.register(CalculatorTool())

    engine = ExecutionEngine(
        agent=agent,
        tool_registry=registry,
        policy_engine=PolicyEngine(),
        replanner=replanner,
    )

    task = Task(
        description="Test replanning execution",
    )

    result = engine.run(task)

    assert result.status == TaskStatus.COMPLETED
    assert replanner.calls == 1
    assert len(engine.audit_logger.events()) == 1
    assert engine.audit_logger.events()[0].output == 30
    
def test_execution_engine_stops_after_max_replans():
    class AlwaysReplanAgent(Agent):
        def plan(self, task):
            return Plan(
                task_id=task.id,
                steps=[
                    PlanStep(
                        id="step_1",
                        description="Incomplete implementation",
                    )
                ],
                requirements=["requirement that is never satisfied"],
            )

    class CountingReplanner(Replanner):
        def __init__(self):
            self.calls = 0

        def replan(self, plan, evaluation):
            self.calls += 1

            return Plan(
                task_id=plan.task_id,
                steps=[
                    PlanStep(
                        id=f"replan_{self.calls}",
                        description="Still incomplete",
                    )
                ],
                requirements=plan.requirements.copy(),
                constraints=plan.constraints.copy(),
            )

    task = Task(
        description="Test bounded replanning",
        requirements=["requirement that is never satisfied"],
    )

    replanner = CountingReplanner()

    engine = ExecutionEngine(
        agent=AlwaysReplanAgent(),
        tool_registry=ToolRegistry(),
        policy_engine=PolicyEngine(),
        replanner=replanner,
        max_replans=2,
    )

    result = engine.run(task)

    assert result.status == TaskStatus.FAILED
    assert replanner.calls == 2

    observations = result.observations
    assert any(
    "REPLAN LIMIT REACHED" in str(observation)
    for observation in observations
)