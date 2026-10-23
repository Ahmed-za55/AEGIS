from .agent import Agent
from .models import Plan, PlanStep, Task


class EngineeringAgent(Agent):

    def plan(self, task: Task) -> Plan:

        steps = [
            PlanStep(
                id="analyze",
                description=(
                    "Analyze task requirements and constraints"
                ),
            ),
            PlanStep(
                id="implement",
                description="Implement the required solution",
            ),
            PlanStep(
                id="verify",
                description=(
                    "Verify the solution against requirements "
                    "and expected outcome"
                ),
            ),
        ]

        return Plan(
            task_id=task.id,
            steps=steps,
            strategy="Analyze, implement, and verify",
            expected_result=task.expected_outcome,
            requirements=task.requirements.copy(),
            constraints=task.constraints.copy(),
        )