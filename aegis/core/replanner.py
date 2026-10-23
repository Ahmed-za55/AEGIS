from .evaluator import EvaluationResult
from .models import Plan, PlanStep


class Replanner:

    def replan(
        self,
        plan: Plan,
        evaluation: EvaluationResult,
    ) -> Plan:

        new_steps = plan.steps.copy()

        next_step_number = len(new_steps) + 1

        for requirement in evaluation.missing_requirements:

            new_steps.append(
                PlanStep(
                    id=f"replan_{next_step_number}",
                    description=(
                        f"Implement requirement: "
                        f"{requirement}"
                    ),
                )
            )

            next_step_number += 1

        for constraint in evaluation.violated_constraints:

            new_steps.append(
                PlanStep(
                    id=f"replan_{next_step_number}",
                    description=(
                        f"Ensure constraint: "
                        f"{constraint}"
                    ),
                )
            )

            next_step_number += 1

        return Plan(
            task_id=plan.task_id,
            steps=new_steps,
            strategy=(
                "Replanned to address evaluation failures"
            ),
            expected_result=plan.expected_result,
            requirements=plan.requirements.copy(),
            constraints=plan.constraints.copy(),
        )