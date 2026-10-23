from dataclasses import dataclass

from .models import Plan
from .registry import ToolRegistry


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: list[str]


class PlanValidator:

    def validate(
        self,
        plan: Plan,
        tool_registry: ToolRegistry,
        task_id: str | None = None,
    ) -> ValidationResult:

        errors: list[str] = []

        # Validate plan task identity
        if not plan.task_id:
            errors.append(
                "Plan task_id is required."
            )

        if task_id is not None and plan.task_id != task_id:
            errors.append(
                "Plan task_id does not match the requested task."
            )

        # Validate plan steps
        if not plan.steps:
            errors.append(
                "Plan must contain at least one step."
            )

        step_ids: set[str] = set()

        for step in plan.steps:

            if not step.id:
                errors.append(
                    "Every plan step must have an id."
                )

            elif step.id in step_ids:
                errors.append(
                    f"Duplicate plan step id: {step.id}"
                )

            step_ids.add(step.id)

            if not step.description:
                errors.append(
                    "Every plan step must have a description."
                )

            # Validate tool calls
            if step.tool_call is not None:

                tool_name = step.tool_call.tool_name

                try:
                    tool_registry.get(tool_name)
                except KeyError:
                    errors.append(
                        f"Tool not found: {tool_name}"
                    )

        # Validate requirements
        requirement_set: set[str] = set()

        for requirement in plan.requirements:

            if requirement in requirement_set:
                errors.append(
                    f"Duplicate plan requirement: {requirement}"
                )

            requirement_set.add(requirement)

        # Validate constraints
        constraint_set: set[str] = set()

        for constraint in plan.constraints:

            if constraint in constraint_set:
                errors.append(
                    f"Duplicate plan constraint: {constraint}"
                )

            constraint_set.add(constraint)

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
        )