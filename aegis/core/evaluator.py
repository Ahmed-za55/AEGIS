from dataclasses import dataclass

from .models import Plan


@dataclass(frozen=True)
class EvaluationResult:
    valid: bool
    coverage: float
    missing_requirements: list[str]
    constraint_coverage: float
    violated_constraints: list[str]


class PlanEvaluator:

    def evaluate(self, plan: Plan) -> EvaluationResult:

        descriptions = [
            step.description.lower()
            for step in plan.steps
        ]

        # -------------------------
        # Requirement evaluation
        # -------------------------

        missing_requirements: list[str] = []

        ignored_requirement_words = {
            "support",
            "handle",
            "allow",
            "provide",
            "enable",
            "ensure",
        }

        for requirement in plan.requirements:

            words = requirement.lower().split()

            meaningful_words = [
                word
                for word in words
                if word not in ignored_requirement_words
            ]

            covered = any(
                all(
                    word in description
                    for word in meaningful_words
                )
                for description in descriptions
            )

            if not covered:
                missing_requirements.append(
                    requirement
                )

        if plan.requirements:
            coverage = (
                len(plan.requirements)
                - len(missing_requirements)
            ) / len(plan.requirements)
        else:
            coverage = 1.0

        # -------------------------
        # Constraint evaluation
        # -------------------------

        violated_constraints: list[str] = []

        for constraint in plan.constraints:

            normalized_constraint = (
                constraint.lower()
                .replace("()", "")
            )

            # Special handling for negative constraints.
            #
            # Example:
            # "Do not use eval()"
            #
            # Implementation:
            # "without using eval"
            if normalized_constraint.startswith("do not use "):

                target = normalized_constraint[
                    len("do not use "):
                ].strip()

                covered = any(
                    (
                        f"without using {target}" in description
                        or f"without {target}" in description
                    )
                    for description in descriptions
                )

            else:

                ignored_constraint_words = {
                    "handle",
                    "allow",
                    "provide",
                    "enable",
                    "ensure",
                    "must",
                    "should",
                }

                words = normalized_constraint.split()

                meaningful_words = [
                    word
                    for word in words
                    if word not in ignored_constraint_words
                ]

                covered = any(
                    all(
                        word in description
                        for word in meaningful_words
                    )
                    for description in descriptions
                )

            if not covered:
                violated_constraints.append(
                    constraint
                )

        if plan.constraints:
            constraint_coverage = (
                len(plan.constraints)
                - len(violated_constraints)
            ) / len(plan.constraints)
        else:
            constraint_coverage = 1.0

        # -------------------------
        # Final evaluation
        # -------------------------

        valid = (
            len(missing_requirements) == 0
            and len(violated_constraints) == 0
        )

        return EvaluationResult(
            valid=valid,
            coverage=coverage,
            missing_requirements=missing_requirements,
            constraint_coverage=constraint_coverage,
            violated_constraints=violated_constraints,
        )