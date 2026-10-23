from dataclasses import dataclass
from enum import Enum


class PlanDecision(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    REPLAN = "REPLAN"


@dataclass(frozen=True)
class PlanDecisionResult:
    decision: PlanDecision
    reason: str
    requirement_coverage: float
    constraint_coverage: float


class PlanDecisionEngine:

    def decide(
        self,
        coverage: float,
        constraint_coverage: float,
    ) -> PlanDecisionResult:

        if constraint_coverage < 1.0:
            return PlanDecisionResult(
                decision=PlanDecision.REJECT,
                reason="Plan violates one or more constraints.",
                requirement_coverage=coverage,
                constraint_coverage=constraint_coverage,
            )

        if coverage < 1.0:
            return PlanDecisionResult(
                decision=PlanDecision.REPLAN,
                reason="Plan does not cover all requirements.",
                requirement_coverage=coverage,
                constraint_coverage=constraint_coverage,
            )

        return PlanDecisionResult(
            decision=PlanDecision.ACCEPT,
            reason="Plan fully satisfies requirements and constraints.",
            requirement_coverage=coverage,
            constraint_coverage=constraint_coverage,
        )