from aegis.core.decision import (
    PlanDecision,
    PlanDecisionEngine,
)


def test_decision_engine_accepts_complete_plan():
    engine = PlanDecisionEngine()

    result = engine.decide(
        coverage=1.0,
        constraint_coverage=1.0,
    )

    assert result.decision == PlanDecision.ACCEPT


def test_decision_engine_requests_replan_for_missing_requirements():
    engine = PlanDecisionEngine()

    result = engine.decide(
        coverage=0.5,
        constraint_coverage=1.0,
    )

    assert result.decision == PlanDecision.REPLAN


def test_decision_engine_rejects_constraint_violation():
    engine = PlanDecisionEngine()

    result = engine.decide(
        coverage=1.0,
        constraint_coverage=0.5,
    )

    assert result.decision == PlanDecision.REJECT
    
def test_decision_engine_accepts_full_coverage_only():
    engine = PlanDecisionEngine()

    result = engine.decide(
        coverage=1.0,
        constraint_coverage=1.0,
    )

    assert result.decision == PlanDecision.ACCEPT
    assert result.reason == (
        "Plan fully satisfies requirements and constraints."
    )


def test_decision_engine_replans_for_missing_requirements():
    engine = PlanDecisionEngine()

    result = engine.decide(
        coverage=0.8,
        constraint_coverage=1.0,
    )

    assert result.decision == PlanDecision.REPLAN
    assert "requirements" in result.reason.lower()


def test_decision_engine_rejects_constraint_violations():
    engine = PlanDecisionEngine()

    result = engine.decide(
        coverage=1.0,
        constraint_coverage=0.8,
    )

    assert result.decision == PlanDecision.REJECT
    assert "constraints" in result.reason.lower() 