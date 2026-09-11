from app.engines.kernel import evaluate_plan
from app.scenarios import prompt_injection_exfiltration, unsafe_sql_plan, high_value_payment, safe_analytics


def test_prompt_injection_is_blocked():
    result = evaluate_plan(prompt_injection_exfiltration())
    assert result.decision.value == "BLOCK"
    assert result.risk_score >= 80


def test_unsafe_sql_is_safely_rewritten():
    result = evaluate_plan(unsafe_sql_plan())
    assert result.decision.value == "REWRITE"
    assert result.action_results[-1].rewritten_action is not None
    assert result.action_results[-1].rewritten_action.operation == "select"


def test_large_payment_requires_approval():
    result = evaluate_plan(high_value_payment())
    assert result.decision.value == "REQUIRE_APPROVAL"


def test_safe_analytics_is_allowed():
    result = evaluate_plan(safe_analytics())
    assert result.decision.value in {"ALLOW", "ALLOW_WITH_LOG"}
