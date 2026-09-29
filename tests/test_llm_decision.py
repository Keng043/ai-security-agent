from agent.benchmark import default_cases, run_benchmark
from agent.llm_decision import LLMDecisionAdapter

def test_llm_baseline_matches_expected_cases():
    results = run_benchmark(default_cases(), LLMDecisionAdapter())
    assert len(results) == 4
    assert all(result.passed for result in results)

def test_llm_decision_has_bounded_confidence():
    decision = LLMDecisionAdapter().decide(default_cases()[0].finding)
    assert 0.0 <= decision.confidence <= 1.0
