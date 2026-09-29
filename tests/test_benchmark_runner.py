from agent.benchmark_runner import run_all

def test_all_engines_are_reported():
    result = run_all()
    assert set(result) == {"rule", "llm_baseline"}
    assert result["rule"]["total"] == 4
    assert result["llm_baseline"]["total"] == 4
    assert result["rule"]["passed"] == 4
    assert result["llm_baseline"]["passed"] == 4
