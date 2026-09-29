from agent.benchmark import default_cases, run_benchmark

def test_default_benchmark_cases_are_consistent():
    results = run_benchmark(default_cases())
    assert len(results) == 4
    assert all(result.passed for result in results)
