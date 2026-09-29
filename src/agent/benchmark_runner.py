import json
import os
from pathlib import Path
from .benchmark import default_cases, run_benchmark
from .decision_engine import RuleDecisionEngine
from .llm_decision import LLMDecisionAdapter
from .jev_decision import JevDecisionAdapter

def run_all() -> dict:
    cases = default_cases()
    engines = {"rule": RuleDecisionEngine(), "llm_baseline": LLMDecisionAdapter()}
    if os.getenv("TYPESAFE_API_KEY"):
        engines["jev"] = JevDecisionAdapter()
    output = {}
    for name, engine in engines.items():
        results = run_benchmark(cases, engine)
        output[name] = {"passed": sum(r.passed for r in results), "total": len(results), "results": [r.__dict__ for r in results]}
    return output

def write_benchmark(path: str) -> dict:
    result = run_all()
    Path(path).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result

def print_benchmark(result: dict) -> None:
    print("Decision Benchmark")
    print("=" * 48)
    print(f"{'Engine':<20} {'Passed':>8} {'Total':>8}")
    print("-" * 48)
    for name, data in result.items():
        print(f"{name:<20} {data['passed']:>8} {data['total']:>8}")
    print("\nCases")
    for name, data in result.items():
        print(f"\n{name}")
        for item in data["results"]:
            mark = "PASS" if item["passed"] else "FAIL"
            print(f"  [{mark}] {item['name']}: expected={item['expected']} actual={item['actual']}")