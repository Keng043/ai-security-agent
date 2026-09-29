from dataclasses import dataclass
from .decision_engine import RuleDecisionEngine
from .models import Finding

@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    finding: Finding
    expected_action: str

@dataclass(frozen=True)
class BenchmarkResult:
    name: str
    expected: str
    actual: str
    passed: bool

def run_benchmark(cases: list[BenchmarkCase], engine=None) -> list[BenchmarkResult]:
    engine = engine or RuleDecisionEngine()
    results = []
    for case in cases:
        actual = engine.decide(case.finding).action
        results.append(BenchmarkResult(
            case.name, case.expected_action, actual, actual == case.expected_action
        ))
    return results

def default_cases() -> list[BenchmarkCase]:
    return [
        BenchmarkCase(
            "medium-header-gap",
            Finding("http_headers", "Missing CSP", "medium", "CSP missing", "Add CSP"),
            "verify",
        ),
        BenchmarkCase(
            "low-header-gap",
            Finding("http_headers", "Missing XFO", "low", "XFO missing", "Set XFO"),
            "report",
        ),
        BenchmarkCase(
            "high-risk-finding",
            Finding("auth", "Weak authentication control", "high", "Evidence present", "Review authentication"),
            "verify",
        ),
        BenchmarkCase(
            "informational-finding",
            Finding("metadata", "Server version disclosed", "info", "Version header present", "Reduce disclosure"),
            "report",
        ),
    ]
