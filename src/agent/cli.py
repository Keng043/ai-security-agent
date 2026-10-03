import argparse
import sys

from .decision_engine import RuleDecisionEngine
from .http_scanner import scan_http
from .llm_provider import LLMProviderError, OpenAICompatibleDecisionProvider
from .pipeline import AssessmentPipeline
from .report import write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI Security Agent - authorized HTTP assessment")
    parser.add_argument("url", help="Authorized HTTP/HTTPS target, preferably localhost for the lab")
    parser.add_argument("--report", default="security-report.json")
    parser.add_argument(
        "--decision-provider", choices=("rule", "llm"), default="rule",
        help="Decision engine (default: deterministic rule engine)",
    )
    return parser


def create_pipeline(provider: str = "rule") -> AssessmentPipeline:
    if provider == "rule":
        engine = RuleDecisionEngine()
    elif provider == "llm":
        engine = OpenAICompatibleDecisionProvider()
    else:
        raise ValueError(f"Unsupported decision provider: {provider}")
    return AssessmentPipeline(decision_engine=engine)


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    target, findings = scan_http(args.url)
    try:
        result = create_pipeline(args.decision_provider).run(target, findings)
    except LLMProviderError as exc:
        print(f"Decision provider error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    write_json(args.report, target, findings, decisions=result["decisions"])
    print(f"Target: {target['url']}")
    print(f"Status: {target['status']}")
    print(f"Findings: {len(findings)}")
    for finding, decision in zip(findings, result["decisions"]):
        print(f"[{finding.severity.upper()}] {finding.title} -> {decision['action']}: {decision['reason']}")
    print(f"Report: {args.report}")


if __name__ == "__main__":
    main()
