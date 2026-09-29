from .decision_engine import RuleDecisionEngine
from .llm import LocalLLMAdapter

class AssessmentPipeline:
    def __init__(self, decision_engine=None, llm=None):
        self.decision_engine = decision_engine or RuleDecisionEngine()
        self.llm = llm or LocalLLMAdapter()

    def run(self, target: dict, findings: list) -> dict:
        decisions = self.decision_engine.plan(findings)
        analyses = [self.llm.analyze(f) for f in findings]
        return {
            "target": target,
            "findings": [f.to_dict() for f in findings],
            "decisions": [d.__dict__ for d in decisions],
            "analysis": [a.__dict__ for a in analyses],
        }
