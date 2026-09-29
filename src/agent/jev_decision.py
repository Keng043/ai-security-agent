import os
from .decision_engine import Decision
from .models import Finding

class JevDecisionAdapter:
    """Optional live Jev adapter. Requires TYPESAFE_API_KEY and typesafe-sdk."""

    def __init__(self, client=None):
        self.client = client
        if self.client is None:
            try:
                from typesafe_sdk import Choice, TypeSafeClient
            except ImportError as exc:
                raise RuntimeError("Install typesafe-sdk to use live Jev") from exc
            if not os.getenv("TYPESAFE_API_KEY"):
                raise RuntimeError("TYPESAFE_API_KEY is not set")
            self._Choice = Choice
            self.client = TypeSafeClient()
        else:
            self._Choice = lambda **kwargs: kwargs

    def decide(self, finding: Finding) -> Decision:
        question = self._Choice(
            instructions="Choose the safest next action for an authorized, non-destructive security assessment.",
            criteria={
                "report": "Report the finding without active verification.",
                "verify": "Collect additional safe evidence before escalation.",
            },
        )
        state = {
            "check": finding.check,
            "title": finding.title,
            "severity": finding.severity,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
        }
        response = self.client.system_one(state=state, questions={"action": question})
        answer = response.answers["action"]
        action = answer.choice
        probabilities = getattr(answer, "probabilities", {}) or {}
        confidence = float(probabilities.get(action, 0.0))
        return Decision(
            finding.check,
            action,
            "Jev selected a typed decision from the supplied security evidence.",
            confidence,
        )
