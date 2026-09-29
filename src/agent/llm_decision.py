from dataclasses import dataclass
from .decision_engine import Decision
from .models import Finding

@dataclass(frozen=True)
class LLMDecisionAdapter:
    """Offline LLM-style baseline with deterministic behavior."""

    def decide(self, finding: Finding) -> Decision:
        if finding.severity in {"high", "critical"}:
            return Decision(finding.check, "verify", "High-impact finding needs additional evidence.", 0.90)
        if finding.severity == "medium":
            return Decision(finding.check, "verify", "Medium severity warrants evidence verification.", 0.82)
        return Decision(finding.check, "report", "Lower-impact finding can be reported safely.", 0.76)
