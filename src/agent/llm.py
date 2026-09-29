from dataclasses import dataclass
from .models import Finding

@dataclass(frozen=True)
class Analysis:
    title: str
    explanation: str
    remediation: str

class LocalLLMAdapter:
    """LLM boundary. MVP uses deterministic text and makes no external calls."""

    def analyze(self, finding: Finding) -> Analysis:
        return Analysis(
            title=finding.title,
            explanation=finding.evidence,
            remediation=finding.recommendation,
        )
