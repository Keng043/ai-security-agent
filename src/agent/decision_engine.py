from dataclasses import dataclass
from .models import Finding, Severity

SEVERITY_RANK: dict[Severity, int] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

@dataclass(frozen=True)
class Decision:
    finding_check: str
    action: str
    reason: str
    confidence: float

class RuleDecisionEngine:
    """Deterministic decision layer; replaceable by a Jev adapter later."""

    def decide(self, finding: Finding) -> Decision:
        rank = SEVERITY_RANK[finding.severity]
        if rank >= SEVERITY_RANK["medium"]:
            action = "verify"
            reason = "Finding is medium-or-higher severity; collect additional evidence before escalation."
        else:
            action = "report"
            reason = "Low-impact posture issue can be reported without active verification."
        return Decision(finding.check, action, reason, 1.0)

    def plan(self, findings: list[Finding]) -> list[Decision]:
        return [self.decide(finding) for finding in findings]
