from dataclasses import dataclass, asdict
from typing import Literal

Severity = Literal["info", "low", "medium", "high", "critical"]

@dataclass(frozen=True)
class Finding:
    check: str
    title: str
    severity: Severity
    evidence: str
    recommendation: str

    def to_dict(self) -> dict:
        return asdict(self)
