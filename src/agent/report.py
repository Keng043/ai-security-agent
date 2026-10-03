import json
from .models import Finding

def write_json(path: str, target: dict, findings: list[Finding], decisions: list[dict] | None = None, analysis: list[dict] | None = None) -> None:
    payload = {"target": target, "findings": [finding.to_dict() for finding in findings]}
    if decisions is not None:
        payload["decisions"] = decisions
    if analysis is not None:
        payload["analysis"] = analysis
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
