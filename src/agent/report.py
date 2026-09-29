import json
from .models import Finding

def write_json(path: str, target: dict, findings: list[Finding]) -> None:
    payload = {"target": target, "findings": [finding.to_dict() for finding in findings]}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
