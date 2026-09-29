from agent.jev_decision import JevDecisionAdapter
from agent.models import Finding

class FakeAnswer:
    choice = "verify"
    probabilities = {"verify": 0.91, "report": 0.09}

class FakeResponse:
    answers = {"action": FakeAnswer()}

class FakeClient:
    def system_one(self, *, state, questions):
        assert state["severity"] == "high"
        assert "action" in questions
        return FakeResponse()

def test_jev_adapter_maps_typed_choice_to_decision():
    finding = Finding("auth", "Weak auth", "high", "evidence", "review")
    decision = JevDecisionAdapter(FakeClient()).decide(finding)
    assert decision.action == "verify"
    assert decision.confidence == 0.91
