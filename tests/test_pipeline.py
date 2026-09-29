from agent.models import Finding
from agent.pipeline import AssessmentPipeline

def test_pipeline_routes_medium_to_verification():
    finding = Finding(
        "http_headers", "Missing CSP", "medium",
        "CSP missing", "Add CSP"
    )
    result = AssessmentPipeline().run({"url": "http://localhost"}, [finding])
    assert result["decisions"][0]["action"] == "verify"
    assert result["analysis"][0]["remediation"] == "Add CSP"

def test_pipeline_reports_low_without_verification():
    finding = Finding(
        "http_headers", "Missing XFO", "low",
        "XFO missing", "Set XFO"
    )
    result = AssessmentPipeline().run({"url": "http://localhost"}, [finding])
    assert result["decisions"][0]["action"] == "report"
