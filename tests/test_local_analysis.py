import json
import os
import unittest
from unittest.mock import patch

from agent.decision_engine import RuleDecisionEngine
from agent.llm import LocalOpenAICompatibleAnalysisAdapter
from agent.llm_provider import LLMProviderError
from agent.models import Finding
from agent.pipeline import AssessmentPipeline


class FakeResponse:
    def __init__(self, content):
        self.content = content
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        return False
    def read(self):
        body = {"choices": [{"message": {"content": json.dumps(self.content)}}]}
        return json.dumps(body).encode("utf-8")


class LocalAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.finding = Finding("headers", "Missing CSP", "medium", "CSP absent", "Add a CSP")

    def test_local_model_only_generates_analysis_and_needs_no_api_key(self):
        captured = {}
        def transport(request, timeout):
            captured["url"] = request.full_url
            captured["authorization"] = request.get_header("Authorization")
            captured["payload"] = json.loads(request.data)
            return FakeResponse({
                "title": "Missing CSP",
                "explanation": "The response has no Content-Security-Policy header.",
                "remediation": "Add a restrictive Content-Security-Policy.",
            })
        env = {
            "AI_SECURITY_LOCAL_LLM_BASE_URL": "http://127.0.0.1:11434/v1",
            "AI_SECURITY_LOCAL_LLM_MODEL": "mock-local-model",
        }
        with patch.dict(os.environ, env, clear=True):
            adapter = LocalOpenAICompatibleAnalysisAdapter(transport=transport)
            pipeline = AssessmentPipeline(llm=adapter)
            result = pipeline.run({"url": "http://localhost"}, [self.finding])
        self.assertEqual(result["decisions"][0]["action"], "verify")
        self.assertEqual(result["analysis"][0]["explanation"], "The response has no Content-Security-Policy header.")
        self.assertEqual(result["analysis"][0]["remediation"], "Add a restrictive Content-Security-Policy.")
        self.assertEqual(captured["url"], "http://127.0.0.1:11434/v1/chat/completions")
        self.assertIsNone(captured["authorization"])
        self.assertEqual(captured["payload"]["model"], "mock-local-model")
        self.assertIn("Do not change", captured["payload"]["messages"][0]["content"])

    def test_local_analysis_rejects_remote_endpoint_before_request(self):
        env = {
            "AI_SECURITY_LOCAL_LLM_BASE_URL": "https://remote.example/v1",
            "AI_SECURITY_LOCAL_LLM_MODEL": "mock-local-model",
        }
        with patch.dict(os.environ, env, clear=True):
            adapter = LocalOpenAICompatibleAnalysisAdapter(
                transport=lambda *_a, **_k: self.fail("remote endpoint was called")
            )
            with self.assertRaisesRegex(LLMProviderError, "localhost or a loopback"):
                adapter.analyze(self.finding)

    def test_local_analysis_requires_model_name(self):
        with patch.dict(os.environ, {"AI_SECURITY_LOCAL_LLM_BASE_URL": "http://localhost:11434/v1"}, clear=True):
            adapter = LocalOpenAICompatibleAnalysisAdapter(
                transport=lambda *_a, **_k: self.fail("endpoint was called")
            )
            with self.assertRaisesRegex(LLMProviderError, "AI_SECURITY_LOCAL_LLM_MODEL"):
                adapter.analyze(self.finding)

    def test_local_analysis_rejects_incomplete_output(self):
        env = {"AI_SECURITY_LOCAL_LLM_MODEL": "mock-local-model"}
        with patch.dict(os.environ, env, clear=True):
            adapter = LocalOpenAICompatibleAnalysisAdapter(
                transport=lambda *_a, **_k: FakeResponse({"title": "Only title"})
            )
            with self.assertRaisesRegex(LLMProviderError, "title, explanation, and remediation"):
                adapter.analyze(self.finding)


if __name__ == "__main__":
    unittest.main()
