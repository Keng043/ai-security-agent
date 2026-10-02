import json
import os
import unittest
from unittest.mock import patch

from agent.llm_provider import OpenAICompatibleDecisionProvider
from agent.models import Finding
from agent.pipeline import AssessmentPipeline


class FakeResponse:
    def __init__(self, body):
        self.body = body
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        return False
    def read(self):
        return json.dumps({"choices": [{"message": {"content": json.dumps(self.body)}}]}).encode()


class LLMProviderTests(unittest.TestCase):
    def setUp(self):
        self.finding = Finding("headers", "Missing CSP", "medium", "No CSP", "Add CSP")

    def test_sends_env_credential_and_parses_bounded_decision(self):
        captured = {}
        def transport(request, timeout):
            captured["authorization"] = request.get_header("Authorization")
            captured["payload"] = json.loads(request.data)
            captured["timeout"] = timeout
            return FakeResponse({"action": "verify", "reason": "Check evidence", "confidence": 0.8})
        with patch.dict(os.environ, {"AI_SECURITY_LLM_API_KEY": "mock-secret"}, clear=True):
            decision = OpenAICompatibleDecisionProvider(transport=transport).decide(self.finding)
        self.assertEqual(decision.finding_check, "headers")
        self.assertEqual(decision.action, "verify")
        self.assertEqual(decision.confidence, 0.8)
        self.assertEqual(captured["authorization"], "Bearer mock-secret")
        self.assertEqual(captured["timeout"], 20.0)
        self.assertEqual(captured["payload"]["temperature"], 0)

    def test_rejects_remote_plain_http_before_sending_credentials(self):
        with patch.dict(os.environ, {
            "AI_SECURITY_LLM_API_KEY": "mock",
            "AI_SECURITY_LLM_BASE_URL": "http://api.example.test/v1",
        }, clear=True):
            provider = OpenAICompatibleDecisionProvider(
                transport=lambda *_a, **_k: self.fail("insecure endpoint was called")
            )
            with self.assertRaisesRegex(ValueError, "must use HTTPS"):
                provider.decide(self.finding)

    def test_allows_http_loopback_for_local_test_servers(self):
        captured = {}
        def transport(request, timeout):
            captured["url"] = request.full_url
            return FakeResponse({"action": "report", "reason": "Local", "confidence": 0.5})
        with patch.dict(os.environ, {
            "AI_SECURITY_LLM_API_KEY": "mock",
            "AI_SECURITY_LLM_BASE_URL": "http://127.0.0.1:8081/v1",
        }, clear=True):
            OpenAICompatibleDecisionProvider(transport=transport).decide(self.finding)
        self.assertEqual(captured["url"], "http://127.0.0.1:8081/v1/chat/completions")

    def test_rejects_embedded_credentials_in_endpoint_url(self):
        with patch.dict(os.environ, {
            "AI_SECURITY_LLM_API_KEY": "mock",
            "AI_SECURITY_LLM_BASE_URL": "https://user:pass@example.test/v1",
        }, clear=True):
            with self.assertRaisesRegex(ValueError, "embedded credentials"):
                OpenAICompatibleDecisionProvider(transport=lambda *_a, **_k: self.fail("request called")).decide(self.finding)

    def test_provider_integrates_with_pipeline_without_replacing_local_analysis(self):
        with patch.dict(os.environ, {"AI_SECURITY_LLM_API_KEY": "mock"}, clear=True):
            provider = OpenAICompatibleDecisionProvider(transport=lambda *_a, **_k: FakeResponse(
                {"action": "report", "reason": "Evidence is limited", "confidence": 0.6}
            ))
            result = AssessmentPipeline(decision_engine=provider).run(
                {"url": "http://localhost"}, [self.finding]
            )
        self.assertEqual(result["decisions"][0]["action"], "report")
        self.assertEqual(result["analysis"][0]["remediation"], "Add CSP")

    def test_requires_api_key_without_network(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "AI_SECURITY_LLM_API_KEY"):
                OpenAICompatibleDecisionProvider(transport=lambda *_a, **_k: self.fail("network called")).decide(self.finding)

    def test_rejects_unsupported_action_and_unbounded_confidence(self):
        for value in ({"action": "execute", "reason": "bad", "confidence": 0.5},
                      {"action": "report", "reason": "bad", "confidence": 2}):
            with self.subTest(value=value), patch.dict(os.environ, {"AI_SECURITY_LLM_API_KEY": "mock"}, clear=True):
                provider = OpenAICompatibleDecisionProvider(transport=lambda *_a, **_k: FakeResponse(value))
                with self.assertRaises(ValueError):
                    provider.decide(self.finding)


if __name__ == "__main__":
    unittest.main()
