import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from agent.cli import build_parser, create_pipeline, main
from agent.decision_engine import RuleDecisionEngine
from agent.llm import LocalOpenAICompatibleAnalysisAdapter
from agent.llm_provider import LLMProviderError, OpenAICompatibleDecisionProvider


class CLITests(unittest.TestCase):
    def test_rule_provider_remains_the_default(self):
        args = build_parser().parse_args(["http://localhost"])
        self.assertEqual(args.decision_provider, "rule")
        self.assertEqual(args.analysis_provider, "deterministic")
        self.assertIsInstance(create_pipeline(args.decision_provider).decision_engine, RuleDecisionEngine)

    def test_llm_providers_can_be_selected_without_making_requests(self):
        with patch.dict("os.environ", {}, clear=True):
            local_pipeline = create_pipeline("rule", "local-llm")
            remote_pipeline = create_pipeline("llm")
        self.assertIsInstance(local_pipeline.decision_engine, RuleDecisionEngine)
        self.assertIsInstance(local_pipeline.llm, LocalOpenAICompatibleAnalysisAdapter)
        self.assertIsInstance(remote_pipeline.decision_engine, OpenAICompatibleDecisionProvider)

    def test_cli_keeps_rule_decision_and_uses_local_llm_for_analysis(self):
        seen = {}

        class MockHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self):
                seen["path"] = self.path
                seen["authorization"] = self.headers.get("Authorization")
                seen["request"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                content = json.dumps({
                    "title": "Missing Content-Security-Policy",
                    "explanation": "The local model reviewed the missing header evidence.",
                    "remediation": "Add a restrictive Content-Security-Policy.",
                })
                body = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        report_path = None
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                report_path = Path(temp_dir) / "report.json"
                base_url = f"http://127.0.0.1:{server.server_port}/v1"
                with patch.dict("os.environ", {
                    "AI_SECURITY_LOCAL_LLM_MODEL": "test-local-model",
                    "AI_SECURITY_LOCAL_LLM_BASE_URL": base_url,
                }), redirect_stdout(io.StringIO()):
                    main([
                        f"http://127.0.0.1:{server.server_port}/",
                        "--analysis-provider", "local-llm", "--report", str(report_path),
                    ])
                report = json.loads(report_path.read_text(encoding="utf-8"))
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

        self.assertEqual(seen["path"], "/v1/chat/completions")
        self.assertIsNone(seen["authorization"])
        self.assertEqual(seen["request"]["model"], "test-local-model")
        self.assertIn("Do not change", seen["request"]["messages"][0]["content"])
        self.assertTrue(report["findings"])
        self.assertEqual(report["decisions"][0]["action"], "verify")
        self.assertEqual(report["analysis"][0]["explanation"], "The local model reviewed the missing header evidence.")

    def test_cli_shows_provider_failure_and_skips_report(self):
        class BrokenPipeline:
            def run(self, *_args):
                raise LLMProviderError("LLM request timed out; try again later.")
        stderr = io.StringIO()
        with patch("agent.cli.scan_http", return_value=({"url": "http://localhost", "status": 200}, [])), \
             patch("agent.cli.create_pipeline", return_value=BrokenPipeline()), \
             patch("agent.cli.write_json") as write_json, redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                main(["http://localhost", "--decision-provider", "llm"])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("Decision provider error", stderr.getvalue())
        write_json.assert_not_called()

    def test_cli_rejects_unknown_provider(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["http://localhost", "--decision-provider", "unknown"])


if __name__ == "__main__":
    unittest.main()
