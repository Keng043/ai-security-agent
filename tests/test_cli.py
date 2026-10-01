import unittest
from unittest.mock import patch

from agent.cli import build_parser, create_pipeline
from agent.decision_engine import RuleDecisionEngine
from agent.llm_provider import OpenAICompatibleDecisionProvider


class CLITests(unittest.TestCase):
    def test_rule_provider_remains_the_default(self):
        args = build_parser().parse_args(["http://localhost"])
        self.assertEqual(args.decision_provider, "rule")
        self.assertIsInstance(create_pipeline(args.decision_provider).decision_engine, RuleDecisionEngine)

    def test_llm_provider_can_be_selected_without_making_a_request(self):
        with patch.dict("os.environ", {}, clear=True):
            pipeline = create_pipeline("llm")
        self.assertIsInstance(pipeline.decision_engine, OpenAICompatibleDecisionProvider)

    def test_cli_rejects_unknown_provider(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["http://localhost", "--decision-provider", "unknown"])


if __name__ == "__main__":
    unittest.main()
