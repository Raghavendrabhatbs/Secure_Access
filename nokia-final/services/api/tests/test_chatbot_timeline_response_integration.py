import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.main import app


class RecordingProvider:
    def __init__(self):
        self.calls = []

    def generate(self, question: str, intent: str, evidence: dict):
        self.calls.append({"question": question, "intent": intent, "evidence": evidence})
        return "llm should not be called for deterministic timeline responses"


class ChatbotTimelineResponseIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def _post(self, question: str, session_id: str):
        provider = RecordingProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": question,
                    "session_id": session_id,
                },
            )

        self.assertEqual(response.status_code, 200)
        return response.json(), provider

    def test_timeline_summary_question_is_rule_based(self):
        payload, provider = self._post("Show me the timeline of this session.", self.risky_session_id)

        self.assertEqual(payload["intent"], "TIMELINE_SUMMARY")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("Session timeline:", payload["answer"])
        self.assertIn("sudo su -", payload["answer"])
        self.assertIn("sudo useradd hacker123", payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])
        self.assertIn("Overall risk: HIGH", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_chronological_commands_question_is_rule_based(self):
        payload, provider = self._post(
            "What commands were executed chronologically?",
            self.risky_session_id,
        )

        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("sudo su -", payload["answer"])
        self.assertIn("history -c", payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_before_privilege_escalation_question(self):
        payload, provider = self._post(
            "Show the timeline before the privilege escalation.",
            self.risky_session_id,
        )

        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("before the first PRIVILEGE_ESCALATION", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_after_privilege_escalation_question(self):
        payload, provider = self._post(
            "Show the timeline after the privilege escalation.",
            self.risky_session_id,
        )

        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("after the first PRIVILEGE_ESCALATION", payload["answer"])
        self.assertIn("sudo useradd hacker123", payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_benign_timeline_summary_has_none_risk(self):
        payload, provider = self._post("Show me the timeline of this session.", self.benign_session_id)

        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("Overall risk: NONE", payload["answer"])
        self.assertIn("whoami", payload["answer"])
        self.assertEqual(provider.calls, [])


if __name__ == "__main__":
    unittest.main()
