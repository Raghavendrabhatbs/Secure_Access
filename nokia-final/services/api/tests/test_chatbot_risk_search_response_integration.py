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
        return "provider should not be used for explicit risk-category searches"


class ChatbotRiskSearchResponseIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def test_privilege_escalation_response_uses_formatter(self):
        provider = RecordingProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={"question": "Which sessions contain privilege escalation?"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        answer = payload["answer"]
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        # Heading
        self.assertIn("Sessions with PRIVILEGE_ESCALATION:", answer)
        # Session identifier
        self.assertIn(self.risky_session_id, answer)
        # Risk level — produced by formatter, not LLM
        self.assertIn("Risk: HIGH", answer)
        # Commands section
        self.assertIn("Commands:", answer)
        self.assertIn("- sudo su -", answer)
        # Findings section
        self.assertIn("Findings:", answer)
        self.assertIn("- PRIVILEGE_ESCALATION / HIGH", answer)
        # Provider was not called
        self.assertEqual(provider.calls, [])

    def test_permission_modification_response_uses_formatter(self):
        provider = RecordingProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={"question": "Show sessions with permission modification."},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        answer = payload["answer"]
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("Sessions with PERMISSION_MODIFICATION:", answer)
        self.assertIn(self.risky_session_id, answer)
        self.assertIn("Risk: HIGH", answer)
        self.assertIn("- chmod 777 /etc/passwd", answer)
        self.assertIn("- PERMISSION_MODIFICATION / HIGH", answer)
        self.assertEqual(provider.calls, [])

    def test_no_match_category_uses_formatter_empty_message(self):
        provider = RecordingProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={"question": "Which sessions contain destructive operation?"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        answer = payload["answer"]
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertFalse(payload["evidence_available"])
        self.assertIn("DESTRUCTIVE_OPERATION", answer)
        self.assertIn("retrieved session evidence", answer)
        self.assertNotIn("sudo", answer)
        self.assertNotIn("chmod", answer)
        self.assertEqual(provider.calls, [])

    def test_benign_session_not_in_privilege_escalation_response(self):
        provider = RecordingProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={"question": "Which sessions contain privilege escalation?"},
            )

        payload = response.json()
        self.assertNotIn(self.benign_session_id, payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_account_modification_response_structure(self):
        provider = RecordingProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={"question": "Find sessions with account modification."},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        answer = payload["answer"]
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("Sessions with ACCOUNT_MODIFICATION:", answer)
        self.assertIn(self.risky_session_id, answer)
        self.assertIn("- sudo useradd hacker123", answer)
        self.assertIn("- ACCOUNT_MODIFICATION / MEDIUM", answer)
        self.assertEqual(provider.calls, [])


if __name__ == "__main__":
    unittest.main()
