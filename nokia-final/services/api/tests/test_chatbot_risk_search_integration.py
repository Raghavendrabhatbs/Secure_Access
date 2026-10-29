import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.main import app


class RecordingRiskSearchProvider:
    def __init__(self):
        self.calls = []

    def generate(self, question: str, intent: str, evidence: dict):
        self.calls.append(
            {
                "question": question,
                "intent": intent,
                "evidence": evidence,
            }
        )
        return "provider should not be used for explicit risk-category searches"


class ChatbotRiskSearchIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def test_privilege_escalation_question_uses_risk_filter(self):
        provider = RecordingRiskSearchProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": "Which sessions contain privilege escalation?",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "SESSION_SEARCH")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertTrue(payload["evidence_available"])
        self.assertIn(self.risky_session_id, payload["answer"])
        self.assertIn("Risk: HIGH", payload["answer"])
        self.assertIn("PRIVILEGE_ESCALATION", payload["answer"])
        self.assertIn("sudo su -", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_permission_modification_question_uses_risk_filter(self):
        provider = RecordingRiskSearchProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": "Show sessions with permission modification.",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "SESSION_SEARCH")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertTrue(payload["evidence_available"])
        self.assertIn(self.risky_session_id, payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])
        self.assertIn("PERMISSION_MODIFICATION", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_account_modification_question_uses_risk_filter(self):
        provider = RecordingRiskSearchProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": "Find sessions with account modification.",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "SESSION_SEARCH")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertTrue(payload["evidence_available"])
        self.assertIn(self.risky_session_id, payload["answer"])
        self.assertIn("sudo useradd hacker123", payload["answer"])
        self.assertIn("ACCOUNT_MODIFICATION", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_no_match_risk_category_returns_empty_result(self):
        provider = RecordingRiskSearchProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": "Which sessions contain destructive operation?",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "SESSION_SEARCH")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertFalse(payload["evidence_available"])
        self.assertIn("DESTRUCTIVE_OPERATION", payload["answer"])
        self.assertIn("retrieved session evidence", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_benign_session_is_not_returned_for_risk_category_query(self):
        provider = RecordingRiskSearchProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": "Which sessions contain privilege escalation?",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertNotIn(self.benign_session_id, payload["answer"])
        self.assertEqual(provider.calls, [])


if __name__ == "__main__":
    unittest.main()
