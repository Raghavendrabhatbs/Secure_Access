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
        self.calls.append(
            {
                "question": question,
                "intent": intent,
                "evidence": evidence,
            }
        )
        return "provider should not be used for deterministic risk responses"


class ChatbotRiskResponseIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"

    def test_overall_risk_level_uses_deterministic_risk_response(self):
        provider = RecordingProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": "What is the overall risk level of this SSH session?",
                    "session_id": self.session_id,
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "RISK_ANALYSIS")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertTrue(payload["evidence_available"])
        self.assertIn("Overall risk: HIGH", payload["answer"])
        self.assertIn("Findings: 4", payload["answer"])
        self.assertIn("HIGH: 3", payload["answer"])
        self.assertIn("MEDIUM: 1", payload["answer"])
        self.assertIn("LOW: 0", payload["answer"])
        self.assertIn("Risk categories:", payload["answer"])
        self.assertIn("- ACCOUNT_MODIFICATION", payload["answer"])
        self.assertIn("- PERMISSION_MODIFICATION", payload["answer"])
        self.assertIn("- PRIVILEGE_ESCALATION", payload["answer"])
        self.assertIn("Risky commands:", payload["answer"])
        self.assertIn("- sudo su -: PRIVILEGE_ESCALATION (HIGH)", payload["answer"])
        self.assertIn(
            "- sudo useradd hacker123: PRIVILEGE_ESCALATION (HIGH), ACCOUNT_MODIFICATION (MEDIUM)",
            payload["answer"],
        )
        self.assertIn("- chmod 777 /etc/passwd: PERMISSION_MODIFICATION (HIGH)", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_why_question_uses_deterministic_risk_response(self):
        provider = RecordingProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": "Why is this session high risk?",
                    "session_id": self.session_id,
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "RISK_ANALYSIS")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertTrue(payload["evidence_available"])
        self.assertIn("Overall risk: HIGH", payload["answer"])
        self.assertIn("Findings: 4", payload["answer"])
        self.assertIn("Risky commands:", payload["answer"])
        self.assertIn("sudo su -", payload["answer"])
        self.assertIn("sudo useradd hacker123", payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])
        self.assertEqual(provider.calls, [])


if __name__ == "__main__":
    unittest.main()
