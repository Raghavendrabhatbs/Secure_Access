import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.main import app


class RecordingCrossSessionRiskProvider:
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
        matched_sessions = evidence.get("matched_sessions", [])
        if matched_sessions:
            first_session = matched_sessions[0]
            command_names = [
                command["command"]
                for command in first_session.get("matching_commands", [])
                if command.get("command")
            ]
            return (
                f"Matching session {first_session['session_id']} included commands: "
                f"{', '.join(command_names)}."
            )
        return "No matching sessions were identified."


class ChatbotCrossSessionRiskIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def test_privilege_escalation_session_search_is_deterministic(self):
        provider = RecordingCrossSessionRiskProvider()
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
        self.assertIn("sudo useradd hacker123", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_chmod_search_preserves_matching_command_evidence(self):
        provider = RecordingCrossSessionRiskProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": "Find sessions where chmod 777 was executed.",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "SESSION_SEARCH")
        self.assertEqual(payload["retrieval_mode"], "llm")
        self.assertTrue(payload["evidence_available"])
        self.assertIn(self.risky_session_id, payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])

        self.assertEqual(len(provider.calls), 1)
        llm_call = provider.calls[0]
        self.assertEqual(llm_call["intent"], "SESSION_SEARCH")
        self.assertEqual(llm_call["evidence"]["matched_sessions"][0]["session_id"], self.risky_session_id)
        self.assertEqual(
            [command["command"] for command in llm_call["evidence"]["matched_sessions"][0]["matching_commands"]],
            ["chmod 777 /etc/passwd"],
        )
        self.assertEqual(
            llm_call["evidence"]["matched_sessions"][0]["risk_summary"]["overall_severity"],
            "HIGH",
        )
        self.assertIn(
            "PERMISSION_MODIFICATION",
            [
                finding["category"]
                for finding in llm_call["evidence"]["matched_sessions"][0]["matching_commands"][0]["risk_findings"]
            ],
        )

    def test_harmless_activity_does_not_fabricate_risk(self):
        provider = RecordingCrossSessionRiskProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": "Which sessions contain harmless activity?",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "SESSION_SEARCH")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertFalse(payload["evidence_available"])
        self.assertNotIn("HIGH", payload["answer"])
        self.assertNotIn("MEDIUM", payload["answer"])
        self.assertNotIn("LOW", payload["answer"])
        self.assertEqual(provider.calls, [])


if __name__ == "__main__":
    unittest.main()
