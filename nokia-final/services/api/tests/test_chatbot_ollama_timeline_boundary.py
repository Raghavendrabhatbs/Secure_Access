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
        return "provider boundary captured"


class ChatbotOllamaTimelineBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def _ask(self, question: str, session_id: str):
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
        payload = response.json()
        self.assertEqual(payload["retrieval_mode"], "llm")
        self.assertEqual(len(provider.calls), 1)
        return payload, provider.calls[0]["evidence"]

    def test_provider_receives_timeline_and_analysis_for_risky_session(self):
        _, evidence = self._ask(
            "Please explain the suspicious behavior in this SSH session.",
            self.risky_session_id,
        )

        self.assertIn("session", evidence)
        self.assertIn("commands", evidence)
        self.assertIn("events", evidence)
        self.assertIn("risk_summary", evidence)
        self.assertIn("timeline", evidence)
        self.assertIn("timeline_analysis", evidence)

        self.assertTrue(evidence["timeline"])
        self.assertEqual(evidence["timeline_analysis"]["overall_severity"], "HIGH")

    def test_provider_receives_expected_risky_command_facts(self):
        _, evidence = self._ask(
            "Summarize what looks suspicious in this session.",
            self.risky_session_id,
        )

        commands = [
            item.get("command")
            for item in evidence.get("timeline", [])
            if item.get("event_type") == "COMMAND"
        ]

        self.assertIn("sudo su -", commands)
        self.assertIn("sudo useradd hacker123", commands)
        self.assertIn("chmod 777 /etc/passwd", commands)

    def test_provider_receives_expected_risky_findings(self):
        _, evidence = self._ask(
            "Explain why this session appears risky.",
            self.risky_session_id,
        )

        timeline = evidence.get("timeline", [])
        labels = {
            (finding.get("category"), finding.get("severity"))
            for entry in timeline
            for finding in entry.get("risk_findings", [])
        }

        self.assertIn(("PRIVILEGE_ESCALATION", "HIGH"), labels)
        self.assertIn(("ACCOUNT_MODIFICATION", "MEDIUM"), labels)
        self.assertIn(("PERMISSION_MODIFICATION", "HIGH"), labels)

    def test_provider_receives_analysis_counts_and_categories(self):
        _, evidence = self._ask(
            "Provide a technical explanation of what happened.",
            self.risky_session_id,
        )

        analysis = evidence["timeline_analysis"]
        self.assertEqual(analysis["overall_severity"], "HIGH")
        self.assertGreaterEqual(analysis["entry_count"], analysis["command_count"])
        self.assertIn("PRIVILEGE_ESCALATION", analysis["risk_categories"])
        self.assertIn("ACCOUNT_MODIFICATION", analysis["risk_categories"])
        self.assertIn("PERMISSION_MODIFICATION", analysis["risk_categories"])

        risk_summary = evidence["risk_summary"]
        self.assertEqual(risk_summary["overall_severity"], "HIGH")
        self.assertEqual(risk_summary["high_count"], 3)
        self.assertEqual(risk_summary["medium_count"], 1)

    def test_provider_receives_benign_none_risk_without_fabrication(self):
        _, evidence = self._ask(
            "Provide a technical explanation of what happened.",
            self.benign_session_id,
        )

        analysis = evidence["timeline_analysis"]
        self.assertEqual(analysis["overall_severity"], "NONE")
        self.assertEqual(analysis["high_count"], 0)
        self.assertEqual(analysis["medium_count"], 0)
        self.assertEqual(analysis["low_count"], 0)

        for entry in evidence.get("timeline", []):
            if entry.get("event_type") == "COMMAND":
                self.assertEqual(entry.get("risk_findings", []), [])


if __name__ == "__main__":
    unittest.main()
