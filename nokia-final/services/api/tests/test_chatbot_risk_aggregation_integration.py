import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.main import app


class RecordingRiskSummaryLLMProvider:
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

        risk_summary = evidence.get("risk_summary", {})
        categories = risk_summary.get("categories", [])
        categories_text = ", ".join(categories) if categories else "None"

        return (
            "Session Risk Summary: "
            f"Overall severity: {risk_summary.get('overall_severity', 'NONE')}. "
            f"Finding count: {risk_summary.get('finding_count', 0)}. "
            f"High: {risk_summary.get('high_count', 0)}. "
            f"Medium: {risk_summary.get('medium_count', 0)}. "
            f"Low: {risk_summary.get('low_count', 0)}. "
            f"Categories: {categories_text}."
        )


class ChatbotRiskAggregationIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def test_risky_session_exposes_aggregated_risk_summary(self):
        provider = RecordingRiskSummaryLLMProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": "What is the overall risk level of this SSH session?",
                    "session_id": self.risky_session_id,
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
        self.assertIn("PRIVILEGE_ESCALATION", payload["answer"])
        self.assertIn("ACCOUNT_MODIFICATION", payload["answer"])
        self.assertIn("PERMISSION_MODIFICATION", payload["answer"])
        self.assertIn("Risky commands:", payload["answer"])
        self.assertIn("sudo su -", payload["answer"])
        self.assertIn("sudo useradd hacker123", payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_benign_session_exposes_none_risk_summary(self):
        provider = RecordingRiskSummaryLLMProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": "What is the overall risk level of this SSH session?",
                    "session_id": self.benign_session_id,
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "RISK_ANALYSIS")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertTrue(payload["evidence_available"])
        self.assertIn("Overall risk: NONE", payload["answer"])
        self.assertIn(
            "No risk findings were identified in the retrieved session evidence.",
            payload["answer"],
        )
        self.assertEqual(provider.calls, [])


if __name__ == "__main__":
    unittest.main()
