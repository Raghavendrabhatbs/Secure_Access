import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.main import app


class RiskRecordingLLMProvider:
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
        risk_commands = [
            command
            for command in evidence.get("commands", [])
            if command.get("risk_findings")
        ]
        if not risk_commands:
            return "No risk findings were identified in the retrieved session evidence."

        segments = []
        for command in risk_commands:
            finding_labels = [
                f"{finding['category']} ({finding['severity']})"
                for finding in command.get("risk_findings", [])
            ]
            segments.append(f"{command['command']}: {', '.join(finding_labels)}")
        return "Risk findings: " + "; ".join(segments) + "."


class ChatbotRiskIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def test_risk_questions_use_real_risk_findings(self):
        questions = [
            "Was anything risky executed in this session?",
            "Did this session contain privilege escalation?",
            "Were any dangerous commands executed?",
        ]

        for question in questions:
            provider = RiskRecordingLLMProvider()
            with self.subTest(question=question):
                with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
                    client = TestClient(app)
                    response = client.post(
                        "/chat/query",
                        json={
                            "question": question,
                            "session_id": self.risky_session_id,
                        },
                    )

                self.assertEqual(response.status_code, 200)
                payload = response.json()
                self.assertEqual(payload["intent"], "RISK_ANALYSIS")
                self.assertEqual(payload["retrieval_mode"], "llm")
                self.assertTrue(payload["evidence_available"])
                self.assertIn("sudo su -", payload["answer"])
                self.assertIn("PRIVILEGE_ESCALATION", payload["answer"])
                self.assertIn("sudo useradd hacker123", payload["answer"])
                self.assertIn("ACCOUNT_MODIFICATION", payload["answer"])
                self.assertIn("chmod 777 /etc/passwd", payload["answer"])
                self.assertIn("PERMISSION_MODIFICATION", payload["answer"])

                self.assertEqual(len(provider.calls), 1)
                llm_call = provider.calls[0]
                self.assertEqual(llm_call["intent"], "RISK_ANALYSIS")
                self.assertEqual(llm_call["evidence"]["session"]["session_id"], self.risky_session_id)
                risk_commands = {
                    command["command"]: [
                        (finding["category"], finding["severity"], finding["rule"])
                        for finding in command.get("risk_findings", [])
                    ]
                    for command in llm_call["evidence"]["commands"]
                }
                self.assertEqual(
                    risk_commands["sudo su -"],
                    [("PRIVILEGE_ESCALATION", "HIGH", "SUDO")],
                )
                self.assertEqual(
                    risk_commands["sudo useradd hacker123"],
                    [
                        ("PRIVILEGE_ESCALATION", "HIGH", "SUDO"),
                        ("ACCOUNT_MODIFICATION", "MEDIUM", "USERADD"),
                    ],
                )
                self.assertEqual(
                    risk_commands["chmod 777 /etc/passwd"],
                    [("PERMISSION_MODIFICATION", "HIGH", "CHMOD_777")],
                )

    def test_benign_session_does_not_fabricate_risk(self):
        provider = RiskRecordingLLMProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": f"Was anything risky executed in session {self.benign_session_id}?",
                    "session_id": self.benign_session_id,
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "RISK_ANALYSIS")
        self.assertEqual(payload["retrieval_mode"], "llm")
        self.assertTrue(payload["evidence_available"])
        self.assertEqual(
            payload["answer"],
            "No risk findings were identified in the retrieved session evidence.",
        )

        self.assertEqual(len(provider.calls), 1)
        llm_call = provider.calls[0]
        self.assertEqual(llm_call["intent"], "RISK_ANALYSIS")
        self.assertEqual(llm_call["evidence"]["session"]["session_id"], self.benign_session_id)
        benign_commands = {command["command"]: command for command in llm_call["evidence"]["commands"]}
        self.assertIn("whoami", benign_commands)
        self.assertEqual(benign_commands["whoami"]["risk_findings"], [])


if __name__ == "__main__":
    unittest.main()
