import sys
import types
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.main import app
from app.services.llm.ollama_provider import OllamaProvider


class FakeOllamaClient:
    prompts: list[str] = []

    def __init__(self, host: str | None = None):
        self.host = host

    def generate(self, model: str, prompt: str, stream: bool = False):
        self.__class__.prompts.append(prompt)

        if "Explain why this session was considered high risk." in prompt:
            return {
                "response": (
                    "This session is high risk because the retrieved session evidence "
                    "shows PRIVILEGE_ESCALATION / HIGH, ACCOUNT_MODIFICATION / MEDIUM, "
                    "and PERMISSION_MODIFICATION / HIGH."
                )
            }

        if "Summarize this SSH session." in prompt or "Summarize the last session." in prompt:
            return {
                "response": (
                    "The retrieved session evidence shows sudo su -, sudo useradd hacker123, "
                    "chmod 777 /etc/passwd, and history -c in chronological session activity."
                )
            }

        if "Analyze which commands were executed in this session." in prompt:
            return {
                "response": (
                    "The recorded commands in the retrieved session evidence are sudo su -, "
                    "sudo useradd hacker123, chmod 777 /etc/passwd, and history -c."
                )
            }

        if "Explain whether the user deleted the database." in prompt:
            return {
                "response": (
                    "The retrieved session evidence does not show a database deletion command."
                )
            }

        if "Explain whether the user restarted the server." in prompt:
            return {
                "response": (
                    "The retrieved session evidence does not show a server restart event or command."
                )
            }

        if "Explain the risk of this session." in prompt and '"overall_severity": "NONE"' in prompt:
            return {
                "response": (
                    "The retrieved session evidence shows overall severity NONE and no risk findings."
                )
            }

        return {"response": "The retrieved session evidence does not contain the requested information."}


class OllamaTimelineResponseTest(unittest.TestCase):
    def setUp(self):
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"
        FakeOllamaClient.prompts = []

    def _ask(self, question: str, session_id: str):
        fake_ollama_module = types.SimpleNamespace(Client=FakeOllamaClient)
        with patch.dict(sys.modules, {"ollama": fake_ollama_module}):
            with patch("app.services.chatbot_service.build_llm_provider", return_value=OllamaProvider()):
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
        self.assertTrue(FakeOllamaClient.prompts)
        return payload, FakeOllamaClient.prompts[-1]

    def test_high_risk_question_uses_grounded_ollama_response(self):
        payload, prompt = self._ask(
            "Explain why this session was considered high risk.",
            self.risky_session_id,
        )

        self.assertIn("PRIVILEGE_ESCALATION / HIGH", payload["answer"])
        self.assertIn("ACCOUNT_MODIFICATION / MEDIUM", payload["answer"])
        self.assertIn("PERMISSION_MODIFICATION / HIGH", payload["answer"])
        self.assertIn('"timeline_analysis"', prompt)

    def test_session_summary_question_uses_grounded_ollama_response(self):
        payload, prompt = self._ask("Summarize this SSH session.", self.risky_session_id)

        self.assertIn("sudo su -", payload["answer"])
        self.assertIn("sudo useradd hacker123", payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])
        self.assertIn('"timeline"', prompt)

    def test_last_session_summary_uses_grounded_ollama_response(self):
        payload, prompt = self._ask("Summarize the last session.", "")

        self.assertIn("sudo su -", payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])
        self.assertIn('"timeline"', prompt)
        self.assertIn("coherent chronological paragraph", prompt)

    def test_commands_question_mentions_only_recorded_commands(self):
        payload, prompt = self._ask(
            "Analyze which commands were executed in this session.",
            self.risky_session_id,
        )

        self.assertIn("sudo su -", payload["answer"])
        self.assertIn("sudo useradd hacker123", payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])
        self.assertNotIn("drop database", payload["answer"].lower())
        self.assertIn('"commands"', prompt)

    def test_negative_database_deletion_question_stays_grounded(self):
        payload, prompt = self._ask(
            "Explain whether the user deleted the database.",
            self.risky_session_id,
        )

        self.assertEqual(
            payload["answer"],
            "The retrieved session evidence does not show a database deletion command.",
        )
        self.assertIn("not present in the retrieved session evidence", prompt)

    def test_unknown_event_question_stays_grounded(self):
        payload, _ = self._ask(
            "Explain whether the user restarted the server.",
            self.risky_session_id,
        )

        self.assertEqual(
            payload["answer"],
            "The retrieved session evidence does not show a server restart event or command.",
        )

    def test_benign_session_risk_answer_does_not_fabricate_findings(self):
        payload, prompt = self._ask(
            "Explain the risk of this session.",
            self.benign_session_id,
        )

        self.assertIn("overall severity NONE", payload["answer"])
        self.assertIn("no risk findings", payload["answer"])
        self.assertIn('"overall_severity": "NONE"', prompt)
        self.assertNotIn("PRIVILEGE_ESCALATION / HIGH", payload["answer"])


if __name__ == "__main__":
    unittest.main()
