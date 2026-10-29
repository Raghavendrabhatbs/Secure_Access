import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.core.assistant_auth import AssistantUser, require_assistant_user
from app.db.database import get_db
from app.main import app


class FakeChatbotQueryService:
    def __init__(self):
        self.calls = []

    def answer_question(self, question, session_id=None, **_kwargs):
        self.calls.append(question)
        if session_id == "session-1":
            return {
                "answer": "I couldn't retrieve session evidence to answer that question.",
                "intent": "COMMAND_LOOKUP",
                "retrieval_mode": "rule-based",
                "session_id": session_id,
                "evidence_available": False,
                "evidence_summary": "Session session-1 was not found in the database.",
            }
        if question.lower() == "system status":
            return {
                "answer": "System Status: PostgreSQL connected.",
                "intent": "SYSTEM_STATUS",
                "retrieval_mode": "rule-based",
                "evidence_available": True,
                "evidence_summary": "System health status checked.",
            }
        if question.lower() == "when was it accessed?":
            return {
                "answer": "Access was recorded at 09:00 UTC.",
                "intent": "TEMPORAL_ACCESS",
                "retrieval_mode": "rule-based",
                "evidence_available": True,
                "evidence_summary": "Retrieved session access time.",
            }
        return {
            "answer": "There are 0 unique session(s).",
            "intent": "SESSION_COUNT",
            "retrieval_mode": "rule-based",
            "evidence_available": False,
            "evidence_summary": "Counted 0 unique session(s).",
        }


class ChatbotQueryApiTest(unittest.TestCase):
    def setUp(self):
        def override_get_db():
            yield {"fake": True}

        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[require_assistant_user] = lambda: AssistantUser("test-analyst", "admin")
        self.service = FakeChatbotQueryService()
        self.service_patch = patch("app.api.routes.ChatbotQueryService", return_value=self.service)
        self.service_patch.start()

    def tearDown(self):
        self.service_patch.stop()
        app.dependency_overrides.clear()

    def test_chat_query_returns_grounded_answer(self):
        client = TestClient(app)
        response = client.post(
            "/chat/query",
            json={"question": "What commands were used in session session-1?", "session_id": "session-1"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["session_id"], "session-1")
        self.assertEqual(payload["intent"], "COMMAND_LOOKUP")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertFalse(payload["evidence_available"])
        self.assertIn("couldn't retrieve session evidence", payload["answer"])
        self.assertEqual(len(self.service.calls), 1)

    def test_chat_query_accepts_message_alias_and_returns_mode(self):
        client = TestClient(app)
        response = client.post(
            "/chat/query",
            json={"message": "How many SSH sessions are there?"},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertEqual(payload["mode"], "rule-based")
        self.assertIn("answer", payload)

    def test_blank_question_falls_back_to_valid_message(self):
        response = TestClient(app).post(
            "/chat/query",
            json={"question": "   ", "message": "system status"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("system status", self.service.calls[-1].lower())

    def test_chat_query_status_is_deterministic(self):
        client = TestClient(app)
        response = client.post("/chat/query", json={"question": "system status"})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "SYSTEM_STATUS")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("System Status", payload["answer"])
        self.assertEqual(payload["evidence_summary"], "System health status checked.")
        self.assertEqual(len(self.service.calls), 1)

    def test_chat_query_accepts_temporal_access_intent(self):
        response = TestClient(app).post(
            "/chat/query",
            json={"message": "When was it accessed?"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["intent"], "TEMPORAL_ACCESS")


if __name__ == "__main__":
    unittest.main()
