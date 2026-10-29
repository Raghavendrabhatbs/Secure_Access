import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.database import SessionLocal
from app.services.chatbot_service import ChatbotQueryService
from app.services.session_query_service import SessionQueryService


class ConversationFollowUpIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.sessions = SessionQueryService(self.db)
        self.chatbot = ChatbotQueryService(self.db, llm_provider=None)

        # Pick a session that has at least one command so follow-ups can resolve.
        self.session_id = None
        self.first_command = None
        self.second_command = None
        self.username = None
        for session in self.sessions.list_sessions(limit=25):
            session_identifier = session.session_id or session.unique_id
            commands = self.sessions.get_command_evidence(session_identifier)
            named = [item for item in commands if item.command]
            if len(named) >= 2:
                self.session_id = session_identifier
                self.first_command = named[0].command
                self.second_command = named[1].command
                self.username = session.username or "unknown"
                break
        if self.session_id is None:
            self.skipTest("No session with 2+ commands available for follow-up tests")

    def tearDown(self):
        self.db.close()

    def test_when_followup_returns_execution_time(self):
        result = self.chatbot.answer_question(
            "when was it executed?",
            session_id=self.session_id,
            resolved_command=self.first_command,
            followup_type="when",
        )
        self.assertEqual(result["intent"], "COMMAND_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn(self.session_id, result["answer"])
        self.assertIn(self.first_command, result["answer"])
        self.assertIn(" at ", result["answer"])
        self.assertIn("UTC", result["answer"])

    def test_who_followup_returns_username(self):
        result = self.chatbot.answer_question(
            "who executed it?",
            session_id=self.session_id,
            resolved_command=self.first_command,
            followup_type="who",
        )
        self.assertEqual(result["intent"], "SESSION_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertIn(self.username, result["answer"])
        self.assertIn(self.session_id, result["answer"])

    def test_risk_followup_returns_severity(self):
        result = self.chatbot.answer_question(
            "was that risky?",
            session_id=self.session_id,
            followup_type="risk",
        )
        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertIn(self.session_id, result["answer"])
        self.assertTrue(
            any(level in result["answer"] for level in ("HIGH", "MEDIUM", "LOW", "no risk findings"))
        )

    def test_after_followup_returns_adjacent_command(self):
        result = self.chatbot.answer_question(
            "what happened after it?",
            session_id=self.session_id,
            resolved_command=self.first_command,
            followup_type="after",
        )
        self.assertEqual(result["intent"], "COMMAND_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertIn(self.first_command, result["answer"])
        self.assertIn(self.session_id, result["answer"])

    def test_where_followup_returns_host(self):
        result = self.chatbot.answer_question(
            "where did it run?",
            session_id=self.session_id,
            followup_type="where",
        )
        self.assertEqual(result["intent"], "SESSION_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertIn("host:", result["answer"])
        self.assertIn(self.session_id, result["answer"])

    def test_followup_with_missing_context_falls_through(self):
        result = self.chatbot.answer_question(
            "was it risky?",
            session_id=None,
            resolved_command=None,
            followup_type="risk",
        )
        # Without a session/command anchor the follow-up handler should not fire;
        # the answer should not incorrectly claim severity for a non-existent session.
        self.assertNotIn("Session `None`", result["answer"])


if __name__ == "__main__":
    unittest.main()
