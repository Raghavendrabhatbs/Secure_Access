import sys
from pathlib import Path
import unittest
from datetime import date

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.database import SessionLocal
from app.services.analytics_query_service import AnalyticsQueryService
from app.services.chatbot_service import ChatbotQueryService
from app.services.phase2_query_service import Phase2QueryService
from app.services.query_understanding_service import extract_comparison_dates, extract_hour_range
from app.services.session_query_service import SessionQueryService


KNOWN_DATE = date(2026, 8, 20)
KNOWN_SESSION_ID = "79a6a8f5-4e28-4a1d-8e85-2df716113d8b"


class Phase2AnalyticsTest(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.sessions = SessionQueryService(self.db)
        self.analytics = AnalyticsQueryService(self.sessions)
        self.phase2 = Phase2QueryService(self.sessions)
        self.chatbot = ChatbotQueryService(self.db, llm_provider=None)

    def tearDown(self):
        self.db.close()

    def test_extract_hour_range(self):
        self.assertEqual(extract_hour_range("between 9am and 11am"), (9, 11))
        self.assertEqual(extract_hour_range("from 9:00 to 11:00 on 2026-08-20"), (9, 11))
        self.assertEqual(extract_hour_range("activity 12pm-1pm"), (12, 13))

    def test_extract_comparison_dates(self):
        today = date(2026, 8, 20)
        self.assertEqual(
            extract_comparison_dates("compare today vs yesterday", today=today),
            (today, date(2026, 8, 19)),
        )

    def test_hour_window_activity(self):
        result = self.phase2.try_answer(
            "What happened between 12pm and 1pm on 2026-08-20?"
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["intent"], "TEMPORAL_ACCESS")
        self.assertTrue(result["evidence_available"])

    def test_first_privilege_escalation_on_date(self):
        record = self.analytics.first_risk_finding_on_date(KNOWN_DATE, "PRIVILEGE_ESCALATION")
        self.assertIsNotNone(record)

        result = self.chatbot.answer_question(
            "When was the first privilege escalation on 2026-08-20?"
        )
        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertTrue(result["evidence_available"])
        self.assertIn("privilege escalation", result["answer"].lower())

    def test_most_dangerous_user_ranking(self):
        ranked = self.analytics.rank_users_by_risk(KNOWN_DATE, KNOWN_DATE, limit=5)
        self.assertGreaterEqual(len(ranked), 1)
        self.assertEqual(ranked[0].username, "admin")

        result = self.chatbot.answer_question("Who is the most dangerous user on 2026-08-20?")
        self.assertEqual(result["intent"], "CROSS_SESSION_ANALYSIS")
        self.assertTrue(result["evidence_available"])
        self.assertIn("admin", result["answer"])

    def test_step_by_step_walkthrough(self):
        result = self.chatbot.answer_question(
            f"Walk me through session {KNOWN_SESSION_ID} step by step"
        )
        self.assertEqual(result["intent"], "TIMELINE_QUERY")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Session timeline:", result["answer"])

    def test_compare_periods(self):
        comparison = self.analytics.compare_daily_summaries(KNOWN_DATE, date(2026, 8, 19))
        self.assertEqual(comparison.summary_a.session_count, 4)
        self.assertEqual(comparison.summary_b.session_count, 0)

        result = self.chatbot.answer_question("Compare 2026-08-20 vs yesterday")
        self.assertEqual(result["intent"], "CROSS_SESSION_ANALYSIS")
        self.assertTrue(result["evidence_available"])
        self.assertIn("2026-08-20", result["answer"])
        self.assertIn("2026-08-19", result["answer"])

    def test_first_command_after_login(self):
        result = self.chatbot.answer_question(
            f"What was the first command after login in session {KNOWN_SESSION_ID}?"
        )
        self.assertEqual(result["intent"], "COMMAND_LOOKUP")
        self.assertTrue(result["evidence_available"])
        self.assertIn(KNOWN_SESSION_ID, result["answer"])


if __name__ == "__main__":
    unittest.main()
