import sys
from pathlib import Path
import unittest
from datetime import date
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.database import SessionLocal
from app.services.analytics_query_service import AnalyticsQueryService
from app.services.chatbot_service import ChatbotQueryService
from app.services.phase1_query_service import Phase1QueryService
from app.services.risk_classifier import classify_command_risks
from app.services.session_query_service import SessionQueryService


class Phase1AnalyticsTest(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.sessions = SessionQueryService(self.db)
        self.analytics = AnalyticsQueryService(self.sessions)
        self.phase1 = Phase1QueryService(self.sessions)
        self.chatbot = ChatbotQueryService(self.db, llm_provider=None)

    def tearDown(self):
        self.db.close()

    def test_extended_risk_rules(self):
        self.assertTrue(any(f.rule == "HISTORY_CLEAR" for f in classify_command_risks("history -c")))
        self.assertTrue(any(f.rule == "NETWORK_TRANSFER" for f in classify_command_risks("wget http://example.com/x")))
        self.assertTrue(any(f.rule == "ETC_PASSWD" for f in classify_command_risks("cat /etc/passwd")))

    def test_daily_summary_for_known_date(self):
        summary = self.analytics.build_daily_summary(date(2026, 8, 20))
        self.assertGreater(summary.session_count, 0)
        self.assertIn("admin", summary.users)

    def test_last_n_users(self):
        records = self.analytics.last_n_users(limit=3)
        self.assertGreaterEqual(len(records), 1)

    def test_command_frequency(self):
        frequencies = self.analytics.command_frequency_between(date(2026, 8, 20), date(2026, 8, 20), limit=5)
        self.assertGreater(len(frequencies), 0)

    def test_phase1_session_count_question(self):
        result = self.phase1.try_answer("How many sessions were there on 2026-08-20?")
        self.assertIsNotNone(result)
        self.assertEqual(result["intent"], "SESSION_COUNT")
        self.assertTrue(result["evidence_available"])

    def test_requested_period_and_timing_phrasings_are_deterministic(self):
        cases = (
            ("Show me sessions from this week", "SESSION_LOOKUP", "Sessions for"),
            ("Show me login and logout times for today", "SESSION_TIMING", "sessions on"),
            ("Peak hour login", "CROSS_SESSION_ANALYSIS", "Peak login hour"),
            ("Which hour has the most SSH activity?", "CROSS_SESSION_ANALYSIS", "busiest hour"),
        )

        with patch("app.services.query_understanding_service.configured_today", return_value=date(2026, 8, 20)), patch(
            "app.services.phase1_query_service.configured_today", return_value=date(2026, 8, 20)
        ):
            for question, intent, answer_text in cases:
                with self.subTest(question=question):
                    result = self.chatbot.answer_question(question)
                    self.assertEqual(result["intent"], intent)
                    self.assertIn(answer_text.lower(), result["answer"].lower())

    def test_high_risk_listing_honors_requested_period(self):
        result = self.chatbot.answer_question("Show all high risk sessions on 2026-08-20")

        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertIn("2026-08-20", result["answer"])

    def test_user_session_analytics_are_not_admin_only(self):
        result = self.chatbot.answer_question("How many total sessions does alice have?")

        self.assertEqual(result["intent"], "SESSION_COUNT")
        self.assertIn("alice", result["answer"].lower())

    def test_requested_ssh_analytics_catalogue_uses_grounded_routes(self):
        questions = (
            "How many total sessions are there?",
            "How many sessions happened today?",
            "How many sessions happened yesterday?",
            "How many sessions happened this week?",
            "How many sessions happened on August 20?",
            "Which date had the most sessions?",
            "How many sessions are active right now?",
            "How many sessions are inactive?",
            "Show active and inactive session count",
            "Show me sessions from this week",
            "Show me the most recent session",
            "How many sessions were executed by admin datewise?",
            "How many total sessions does admin have?",
            "Who accessed the system today?",
            "Who accessed the system yesterday?",
            "Who accessed the system on August 20?",
            "Who is currently logged in?",
            "Who logged in last?",
            "What time did admin log in today?",
            "Show me login and logout times for today",
            "Which session was the longest?",
            "Which session was the shortest?",
            "What is the average session duration?",
            "Were there any high risk sessions today?",
            "Were there any high risk sessions this week?",
            "Show all high risk sessions",
            "Were there any privilege escalation attempts?",
            "Was there any log tampering?",
            "Did anyone clear their history?",
            "Did anyone try to cover their tracks?",
            "What is the most dangerous command ever run?",
            "Which session had the most risk?",
            "Compare today with yesterday",
            "Which hour has the most SSH activity?",
            "What exact time did admin log in on August 20?",
            "First command admin ran after login today",
            "Last command before logout",
            "How many times was sudo used this week?",
            "Was any sensitive file accessed?",
            "Which admin session is most suspicious?",
            "What does admin typically do when they log in?",
            "Has admin ever logged in after midnight?",
            "Peak login hour",
        )

        with patch("app.services.query_understanding_service.configured_today", return_value=date(2026, 8, 20)), patch(
            "app.services.phase1_query_service.configured_today", return_value=date(2026, 8, 20)
        ):
            for question in questions:
                with self.subTest(question=question):
                    result = self.chatbot.answer_question(question)
                    self.assertNotIn(result["intent"], {"UNKNOWN", "GENERAL_KNOWLEDGE"})
                    self.assertEqual(result["retrieval_mode"], "rule-based")
                    self.assertNotIn("couldn't retrieve session evidence", result["answer"].lower())

    def test_phase1_daily_summary_question(self):
        result = self.chatbot.answer_question("Summarize what happened on 2026-08-20")
        self.assertEqual(result["intent"], "SESSION_SUMMARY")
        self.assertTrue(result["evidence_available"])
        self.assertIn("2026-08-20", result["answer"])

    def test_commands_for_iso_date_are_not_treated_as_hour_window(self):
        result = self.chatbot.answer_question("What all commands were executed on 2026-08-20?")

        self.assertEqual(result["intent"], "COMMAND_SEARCH")
        self.assertTrue(result["evidence_available"])
        self.assertIn("whoami", result["answer"])
        self.assertIn("hostname", result["answer"])
        self.assertNotIn("hour window", result["evidence_summary"])

    def test_phase1_sudo_on_date_question(self):
        result = self.chatbot.answer_question("Did anyone run sudo on 2026-08-20?")
        self.assertEqual(result["intent"], "COMMAND_LOOKUP")
        self.assertTrue(result["evidence_available"])
        self.assertIn("sudo", result["answer"].lower())

    def test_phase1_command_run_recently_question(self):
        result = self.chatbot.answer_question("Was history -c command run recently?")
        self.assertEqual(result["intent"], "COMMAND_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("history -c", result["answer"].lower())
        self.assertTrue(result["answer"].lower().startswith("yes,"))
        self.assertNotIn("Retrieved 20 session(s)", result["answer"])
        self.assertEqual(result["answer"].count("history -c"), 1)

    def test_find_command_usages_recent_deduplicates(self):
        usages = self.analytics.find_command_usages_recent("history -c")
        keys = {
            (
                session.session_id or session.unique_id,
                item.executed_at.isoformat() if item.executed_at else None,
                (item.command or "").strip().lower(),
            )
            for session, item in usages
        }
        self.assertEqual(len(keys), len(usages))

    def test_all_commands_frequency_question(self):
        result = self.chatbot.answer_question(
            "there are overall 63 sessions right so which all commands where executed how many times?"
        )
        self.assertEqual(result["intent"], "COMMAND_SEARCH")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Across", result["answer"])
        self.assertIn("time(s)", result["answer"])
        self.assertNotIn("most recent SSH session", result["answer"])

    def test_latest_session_risk_finding_question(self):
        result = self.chatbot.answer_question("what is the one risk finding in latest session?")
        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("PRIVILEGE_ESCALATION", result["answer"])
        self.assertNotIn("no risk finding", result["answer"].lower())

    def test_important_sessions_question(self):
        result = self.chatbot.answer_question("important sessions")
        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("risk findings", result["answer"].lower())
        self.assertNotIn("couldn't retrieve command evidence", result["answer"].lower())

    def test_important_sessions_with_date_question(self):
        result = self.chatbot.answer_question("give me all important sessions with their date")
        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Conducted on", result["answer"])
        self.assertIn("at ", result["answer"])
        self.assertIn("host:", result["answer"])
        self.assertIn("risk findings", result["answer"].lower())
        self.assertNotIn("Sessions with dates (", result["answer"])

    def test_phase1_last_users_question(self):
        result = self.chatbot.answer_question("Who were the last 3 users to log in?")
        self.assertEqual(result["intent"], "TEMPORAL_ACCESS")
        self.assertTrue(result["evidence_available"])

    def test_sessions_with_dates_question(self):
        result = self.chatbot.answer_question("Give me the sessions with date")
        self.assertEqual(result["intent"], "SESSION_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Sessions with dates", result["answer"])
        self.assertIn("2026-08-", result["answer"])
        self.assertNotIn("couldn't retrieve command evidence", result["answer"].lower())

    def test_admin_sessions_by_date_question(self):
        result = self.chatbot.answer_question("List the sessions executed by the admin date wise")
        self.assertEqual(result["intent"], "SESSION_LOOKUP")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Admin sessions by date", result["answer"])
        self.assertIn("admin", result["answer"].lower())
        self.assertIn("2026-08-20", result["answer"])

    def test_admin_session_count_by_date_includes_session_ids(self):
        result = self.chatbot.answer_question("How many sessions were executed by admin date wise?")
        self.assertEqual(result["intent"], "SESSION_COUNT")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Session IDs:", result["answer"])
        self.assertIn("79a6a8f5-4e28-4a1d-8e85-2df716113d8b", result["answer"])

        count_result = self.chatbot.answer_question("How many sessions were executed by admin datewise?")
        self.assertEqual(count_result["intent"], "SESSION_COUNT")
        self.assertIn("total", count_result["answer"].lower())
        self.assertIn("session(s)", count_result["answer"])

    def test_remaining_sessions_are_grouped_by_other_users(self):
        result = self.chatbot.answer_question(
            "admin has 67 sessions right? rest 11 sessions are executed by whom?"
        )
        self.assertEqual(result["intent"], "CROSS_SESSION_ANALYSIS")
        self.assertTrue(result["evidence_available"])
        self.assertIn("remaining", result["answer"])
        self.assertNotIn("No matching SSH session evidence", result["answer"])

    def test_last_login_question_returns_latest_user_and_time(self):
        result = self.chatbot.answer_question("Who logged in last?")
        self.assertEqual(result["intent"], "TEMPORAL_ACCESS")
        self.assertTrue(result["evidence_available"])
        self.assertIn("last login was by", result["answer"].lower())
        self.assertIn("session", result["answer"].lower())

    def test_privilege_escalation_presence_question_is_risk_analysis(self):
        result = self.chatbot.answer_question("Were there any privilege escalation attempts?")
        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertTrue(result["evidence_available"])
        self.assertIn("privilege escalation", result["answer"].lower())

    def test_misspelled_privilege_escalation_is_still_risk_analysis(self):
        result = self.chatbot.answer_question("Were there any privilage escalation attempts?")
        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertTrue(result["evidence_available"])
        self.assertIn("privilege escalation", result["answer"].lower())

    def test_most_dangerous_command_searches_recorded_sessions(self):
        result = self.chatbot.answer_question("What is the most dangerous command ever seen?")
        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Most dangerous command ever run", result["answer"])
        self.assertIn("Session:", result["answer"])

    def test_highest_risk_session_question_is_risk_analysis(self):
        result = self.chatbot.answer_question("Which session had the most risk?")
        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertTrue(result["evidence_available"])
        self.assertIn("highest-risk session", result["answer"])

    def test_longest_session_uses_recorded_timestamps_when_duration_is_missing(self):
        result = self.chatbot.answer_question("Which session was the longest?")
        self.assertEqual(result["intent"], "SESSION_STATS")
        self.assertTrue(result["evidence_available"])
        self.assertNotIn("Duration: 0s", result["answer"])
        self.assertRegex(result["answer"], r"Duration: (?:\d+h )?\d+m \d+s")

    def test_longest_session_requires_recorded_commands(self):
        result = self.chatbot.answer_question("Which session was the longest?")
        session_id = result["answer"].split("- Session: ", 1)[-1]
        session = self.sessions.get_session(session_id)
        self.assertIsNotNone(session)
        self.assertGreater(len(self.sessions.get_command_evidence(session_id)), 0)

    def test_admin_today_login_window_question(self):
        with patch("app.services.phase1_query_service.configured_today", return_value=date(2026, 8, 20)):
            result = self.chatbot.answer_question(
                "From what time to what time did the admin make sessions or log in today?"
            )
        self.assertEqual(result["intent"], "TEMPORAL_ACCESS")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Admin login/session times for today", result["answer"])
        self.assertIn("Overall:", result["answer"])
        self.assertIn("2026-08-20T", result["answer"])

    def test_dates_of_sessions_question(self):
        result = self.chatbot.answer_question("dates of the sessions")
        self.assertEqual(result["intent"], "SESSION_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Sessions with dates", result["answer"])
        self.assertIn("|", result["answer"])

    def test_session_date_lookup_by_id(self):
        sessions = self.sessions.list_sessions(limit=1)
        self.assertGreater(len(sessions), 0)
        session_id = sessions[0].session_id or sessions[0].unique_id
        result = self.chatbot.answer_question(f"when was session {session_id} executed?")
        self.assertEqual(result["intent"], "SESSION_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn(session_id, result["answer"])
        self.assertIn("executed on", result["answer"].lower())
        self.assertIn("2026-08-", result["answer"])

    def test_give_all_session_ids_lists_uuids(self):
        result = self.chatbot.answer_question("give me all 63 available sessions id")
        self.assertEqual(result["intent"], "SESSION_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Session IDs (", result["answer"])
        # The answer should contain at least one UUID, not just a single command like 'id'.
        import re

        uuid_pattern = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        self.assertIsNotNone(uuid_pattern.search(result["answer"]))
        self.assertNotIn("The matching commands were:", result["answer"])
        self.assertNotIn("couldn't retrieve", result["answer"].lower())

    def test_list_all_session_ids_short_query(self):
        result = self.chatbot.answer_question("list all session ids")
        self.assertEqual(result["intent"], "SESSION_LOOKUP")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Session IDs (", result["answer"])

    def test_session_id_listing_ignores_definitional_question(self):
        result = self.chatbot.answer_question("what is a session id")
        # This is a definitional question — should NOT be a listing.
        self.assertNotIn("Session IDs (", result["answer"])

    def test_risky_session_count_question_is_concise(self):
        result = self.chatbot.answer_question("How many risky sessions?")
        self.assertEqual(result["intent"], "SESSION_COUNT")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        # A count answer should be one short line, not a full risky-session listing.
        self.assertEqual(result["answer"].count("\n"), 0)
        self.assertNotIn("Risky commands:", result["answer"])
        self.assertIn("session(s)", result["answer"])

    def test_session_id_command_list_with_here(self):
        result = self.chatbot.answer_question(
            "f331c40a-c366-464c-ad60-2001c01d517e what all commands were executed here list them"
        )
        self.assertEqual(result["intent"], "COMMAND_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("f331c40a-c366-464c-ad60-2001c01d517e", result["answer"])
        self.assertIn("Commands executed", result["answer"])
        self.assertNotIn("Across 63 SSH session(s)", result["answer"])
        self.assertNotIn("couldn't retrieve command evidence", result["answer"].lower())


if __name__ == "__main__":
    unittest.main()
