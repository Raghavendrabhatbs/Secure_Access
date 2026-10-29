import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from datetime import date
from datetime import datetime, timezone
import os
from unittest.mock import patch

from app.services.chatbot_service import classify_chat_intent, extract_date_range
from app.services.query_understanding_service import QueryUnderstandingService, date_range_utc_bounds


class IntentRoutingTest(unittest.TestCase):
    def test_intent_matrix(self):
        cases = [
            ("What commands ran in session X?", "session-1", "COMMAND_LOOKUP"),
            ("Show me the timeline for session X", "session-1", "TIMELINE_SUMMARY"),
            ("What happened in session X?", "session-1", "SESSION_LOOKUP"),
            ("Was anything dangerous done?", None, "RISK_ANALYSIS"),
            ("Was this session risky?", "session-1", "RISK_ANALYSIS"),
            ("Find sessions where sudo was used", None, "SESSION_SEARCH"),
            ("Find sessions where chmod 777 was executed", None, "SESSION_SEARCH"),
            ("Which sessions modified /etc/passwd?", None, "SESSION_SEARCH"),
            ("Show sessions involving passwd and sudo", None, "SESSION_SEARCH"),
            ("Search sessions with useradd", None, "SESSION_SEARCH"),
            ("Across sessions, where was history -c used?", None, "SESSION_SEARCH"),
            ("What happened in sessions involving sudo?", None, "SESSION_SEARCH"),
            ("Show other sessions containing /etc/shadow", None, "SESSION_SEARCH"),
            ("Any sessions with wget?", None, "SESSION_SEARCH"),
            ("Find commands using useradd", None, "COMMAND_SEARCH"),
            ("Search for command output containing hostname", None, "COMMAND_SEARCH"),
            ("What were the sessions today?", None, "SESSION_LIST"),
            ("What were the sessions on 22-10-2026?", None, "SESSION_LIST"),
            ("Sessions till now", None, "SESSION_LIST"),
            ("What are the sessions performed till now?", None, "SESSION_LIST"),
            ("Show all SSH sessions", None, "SESSION_LIST"),
            ("Which sessions executed ip addr?", None, "SESSION_SEARCH"),
            ("What happened in the world today?", None, "CURRENT_EVENTS"),
            ("What cybersecurity events are coming up?", None, "UPCOMING_EVENTS"),
            ("What are the latest AI developments?", None, "CURRENT_EVENTS"),
            ("What technology events are scheduled next month?", None, "UPCOMING_EVENTS"),
            ("Show sessions and their latest commands", None, "SESSION_SEARCH"),
            ("What does grep do?", None, "COMMAND_EXPLANATION"),
            ("How does Kubernetes scheduling work?", None, "GENERAL_QUESTION"),
            ("What time is it now?", None, "CURRENT_WEATHER_OR_TIME"),
            ("Search event log for failed login", None, "EVENT_SEARCH"),
            ("Show all web recordings", None, "RECORDING_SEARCH"),
            ("When did this session start?", "session-1", "SESSION_LOOKUP"),
            ("Who used this session?", "session-1", "SESSION_LOOKUP"),
            ("Was sudo used in session X?", "session-1", "COMMAND_LOOKUP"),
            ("Show the events for session X", "session-1", "TIMELINE_SUMMARY"),
            ("", None, "UNKNOWN"),
        ]

        for question, session_id, expected_intent in cases:
            with self.subTest(question=question, session_id=session_id):
                self.assertEqual(
                    classify_chat_intent(question, session_id),
                    expected_intent,
                )

    def test_required_session_intelligence_questions_route_to_their_data_intent(self):
        session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        cases = [
            ("What sessions occurred today?", None, "SESSION_LIST"),
            ("Show yesterday's SSH sessions.", None, "SESSION_LIST"),
            ("What sessions were recorded on 22-10-2026?", None, "SESSION_LIST"),
            ("Show sessions between October 20 and October 24, 2026.", None, "SESSION_LIST"),
            ("What sessions have occurred so far today?", None, "SESSION_LIST"),
            ("How many sessions were recorded today?", None, "SESSION_COUNT"),
            ("Show all historical SSH sessions.", None, "SESSION_LIST"),
            ("Show all web sessions from yesterday.", None, "SESSION_LIST"),
            ("Which sessions executed `ip addr`?", None, "SESSION_SEARCH"),
            (f"Show the commands executed in session {session_id}.", None, "COMMAND_LOOKUP"),
            ("Which sessions have recordings?", None, "RECORDING_SEARCH"),
            ("Which sessions are currently active?", None, "USER_ACTIVITY"),
            ("Are any sessions scheduled for tomorrow?", None, "SESSION_LIST"),
            ("Compare today's sessions with yesterday's.", None, "SESSION_STATS"),
            ("Show all sessions for user alice.", None, "SESSION_LIST"),
            (f"Summarize session {session_id}.", None, "SESSION_LOOKUP"),
        ]

        for question, session, expected in cases:
            with self.subTest(question=question):
                self.assertEqual(classify_chat_intent(question, session), expected)

    def test_temporal_date_range_detection(self):
        today = date(2026, 8, 20)

        cases = [
            ("Who accessed today?", (date(2026, 8, 20), date(2026, 8, 20))),
            ("Who accessed yesterday?", (date(2026, 8, 19), date(2026, 8, 19))),
            ("Who accessed this week?", (date(2026, 8, 17), date(2026, 8, 20))),
            ("Who accessed on 2026-08-03?", (date(2026, 8, 3), date(2026, 8, 3))),
            ("What were the sessions on 22-10-2026?", (date(2026, 10, 22), date(2026, 10, 22))),
            ("Between 20-10-2026 and 24-10-2026, what sessions?", (date(2026, 10, 20), date(2026, 10, 24))),
            ("Who accessed on August 18?", (date(2026, 8, 18), date(2026, 8, 18))),
            ("Show sessions since 2026-08-03", (date(2026, 8, 3), date(2026, 8, 20))),
            ("How many SSH sessions are there?", None),
            ("What sessions were recorded on 22-10-2026?", (date(2026, 10, 22), date(2026, 10, 22))),
            (
                "Show sessions between October 20 and October 24, 2026.",
                (date(2026, 10, 20), date(2026, 10, 24)),
            ),
            (
                "Show sessions from 2026-10-20 to 2026-10-24.",
                (date(2026, 10, 20), date(2026, 10, 24)),
            ),
            ("Show all sessions from the previous day.", (date(2026, 8, 19), date(2026, 8, 19))),
            ("Show sessions from the previous week.", (date(2026, 8, 10), date(2026, 8, 16))),
            ("Show sessions from the current month.", (date(2026, 8, 1), date(2026, 8, 20))),
        ]

        for question, expected_range in cases:
            with self.subTest(question=question):
                self.assertEqual(extract_date_range(question, today=today), expected_range)

    def test_iso_date_is_not_parsed_as_hour_range(self):
        from app.services.query_understanding_service import extract_hour_range

        self.assertIsNone(extract_hour_range("what commands were executed on 2026-08-25?"))
        self.assertIsNone(extract_hour_range("what sessions were recorded on 22-10-2026?"))
        self.assertEqual(extract_hour_range("what activity occurred on 2026-08-25 between 9am and 11am?"), (9, 11))

    def test_local_date_bounds_respect_daylight_saving_transitions(self):
        with patch.dict(os.environ, {"CHATBOT_TIMEZONE": "America/New_York"}):
            spring_start, spring_end = date_range_utc_bounds(date(2026, 3, 8), date(2026, 3, 8))
            fall_start, fall_end = date_range_utc_bounds(date(2026, 11, 1), date(2026, 11, 1))

        self.assertEqual(spring_start, datetime(2026, 3, 8, 5, tzinfo=timezone.utc))
        self.assertEqual(spring_end, datetime(2026, 3, 9, 4, tzinfo=timezone.utc))
        self.assertEqual(fall_start, datetime(2026, 11, 1, 4, tzinfo=timezone.utc))
        self.assertEqual(fall_end, datetime(2026, 11, 2, 5, tzinfo=timezone.utc))

    def test_query_understanding_latest_ssh_session_and_generic_user(self):
        service = QueryUnderstandingService()

        latest_plan = service.understand("What happened in the latest SSH session?")
        self.assertEqual(latest_plan.scope, "latest_session")
        self.assertEqual(latest_plan.users, [])
        self.assertEqual(latest_plan.needs, {"sessions", "commands", "events"})

        recent_plan = service.understand(
            "recently which ssh session was done and list all the commands that were executed in it"
        )
        self.assertEqual(recent_plan.scope, "latest_session")
        self.assertIsNone(recent_plan.command)
        self.assertIn("commands", recent_plan.needs)
        self.assertTrue(recent_plan.requires_grounded_retrieval())

        generic_user_plan = service.understand("What did the user do before the risky command?")
        self.assertEqual(generic_user_plan.users, [])
        self.assertIn("commands", generic_user_plan.needs)
        self.assertIn("risk_findings", generic_user_plan.needs)

    def test_query_plans_cover_knowledge_and_precise_command_lookups(self):
        service = QueryUnderstandingService()

        explanation = service.understand("What does ls do?")
        self.assertEqual(explanation.query_type, "COMMAND_EXPLANATION")
        self.assertEqual(explanation.command, "ls")
        self.assertEqual(explanation.needs, set())

        timestamp = service.understand("At what time was hostname executed?")
        self.assertEqual(timestamp.query_type, "COMMAND_LOOKUP")
        self.assertEqual(timestamp.command, "hostname")
        self.assertEqual(timestamp.needs, {"sessions", "commands"})

        knowledge = service.understand("What is SSH?")
        self.assertEqual(knowledge.query_type, "COMMAND_EXPLANATION")
        self.assertEqual(knowledge.command, "SSH")

    def test_query_plans_cover_mixed_and_cross_session_questions(self):
        service = QueryUnderstandingService()

        mixed = service.understand("What does ls do, and did admin use it?")
        self.assertEqual(mixed.query_type, "MIXED_QUERY")
        self.assertEqual(mixed.command, "ls")
        self.assertTrue(mixed.requires_grounded_retrieval())

        cross_session = service.understand("Which user had the most high-risk activity?")
        self.assertEqual(cross_session.query_type, "CROSS_SESSION_ANALYSIS")
        self.assertTrue(cross_session.requires_grounded_retrieval())

        session_search = service.understand("Which sessions contain harmless activity?")
        self.assertEqual(session_search.query_type, "SESSION_SEARCH")

    def test_acceptance_plans_cover_command_timeline_and_comparison(self):
        service = QueryUnderstandingService()

        explanation = service.understand("Explain chmod 777.")
        self.assertEqual(explanation.query_type, "COMMAND_EXPLANATION")
        self.assertEqual(explanation.command, "chmod 777")
        self.assertFalse(explanation.requires_grounded_retrieval())

        before = service.understand("What happened before sudo su -?")
        self.assertEqual(before.query_type, "TIMELINE_QUERY")
        self.assertEqual(before.command, "sudo su -")
        self.assertTrue(before.requires_grounded_retrieval())

        comparison = service.understand("Compare the high-risk and normal sessions.")
        self.assertEqual(comparison.query_type, "CROSS_SESSION_ANALYSIS")
        self.assertTrue(comparison.requires_grounded_retrieval())


if __name__ == "__main__":
    unittest.main()
