import sys
from datetime import datetime, timezone
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.assistant_auth import AssistantUser, require_assistant_user
from app.db.database import get_db
from app.main import app
from app.services.unified_session_query_service import UnifiedSessionQueryService
from fastapi.testclient import TestClient


class UnifiedSessionQueryServiceTest(unittest.TestCase):
    def setUp(self):
        self.ssh_query = Mock()
        self.web_query = Mock()
        self.service = UnifiedSessionQueryService(self.ssh_query, self.web_query)
        self.ssh_query.list_all_sessions.return_value = [
            SimpleNamespace(
                protocol="SSH",
                session_type="SSH",
                session_id="ssh-current",
                unique_id="ssh-current",
                username="alice",
                target="linux-host",
                started_at=datetime(2026, 10, 24, 8, tzinfo=timezone.utc),
                login_time=None,
            )
        ]
        self.ssh_query.query_sessions.return_value = (
            self.ssh_query.list_all_sessions.return_value,
            1,
        )
        self.web_query.list_sessions.return_value = {
            "items": [
                {
                    "sessionId": "session-webcurrent",
                    "username": "alice",
                    "target": "web-host",
                    "startedAt": "2026-10-24T09:00:00Z",
                    "eventCount": 42,
                    "recordingStatus": "finalized",
                }
            ],
            "total": 1,
        }

    def test_overview_queries_cover_both_protocols_and_preserve_single_session_lookup(self):
        self.assertTrue(UnifiedSessionQueryService.should_answer("How many sessions are recorded?"))
        self.assertTrue(UnifiedSessionQueryService.should_answer("List SSH and web sessions"))
        self.assertTrue(UnifiedSessionQueryService.should_answer("What sessions occurred today?"))
        self.assertTrue(UnifiedSessionQueryService.should_answer("Show yesterday's SSH sessions"))
        self.assertTrue(UnifiedSessionQueryService.should_answer("Show all historical SSH sessions"))
        self.assertTrue(UnifiedSessionQueryService.should_answer("Which sessions have recordings?"))
        self.assertTrue(UnifiedSessionQueryService.should_answer("Which sessions are currently active?"))
        self.assertTrue(UnifiedSessionQueryService.should_answer("Are any sessions scheduled for tomorrow?"))
        self.assertFalse(UnifiedSessionQueryService.should_answer("Show the most recent session"))
        self.assertFalse(UnifiedSessionQueryService.should_answer("What commands did SSH users run?"))
        self.assertFalse(UnifiedSessionQueryService.should_answer("Which sessions executed ip addr?"))
        self.assertFalse(UnifiedSessionQueryService.should_answer("Show commands executed in session X"))

    def test_counts_and_lists_current_ssh_and_web_records(self):
        count = self.service.answer_question(
            "How many sessions are recorded?",
            AssistantUser("auditor", "auditor_viewer"),
        )
        self.assertIn("1 SSH session(s) and 1 web session(s) (2 total)", count["answer"])
        self.assertEqual(count["intent"], "SESSION_COUNT")

        listing = self.service.answer_question(
            "Show all SSH and web sessions",
            AssistantUser("auditor", "auditor_viewer"),
        )
        self.assertIn("[WEB] `session-webcurrent`", listing["answer"])
        self.assertIn("[SSH] `ssh-current`", listing["answer"])
        self.assertEqual(
            [item["protocol"] for item in listing["conversation_entities"]["sessions"]],
            ["WEB", "SSH"],
        )
        self.ssh_query.query_sessions.assert_called_with(
            limit=25,
            offset=0,
            username=None,
            target=None,
            protocol="SSH",
            start_date=None,
            end_date=None,
            active=None,
            has_recording=None,
            occurred_before=self.ssh_query.query_sessions.call_args.kwargs["occurred_before"],
        )
        self.web_query.list_sessions.assert_called_with(
            limit=25,
            offset=0,
            username=None,
            target=None,
            start_date=None,
            end_date=None,
            has_recording=None,
            occurred_before=self.web_query.list_sessions.call_args.kwargs["occurred_before"],
        )

    def test_developer_overview_is_scoped_and_reads_fresh_records_each_request(self):
        user = AssistantUser("alice", "developer")
        self.service.answer_question("How many sessions?", user)

        self.ssh_query.query_sessions.return_value = (
            self.ssh_query.list_all_sessions.return_value,
            1,
        )
        self.web_query.list_sessions.return_value = {
            "items": [
                {
                    "sessionId": "session-webfuture",
                    "username": "alice",
                    "target": "web-host",
                    "startedAt": "2026-10-24T11:00:00Z",
                    "eventCount": 1,
                }
            ],
            "total": 1,
        }
        answer = self.service.answer_question("How many sessions?", user)

        self.assertIn("1 SSH session(s) and 1 web session(s) (2 total)", answer["answer"])
        self.web_query.list_sessions.assert_called_with(
            limit=25,
            offset=0,
            username="alice",
            target=None,
            start_date=None,
            end_date=None,
            has_recording=None,
            occurred_before=self.web_query.list_sessions.call_args.kwargs["occurred_before"],
        )
        self.ssh_query.query_sessions.assert_called_with(
            limit=25,
            offset=0,
            username="alice",
            target=None,
            protocol="SSH",
            start_date=None,
            end_date=None,
            active=None,
            has_recording=None,
            occurred_before=self.ssh_query.query_sessions.call_args.kwargs["occurred_before"],
        )

    def test_scheduled_future_session_questions_do_not_invent_records(self):
        answer = self.service.answer_question(
            "Are any sessions scheduled for tomorrow?",
            AssistantUser("auditor", "auditor_viewer"),
        )

        self.assertFalse(answer["evidence_available"])
        self.assertIn("not a scheduled-session register", answer["answer"])
        self.ssh_query.query_sessions.assert_not_called()
        self.web_query.list_sessions.assert_not_called()

    def test_session_listing_applies_protocol_user_target_dates_and_page_filters(self):
        from datetime import date

        self.ssh_query.query_sessions.return_value = ([], 0)
        with patch(
            "app.services.unified_session_query_service.configured_today",
            return_value=date(2026, 10, 24),
        ):
            self.service.answer_question(
                "Show yesterday's SSH sessions for alice on host prod page 2",
                AssistantUser("auditor", "auditor_viewer"),
            )

        self.ssh_query.query_sessions.assert_called_once()
        arguments = self.ssh_query.query_sessions.call_args.kwargs
        self.assertEqual(arguments["offset"], 25)
        self.assertEqual(arguments["username"], "alice")
        self.assertEqual(arguments["target"], "prod")
        self.assertEqual(arguments["protocol"], "SSH")
        self.assertEqual(arguments["start_date"], date(2026, 10, 23))
        self.assertEqual(arguments["end_date"], date(2026, 10, 23))
        self.web_query.list_sessions.assert_not_called()

    def test_comparison_queries_each_date_as_a_separate_database_range(self):
        from datetime import date
        self.ssh_query.query_sessions.side_effect = [([], 2), ([], 1)]
        self.web_query.list_sessions.side_effect = [
            {"items": [], "total": 3},
            {"items": [], "total": 4},
        ]
        with patch(
            "app.services.unified_session_query_service.configured_today",
            return_value=date(2026, 10, 24),
        ):
            answer = self.service.answer_question(
                "Compare today's sessions with yesterday's.",
                AssistantUser("auditor", "auditor_viewer"),
            )

        self.assertIn("today (2026-10-24): 5", answer["answer"])
        self.assertIn("Yesterday (2026-10-23): 5", answer["answer"])
        self.assertEqual(
            self.ssh_query.query_sessions.call_args_list[0].kwargs["start_date"],
            date(2026, 10, 24),
        )
        self.assertEqual(
            self.ssh_query.query_sessions.call_args_list[1].kwargs["start_date"],
            date(2026, 10, 23),
        )

    def test_chat_route_uses_both_sources_for_generic_session_overview(self):
        def override_get_db():
            yield object()

        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[require_assistant_user] = lambda: AssistantUser(
            "auditor",
            "auditor_viewer",
        )
        expected = {
            "answer": "Found 3 SSH session(s) and 2 web session(s) (5 total).",
            "intent": "SESSION_COUNT",
            "retrieval_mode": "rule-based",
            "evidence_available": True,
            "evidence_summary": "Retrieved current records from PostgreSQL and Warpgate.",
        }
        try:
            with patch(
                "app.api.routes.UnifiedSessionQueryService"
            ) as unified_service:
                unified_service.return_value.answer_question.return_value = expected
                response = TestClient(app).post(
                    "/chat/query",
                    json={"message": "How many sessions are recorded?"},
                )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["answer"], expected["answer"])
            unified_service.return_value.answer_question.assert_called_once()
        finally:
            app.dependency_overrides.clear()


if __name__ == "__main__":
    unittest.main()
