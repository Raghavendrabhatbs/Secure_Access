from datetime import date, datetime, timezone
from uuid import uuid4
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.db.database import SessionLocal
from app.services.session_query_service import SessionQueryService
from shared.models.command import Command
from shared.models.event import Event
from shared.models.session import Session as SessionModel


class SessionQueryServiceIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.service = SessionQueryService(self.db)
        self.multi_term_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"

    def tearDown(self):
        self.db.close()

    def test_search_command_matches_returns_real_multi_term_evidence(self):
        matches = self.service.search_command_matches(["sudo", "passwd"])

        self.assertTrue(matches)
        self.assertEqual(matches[0].session_id, self.multi_term_session_id)
        self.assertEqual(matches[0].command, "sudo su -")

        matched_commands = {match.command: tuple(match.matched_terms) for match in matches if match.session_id == self.multi_term_session_id}
        self.assertIn("sudo su -", matched_commands)
        self.assertIn("sudo", matched_commands["sudo su -"])
        self.assertIn("chmod 777 /etc/passwd", matched_commands)
        self.assertIn("passwd", matched_commands["chmod 777 /etc/passwd"])
        self.assertEqual(
            [match.command for match in matches if match.session_id == self.multi_term_session_id][:3],
            ["sudo su -", "sudo useradd hacker123", "chmod 777 /etc/passwd"],
        )

    def test_search_sessions_by_command_terms_returns_real_session_context(self):
        matches = self.service.search_sessions_by_command_terms(["sudo", "passwd"])

        self.assertTrue(matches)
        first_match = matches[0]
        self.assertEqual(first_match.session_id, self.multi_term_session_id)
        self.assertEqual(first_match.username, "admin")
        self.assertEqual(first_match.protocol, "SSH")
        self.assertEqual(first_match.matched_terms, ["sudo", "passwd"])
        self.assertEqual(
            [command.command for command in first_match.matching_commands[:3]],
            ["sudo su -", "sudo useradd hacker123", "chmod 777 /etc/passwd"],
        )

    def test_search_sessions_by_command_terms_returns_empty_for_no_terms(self):
        self.assertEqual(self.service.search_sessions_by_command_terms([]), [])

    def test_command_archive_analysis_scans_risk_findings_and_searches_full_archive(self):
        risky = self.service.analyze_command_archive(risky_only=True, limit=100)

        self.assertGreater(risky["session_count"], 0)
        self.assertGreater(risky["command_count"], 0)
        self.assertGreater(risky["risky_command_count"], 0)
        self.assertTrue(
            any(
                match["session_id"] == self.multi_term_session_id
                and match["command"] == "chmod 777 /etc/passwd"
                for match in risky["matches"]
            )
        )
        self.assertIn("CREDENTIAL_FILE_ACCESS", risky["risk_categories"])

        searched = self.service.analyze_command_archive(search="sudo su -")
        self.assertEqual(searched["match_count"], 1)
        self.assertEqual(searched["matches"][0]["command"], "sudo su -")

    def test_command_archive_returns_paged_session_summaries_with_command_inputs(self):
        session_id = f"test-summary-{uuid4()}"
        started_at = datetime(2032, 5, 6, 12, 0, tzinfo=timezone.utc)
        self.db.add(
            SessionModel(
                unique_id=session_id,
                session_id=session_id,
                username="summary-fixture",
                protocol="SSH",
                started_at=started_at,
            )
        )
        self.db.flush()
        self.db.add_all(
            [
                Command(
                    session_id=session_id,
                    sequence_number=1,
                    command="whoami",
                ),
                Command(
                    session_id=session_id,
                    sequence_number=2,
                    command="sudo -l",
                ),
            ]
        )
        self.db.flush()

        result = self.service.analyze_command_archive(
            username="summary-fixture",
            session_limit=1,
        )

        self.assertEqual(result["session_summaries_total"], 1)
        self.assertTrue(result["session_summaries_complete"])
        self.assertIsNone(result["next_session_offset"])
        self.assertEqual(
            result["session_summaries"][0]["commands"],
            ["whoami", "sudo -l"],
        )
        self.assertEqual(result["session_summaries"][0]["command_count"], 2)
        self.assertEqual(result["session_summaries"][0]["risky_command_count"], 1)
        self.db.rollback()

    def test_command_log_page_includes_full_output_and_total_count(self):
        session_id = f"test-command-log-{uuid4()}"
        self.db.add(
            SessionModel(
                unique_id=session_id,
                session_id=session_id,
                username="log-fixture",
                protocol="SSH",
            )
        )
        self.db.flush()
        full_output = "log-line-" * 1000
        self.db.add_all(
            [
                Command(
                    session_id=session_id,
                    sequence_number=1,
                    command="first",
                    output=full_output,
                ),
                Command(
                    session_id=session_id,
                    sequence_number=2,
                    command="second",
                    output="second-output",
                ),
            ]
        )
        self.db.flush()

        commands, total = self.service.get_commands_page(
            session_id,
            limit=1,
            offset=0,
        )

        self.assertEqual(total, 2)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0].command, "first")
        self.assertEqual(commands[0].output, full_output)
        self.db.rollback()

    def test_duplicate_representations_count_once_and_merge_recording_metadata(self):
        session_id = f"test-session-{uuid4()}"
        starting_count = self.service.count_unique_sessions()
        starting_command_count = self.service.sum_total_commands()
        started_at = datetime(2031, 6, 10, 12, 0, tzinfo=timezone.utc)
        self.db.add_all(
            [
                SessionModel(
                    unique_id=session_id,
                    session_id=session_id,
                    username="fixture-user",
                    protocol="SSH",
                    started_at=started_at,
                    ended_at=started_at,
                    total_commands=3,
                ),
                SessionModel(
                    unique_id=f"{session_id}_recording",
                    session_id=session_id,
                    recording_id="fixture-recording",
                    recording_path="/fixture/recording.ndjson",
                    commands=["whoami"],
                    flagged=[{"rule": "fixture-rule"}],
                    total_commands=3,
                ),
            ]
        )
        self.db.flush()

        merged = self.service.get_session(session_id)
        self.assertEqual(self.service.count_unique_sessions(), starting_count + 1)
        self.assertEqual(self.service.sum_total_commands(), starting_command_count + 3)
        self.assertEqual(
            self.service.count_sessions_started_between(date(2031, 6, 10), date(2031, 6, 10)),
            1,
        )
        self.assertEqual(merged.unique_id, session_id)
        self.assertEqual(merged.username, "fixture-user")
        self.assertEqual(merged.recording_id, "fixture-recording")
        self.assertEqual(merged.recording_path, "/fixture/recording.ndjson")
        self.assertEqual(merged.commands, ["whoami"])
        self.assertEqual(merged.flagged, [{"rule": "fixture-rule"}])
        self.db.rollback()

    def test_missing_optional_fields_remain_countable_and_empty_date_is_zero(self):
        session_id = f"test-session-{uuid4()}"
        self.db.add(SessionModel(unique_id=session_id, session_id=None))
        self.db.flush()

        self.assertIsNone(self.service.get_session(session_id).session_id)
        self.assertEqual(
            self.service.count_sessions_started_between(date(2099, 1, 1), date(2099, 1, 2)),
            0,
        )
        self.db.rollback()

    def test_query_sessions_filters_logical_records_and_paginates_in_database(self):
        session_id = f"test-session-{uuid4()}"
        started_at = datetime(2032, 4, 5, 11, 30, tzinfo=timezone.utc)
        self.db.add_all(
            [
                SessionModel(
                    unique_id=session_id,
                    session_id=session_id,
                    username="query-fixture",
                    target="prod-linux",
                    protocol="SSH",
                    started_at=started_at,
                ),
                SessionModel(
                    unique_id=f"{session_id}_recording",
                    session_id=session_id,
                    recording_id="query-recording",
                    recording_path="/fixture/query-recording.ndjson",
                ),
            ]
        )
        self.db.flush()

        sessions, total = self.service.query_sessions(
            username="QUERY-FIXTURE",
            target="prod",
            protocol="SSH",
            start_date=date(2032, 4, 5),
            end_date=date(2032, 4, 5),
            has_recording=True,
            limit=1,
        )
        empty_page, repeated_total = self.service.query_sessions(
            username="query-fixture",
            start_date=date(2032, 4, 5),
            end_date=date(2032, 4, 5),
            limit=1,
            offset=1,
        )

        self.assertEqual(total, 1)
        self.assertEqual(sessions[0].unique_id, session_id)
        self.assertEqual(sessions[0].recording_id, "query-recording")
        self.assertEqual(repeated_total, 1)
        self.assertEqual(empty_page, [])
        self.db.rollback()

    def test_active_session_requires_a_start_lifecycle_event_without_an_end_event(self):
        session_id = f"test-active-{uuid4()}"
        started_at = datetime.now(timezone.utc)
        self.db.add(
            SessionModel(
                unique_id=session_id,
                session_id=session_id,
                username="lifecycle-fixture",
                protocol="SSH",
                started_at=started_at,
                ended_at=None,
            )
        )
        self.db.flush()

        active_ids = {
            session.session_id or session.unique_id
            for session in self.service.list_active_sessions()
        }
        self.assertNotIn(session_id, active_ids)

        self.db.add(
            Event(
                id=f"test-event-{uuid4()}",
                session_id=session_id,
                event_type="session_started",
                timestamp=started_at,
            )
        )
        self.db.flush()
        active_ids = {
            session.session_id or session.unique_id
            for session in self.service.list_active_sessions()
        }
        self.assertIn(session_id, active_ids)

        self.db.add(
            Event(
                id=f"test-event-{uuid4()}",
                session_id=session_id,
                event_type="session_ended",
                timestamp=datetime.now(timezone.utc),
            )
        )
        self.db.flush()
        active_ids = {
            session.session_id or session.unique_id
            for session in self.service.list_active_sessions()
        }
        self.assertNotIn(session_id, active_ids)
        self.db.rollback()


if __name__ == "__main__":
    unittest.main()