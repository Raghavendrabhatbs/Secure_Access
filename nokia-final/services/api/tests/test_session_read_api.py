import sys
from datetime import datetime, timezone
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.core.assistant_auth import AssistantUser, require_assistant_user
from app.db.database import get_db
from app.main import app


class FakeSessionQueryService:
    def __init__(self, db):
        self._db = db

    def list_sessions(self, limit: int = 100, offset: int = 0):
        return [self._db["session"]]

    def get_session(self, session_id: str):
        if session_id == self._db["session"].unique_id:
            return self._db["session"]
        return None

    def get_commands(self, session_id: str):
        if session_id == self._db["session"].unique_id:
            return self._db["commands"]
        return []

    def get_commands_page(self, session_id: str, *, limit: int = 50, offset: int = 0):
        commands = self.get_commands(session_id)
        return commands[offset : offset + limit], len(commands)

    def get_events(self, session_id: str):
        if session_id == self._db["session"].unique_id:
            return self._db["events"]
        return []

    def analyze_command_archive(self, **kwargs):
        self._db["command_analysis_args"] = kwargs
        return {
            "scope": "postgresql",
            "session_count": 1,
            "command_count": 2,
            "risky_command_count": 0,
            "risk_categories": {},
            "sessions": [],
            "matches": [],
            "match_count": 0,
            "offset": kwargs["offset"],
            "limit": kwargs["limit"],
            "complete": True,
        }


class SessionReadApiTest(unittest.TestCase):
    def setUp(self):
        self.session = SimpleNamespace(
            unique_id="session-1",
            session_id="session-1",
            username="alice",
            protocol="ssh",
            remote_address="10.0.0.5",
            started_at=datetime(2026, 8, 8, 10, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 8, 8, 10, 5, tzinfo=timezone.utc),
            recording_id="recording-1",
            recording_path="/data/recordings/session-1/recording-1",
            total_commands=2,
            session_type="SSH",
            target="server-1",
            login_time=datetime(2026, 8, 8, 10, 0, tzinfo=timezone.utc),
            logout_time=datetime(2026, 8, 8, 10, 5, tzinfo=timezone.utc),
            duration="5m",
            duration_seconds=300.0,
            created_at=datetime(2026, 8, 8, 10, 0, tzinfo=timezone.utc),
            risk="low",
        )
        self.commands = [
            SimpleNamespace(
                id="session-1:1",
                session_id="session-1",
                sequence_number=1,
                command="whoami",
                output="alice",
                executed_at=datetime(2026, 8, 8, 10, 1, tzinfo=timezone.utc),
                exit_code=None,
            ),
            SimpleNamespace(
                id="session-1:2",
                session_id="session-1",
                sequence_number=2,
                command="hostname",
                output="host-1",
                executed_at=datetime(2026, 8, 8, 10, 2, tzinfo=timezone.utc),
                exit_code=None,
            ),
        ]
        self.events = [
            SimpleNamespace(
                id="evt-session-started",
                session_id="session-1",
                event_type="session_started",
                timestamp=datetime(2026, 8, 8, 10, 0, tzinfo=timezone.utc),
                severity=None,
                message="Session started",
                payload={"protocol": "ssh"},
            ),
            SimpleNamespace(
                id="evt-command-1",
                session_id="session-1",
                event_type="command_executed",
                timestamp=datetime(2026, 8, 8, 10, 1, tzinfo=timezone.utc),
                severity=None,
                message="Command executed: whoami",
                payload={"sequence_number": 1, "command": "whoami"},
            ),
        ]
        self.fake_db = {
            "session": self.session,
            "commands": self.commands,
            "events": self.events,
        }

        def override_get_db():
            yield self.fake_db

        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[require_assistant_user] = lambda: AssistantUser("test-analyst", "admin")
        self.patcher = patch("app.api.routes.SessionQueryService", FakeSessionQueryService)
        self.patcher.start()
        self.client = TestClient(app)

    def tearDown(self):
        self.patcher.stop()
        app.dependency_overrides.clear()

    def test_list_sessions(self):
        response = self.client.get("/sessions")
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["session_id"], "session-1")
        self.assertEqual(payload[0]["recording_path"], "/data/recordings/session-1/recording-1")

    def test_list_sessions_uses_legacy_login_and_logout_timestamps(self):
        self.session.started_at = None
        self.session.ended_at = None
        self.session.login_time = datetime(2026, 10, 24, 10, 0)
        self.session.logout_time = datetime(2026, 10, 24, 10, 5)

        response = self.client.get("/sessions")

        self.assertEqual(response.status_code, 200)
        payload = response.json()[0]
        self.assertEqual(
            datetime.fromisoformat(payload["started_at"]),
            datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(
            datetime.fromisoformat(payload["ended_at"]),
            datetime(2026, 10, 24, 10, 5, tzinfo=timezone.utc),
        )

    def test_get_session(self):
        response = self.client.get("/sessions/session-1")
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertEqual(payload["session_id"], "session-1")
        self.assertEqual(payload["risk"], "low")

    def test_get_commands(self):
        response = self.client.get("/sessions/session-1/commands")
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertEqual(len(payload), 2)
        self.assertEqual(payload[0]["command"], "whoami")

    def test_get_command_log_returns_output_and_pagination_metadata(self):
        response = self.client.get(
            "/sessions/session-1/command-log",
            params={"limit": 1, "offset": 1},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["total"], 2)
        self.assertEqual(payload["commands"][0]["command"], "hostname")
        self.assertEqual(payload["commands"][0]["output"], "host-1")
        self.assertEqual(payload["commands"][0]["output_total"], 6)
        self.assertTrue(payload["commands"][0]["output_complete"])
        self.assertEqual(payload["next_offset"], None)
        self.assertTrue(payload["complete"])

    def test_get_command_log_bounds_large_output_and_marks_truncation(self):
        original_output = self.commands[0].output
        self.commands[0].output = "x" * 4001

        response = self.client.get(
            "/sessions/session-1/command-log",
            params={"limit": 1},
        )

        self.assertEqual(response.status_code, 200)
        command = response.json()["commands"][0]
        self.assertEqual(len(command["output"]), 4000)
        self.assertEqual(command["output_next_offset"], 4000)
        self.assertEqual(command["output_total"], 4001)
        self.assertFalse(command["output_complete"])
        self.assertEqual(len(self.commands[0].output), 4001)

        continuation = self.client.get(
            "/sessions/session-1/command-log",
            params={
                "limit": 1,
                "output_offset": command["output_next_offset"],
            },
        )
        self.assertEqual(continuation.status_code, 200)
        continued_command = continuation.json()["commands"][0]
        self.assertEqual(continued_command["output"], "x")
        self.assertTrue(continued_command["output_complete"])
        self.commands[0].output = original_output

    def test_developer_cannot_read_another_users_command_log(self):
        app.dependency_overrides[require_assistant_user] = lambda: AssistantUser(
            "bob",
            "developer",
        )

        response = self.client.get("/sessions/session-1/command-log")

        self.assertEqual(response.status_code, 404)

    def test_command_analysis_is_role_scoped_and_paged(self):
        response = self.client.get(
            "/sessions/command-analysis",
            params={"risky_only": "true", "limit": 10, "offset": 5},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["scope"], "postgresql")
        self.assertEqual(
            self.fake_db["command_analysis_args"],
            {
                "search": None,
                "risky_only": True,
                "username": None,
                "limit": 10,
                "offset": 5,
                "session_limit": 25,
                "session_offset": 0,
            },
        )

    def test_command_analysis_limits_developers_to_their_own_sessions(self):
        app.dependency_overrides[require_assistant_user] = lambda: AssistantUser(
            "alice",
            "developer",
        )

        response = self.client.get(
            "/sessions/command-analysis",
            params={"search": "sudo"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self.fake_db["command_analysis_args"]["username"],
            "alice",
        )

    def test_command_analysis_supports_archive_summary_without_filters(self):
        response = self.client.get("/sessions/command-analysis")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["command_count"], 2)

    def test_get_events(self):
        response = self.client.get("/sessions/session-1/events")
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertEqual(len(payload), 2)
        self.assertEqual(payload[0]["event_type"], "session_started")

    def test_session_timeline(self):
        response = self.client.get("/sessions/session-1/timeline")
        self.assertEqual(response.status_code, 200)

        payload = response.json()
        self.assertEqual(payload["session"]["session_id"], "session-1")
        self.assertEqual(len(payload["commands"]), 2)
        self.assertEqual(len(payload["events"]), 2)

    def test_missing_session_returns_404(self):
        response = self.client.get("/sessions/missing")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
