from __future__ import annotations

import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.api import routes
from app.main import app
from app.api.routes import AssistantUser, SSHAnalyzeResponse


class SecurityBlocklistApiTests(unittest.TestCase):
    def setUp(self):
        routes._alert_dedupe.clear()
        self.secret = "test-alert-secret"
        self.env_patch = patch.dict(os.environ, {"ALERT_SECRET": self.secret})
        self.env_patch.start()
        self.client = TestClient(app)
        self.engine_patch = patch("app.api.routes.engine")
        self.engine = self.engine_patch.start()

    def tearDown(self):
        self.engine_patch.stop()
        self.env_patch.stop()

    def test_block_endpoint_requires_alert_secret(self):
        response = self.client.post(
            "/security/block",
            json={"username": "alice"},
        )

        self.assertEqual(response.status_code, 403)
        self.engine.begin.assert_not_called()

    def test_block_endpoint_upserts_parameterized_user_record(self):
        response = self.client.post(
            "/security/block",
            headers={"X-Alert-Secret": self.secret},
            json={
                "username": "alice",
                "reason": "critical command policy",
                "command": "synthetic blocked command",
                "severity": "CRITICAL",
                "session_id": "session-1",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "blocked", "username": "alice"})
        connection = self.engine.begin.return_value.__enter__.return_value
        statement, parameters = connection.execute.call_args.args
        self.assertIn("ON CONFLICT (username)", str(statement))
        self.assertEqual(parameters["username"], "alice")
        self.assertEqual(parameters["session_id"], "session-1")

    def test_check_endpoint_reports_active_state(self):
        connection = self.engine.connect.return_value.__enter__.return_value
        connection.execute.return_value.first.return_value = SimpleNamespace(id=1)

        response = self.client.get(
            "/security/check/alice",
            headers={"X-Alert-Secret": self.secret},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"blocked": True})
        _, parameters = connection.execute.call_args.args
        self.assertEqual(parameters, {"username": "alice"})

    def test_check_endpoint_fails_closed_when_database_is_unavailable(self):
        self.engine.connect.side_effect = RuntimeError("database offline")

        response = self.client.get(
            "/security/check/alice",
            headers={"X-Alert-Secret": self.secret},
        )

        self.assertEqual(response.status_code, 503)
        self.assertIn("Unable to verify", response.json()["detail"])
        self.assertNotIn("database offline", response.json()["detail"])

    def test_unblock_and_list_endpoints_use_alert_secret(self):
        connection = self.engine.begin.return_value.__enter__.return_value
        connection.execute.return_value.first.return_value = SimpleNamespace(username="alice")
        response = self.client.post(
            "/security/unblock/alice?unblocked_by=operator",
            headers={"X-Alert-Secret": self.secret},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "unblocked")
        _, parameters = connection.execute.call_args.args
        self.assertEqual(parameters, {"username": "alice", "unblocked_by": "operator"})

        list_connection = self.engine.connect.return_value.__enter__.return_value
        list_connection.execute.return_value.mappings.return_value.all.return_value = [
            {"username": "bob", "severity": "HIGH"}
        ]
        response = self.client.get(
            "/security/blocked",
            headers={"X-Alert-Secret": self.secret},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"blocked_users": [{"username": "bob", "severity": "HIGH"}]},
        )

    @patch("services.agent.email_alerter.send_alert")
    def test_ssh_alert_passes_category_and_severity_to_email(self, send_alert):
        response = self.client.post(
            "/ssh/alert",
            headers={"X-Alert-Secret": self.secret},
            json={
                "command": "synthetic blocked command",
                "reason": "policy violation",
                "username": "alice",
                "session_id": "session-1",
                "category": "Destructive Command",
                "severity": "CRITICAL",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "alert queued"})
        send_alert.assert_called_once()
        self.assertEqual(send_alert.call_args.kwargs["category"], "Destructive Command")
        self.assertEqual(send_alert.call_args.kwargs["severity"], "CRITICAL")

    @patch("services.agent.email_alerter.send_alert")
    @patch("app.api.routes._ssh_verdict")
    def test_blocked_ssh_analysis_emails_matching_severity_and_user(
        self, verdict, send_alert
    ):
        verdict.return_value = SSHAnalyzeResponse(
            verdict="block",
            risk_score=0.65,
            reason="Matched configured medium-risk rules.",
        )

        response = self.client.post(
            "/ssh/analyze",
            json={
                "command": "synthetic risky command",
                "session_id": "session-2",
                "username": "alice",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["verdict"], "block")
        send_alert.assert_called_once()
        self.assertEqual(send_alert.call_args.kwargs["severity"], "MEDIUM")
        self.assertEqual(send_alert.call_args.kwargs["username"], "alice")

    def test_duplicate_ssh_alert_events_are_suppressed(self):
        self.assertTrue(routes._claim_alert_event("session-1", "alice", "reboot"))
        self.assertFalse(routes._claim_alert_event("session-1", "ALICE", "reboot"))
        self.assertTrue(routes._claim_alert_event("session-1", "bob", "reboot"))

    def test_admin_can_list_active_warpgate_sessions_through_backend(self):
        fake_client = Mock()
        fake_client.list_active_sessions.return_value = [
            {
                "id": "94e34c21-156c-4a41-9cf2-ccedc1520669",
                "username": "alice",
                "target": "ssh-demo",
                "protocol": "SSH",
                "started": "2026-10-25T10:00:00Z",
                "ended": None,
                "node_hostname": "wsl-host",
            }
        ]
        with patch(
            "app.api.routes.require_assistant_user",
            return_value=AssistantUser(username="operator", role="admin"),
        ), patch("app.api.routes._warpgate_client", return_value=fake_client):
            response = self.client.get(
                "/admin/warpgate/sessions/active",
                headers={"Cookie": "warpgate-http-session=test-cookie; unrelated=hidden"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["sessions"]), 1)
        fake_client.list_active_sessions.assert_called_once_with(
            "warpgate-http-session=test-cookie"
        )

    def test_non_admin_cannot_list_or_terminate_warpgate_sessions(self):
        fake_client = Mock()
        with patch(
            "app.api.routes.require_assistant_user",
            return_value=AssistantUser(username="developer", role="developer"),
        ), patch("app.api.routes._warpgate_client", return_value=fake_client):
            response = self.client.get(
                "/admin/warpgate/sessions/active",
                headers={"Cookie": "warpgate-http-session=test-cookie"},
            )

        self.assertEqual(response.status_code, 403)
        fake_client.list_active_sessions.assert_not_called()

    def test_admin_manual_termination_returns_verified_result(self):
        fake_client = Mock()
        fake_client.terminate_session.return_value = {
            "status": "confirmed",
            "session": {
                "id": "94e34c21-156c-4a41-9cf2-ccedc1520669",
                "username": "alice",
                "target": "ssh-demo",
                "protocol": "SSH",
                "started": "2026-10-25T10:00:00Z",
                "ended": "2026-10-25T10:05:00Z",
                "node_hostname": "wsl-host",
            },
        }
        with patch(
            "app.api.routes.require_assistant_user",
            return_value=AssistantUser(username="operator", role="admin"),
        ), patch("app.api.routes._warpgate_client", return_value=fake_client):
            response = self.client.post(
                "/admin/warpgate/sessions/94e34c21-156c-4a41-9cf2-ccedc1520669/terminate",
                headers={"Cookie": "warpgate-http-session=test-cookie"},
                json={"reason": "operator confirmation"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "confirmed")
        fake_client.terminate_session.assert_called_once_with(
            "warpgate-http-session=test-cookie",
            "94e34c21-156c-4a41-9cf2-ccedc1520669",
        )


if __name__ == "__main__":
    unittest.main()
