import sys
from pathlib import Path
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.core.assistant_auth import AssistantUser, require_assistant_user
from app.main import app
from app.services.chatbot_service import (
    ChatbotQueryService,
    _is_latest_session_risk_query,
)


class RecordingLLMProvider:
    def __init__(self):
        self.calls = []

    def generate(self, question: str, intent: str, evidence: dict):
        self.calls.append(
            {
                "question": question,
                "intent": intent,
                "evidence": evidence,
            }
        )
        if "AWS account ID" in question:
            return "The available session evidence does not contain an AWS account ID."

        matched_sessions = evidence.get("matched_sessions", [])
        if matched_sessions:
            first_session = matched_sessions[0]
            command_names = [item["command"] for item in first_session.get("matching_commands", []) if item.get("command")]
            return (
                f"Matching session {first_session['session_id']} included commands: "
                f"{', '.join(command_names)}."
            )

        commands = [item["command"] for item in evidence.get("commands", []) if item.get("command")]
        return f"This session executed the following commands: {', '.join(commands)}."


class UnavailableLLMProvider:
    def generate(self, question: str, intent: str, evidence: dict):
        return None


class ChatbotQueryIntegrationTest(unittest.TestCase):
    def setUp(self):
        app.dependency_overrides[require_assistant_user] = lambda: AssistantUser("test-analyst", "admin")
        self.session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"
        self.cross_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"

    def tearDown(self):
        app.dependency_overrides.clear()

    def test_recent_ssh_summary_ignores_a_newer_http_session(self):
        service = object.__new__(ChatbotQueryService)
        ssh_session = SimpleNamespace(
            unique_id="ssh-session",
            session_id="ssh-session",
            username="alice",
            started_at=datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 10, 24, 10, 1, tzinfo=timezone.utc),
            login_time=None,
            logout_time=None,
            duration=None,
            protocol="SSH",
            session_type="SSH",
            risk=None,
            recording_id=None,
            recording_path=None,
            commands=[],
        )
        http_session = SimpleNamespace(
            unique_id="newer-http-session",
            session_id="newer-http-session",
            username="alice",
            started_at=datetime(2026, 10, 24, 11, 0, tzinfo=timezone.utc),
            protocol="HTTP",
            session_type="HTTP",
        )
        query_calls = []
        service._session_query_service = SimpleNamespace(
            query_sessions=lambda **kwargs: (
                query_calls.append(kwargs) or
                ([ssh_session] if kwargs.get("protocol") == "SSH" else [http_session], 1)
            ),
            get_command_evidence=lambda _session_id: [],
        )

        result = service._try_last_session_details(
            "Summarize the most recent SSH session"
        )

        self.assertIsNotNone(result)
        self.assertFalse(result["evidence_available"])
        self.assertEqual(result["session_id"], "ssh-session")
        self.assertTrue(query_calls)
        self.assertEqual(query_calls[0]["protocol"], "SSH")
        self.assertIn("command activity could not be verified", result["answer"])

    def test_latest_session_summary_uses_command_table_evidence(self):
        service = object.__new__(ChatbotQueryService)
        ssh_session = SimpleNamespace(
            unique_id="ssh-session",
            session_id="ssh-session",
            username="alice",
            started_at=datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc),
            ended_at=datetime(2026, 10, 24, 10, 1, tzinfo=timezone.utc),
            login_time=None,
            logout_time=None,
            duration=None,
            protocol="SSH",
            session_type="SSH",
            risk="LOW",
            recording_id=None,
            recording_path=None,
            commands=[],
        )
        command = SimpleNamespace(
            command="pwd",
            output="/home/alice",
            exit_code=0,
        )
        service._session_query_service = SimpleNamespace(
            query_sessions=lambda **_kwargs: ([ssh_session], 1),
            get_command_evidence=lambda _session_id: [command],
        )

        result = service._try_last_session_details(
            "Summarize the most recent SSH session"
        )

        self.assertIsNotNone(result)
        self.assertTrue(result["evidence_available"])
        self.assertIn("Protocol: SSH", result["answer"])
        self.assertIn("Commands executed (1): pwd", result["answer"])
        self.assertIn("Duration: 1m 0s", result["answer"])
        self.assertIn("/home/alice", result["answer"])
        self.assertIn("Exit code: 0", result["answer"])

    def test_latest_ssh_risk_question_reports_command_output_evidence(self):
        question = "Were any risky commands executed in the most recent SSH session?"
        self.assertTrue(_is_latest_session_risk_query(question))

        service = object.__new__(ChatbotQueryService)
        ssh_session = SimpleNamespace(
            unique_id="ssh-session",
            session_id="ssh-session",
            username="alice",
            started_at=datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc),
            protocol="SSH",
        )
        command = SimpleNamespace(
            command="pwd",
            output="/home/alice",
            exit_code=0,
            risk_findings=[],
        )
        query_calls = []
        service._session_query_service = SimpleNamespace(
            query_sessions=lambda **kwargs: (
                query_calls.append(kwargs) or ([ssh_session], 1)
            ),
            get_command_evidence=lambda _session_id: [command],
        )

        result = service._answer_latest_session_risk_findings(question, None)

        self.assertEqual(query_calls[0]["protocol"], "SSH")
        self.assertTrue(result["evidence_available"])
        self.assertIn("No recorded command matched the configured risk rules", result["answer"])
        self.assertIn("/home/alice", result["answer"])
        self.assertIn("does not establish that command output was harmless", result["answer"])

    def test_latest_ssh_risky_command_includes_execution_date_and_time(self):
        service = object.__new__(ChatbotQueryService)
        ssh_session = SimpleNamespace(
            unique_id="ssh-session",
            session_id="ssh-session",
            started_at=datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc),
        )
        command = SimpleNamespace(
            command="sudo stat /etc/shadow",
            output="File: /etc/shadow",
            executed_at=datetime(2026, 10, 24, 10, 15, 30, tzinfo=timezone.utc),
            exit_code=0,
            risk_findings=[
                SimpleNamespace(category="CREDENTIAL_FILE_ACCESS", severity="HIGH")
            ],
        )
        service._session_query_service = SimpleNamespace(
            query_sessions=lambda **_kwargs: ([ssh_session], 1),
            get_command_evidence=lambda _session_id: [command],
        )

        result = service._answer_latest_session_risk_findings(
            "Were any risky commands executed in the latest SSH session?",
            None,
        )

        self.assertIn(
            "2026-10-24 10:15:30 UTC",
            result["answer"],
        )
        self.assertIn("CREDENTIAL_FILE_ACCESS (HIGH)", result["answer"])

    def test_latest_ssh_risk_lookup_does_not_claim_clean_session_without_commands(self):
        service = object.__new__(ChatbotQueryService)
        ssh_session = SimpleNamespace(
            unique_id="ssh-session",
            session_id="ssh-session",
            started_at=datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc),
        )
        service._session_query_service = SimpleNamespace(
            query_sessions=lambda **_kwargs: ([ssh_session], 1),
            get_command_evidence=lambda _session_id: [],
        )

        result = service._answer_latest_session_risk_findings(
            "Were any risky commands executed in the latest SSH session?",
            None,
        )

        self.assertFalse(result["evidence_available"])
        self.assertIn("can't determine whether risky commands were executed", result["answer"])

    def test_session_command_lookup_uses_real_postgres_evidence(self):
        provider = RecordingLLMProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": f"What commands were executed in session {self.session_id}?",
                    "session_id": self.session_id,
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()

        self.assertEqual(payload["intent"], "COMMAND_LOOKUP")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertTrue(payload["evidence_available"])
        self.assertEqual(payload["session_id"], self.session_id)
        self.assertIn("4 command(s)", payload["evidence_summary"])
        self.assertIn("0 risk finding(s)", payload["evidence_summary"])
        self.assertIn("whoami", payload["answer"])
        self.assertIn("hostname", payload["answer"])
        self.assertIn("date", payload["answer"])
        self.assertIn('echo "test august 3"', payload["answer"])

        self.assertEqual(provider.calls, [])

    def test_total_session_count_uses_distinct_database_identity(self):
        with patch(
            "app.services.chatbot_service.build_llm_provider",
            return_value=UnavailableLLMProvider(),
        ), patch(
            "app.services.web_session_query_service.WebSessionQueryService.list_sessions",
            return_value={"items": [], "total": 0},
        ):
            response = TestClient(app).post(
                "/chat/query",
                json={"message": "How many distinct sessions are recorded?"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "SESSION_COUNT")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertTrue(payload["evidence_available"])
        self.assertIn("6 SSH session(s)", payload["answer"])
        self.assertIn("0 web session(s)", payload["answer"])
        self.assertIn("6 total", payload["answer"])

    def test_saved_conversation_history_is_scoped_to_authenticated_username(self):
        conversation_id = str(uuid4())
        client = TestClient(app)
        response = client.post(
            "/chat/query",
            json={"message": "system status", "conversation_id": conversation_id},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["conversation_id"], conversation_id)
        self.assertEqual(
            client.get(f"/chat/conversations/{conversation_id}/messages").status_code,
            200,
        )

        app.dependency_overrides[require_assistant_user] = lambda: AssistantUser("other-analyst", "admin")
        self.assertEqual(
            client.get(f"/chat/conversations/{conversation_id}/messages").status_code,
            404,
        )

    def test_global_user_command_question_uses_real_evidence(self):
        provider = RecordingLLMProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={"question": "What commands did admin execute?"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["evidence_available"])
        self.assertEqual(payload["intent"], "GROUNDED_ANALYSIS")
        self.assertTrue(provider.calls[0]["evidence"]["sessions"])
        commands = [
            command["command"]
            for session in provider.calls[0]["evidence"]["sessions"]
            for command in session.get("commands", [])
        ]
        self.assertIn("whoami", commands)
        self.assertIn("sudo su -", commands)

    def test_status_is_a_rule_based_system_health_check(self):
        with patch("app.services.chatbot_service.build_llm_provider", return_value=UnavailableLLMProvider()):
            client = TestClient(app)
            response = client.post("/chat/query", json={"question": "Status"})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "SYSTEM_STATUS")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("PostgreSQL connected", payload["answer"])

    def test_most_recent_session_is_rule_based(self):
        with patch("app.services.chatbot_service.build_llm_provider", return_value=UnavailableLLMProvider()):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={"question": "Show me the most recent session"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "SESSION_LOOKUP")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("Most recent session", payload["answer"])

    def test_admin_sessions_by_date_does_not_fall_through_to_grounded_analysis(self):
        with patch("app.services.chatbot_service.build_llm_provider", return_value=UnavailableLLMProvider()):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={"question": "List the sessions executed by the admin date wise"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["intent"], "SESSION_LOOKUP")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertTrue(payload["evidence_available"])
        self.assertIn("Admin sessions by date", payload["answer"])
        self.assertNotIn("No matching SSH session evidence", payload["answer"])

    def test_session_duration_uses_latest_real_session(self):
        with patch("app.services.chatbot_service.build_llm_provider", return_value=UnavailableLLMProvider()):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={"question": "How long was admin's session?"},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["answer"], "admin's session lasted 5 minutes.")
        self.assertEqual(payload["intent"], "USER_ACTIVITY")
        self.assertEqual(payload["retrieval_mode"], "rule-based")

    def test_session_duration_reports_active_session(self):
        active_session = SimpleNamespace(
            session_id="active-session",
            unique_id="active-session",
            username="admin",
            started_at=datetime.now(timezone.utc),
            ended_at=None,
        )
        with patch(
            "app.services.chatbot_service.SessionQueryService.get_latest_session_for_user",
            return_value=active_session,
        ), patch("app.services.chatbot_service.build_llm_provider", return_value=UnavailableLLMProvider()):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={"question": "How long was admin's session?"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("admin's session is still active; running for", response.json()["answer"])

    def test_session_duration_reports_missing_user_session(self):
        with patch("app.services.chatbot_service.build_llm_provider", return_value=UnavailableLLMProvider()):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={"question": "How long was user nobody's session?"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["answer"], "No sessions found for nobody.")

    def test_chat_query_falls_back_when_llm_is_unavailable(self):
        with patch("app.services.chatbot_service.build_llm_provider", return_value=UnavailableLLMProvider()):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": f"What commands were executed in session {self.session_id}?",
                    "session_id": self.session_id,
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()

        self.assertEqual(payload["intent"], "COMMAND_LOOKUP")
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertTrue(payload["evidence_available"])
        self.assertIn("whoami", payload["answer"])
        self.assertIn("hostname", payload["answer"])
        self.assertIn("date", payload["answer"])
        self.assertIn('echo "test august 3"', payload["answer"])

    def test_chat_query_reports_unavailable_information_when_evidence_does_not_contain_it(self):
        provider = RecordingLLMProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": "What was the user's AWS account ID?",
                    "session_id": self.session_id,
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()

        self.assertEqual(payload["retrieval_mode"], "llm")
        self.assertTrue(payload["evidence_available"])
        self.assertEqual(
            payload["answer"],
            "The available session evidence does not contain an AWS account ID.",
        )
        self.assertEqual(len(provider.calls), 1)
        self.assertNotIn("aws_account_id", provider.calls[0]["evidence"])

    def test_chat_query_uses_multi_term_cross_session_retrieval(self):
        provider = RecordingLLMProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": "Which sessions used sudo and passwd?",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()

        self.assertEqual(payload["intent"], "SESSION_SEARCH")
        self.assertEqual(payload["retrieval_mode"], "llm")
        self.assertTrue(payload["evidence_available"])
        self.assertIn("sudo", payload["evidence_summary"])
        self.assertIn("passwd", payload["evidence_summary"])
        self.assertIn(self.cross_session_id, payload["answer"])
        self.assertIn("sudo su -", payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])

        self.assertEqual(len(provider.calls), 1)
        llm_call = provider.calls[0]
        self.assertEqual(llm_call["intent"], "SESSION_SEARCH")
        self.assertEqual(llm_call["evidence"]["search_terms"], ["sudo", "passwd"])
        self.assertEqual(llm_call["evidence"]["matched_sessions"][0]["session_id"], self.cross_session_id)
        self.assertEqual(
            [item["command"] for item in llm_call["evidence"]["matched_sessions"][0]["matching_commands"][:3]],
            ["sudo su -", "sudo useradd hacker123", "chmod 777 /etc/passwd"],
        )


if __name__ == "__main__":
    unittest.main()
