from __future__ import annotations

from contextlib import nullcontext
from datetime import date, datetime, timezone
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from backend.chatbot_service import (
    ChatbotService,
    SYSTEM_DATA_QUERY,
    _fallback_tool_call,
    _tools_for_question,
)
from backend.config import ConfigurationError, Settings
from backend.groq_client import (
    GroqPayloadTooLargeError,
    GroqProvider,
    GroqProviderError,
    GroqRateLimitError,
)
from backend.app import app
from backend.security import (
    AssistantIdentity,
    AuthenticationError,
    authenticate_cookie,
    parse_session_cookie,
    sanitize_for_llm,
)
from backend.secure_access_client import SecureAccessClient
from backend.secure_access_client import DataSourceError
from backend.time_ranges import (
    date_range_from_question,
    is_after_cutoff,
    time_bounds_from_question,
)
from backend.tool_registry import (
    AnalyzeWebRecordingsArguments,
    AuditLogArguments,
    CommandArchiveArguments,
    IncidentArguments,
    ListSessionsArguments,
    ToolRegistry,
)
from fastapi.testclient import TestClient


def settings(**overrides):
    values = {
        "groq_api_key": "test-only",
        "groq_model": "openai/gpt-oss-120b",
        "groq_timeout_seconds": 2.0,
        "secure_access_timeout_seconds": 2.0,
        "secure_access_api_url": "http://secure-access.test",
        "warpgate_url": "https://warpgate.test",
        "warpgate_ca_bundle": None,
        "app_timezone": "Asia/Kolkata",
        "audit_database_url": None,
        "audit_query_timeout_seconds": 2.0,
    }
    values.update(overrides)
    return Settings(**values)


class AddonUnitTests(unittest.TestCase):
    def test_multiple_groq_keys_load_from_environment_with_legacy_fallback(self):
        with patch.dict(
            os.environ,
            {
                "GROQ_API_KEYS": " first-key, second-key ; first-key ",
                "GROQ_API_KEY": "legacy-key",
            },
            clear=True,
        ):
            configured = Settings.from_env()
        self.assertEqual(
            configured.groq_api_keys,
            ("first-key", "second-key"),
        )
        self.assertEqual(configured.groq_api_key, "first-key")

        with patch.dict(
            os.environ,
            {"GROQ_API_KEY": "legacy-key"},
            clear=True,
        ):
            configured = Settings.from_env()
        self.assertEqual(configured.groq_api_keys, ("legacy-key",))
        self.assertEqual(configured.groq_api_key, "legacy-key")

    def test_groq_provider_fails_over_to_next_key_on_rate_limit(self):
        first_client = Mock()
        first_error = RuntimeError("private provider response")
        first_error.status_code = 429
        first_error.response = SimpleNamespace(headers={"retry-after": "2"})
        first_client.chat.completions.create.side_effect = first_error

        second_client = Mock()
        second_client.chat.completions.create.return_value = "success"
        created_keys = []

        def client_factory(api_key):
            created_keys.append(api_key)
            return {
                "first-secret-key": first_client,
                "second-secret-key": second_client,
            }[api_key]

        configured = settings(
            groq_api_key="first-secret-key",
            groq_api_keys=("first-secret-key", "second-secret-key"),
        )
        provider = GroqProvider(configured, client_factory=client_factory)

        response = provider.complete(
            messages=[{"role": "user", "content": "synthetic request"}],
            tools=None,
        )

        self.assertEqual(response, "success")
        self.assertEqual(created_keys, ["first-secret-key", "second-secret-key"])
        first_client.chat.completions.create.assert_called_once()
        second_client.chat.completions.create.assert_called_once()

        provider.complete(
            messages=[{"role": "user", "content": "next round"}],
            tools=None,
        )
        first_client.chat.completions.create.assert_called_once()
        self.assertEqual(second_client.chat.completions.create.call_count, 2)

    def test_groq_provider_fails_over_after_authentication_or_permission_error(self):
        for status_code in (401, 403):
            with self.subTest(status_code=status_code):
                first_client = Mock()
                error = RuntimeError("private provider response")
                error.status_code = status_code
                first_client.chat.completions.create.side_effect = error
                second_client = Mock()
                second_client.chat.completions.create.return_value = "success"
                keys = ("first-secret-key", "second-secret-key")
                provider = GroqProvider(
                    settings(groq_api_key=keys[0], groq_api_keys=keys),
                    client_factory=lambda key: (
                        first_client if key == keys[0] else second_client
                    ),
                )

                response = provider.complete(messages=[], tools=None)

                self.assertEqual(response, "success")
                first_client.chat.completions.create.assert_called_once()
                second_client.chat.completions.create.assert_called_once()

    def test_groq_provider_tries_three_configured_keys_in_order(self):
        keys = ("first-secret-key", "second-secret-key", "third-secret-key")
        clients = []
        for status_code in (401, 403):
            client = Mock()
            error = RuntimeError("private provider response")
            error.status_code = status_code
            client.chat.completions.create.side_effect = error
            clients.append(client)
        clients.append(Mock())
        clients[2].chat.completions.create.return_value = "success"

        provider = GroqProvider(
            settings(groq_api_key=keys[0], groq_api_keys=keys),
            client_factory=lambda key: clients[keys.index(key)],
        )

        self.assertEqual(provider.complete(messages=[], tools=None), "success")
        for client in clients:
            client.chat.completions.create.assert_called_once()

    def test_groq_provider_continues_after_mixed_rate_and_auth_failures(self):
        keys = ("first-secret-key", "second-secret-key", "third-secret-key")
        statuses = (429, 401, 403)
        clients = []
        for status_code in statuses:
            client = Mock()
            error = RuntimeError("private provider response")
            error.status_code = status_code
            if status_code == 429:
                error.response = SimpleNamespace(headers={"retry-after": "9"})
            client.chat.completions.create.side_effect = error
            clients.append(client)

        provider = GroqProvider(
            settings(groq_api_key=keys[0], groq_api_keys=keys),
            client_factory=lambda key: clients[keys.index(key)],
        )
        with self.assertRaises(GroqRateLimitError) as raised:
            provider.complete(messages=[], tools=None)

        self.assertEqual(raised.exception.retry_after_seconds, 9)
        for client in clients:
            client.chat.completions.create.assert_called_once()

    def test_all_rejected_groq_keys_return_actionable_error_without_key_material(self):
        keys = ("first-secret-key", "second-secret-key", "third-secret-key")
        clients = []
        for status_code in (401, 403, 401):
            client = Mock()
            error = RuntimeError("private provider response")
            error.status_code = status_code
            client.chat.completions.create.side_effect = error
            clients.append(client)

        provider = GroqProvider(
            settings(groq_api_key=keys[0], groq_api_keys=keys),
            client_factory=lambda key: clients[keys.index(key)],
        )
        with self.assertRaises(GroqProviderError) as raised:
            provider.complete(messages=[], tools=None)

        self.assertIn("All configured Groq API keys were rejected", str(raised.exception))
        self.assertNotIn("first-secret-key", str(raised.exception))
        self.assertNotIn("private provider response", str(raised.exception))
        for client in clients:
            client.chat.completions.create.assert_called_once()

    def test_all_groq_keys_rate_limited_return_final_retry_delay(self):
        keys = ("first-secret-key", "second-secret-key")
        clients = []
        for retry_after in ("7", "12"):
            client = Mock()
            error = RuntimeError("private provider response")
            error.status_code = 429
            error.response = SimpleNamespace(headers={"retry-after": retry_after})
            client.chat.completions.create.side_effect = error
            clients.append(client)

        provider = GroqProvider(
            settings(groq_api_key=keys[0], groq_api_keys=keys),
            client_factory=lambda key: clients[keys.index(key)],
        )
        with self.assertRaises(GroqRateLimitError) as raised:
            provider.complete(messages=[], tools=None)

        self.assertEqual(raised.exception.retry_after_seconds, 12)
        self.assertNotIn("private provider response", str(raised.exception))
        for client in clients:
            client.chat.completions.create.assert_called_once()

    def test_groq_provider_does_not_rotate_keys_for_non_rate_limit_errors(self):
        first_client = Mock()
        error = RuntimeError("invalid request")
        error.status_code = 400
        first_client.chat.completions.create.side_effect = error
        second_client = Mock()
        provider = GroqProvider(
            settings(
                groq_api_key="first-secret-key",
                groq_api_keys=("first-secret-key", "second-secret-key"),
            ),
            client_factory=lambda key: (
                first_client if key == "first-secret-key" else second_client
            ),
        )

        with self.assertRaises(GroqProviderError):
            provider.complete(messages=[], tools=None)

        first_client.chat.completions.create.assert_called_once()
        second_client.chat.completions.create.assert_not_called()

    def test_gpt_oss_tool_requests_disable_parallel_tool_calls(self):
        client = Mock()
        client.chat.completions.create.return_value = "response"
        provider = GroqProvider(settings(), client=client)
        tools = [
            {
                "type": "function",
                "function": {"name": "get_session_counts", "parameters": {}},
            }
        ]

        response = provider.complete(
            messages=[{"role": "user", "content": "How many SSH sessions?"}],
            tools=tools,
            tool_choice="required",
        )

        self.assertEqual(response, "response")
        self.assertIs(
            client.chat.completions.create.call_args.kwargs["parallel_tool_calls"],
            False,
        )
        self.assertEqual(
            client.chat.completions.create.call_args.kwargs["tools"],
            tools,
        )

    def test_groq_request_without_tools_omits_parallel_tool_setting(self):
        client = Mock()
        provider = GroqProvider(settings(), client=client)

        provider.complete(
            messages=[{"role": "user", "content": "Explain SSH"}],
            tools=None,
        )

        self.assertNotIn(
            "parallel_tool_calls",
            client.chat.completions.create.call_args.kwargs,
        )

    def test_groq_tool_request_defaults_to_auto_instead_of_required(self):
        client = Mock()
        provider = GroqProvider(settings(), client=client)

        provider.complete(
            messages=[{"role": "user", "content": "How many SSH sessions?"}],
            tools=[{"type": "function", "function": {"name": "get_session_counts"}}],
        )

        self.assertEqual(
            client.chat.completions.create.call_args.kwargs["tool_choice"],
            "auto",
        )

    def test_question_specific_tool_schemas_reduce_irrelevant_payload(self):
        tools = _tools_for_question("What did the latest SSH command output?")
        names = {tool["function"]["name"] for tool in tools}

        self.assertIn("get_session_commands", names)
        self.assertIn("get_session_details", names)
        self.assertNotIn("analyze_web_recordings", names)
        self.assertNotIn("list_audit_logs", names)
        self.assertLess(len(tools), 11)

    def test_fallback_tool_selection_routes_counts_and_session_commands(self):
        self.assertEqual(
            _fallback_tool_call("How many SSH sessions are recorded?"),
            ("get_session_counts", {"protocol": "ssh"}),
        )
        self.assertEqual(
            _fallback_tool_call(
                "Show commands and output for session "
                "d28f7ace-2742-4b77-ad28-4a6a44f2286d"
            ),
            (
                "get_session_commands",
                {"session_id": "d28f7ace-2742-4b77-ad28-4a6a44f2286d"},
            ),
        )

    def test_model_no_tool_call_falls_back_to_authorized_evidence_lookup(self):
        no_tool_response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=None, tool_calls=[])
                )
            ]
        )
        answer_response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="There are 3 recorded SSH sessions.",
                        tool_calls=[],
                    )
                )
            ]
        )

        class FakeProvider:
            def __init__(self):
                self.calls = []

            def complete(self, **kwargs):
                self.calls.append(kwargs)
                self.assert_auto_tool_choice(kwargs)
                return no_tool_response if len(self.calls) == 1 else answer_response

            @staticmethod
            def assert_auto_tool_choice(kwargs):
                if kwargs["tools"]:
                    assert kwargs["tool_choice"] == "auto"

        provider = FakeProvider()
        registry = Mock()
        registry.execute.return_value = {"ssh_count": 3, "complete": True}
        service = ChatbotService(
            settings(),
            Mock(),
            registry,
            provider_factory=lambda _settings: provider,
        )

        result = service.answer(
            "How many SSH sessions are recorded?",
            AssistantIdentity("auditor", "auditor_viewer"),
        )

        self.assertEqual(result["answer"], "There are 3 recorded SSH sessions.")
        registry.execute.assert_called_once_with(
            "get_session_counts",
            json.dumps({"protocol": "ssh"}),
            "How many SSH sessions are recorded?",
        )
        self.assertEqual(len(provider.calls), 2)
        self.assertTrue(
            any(message["role"] == "tool" for message in provider.calls[1]["messages"])
        )

    def test_cookie_requires_warpgate_session(self):
        with self.assertRaises(AuthenticationError):
            parse_session_cookie("other=value")
        self.assertEqual(
            parse_session_cookie("warpgate-http-session=abc123"),
            "warpgate-http-session=abc123",
        )

    def test_identity_response_is_validated_and_http_ui_requires_login(self):
        response = SimpleNamespace(
            status_code=200,
            json=lambda: {"username": "alice", "application_role": "developer"},
        )
        with patch("backend.security.httpx.get", return_value=response):
            cookie, identity = authenticate_cookie(
                "warpgate-http-session=abc",
                settings(),
            )
        self.assertEqual(cookie, "warpgate-http-session=abc")
        self.assertEqual(identity, AssistantIdentity("alice", "developer"))

        client = TestClient(app)
        self.assertEqual(client.get("/health").status_code, 200)
        self.assertIn("Groq AI mode", client.get("/").text)
        self.assertEqual(
            client.post("/api/chat", json={"message": "How many sessions?"}).status_code,
            401,
        )

    def test_redaction_hides_sensitive_fields_and_inline_credentials(self):
        value = sanitize_for_llm(
            {
                "password": "never send",
                "command": (
                    "curl -H 'Authorization: Bearer secret123' token=abc "
                    "--password pa55 https://user:pw@example.test gsk_"
                    "abcdefghijklmnopqrstuvwxyz123456"
                ),
                "session_id": "session-safe",
            }
        )
        self.assertEqual(value["password"], "[REDACTED]")
        self.assertNotIn("secret123", value["command"])
        self.assertNotIn("token=abc", value["command"])
        self.assertNotIn("pa55", value["command"])
        self.assertNotIn("user:pw", value["command"])
        self.assertNotIn("gsk_abcdefghijklmnopqrstuvwxyz", value["command"])
        self.assertEqual(value["session_id"], "session-safe")

    def test_date_parser_supports_relative_and_numeric_dates(self):
        now = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
        self.assertEqual(
            date_range_from_question("show sessions yesterday", "Asia/Kolkata", now),
            (date(2026, 10, 23), date(2026, 10, 23)),
        )
        self.assertEqual(
            date_range_from_question("sessions on 22-10-2026", "Asia/Kolkata", now),
            (date(2026, 10, 22), date(2026, 10, 22)),
        )

    def test_last_24_hours_and_future_cutoff_are_detected(self):
        now = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
        self.assertEqual(
            date_range_from_question("sessions in the last 24 hours", "UTC", now),
            (date(2026, 10, 23), date(2026, 10, 24)),
        )
        self.assertTrue(is_after_cutoff("2026-10-24T13:00:00Z", now))
        self.assertFalse(is_after_cutoff("2026-10-24T11:00:00Z", now))

    def test_time_ranges_cover_morning_midnight_and_month_start(self):
        now = datetime(2026, 10, 24, 8, tzinfo=timezone.utc)
        since, before = time_bounds_from_question("sessions this morning", "Asia/Kolkata", now)
        self.assertEqual(since, datetime(2026, 10, 23, 18, 30, tzinfo=timezone.utc))
        self.assertEqual(before, datetime(2026, 10, 24, 6, 30, tzinfo=timezone.utc))
        self.assertEqual(
            date_range_from_question("sessions from beginning of month", "Asia/Kolkata", now),
            (date(2026, 10, 1), date(2026, 10, 24)),
        )

    def test_argument_schemas_reject_unknown_or_invalid_parameters(self):
        with self.assertRaises(ValueError):
            ListSessionsArguments.model_validate({"limit": 1000})
        with self.assertRaises(ValueError):
            ListSessionsArguments.model_validate({"sql": "select * from sessions"})
        with self.assertRaises(ValueError):
            AnalyzeWebRecordingsArguments.model_validate({"limit": 11})
        self.assertIsNotNone(CommandArchiveArguments.model_validate({}))
        with self.assertRaises(ValueError):
            CommandArchiveArguments.model_validate({"risky_only": True, "limit": 101})
        with self.assertRaises(ValueError):
            IncidentArguments.model_validate(
                {"start_date": "2026-10-25", "end_date": "2026-10-24"}
            )

    def test_date_filter_arguments_normalize_model_generated_timestamps(self):
        sessions = ListSessionsArguments.model_validate(
            {
                "start_date": "2026-10-24T00:00:00Z",
                "end_date": "2026-10-24T23:59:59Z",
            }
        )
        self.assertEqual(sessions.start_date, date(2026, 10, 24))
        self.assertEqual(sessions.end_date, date(2026, 10, 24))

        incidents = IncidentArguments.model_validate(
            {"start_date": "2026-10-24T12:30:00+05:30"}
        )
        self.assertEqual(incidents.start_date, date(2026, 10, 24))

    def test_developer_identity_is_applied_as_mandatory_ssh_scope(self):
        transport = Mock()
        transport.get.return_value = SimpleNamespace(
            status_code=200,
            json=lambda: [
                {
                    "session_id": "mine",
                    "unique_id": "mine",
                    "username": "alice",
                    "started_at": "2026-10-24T09:00:00Z",
                },
                {
                    "session_id": "other",
                    "unique_id": "other",
                    "username": "bob",
                    "started_at": "2026-10-24T08:00:00Z",
                },
            ],
        )
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("alice", "developer"),
            transport=transport,
        )
        result = client.list_ssh_sessions()
        self.assertEqual([item["session_id"] for item in result["items"]], ["mine"])
        self.assertTrue(result["complete"])

    def test_command_archive_analysis_requests_server_scanned_risk_evidence(self):
        payload = {
            "scope": "postgresql",
            "session_count": 2,
            "command_count": 4,
            "risky_command_count": 1,
            "risk_categories": {"PRIVILEGE_ESCALATION": 1},
            "matches": [{"command": "sudo -l"}],
            "complete": True,
        }
        transport = Mock()
        transport.get.return_value = SimpleNamespace(
            status_code=200,
            json=lambda: payload,
        )
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("auditor", "auditor_viewer"),
            transport=transport,
        )

        result = client.analyze_ssh_command_archive(risky_only=True, limit=10)

        self.assertEqual(result, payload)
        self.assertEqual(
            transport.get.call_args.kwargs["params"],
            {
                "risky_only": True,
                "limit": 10,
                "offset": 0,
                "session_limit": 25,
                "session_offset": 0,
            },
        )
        self.assertTrue(
            transport.get.call_args.args[0].endswith("/sessions/command-analysis")
        )

    def test_session_command_log_retrieval_returns_paged_command_output(self):
        payload = {
            "session_id": "session-1",
            "commands": [
                {
                    "sequence_number": 3,
                    "command": "cat report.log",
                    "output": "complete stored command output",
                    "output_total": 30,
                    "output_offset": 0,
                    "output_next_offset": None,
                    "output_complete": True,
                }
            ],
            "total": 20,
            "limit": 1,
            "offset": 2,
            "next_offset": 3,
            "complete": False,
        }
        transport = Mock()
        transport.get.return_value = SimpleNamespace(
            status_code=200,
            json=lambda: payload,
        )
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("alice", "developer"),
            transport=transport,
        )
        with patch.object(
            client,
            "_find_authorized_ssh_session",
            return_value={"session_id": "session-1", "unique_id": "session-1"},
        ):
            result = client.get_session_command_log(
                "session-1",
                limit=1,
                offset=2,
                output_offset=4000,
                output_limit=2000,
            )

        self.assertEqual(result, payload)
        self.assertTrue(
            transport.get.call_args.args[0].endswith(
                "/sessions/session-1/command-log"
            )
        )
        self.assertEqual(
            transport.get.call_args.kwargs["params"],
            {
                "limit": 1,
                "offset": 2,
                "output_offset": 4000,
                "output_limit": 2000,
            },
        )

    def test_archive_analysis_supports_paged_per_session_summaries(self):
        transport = Mock()
        transport.get.return_value = SimpleNamespace(
            status_code=200,
            json=lambda: {"matches": [], "session_summaries": []},
        )
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("auditor", "auditor_viewer"),
            transport=transport,
        )

        client.analyze_ssh_command_archive(session_limit=10, session_offset=20)

        self.assertEqual(
            transport.get.call_args.kwargs["params"],
            {
                "risky_only": False,
                "limit": 25,
                "offset": 0,
                "session_limit": 10,
                "session_offset": 20,
            },
        )

    def test_session_command_retrieval_does_not_silently_drop_history_after_500(self):
        commands = [
            {"sequence_number": index, "command": f"command-{index}"}
            for index in range(501)
        ]
        transport = Mock()
        transport.get.return_value = SimpleNamespace(
            status_code=200,
            json=lambda: commands,
        )
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("auditor", "auditor_viewer"),
            transport=transport,
        )
        with patch.object(
            client,
            "_find_authorized_ssh_session",
            return_value={"session_id": "session-1", "unique_id": "session-1"},
        ):
            retrieved = client.get_session_related("session-1", "commands")

        self.assertEqual(len(retrieved), 501)

    def test_ssh_pagination_and_new_records_are_read_without_a_cache(self):
        rows = [
            {
                "session_id": f"session-{index}",
                "unique_id": f"session-{index}",
                "username": "alice",
                "started_at": "2026-10-24T09:00:00Z",
            }
            for index in range(1000)
        ]
        transport = Mock()
        transport.get.side_effect = [
            SimpleNamespace(status_code=200, json=lambda: []),
            SimpleNamespace(status_code=200, json=lambda: rows),
            SimpleNamespace(
                status_code=200,
                json=lambda: [
                    {
                        "session_id": "session-latest",
                        "unique_id": "session-latest",
                        "username": "alice",
                        "started_at": "2026-10-24T10:00:00Z",
                    }
                ],
            ),
        ]
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("alice", "developer"),
            transport=transport,
        )
        paged = client.list_ssh_sessions()
        self.assertEqual(paged["total"], 1001)
        self.assertTrue(paged["complete"])
        self.assertEqual(transport.get.call_count, 3)

        transport.get.side_effect = [
            SimpleNamespace(status_code=200, json=lambda: []),
            SimpleNamespace(
                status_code=200,
                json=lambda: [
                    {
                        "session_id": "newly-persisted",
                        "unique_id": "newly-persisted",
                        "username": "alice",
                        "started_at": "2026-10-24T10:00:00Z",
                    }
                ],
            ),
            SimpleNamespace(status_code=200, json=lambda: []),
            SimpleNamespace(status_code=200, json=lambda: []),
        ]
        first = client.list_ssh_sessions()
        second = client.list_ssh_sessions()
        self.assertEqual(first["total"], 1)
        self.assertEqual(second["total"], 0)

    def test_ssh_sessions_include_today_from_live_role_scoped_warpgate_feed(self):
        warpgate_session = {
            "id": "d4cd41ec-2cb4-40f5-a6c2-5fbe063762d6",
            "username": "alice",
            "protocol": "SSH",
            "started": "2026-10-24T14:38:01.345195148Z",
            "ended": None,
            "target": {"name": "prod-linux"},
        }
        web_session = {
            **warpgate_session,
            "id": "b27c4c55-c10d-4204-a6dc-2da50ed41fe1",
            "protocol": "HTTPS",
        }
        transport = Mock()
        transport.get.side_effect = [
            SimpleNamespace(status_code=200, json=lambda: [warpgate_session, web_session]),
            SimpleNamespace(
                status_code=200,
                json=lambda: [
                    {
                        "session_id": warpgate_session["id"],
                        "unique_id": warpgate_session["id"],
                        "username": "alice",
                        "protocol": "SSH",
                        "started_at": "2026-10-24T14:38:01Z",
                    }
                ],
            ),
        ]
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("alice", "developer"),
            transport=transport,
        )

        result = client.list_ssh_sessions(
            start_date=date(2026, 10, 24),
            end_date=date(2026, 10, 24),
            target="prod",
        )

        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["session_id"], warpgate_session["id"])
        self.assertEqual(result["items"][0]["target"], "prod-linux")
        self.assertEqual(result["items"][0]["live_source"], "Warpgate")
        self.assertTrue(result["complete"])
        self.assertEqual(transport.get.call_count, 2)
        self.assertIn("/@warpgate/rrweb/api/warpgate/sessions", transport.get.call_args_list[0].args[0])

    def test_live_warpgate_session_details_do_not_require_a_postgres_mirror(self):
        warpgate_session = {
            "id": "d4cd41ec-2cb4-40f5-a6c2-5fbe063762d6",
            "username": "alice",
            "protocol": "SSH",
            "started": "2026-10-24T14:38:01Z",
            "target": {"name": "prod-linux"},
        }
        transport = Mock()
        transport.get.side_effect = [
            SimpleNamespace(status_code=200, json=lambda: [warpgate_session]),
            SimpleNamespace(status_code=200, json=lambda: []),
        ]
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("alice", "developer"),
            transport=transport,
        )

        result = client.get_session_detail(warpgate_session["id"])

        self.assertEqual(result["target"], "prod-linux")
        self.assertEqual(result["started_at"], "2026-10-24T14:38:01Z")
        self.assertEqual(transport.get.call_count, 2)

    def test_web_recording_activity_is_authorized_bounded_and_excludes_dom_values(self):
        metadata = {
            "sessionId": "session-abcdef123456",
            "username": "alice",
            "target": "prod-web",
            "startedAt": "2026-10-24T10:00:00Z",
        }
        events = [
            {
                "type": 1,
                "timestamp": 1792836000000,
                "data": {"href": "https://example.test/private?token=do-not-forward"},
            },
            {
                "type": 2,
                "timestamp": 1792836001000,
                "data": {"text": "private page content"},
            },
            {
                "type": 3,
                "timestamp": 1792836002000,
                "data": {"source": 5, "text": "private form input"},
            },
        ]
        transport = Mock()
        transport.get.return_value = SimpleNamespace(
            status_code=200,
            json=lambda: metadata,
        )
        stream_response = Mock()
        stream_response.status_code = 200
        stream_response.headers = {}
        stream_response.iter_bytes.return_value = [json.dumps(events).encode()]
        transport.stream.return_value = nullcontext(stream_response)
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("alice", "developer"),
            transport=transport,
        )

        result = client.get_web_recording_activity("session-abcdef123456")

        self.assertEqual(result["activity"]["event_count"], 3)
        self.assertEqual(result["activity"]["activity_types"], {"input_events": 1})
        self.assertEqual(result["activity"]["page_origins"], ["https://example.test"])
        serialized = json.dumps(result)
        self.assertNotIn("private page content", serialized)
        self.assertNotIn("private form input", serialized)
        self.assertNotIn("do-not-forward", serialized)
        self.assertEqual(
            transport.stream.call_args.args[1],
            "https://warpgate.test/@warpgate/rrweb/api/sessions/session-abcdef123456.json",
        )
        self.assertEqual(
            transport.stream.call_args.kwargs["headers"],
            {"Cookie": "warpgate-http-session=abc"},
        )

    def test_web_recording_activity_reports_unfinalized_recording(self):
        transport = Mock()
        transport.get.return_value = SimpleNamespace(
            status_code=200,
            json=lambda: {"sessionId": "session-abcdef123456", "username": "alice"},
        )
        stream_response = Mock()
        stream_response.status_code = 409
        stream_response.headers = {}
        transport.stream.return_value = nullcontext(stream_response)
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("alice", "developer"),
            transport=transport,
        )

        with self.assertRaisesRegex(DataSourceError, "still in progress"):
            client.get_web_recording_activity("session-abcdef123456")

    def test_query_filters_are_applied_without_mixing_web_sessions_into_ssh_results(self):
        identity = AssistantIdentity("auditor", "auditor_viewer")
        client = Mock()
        client.list_ssh_sessions.return_value = {
            "items": [{"session_id": "ssh-1", "started_at": "2026-10-24T09:00:00Z"}],
            "total": 1,
            "complete": True,
        }
        client.enrich_ssh_sessions.side_effect = lambda items: items
        registry = ToolRegistry(settings(), client, identity)
        result = registry.execute(
            "list_sessions",
            json.dumps({"protocol": "all"}),
            "List SSH sessions for alice on host prod",
        )
        self.assertEqual(result["total"], 1)
        client.list_ssh_sessions.assert_called_once()
        self.assertEqual(
            client.list_ssh_sessions.call_args.kwargs["username"],
            "alice",
        )
        self.assertEqual(
            client.list_ssh_sessions.call_args.kwargs["target"],
            "prod",
        )
        client.list_web_sessions.assert_not_called()

    def test_web_recording_activity_tool_routes_through_authorized_client(self):
        identity = AssistantIdentity("alice", "developer")
        client = Mock()
        client.get_web_recording_activity.return_value = {
            "session_id": "session-abcdef123456",
            "activity": {"event_count": 3},
        }
        registry = ToolRegistry(settings(), client, identity)

        result = registry.execute(
            "get_web_recording_activity",
            json.dumps({"session_id": "session-abcdef123456"}),
            "What happened in this browser recording?",
        )

        self.assertEqual(result["activity"]["event_count"], 3)
        client.get_web_recording_activity.assert_called_once_with(
            "session-abcdef123456"
        )

    def test_analyze_web_recordings_pages_live_scope_and_reports_partial_failures(self):
        identity = AssistantIdentity("alice", "developer")
        client = Mock()
        client.list_web_sessions.return_value = {
            "items": [
                {"sessionId": "session-recording-1"},
                {"sessionId": "session-recording-2"},
            ],
            "total": 3,
            "complete": True,
            "source": "live authorized recordings",
        }
        client.get_web_recording_activity.side_effect = [
            {
                "session_id": "session-recording-1",
                "username": "alice",
                "started_at": "2026-10-24T09:00:00Z",
                "activity": {
                    "event_count": 10,
                    "analyzed_event_count": 10,
                    "truncated": False,
                    "activity_types": {"mouse_interactions": 2},
                    "page_origins": ["https://example.test"],
                    "dom_text_included": False,
                    "input_values_included": False,
                },
            },
            DataSourceError("Web recordings", "The Web recording is still in progress."),
        ]
        registry = ToolRegistry(settings(), client, identity)

        result = registry.execute(
            "analyze_web_recordings",
            json.dumps({"limit": 2, "offset": 0}),
            "Analyze all browser recordings",
        )

        client.list_web_sessions.assert_called_once_with(
            start_date=None,
            end_date=None,
            limit=2,
            offset=0,
        )
        self.assertEqual(result["analyzed_count"], 1)
        self.assertEqual(result["unavailable_count"], 1)
        self.assertEqual(result["next_offset"], 2)
        self.assertFalse(result["complete"])
        self.assertFalse(result["items"][0]["activity"]["dom_text_included"])

    def test_analyze_web_recordings_reports_complete_after_final_page(self):
        client = Mock()
        client.list_web_sessions.return_value = {
            "items": [
                {"sessionId": "session-recording-1"},
            ],
            "total": 1,
            "complete": True,
            "source": "live authorized recordings",
        }
        client.get_web_recording_activity.return_value = {
            "session_id": "session-recording-1",
            "activity": {"event_count": 1},
        }
        registry = ToolRegistry(
            settings(),
            client,
            AssistantIdentity("auditor", "auditor_viewer"),
        )

        result = registry.execute(
            "analyze_web_recordings",
            json.dumps({}),
            "Analyze all Web recordings",
        )

        self.assertEqual(result["recordings_total"], 1)
        self.assertEqual(result["next_offset"], None)
        self.assertTrue(result["complete"])

    def test_question_protocol_and_active_status_override_model_misrouting(self):
        identity = AssistantIdentity("auditor", "auditor_viewer")
        client = Mock()
        client.list_ssh_sessions.return_value = {
            "items": [
                {
                    "session_id": "open-1",
                    "unique_id": "open-1",
                    "username": "alice",
                    "started_at": "2026-10-24T09:00:00Z",
                }
            ],
            "total": 1,
            "complete": True,
        }
        client.get_session_related.return_value = [
            {
                "event_type": "session_started",
                "timestamp": "2026-10-24T09:00:00Z",
            }
        ]
        client.enrich_ssh_sessions.side_effect = lambda items: items
        registry = ToolRegistry(settings(), client, identity)
        result = registry.execute(
            "list_sessions",
            json.dumps({"protocol": "all", "active_only": False}),
            "Which SSH sessions are currently active?",
        )
        self.assertEqual(result["total"], 1)
        client.list_web_sessions.assert_not_called()
        client.get_session_related.assert_called_once_with("open-1", "events")

    def test_active_session_count_uses_lifecycle_evidence_not_missing_logout(self):
        identity = AssistantIdentity("auditor", "auditor_viewer")
        client = Mock()
        client.list_ssh_sessions.return_value = {
            "items": [
                {
                    "session_id": "open-1",
                    "unique_id": "open-1",
                    "username": "alice",
                    "started_at": "2026-10-24T09:00:00Z",
                },
                {
                    "session_id": "closed-1",
                    "unique_id": "closed-1",
                    "username": "bob",
                    "started_at": "2026-10-24T08:00:00Z",
                },
            ],
            "total": 2,
            "complete": True,
        }
        client.get_session_related.side_effect = [
            [
                {
                    "event_type": "session_started",
                    "timestamp": "2026-10-24T09:00:00Z",
                }
            ],
            [
                {
                    "event_type": "session_started",
                    "timestamp": "2026-10-24T08:00:00Z",
                },
                {
                    "event_type": "session_ended",
                    "timestamp": "2026-10-24T08:15:00Z",
                },
            ],
        ]
        client.enrich_ssh_sessions.side_effect = lambda items: items
        registry = ToolRegistry(settings(), client, identity)
        result = registry.execute(
            "get_session_counts",
            json.dumps({"protocol": "ssh"}),
            "How many SSH sessions are currently active?",
        )
        self.assertEqual(result["ssh_count"], 1)
        self.assertEqual(result["total"], 1)

    def test_active_web_count_is_unknown_not_a_false_zero(self):
        identity = AssistantIdentity("auditor", "auditor_viewer")
        registry = ToolRegistry(settings(), Mock(), identity)
        result = registry.execute(
            "get_session_counts",
            json.dumps({"protocol": "web"}),
            "How many Web sessions are currently active?",
        )
        self.assertIsNone(result["web_count"])
        self.assertIsNone(result["total"])
        self.assertIn("not exposed", result["web_active_status"])

    def test_ssh_target_filter_uses_authenticated_session_detail(self):
        transport = Mock()
        transport.get.side_effect = [
            SimpleNamespace(status_code=200, json=lambda: []),
            SimpleNamespace(
                status_code=200,
                json=lambda: [
                    {
                        "session_id": "ssh-1",
                        "unique_id": "ssh-1",
                        "username": "alice",
                        "started_at": "2026-10-24T09:00:00Z",
                    }
                ],
            ),
            SimpleNamespace(
                status_code=200,
                json=lambda: {
                    "session_id": "ssh-1",
                    "unique_id": "ssh-1",
                    "username": "alice",
                    "target": "prod-linux",
                },
            ),
        ]
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("alice", "developer"),
            transport=transport,
        )
        result = client.list_ssh_sessions(target="prod")
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["target"], "prod-linux")

    def test_unavailable_session_sources_return_explicit_incomplete_result(self):
        transport = Mock()
        transport.get.side_effect = __import__("httpx").ConnectError("offline")
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("alice", "developer"),
            transport=transport,
        )
        result = client.list_ssh_sessions()
        self.assertEqual(result["items"], [])
        self.assertFalse(result["complete"])
        self.assertEqual(len(result["warnings"]), 2)

    def test_developer_cannot_retrieve_another_users_commands(self):
        transport = Mock()
        transport.get.return_value = SimpleNamespace(
            status_code=200,
            json=lambda: [
                {
                    "session_id": "someone-elses-session",
                    "unique_id": "someone-elses-session",
                    "username": "bob",
                    "started_at": "2026-10-24T09:00:00Z",
                }
            ],
        )
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("alice", "developer"),
            transport=transport,
        )
        with self.assertRaises(DataSourceError):
            client.get_session_related("someone-elses-session", "commands")
        self.assertEqual(transport.get.call_count, 2)

    def test_web_query_cannot_override_developer_scope(self):
        transport = Mock()
        transport.get.return_value = SimpleNamespace(
            status_code=200,
            json=lambda: {"items": [], "total": 0},
        )
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("alice", "developer"),
            transport=transport,
        )
        result = client.list_web_sessions(username="bob")
        self.assertEqual(result["total"], 0)
        self.assertEqual(transport.get.call_args.kwargs["params"]["username"], "alice")

    def test_web_session_count_deduplicates_by_recording_session_id(self):
        record = {
            "sessionId": "session-web-1",
            "username": "auditor",
            "target": "browser",
            "startedAt": "2026-10-24T09:00:00Z",
        }
        transport = Mock()
        transport.get.return_value = SimpleNamespace(
            status_code=200,
            json=lambda: {"items": [record, dict(record)], "total": 2},
        )
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("auditor", "auditor_viewer"),
            transport=transport,
        )
        result = client.list_web_sessions()
        self.assertEqual(result["total"], 1)
        self.assertEqual(len(result["items"]), 1)

    def test_tool_registry_rejects_arbitrary_sql_and_uses_read_only_audit_reader(self):
        identity = AssistantIdentity("auditor", "auditor_viewer")
        reader = Mock()
        reader.list_incidents.return_value = {"items": [], "total": 0}
        registry = ToolRegistry(
            settings(audit_database_url="postgresql://readonly@localhost/safe"),
            Mock(),
            identity,
            incidents_reader=reader,
        )
        with self.assertRaises(ValueError):
            registry.execute("get_session_counts", json.dumps({"sql": "drop table sessions"}), "count")
        result = registry.execute(
            "list_security_incidents",
            json.dumps({"username": "admin"}),
            "list incidents",
        )
        self.assertEqual(result["total"], 0)
        reader.list_incidents.assert_called_once()

    def test_audit_log_reader_fetches_both_sources_with_authenticated_cookie(self):
        transport = Mock()
        transport.get.side_effect = [
            SimpleNamespace(
                status_code=200,
                json=lambda: [{"id": "ui-1", "username": "alice"}],
            ),
            SimpleNamespace(
                status_code=200,
                json=lambda: [{"id": "gateway-1", "username": "alice"}],
            ),
        ]
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("alice", "auditor_viewer"),
            transport=transport,
        )

        result = client.list_audit_logs(search="alice", limit=100)

        self.assertEqual(result["secure_access_events"][0]["id"], "ui-1")
        self.assertEqual(result["warpgate_events"][0]["id"], "gateway-1")
        self.assertTrue(result["complete"])
        self.assertEqual(transport.get.call_count, 2)
        self.assertEqual(
            transport.get.call_args_list[0].kwargs["headers"]["Cookie"],
            "warpgate-http-session=abc",
        )
        self.assertEqual(
            transport.get.call_args_list[0].kwargs["params"],
            {"limit": 100, "search": "alice"},
        )

    def test_developers_cannot_read_admin_auditor_only_audit_logs(self):
        transport = Mock()
        client = SecureAccessClient(
            settings(),
            "warpgate-http-session=abc",
            AssistantIdentity("alice", "developer"),
            transport=transport,
        )

        with self.assertRaisesRegex(DataSourceError, "restricted to admin and auditor"):
            client.list_audit_logs()
        transport.get.assert_not_called()

    def test_audit_log_arguments_enforce_endpoint_limits(self):
        with self.assertRaises(ValueError):
            AuditLogArguments.model_validate({"limit": 501})
        with self.assertRaises(ValueError):
            AuditLogArguments.model_validate({"search": "x" * 201})

    def test_existing_audit_sources_are_reported_as_available(self):
        identity = AssistantIdentity("auditor", "auditor_viewer")
        registry = ToolRegistry(settings(), Mock(), identity)
        status = registry.execute("get_data_source_status", "{}", "status")
        self.assertIn("UI events", status["audit_log"])
        self.assertIn("500 recent", status["audit_log"])
        self.assertIn("no separate third", status["universal_log"])

    def test_application_knowledge_is_verified_and_keeps_addon_separate(self):
        registry = ToolRegistry(
            settings(),
            Mock(),
            AssistantIdentity("auditor", "auditor_viewer"),
        )
        facts = registry.execute("get_application_knowledge", "{}", "How is Secure Access built?")
        self.assertIn("FastAPI", facts["backend"])
        self.assertIn("separate", facts["existing_assistant"])
        self.assertIn("Warpgate gateway audit events", facts["audit_logs"])
        self.assertIn("no scheduled-session source", facts["limitations"])

    def test_system_questions_require_tool_retrieval_and_general_questions_do_not(self):
        self.assertTrue(SYSTEM_DATA_QUERY.search("What did users do in SSH sessions?"))
        self.assertTrue(SYSTEM_DATA_QUERY.search("Search audit logs for access events"))
        self.assertTrue(SYSTEM_DATA_QUERY.search("Summarize all recordings in PostgreSQL"))
        self.assertFalse(SYSTEM_DATA_QUERY.search("Explain how public key cryptography works"))

    def test_archive_summary_queries_prefetch_postgresql_session_and_command_summaries(self):
        provider = Mock()
        provider.complete.return_value = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="The archive contains three sessions.",
                        tool_calls=[],
                    )
                )
            ]
        )
        registry = Mock()
        registry.execute.return_value = {
            "scope": "postgresql",
            "session_count": 3,
            "command_count": 7,
            "session_summaries": [{"session_id": "session-1", "commands": ["whoami"]}],
            "matches": [{"command": "whoami", "output": "sensitive output"}],
            "session_summaries_complete": True,
        }
        service = ChatbotService(
            settings(),
            Mock(),
            registry,
            provider_factory=lambda _settings: provider,
        )

        result = service.answer(
            "Summarize all sessions from the recordings stored in PostgreSQL.",
            AssistantIdentity("auditor", "auditor_viewer"),
        )

        self.assertEqual(result["answer"], "The archive contains three sessions.")
        registry.execute.assert_called_once_with(
            "analyze_ssh_command_archive",
            json.dumps({"limit": 100, "session_limit": 25}),
            "Summarize all sessions from the recordings stored in PostgreSQL.",
        )
        self.assertNotIn(
            "sensitive output",
            provider.complete.call_args.kwargs["messages"][0]["content"],
        )

    def test_groq_is_required_for_session_answers_and_tool_results_are_grounded(self):
        tool_call = SimpleNamespace(
            id="call-1",
            function=SimpleNamespace(
                name="get_session_counts",
                arguments=json.dumps({"protocol": "ssh"}),
            ),
        )
        tool_response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=None, tool_calls=[tool_call])
                )
            ]
        )
        final_response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="There are 3 SSH sessions.", tool_calls=[])
                )
            ]
        )

        class FakeProvider:
            def __init__(self):
                self.responses = [tool_response, final_response]
                self.calls = []

            def complete(self, **kwargs):
                self.calls.append(kwargs)
                return self.responses.pop(0)

        provider = FakeProvider()
        registry = Mock()
        registry.execute.return_value = {"ssh_count": 3, "complete": True}
        identity = AssistantIdentity("auditor", "auditor_viewer")
        service = ChatbotService(
            settings(),
            Mock(),
            registry,
            provider_factory=lambda _settings: provider,
        )
        result = service.answer("How many SSH sessions are recorded?", identity)
        self.assertEqual(result["answer"], "There are 3 SSH sessions.")
        self.assertEqual(result["retrieval_mode"], "groq-grounded")
        self.assertEqual(len(provider.calls), 2)
        self.assertIsNotNone(provider.calls[0]["tools"])
        self.assertEqual(provider.calls[0]["tool_choice"], "auto")
        self.assertEqual(provider.calls[1]["tool_choice"], "auto")
        registry.execute.assert_called_once()

    def test_risky_command_questions_use_archive_wide_postgresql_evidence(self):
        provider = Mock()
        provider.complete.return_value = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="I don't have visibility into command history.",
                        tool_calls=[],
                    )
                )
            ]
        )
        registry = Mock()
        registry.execute.return_value = {
            "scope": "postgresql",
            "session_count": 120,
            "command_count": 340,
            "risky_command_count": 1,
            "match_count": 1,
            "matches": [
                {
                    "session_id": "session-risk",
                    "command": "sudo -l",
                    "output": "sensitive output omitted from model",
                    "risk_findings": [
                        {"severity": "HIGH", "category": "PRIVILEGE_ESCALATION"}
                    ],
                }
            ],
            "complete": True,
        }
        service = ChatbotService(
            settings(),
            Mock(),
            registry,
            provider_factory=lambda _settings: provider,
        )

        result = service.answer(
            "Were any risky commands executed?",
            AssistantIdentity("auditor", "auditor_viewer"),
        )

        self.assertIn("1 command(s) matched", result["answer"])
        self.assertIn("`sudo -l`", result["answer"])
        self.assertNotIn("sensitive output", provider.complete.call_args.kwargs["messages"][0]["content"])
        registry.execute.assert_called_once_with(
            "analyze_ssh_command_archive",
            json.dumps({"risky_only": True, "limit": 100}),
            "Were any risky commands executed?",
        )
        self.assertEqual(result["retrieval_mode"], "groq-grounded")

    def test_high_risk_session_question_uses_archive_evidence_and_includes_timestamps(self):
        provider = Mock()
        registry = Mock()
        registry.execute.return_value = {
            "scope": "postgresql",
            "session_count": 120,
            "command_count": 340,
            "risky_command_count": 2,
            "match_count": 2,
            "matches": [
                {
                    "session_id": "session-recent",
                    "username": "alice",
                    "started_at": "2026-10-25T04:00:00Z",
                    "executed_at": "2026-10-25T04:01:00Z",
                    "command": "sudo -l",
                    "risk_findings": [
                        {"severity": "HIGH", "category": "PRIVILEGE_ESCALATION"}
                    ],
                },
                {
                    "session_id": "session-recent",
                    "username": "alice",
                    "started_at": "2026-10-25T04:00:00Z",
                    "executed_at": "2026-10-25T04:02:00Z",
                    "command": "cat /etc/shadow",
                    "risk_findings": [
                        {"severity": "HIGH", "category": "CREDENTIAL_FILE_ACCESS"}
                    ],
                },
            ],
            "complete": True,
        }
        service = ChatbotService(
            settings(),
            Mock(),
            registry,
            provider_factory=lambda _settings: provider,
        )

        result = service.answer(
            "explain recent high risk sessions",
            AssistantIdentity("auditor", "auditor_viewer"),
        )

        self.assertIn("session-recent", result["answer"])
        self.assertIn("alice", result["answer"])
        self.assertIn("2026-10-25T04:00:00Z", result["answer"])
        self.assertIn("2026-10-25T04:01:00Z", result["answer"])
        self.assertIn("HIGH PRIVILEGE_ESCALATION", result["answer"])
        self.assertIn("command-level rule matches", result["answer"])
        self.assertTrue(result["evidence_available"])
        provider.complete.assert_not_called()
        registry.execute.assert_called_once_with(
            "analyze_ssh_command_archive",
            json.dumps({"risky_only": True, "limit": 100}),
            "explain recent high risk sessions",
        )

    def test_system_question_without_model_tool_call_uses_read_only_fallback(self):
        no_tool_response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=None, tool_calls=[])
                )
            ]
        )
        grounded_response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="There are 3 sessions in the retrieved result.",
                        tool_calls=[],
                    )
                )
            ]
        )

        class FakeProvider:
            def __init__(self):
                self.responses = [no_tool_response, grounded_response]

            def complete(self, **_kwargs):
                return self.responses.pop(0)

        registry = Mock()
        registry.execute.return_value = {"total": 3, "complete": True}
        service = ChatbotService(
            settings(),
            Mock(),
            registry,
            provider_factory=lambda _settings: FakeProvider(),
        )
        result = service.answer(
            "How many sessions are recorded?",
            AssistantIdentity("auditor", "auditor_viewer"),
        )

        self.assertEqual(result["answer"], "There are 3 sessions in the retrieved result.")
        self.assertTrue(result["evidence_available"])
        registry.execute.assert_called_once_with(
            "get_session_counts",
            json.dumps({"protocol": "all"}),
            "How many sessions are recorded?",
        )

    def test_tool_round_limit_returns_answer_with_incomplete_evidence_warning(self):
        tool_call = SimpleNamespace(
            id="call-1",
            function=SimpleNamespace(
                name="get_session_counts",
                arguments=json.dumps({"protocol": "ssh"}),
            ),
        )
        tool_response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=None, tool_calls=[tool_call])
                )
            ]
        )
        final_response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="The retrieved page contains session evidence.",
                        tool_calls=[],
                    )
                )
            ]
        )

        class FakeProvider:
            def complete(self, *, tools, **_kwargs):
                return tool_response if tools is not None else final_response

        service = ChatbotService(
            settings(),
            Mock(),
            Mock(),
            provider_factory=lambda _settings: FakeProvider(),
        )

        result = service.answer(
            "How many SSH sessions are recorded?",
            AssistantIdentity("auditor", "auditor_viewer"),
        )

        self.assertEqual(
            result["answer"],
            "The retrieved page contains session evidence.",
        )
        self.assertIn("results may be incomplete", result["evidence_summary"])

    def test_tool_evidence_has_a_cumulative_request_budget(self):
        tool_call = SimpleNamespace(
            id="call-1",
            function=SimpleNamespace(
                name="get_session_counts",
                arguments=json.dumps({"protocol": "ssh"}),
            ),
        )
        tool_response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=None, tool_calls=[tool_call])
                )
            ]
        )
        final_response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="The available evidence is partial.",
                        tool_calls=[],
                    )
                )
            ]
        )
        calls = []

        class FakeProvider:
            def complete(self, **kwargs):
                calls.append(kwargs)
                return tool_response if kwargs["tools"] is not None else final_response

        registry = Mock()
        registry.execute.return_value = {"result": "x" * 20000}
        service = ChatbotService(
            settings(),
            Mock(),
            registry,
            provider_factory=lambda _settings: FakeProvider(),
        )

        result = service.answer(
            "How many SSH sessions are recorded?",
            AssistantIdentity("auditor", "auditor_viewer"),
        )

        final_tool_content = [
            message["content"]
            for message in calls[-1]["messages"]
            if message["role"] == "tool"
        ]
        self.assertLessEqual(sum(map(len, final_tool_content)), 32000)
        self.assertIn("evidence size limit was reached", result["evidence_summary"])

    def test_provider_payload_rejection_reduces_evidence_and_retries_as_partial(self):
        tool_call = SimpleNamespace(
            id="call-large-result",
            function=SimpleNamespace(
                name="get_session_counts",
                arguments=json.dumps({"protocol": "ssh"}),
            ),
        )
        tool_response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=None, tool_calls=[tool_call])
                )
            ]
        )
        final_response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="The retrieved session count is available.",
                        tool_calls=[],
                    )
                )
            ]
        )

        class FakeProvider:
            def __init__(self):
                self.calls = []
                self.tool_content_snapshots = []

            def complete(self, **kwargs):
                self.calls.append(kwargs)
                self.tool_content_snapshots.append(
                    [
                        message["content"]
                        for message in kwargs["messages"]
                        if message["role"] == "tool"
                    ]
                )
                if len(self.calls) == 1:
                    return tool_response
                if len(self.calls) == 2:
                    raise GroqPayloadTooLargeError("provider payload limit")
                return final_response

        provider = FakeProvider()
        registry = Mock()
        registry.execute.return_value = {"large_values": ["x" * 1000 for _ in range(25)]}
        service = ChatbotService(
            settings(),
            Mock(),
            registry,
            provider_factory=lambda _settings: provider,
        )

        result = service.answer(
            "How many SSH sessions are recorded?",
            AssistantIdentity("auditor", "auditor_viewer"),
        )

        self.assertEqual(len(provider.calls), 3)
        original_tool = provider.tool_content_snapshots[1][0]
        reduced_tool = provider.tool_content_snapshots[2][0]
        self.assertGreater(len(original_tool), len(reduced_tool))
        self.assertIn("incomplete", reduced_tool)
        retried_system = provider.calls[2]["messages"][0]["content"]
        self.assertIn("compacted after the provider rejected", retried_system)
        self.assertTrue(result["evidence_available"])
        self.assertIn("Evidence was reduced", result["evidence_summary"])
        self.assertIn("may be partial", result["evidence_summary"])

    def test_missing_groq_key_and_provider_outages_are_explicit(self):
        with self.assertRaises(ConfigurationError):
            GroqProvider(settings(groq_api_key=""))

        failing = Mock()
        failing.chat.completions.create.side_effect = TimeoutError("private details")
        provider = GroqProvider(settings(), client=failing)
        with self.assertRaises(GroqProviderError) as raised:
            provider.complete(messages=[], tools=None)
        self.assertNotIn("private details", str(raised.exception))
        self.assertIn("timed out", str(raised.exception))

    def test_groq_provider_errors_identify_actionable_status_without_leaking_body(self):
        failing = Mock()

        class RateLimitError(Exception):
            status_code = 429

        rate_limit_error = RateLimitError("secret response body")
        rate_limit_error.response = SimpleNamespace(
            headers={"retry-after": "17"}
        )
        failing.chat.completions.create.side_effect = rate_limit_error
        provider = GroqProvider(settings(), client=failing)

        with self.assertRaises(GroqRateLimitError) as raised:
            provider.complete(messages=[], tools=None)

        self.assertIn("rate-limited", str(raised.exception))
        self.assertIn("17 seconds", str(raised.exception))
        self.assertEqual(raised.exception.retry_after_seconds, 17)
        self.assertNotIn("secret response body", str(raised.exception))
        rate_limit_exception = raised.exception

        reset_error = RateLimitError("provider response omitted")
        reset_error.response = SimpleNamespace(
            headers={"x-ratelimit-reset-tokens": "1m2.5s"}
        )
        failing.chat.completions.create.side_effect = reset_error
        with self.assertRaises(GroqRateLimitError) as raised:
            provider.complete(messages=[], tools=None)
        self.assertEqual(raised.exception.retry_after_seconds, 63)

        client = TestClient(app)
        with (
            patch("backend.app.Settings.from_env", return_value=settings()),
            patch(
                "backend.app.authenticate_cookie",
                return_value=("cookie", AssistantIdentity("alice", "auditor")),
            ),
            patch(
                "backend.app.ChatbotService.answer",
                side_effect=rate_limit_exception,
            ),
        ):
            response = client.post("/api/chat", json={"message": "How many sessions?"})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["retry-after"], "17")
        self.assertIn("17 seconds", response.json()["detail"])

        class PayloadTooLargeError(Exception):
            status_code = 413

        failing.chat.completions.create.side_effect = PayloadTooLargeError(
            "private provider details"
        )
        with self.assertRaises(GroqProviderError) as raised:
            provider.complete(messages=[], tools=None)

        self.assertIn("payload exceeded the provider limit", str(raised.exception))
        self.assertNotIn("private provider details", str(raised.exception))
        self.assertIsInstance(raised.exception, GroqPayloadTooLargeError)


if __name__ == "__main__":
    unittest.main()
