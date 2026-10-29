from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROPOSAL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "groq_ai_addon"))
sys.path.insert(0, str(PROPOSAL_DIR))

from backend.chatbot_service import (  # noqa: E402
    MAX_TOTAL_TOOL_OUTPUT,
    MAX_TOOL_OUTPUT,
    ChatbotService,
    _bounded_evidence_json,
    _assistant_tool_message,
    _tools_for_question,
)
from backend.config import ConfigurationError, Settings  # noqa: E402
from backend.groq_client import GroqProvider, GroqProviderError  # noqa: E402
from backend.security import AssistantIdentity  # noqa: E402
from backend.tool_registry import TOOL_DEFINITIONS  # noqa: E402
from proposal_contract import (  # noqa: E402
    ContractError,
    classify_provider_error,
    validate_model_features,
    validate_tool_choice,
    validate_tool_history,
    validate_tools,
)


def make_settings(**overrides):
    values = {
        "groq_api_key": "test-key-only",
        "groq_model": "openai/gpt-oss-120b",
        "groq_timeout_seconds": 2.0,
        "secure_access_timeout_seconds": 2.0,
        "secure_access_api_url": "http://secure-access.test",
        "warpgate_url": "https://warpgate.test",
        "warpgate_ca_bundle": None,
        "app_timezone": "UTC",
        "audit_database_url": None,
        "audit_query_timeout_seconds": 2.0,
    }
    values.update(overrides)
    return Settings(**values)


def provider_message(content=None, tool_calls=None):
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=content, tool_calls=tool_calls or [])
            )
        ]
    )


def tool_call(call_id, name, arguments):
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=json.dumps(arguments)),
    )


def make_chatbot_service(registry, provider_factory):
    service = ChatbotService(
        make_settings(),
        Mock(),
        registry,
        provider_factory=provider_factory,
    )
    service._system_prompt = lambda _identity, _uses_system_data: "synthetic test prompt"
    return service


class ToolSchemaTests(unittest.TestCase):
    def test_all_tool_definitions_pass_local_schema_validation(self):
        serialized_bytes = validate_tools(TOOL_DEFINITIONS)
        self.assertEqual(len(TOOL_DEFINITIONS), 12)
        self.assertGreater(serialized_bytes, 0)
        self.assertLess(len(TOOL_DEFINITIONS), 128)

    def test_invalid_tool_envelopes_and_schemas_are_rejected(self):
        invalid = [
            [{"type": "not_function", "function": {}}],
            [
                {
                    "type": "function",
                    "function": {
                        "name": "wrong-required",
                        "description": "test",
                        "parameters": {
                            "type": "object",
                            "properties": {"x": {"type": "string"}},
                            "required": ["missing"],
                        },
                    },
                }
            ],
            [
                {
                    "type": "function",
                    "function": {
                        "name": "unsupported",
                        "description": "test",
                        "parameters": {
                            "type": "object",
                            "properties": {},
                            "patternProperties": {},
                        },
                    },
                }
            ],
            [
                {
                    "type": "function",
                    "function": {
                        "name": "double",
                        "description": "test",
                        "parameters": json.dumps({"type": "object", "properties": {}}),
                    },
                }
            ],
        ]
        for tools in invalid:
            with self.subTest(tools=tools), self.assertRaises(ContractError):
                validate_tools(tools)

    def test_duplicate_names_and_more_than_documented_function_limit_are_rejected(self):
        definition = {
            "type": "function",
            "function": {
                "name": "unique",
                "description": "test",
                "parameters": {"type": "object", "properties": {}},
            },
        }
        with self.assertRaisesRegex(ContractError, "duplicate"):
            validate_tools([definition, definition])
        too_many = [
            {
                "type": "function",
                "function": {
                    "name": f"tool_{index}",
                    "description": "test",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
            for index in range(129)
        ]
        with self.assertRaisesRegex(ContractError, "limit"):
            validate_tools(too_many)


class ModelAndChoiceTests(unittest.TestCase):
    def test_tool_choice_supported_and_unsupported_values(self):
        for value in ("auto", "required", "none"):
            with self.subTest(value=value):
                validate_tool_choice(
                    value,
                    tool_names={"get_session_counts"},
                    tools_present=True,
                )
        validate_tool_choice(
            {
                "type": "function",
                "function": {"name": "get_session_counts"},
            },
            tool_names={"get_session_counts"},
            tools_present=True,
        )
        for value in ("sometimes", "required", {"type": "function", "function": {"name": "missing"}}):
            if value == "required":
                with self.assertRaises(ContractError):
                    validate_tool_choice(value, tool_names=set(), tools_present=False)
            else:
                with self.assertRaises(ContractError):
                    validate_tool_choice(value, tool_names=set(), tools_present=True)

    def test_gpt_oss_120b_capabilities_are_checked_without_model_substitution(self):
        validate_model_features(
            "openai/gpt-oss-120b",
            tools_present=True,
            parallel_tool_calls=False,
            response_format="json_object",
            stream=False,
        )
        with self.assertRaisesRegex(ContractError, "parallel"):
            validate_model_features(
                "openai/gpt-oss-120b",
                tools_present=True,
                parallel_tool_calls=True,
                response_format=None,
                stream=False,
            )
        with self.assertRaisesRegex(ContractError, "not verified"):
            validate_model_features(
                "unverified/model",
                tools_present=True,
                parallel_tool_calls=False,
                response_format=None,
                stream=False,
            )

    def test_provider_uses_non_streaming_auto_tool_choice_and_no_json_mode(self):
        client = Mock()
        client.chat.completions.create.return_value = "response"
        provider = GroqProvider(make_settings(), client=client)
        tools = _tools_for_question("How many SSH sessions?")

        provider.complete(
            messages=[{"role": "user", "content": "How many SSH sessions?"}],
            tools=tools,
        )

        sent = client.chat.completions.create.call_args.kwargs
        self.assertEqual(sent["model"], "openai/gpt-oss-120b")
        self.assertEqual(sent["tool_choice"], "auto")
        self.assertIs(sent["parallel_tool_calls"], False)
        self.assertNotIn("stream", sent)
        self.assertNotIn("response_format", sent)


class ToolHistoryTests(unittest.TestCase):
    def test_assistant_tool_message_preserves_call_ids_and_arguments(self):
        message = SimpleNamespace(
            content=None,
            tool_calls=[
                tool_call("call-1", "get_session_counts", {"protocol": "ssh"}),
            ],
        )
        serialized = _assistant_tool_message(message)
        self.assertEqual(serialized["role"], "assistant")
        self.assertEqual(serialized["tool_calls"][0]["id"], "call-1")
        self.assertEqual(serialized["tool_calls"][0]["function"]["name"], "get_session_counts")
        self.assertEqual(
            json.loads(serialized["tool_calls"][0]["function"]["arguments"]),
            {"protocol": "ssh"},
        )

    def test_tool_history_accepts_one_and_multiple_matching_results(self):
        calls = [
            {
                "id": "call-1",
                "type": "function",
                "function": {"name": "get_session_counts", "arguments": '{"protocol":"ssh"}'},
            },
            {
                "id": "call-2",
                "type": "function",
                "function": {"name": "get_data_source_status", "arguments": "{}"},
            },
        ]
        messages = [
            {"role": "user", "content": "test"},
            {"role": "assistant", "content": None, "tool_calls": calls},
            {
                "role": "tool",
                "tool_call_id": "call-1",
                "name": "get_session_counts",
                "content": '{"total": 2}',
            },
            {
                "role": "tool",
                "tool_call_id": "call-2",
                "name": "get_data_source_status",
                "content": '{"available": true}',
            },
        ]
        validate_tool_history(messages)

    def test_tool_history_rejects_orphan_invalid_and_duplicate_call_ids(self):
        with self.assertRaisesRegex(ContractError, "no result"):
            validate_tool_history(
                [
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call-1",
                                "function": {"name": "x", "arguments": "{}"},
                            }
                        ],
                    }
                ]
            )
        with self.assertRaisesRegex(ContractError, "does not match"):
            validate_tool_history(
                [
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call-1",
                                "function": {"name": "x", "arguments": "{}"},
                            }
                        ],
                    },
                    {
                        "role": "tool",
                        "tool_call_id": "other",
                        "name": "x",
                        "content": "{}",
                    },
                ]
            )
        with self.assertRaisesRegex(ContractError, "Orphan"):
            validate_tool_history(
                [{"role": "tool", "tool_call_id": "orphan", "name": "x", "content": "{}"}]
            )


class ChatbotRoundTripTests(unittest.TestCase):
    def test_normal_response_without_tool_calls(self):
        class FakeProvider:
            def complete(self, **kwargs):
                self.kwargs = kwargs
                return provider_message("SSH uses encrypted transport.")

        provider = FakeProvider()
        service = make_chatbot_service(Mock(), lambda _settings: provider)
        result = service.answer(
            "Explain encrypted transport.",
            AssistantIdentity("analyst", "auditor_viewer"),
        )
        self.assertEqual(result["answer"], "SSH uses encrypted transport.")
        self.assertIsNone(provider.kwargs["tools"])
        self.assertEqual(provider.kwargs["tool_choice"], "none")

    def test_one_tool_call_retrieves_and_serializes_bounded_evidence(self):
        call = tool_call("call-count", "get_session_counts", {"protocol": "ssh"})
        responses = [
            provider_message(tool_calls=[call]),
            provider_message("Two SSH sessions were recorded."),
        ]

        class FakeProvider:
            def __init__(self):
                self.requests = []

            def complete(self, **kwargs):
                self.requests.append(kwargs)
                return responses.pop(0)

        registry = Mock()
        registry.execute.return_value = {"ssh_count": 2, "complete": True}
        provider = FakeProvider()
        service = make_chatbot_service(registry, lambda _settings: provider)
        result = service.answer(
            "How many SSH sessions are recorded?",
            AssistantIdentity("analyst", "auditor_viewer"),
        )
        self.assertEqual(result["answer"], "Two SSH sessions were recorded.")
        second_messages = provider.requests[1]["messages"]
        validate_tool_history(second_messages)
        result_message = next(item for item in second_messages if item["role"] == "tool")
        self.assertEqual(result_message["tool_call_id"], "call-count")
        self.assertEqual(json.loads(result_message["content"]), {"ssh_count": 2, "complete": True})

    def test_multiple_tool_calls_receive_one_matching_result_each(self):
        calls = [
            tool_call("call-count", "get_session_counts", {"protocol": "all"}),
            tool_call("call-status", "get_data_source_status", {}),
        ]
        responses = [
            provider_message(tool_calls=calls),
            provider_message("The evidence is available."),
        ]

        class FakeProvider:
            def __init__(self):
                self.requests = []

            def complete(self, **kwargs):
                self.requests.append(kwargs)
                return responses.pop(0)

        registry = Mock()
        registry.execute.side_effect = [
            {"total": 2},
            {"sources": [{"name": "SSH", "available": True}]},
        ]
        provider = FakeProvider()
        service = make_chatbot_service(registry, lambda _settings: provider)
        service.answer(
            "How many sessions and what is data source status?",
            AssistantIdentity("analyst", "auditor_viewer"),
        )
        validate_tool_history(provider.requests[1]["messages"])
        results = [
            item for item in provider.requests[1]["messages"]
            if item["role"] == "tool"
        ]
        self.assertEqual(
            [(item["tool_call_id"], item["name"]) for item in results],
            [
                ("call-count", "get_session_counts"),
                ("call-status", "get_data_source_status"),
            ],
        )
        self.assertEqual(registry.execute.call_count, 2)

    def test_invalid_tool_arguments_abort_without_followup_completion(self):
        call = tool_call("call-invalid", "get_session_counts", {"protocol": "bad"})
        provider = Mock()
        provider.complete.return_value = provider_message(tool_calls=[call])
        registry = Mock()
        registry.execute.side_effect = ValueError("invalid arguments")
        service = make_chatbot_service(registry, lambda _settings: provider)

        with self.assertRaises(Exception) as raised:
            service.answer(
                "How many sessions are recorded?",
                AssistantIdentity("analyst", "auditor_viewer"),
            )
        self.assertEqual(provider.complete.call_count, 1)
        self.assertIn("invalid arguments", str(raised.exception))

    def test_per_result_and_cumulative_evidence_limits_are_preserved(self):
        self.assertEqual(MAX_TOOL_OUTPUT, 10000)
        self.assertEqual(MAX_TOTAL_TOOL_OUTPUT, 32000)
        oversized = _bounded_evidence_json(
            json.dumps({"payload": "x" * 20000}),
            MAX_TOOL_OUTPUT,
            note="Evidence exceeded the per-result limit.",
        )
        self.assertLessEqual(len(oversized), MAX_TOOL_OUTPUT)
        self.assertIn(
            "Evidence exceeded the per-result limit.",
            json.loads(oversized)["note"],
        )
        calls = [
            tool_call(f"call-{round_number}-{tool_number}", name, arguments)
            for round_number in (1, 2)
            for tool_number, (name, arguments) in enumerate(
                [
                    ("get_session_counts", {"protocol": "all"}),
                    ("list_sessions", {"limit": 20}),
                    ("get_session_details", {"session_id": "synthetic"}),
                    ("get_data_source_status", {}),
                ],
                start=1,
            )
        ]
        responses = [
            provider_message(tool_calls=calls[:4]),
            provider_message(tool_calls=calls[4:]),
            provider_message("The result is partial."),
        ]

        class FakeProvider:
            def __init__(self):
                self.requests = []

            def complete(self, **kwargs):
                self.requests.append(kwargs)
                return responses.pop(0)

        registry = Mock()
        registry.execute.return_value = {"payload": "x" * 15000}
        provider = FakeProvider()
        service = make_chatbot_service(registry, lambda _settings: provider)
        result = service.answer(
            "How many sessions and what is data source status?",
            AssistantIdentity("analyst", "auditor_viewer"),
        )
        tool_results = [
            item for item in provider.requests[2]["messages"] if item["role"] == "tool"
        ]
        self.assertEqual(len(tool_results), 8)
        self.assertTrue(
            all(len(item["content"]) <= MAX_TOOL_OUTPUT for item in tool_results)
        )
        self.assertIn("The total evidence limit was reached", tool_results[7]["content"])
        self.assertEqual(result["answer"], "The result is partial.")


class ProviderErrorTests(unittest.TestCase):
    def test_missing_groq_configuration_fails_before_client_use(self):
        with self.assertRaises(ConfigurationError):
            GroqProvider(make_settings(groq_api_key=""))

    def test_provider_http_errors_are_safe_and_do_not_leak_body(self):
        cases = [
            (401, "API key"),
            (403, "API key"),
            (404, "unavailable"),
            (400, "request format"),
            (413, "payload exceeded"),
            (429, "rate-limited"),
            (503, "temporarily unavailable"),
        ]
        for status, expected in cases:
            class ProviderError(Exception):
                status_code = status
                body = {"error": {"code": "secret-code", "message": "private session output"}}

            client = Mock()
            client.chat.completions.create.side_effect = ProviderError("private session output")
            provider = GroqProvider(make_settings(), client=client)
            with self.subTest(status=status), self.assertRaises(GroqProviderError) as raised:
                provider.complete(messages=[], tools=None)
            self.assertIn(expected, str(raised.exception))
            self.assertNotIn("private session output", str(raised.exception))
            self.assertNotIn("secret-code", str(raised.exception))

    def test_provider_timeout_and_connection_errors_are_safe(self):
        for exception, expected in (
            (TimeoutError("private prompt"), "timed out"),
            (ConnectionError("private prompt"), "could not be reached"),
        ):
            client = Mock()
            client.chat.completions.create.side_effect = exception
            provider = GroqProvider(make_settings(), client=client)
            with self.subTest(error=type(exception).__name__), self.assertRaises(
                GroqProviderError
            ) as raised:
                provider.complete(messages=[], tools=None)
            self.assertIn(expected, str(raised.exception))
            self.assertNotIn("private prompt", str(raised.exception))

    def test_proposed_error_categories_cover_context_tools_and_transient_failures(self):
        cases = [
            (400, "invalid_request", "context_length_exceeded", "context length exceeded", "context_length"),
            (400, "invalid_request", "tool_schema_error", "invalid tool schema", "tool_request"),
            (400, "invalid_request", "unsupported_model_feature", "feature not supported", "unsupported_model_feature"),
            (None, "APITimeoutError", None, "private prompt", "timeout"),
            (None, "APIConnectionError", None, "private prompt", "connection"),
            (503, "InternalServerError", None, "private prompt", "temporary_provider_error"),
        ]
        for status, kind, code, message, expected_category in cases:
            with self.subTest(category=expected_category):
                category, safe_message = classify_provider_error(
                    status_code=status,
                    error_type=kind,
                    error_code=code,
                    message=message,
                )
                self.assertEqual(category, expected_category)
                self.assertNotIn("private prompt", safe_message)
                self.assertNotIn("context length exceeded", safe_message)

    def test_tool_execution_does_not_send_unvalidated_arguments(self):
        call = SimpleNamespace(
            id="bad-json",
            function=SimpleNamespace(name="get_session_counts", arguments="{not-json"),
        )
        provider = Mock()
        provider.complete.return_value = provider_message(tool_calls=[call])
        registry = Mock()
        registry.execute.side_effect = ValueError("Tool arguments were not valid JSON.")
        service = make_chatbot_service(registry, lambda _settings: provider)
        with self.assertRaises(Exception):
            service.answer(
                "How many sessions are recorded?",
                AssistantIdentity("analyst", "auditor_viewer"),
            )
        registry.execute.assert_called_once()
        self.assertEqual(provider.complete.call_count, 1)


if __name__ == "__main__":
    unittest.main()
