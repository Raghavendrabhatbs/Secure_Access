from __future__ import annotations

import unittest

from prototype.groq_compat import build_completion_parameters, validate_tool_batch


class GroqCompatibilityTests(unittest.TestCase):
    def test_tool_requests_explicitly_disable_parallel_calls(self):
        tools = [{"type": "function", "function": {"name": "count", "parameters": {}}}]

        parameters = build_completion_parameters(
            model="openai/gpt-oss-120b",
            messages=[{"role": "user", "content": "count sessions"}],
            tools=tools,
        )

        self.assertIs(parameters["parallel_tool_calls"], False)
        self.assertEqual(parameters["tool_choice"], "auto")
        self.assertIs(parameters["tools"], tools)

    def test_non_tool_requests_do_not_send_parallel_tool_setting(self):
        parameters = build_completion_parameters(
            model="openai/gpt-oss-120b",
            messages=[{"role": "user", "content": "explain SSH"}],
            tools=None,
            tool_choice="none",
        )

        self.assertNotIn("parallel_tool_calls", parameters)
        self.assertEqual(parameters["tool_choice"], "none")

    def test_single_tool_call_is_accepted(self):
        validate_tool_batch([object()])

    def test_multiple_tool_calls_are_rejected_for_sequential_model(self):
        with self.assertRaisesRegex(ValueError, "multiple tool calls"):
            validate_tool_batch([object(), object()])


if __name__ == "__main__":
    unittest.main()
