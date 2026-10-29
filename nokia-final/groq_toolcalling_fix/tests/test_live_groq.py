from __future__ import annotations

import os
import re
from pathlib import Path
import sys
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "groq_ai_addon"))

from dotenv import dotenv_values  # noqa: E402
from groq import Groq  # noqa: E402
from backend.chatbot_service import _tools_for_question


@unittest.skipUnless(
    os.getenv("RUN_GROQ_LIVE_TEST") == "1",
    "Set RUN_GROQ_LIVE_TEST=1 to opt into a synthetic live Groq request.",
)
class OptionalLiveGroqTests(unittest.TestCase):
    def test_synthetic_local_tool_request(self):
        config = dotenv_values(PROJECT_ROOT / "groq_ai_addon" / ".env")
        api_key = os.getenv("GROQ_API_KEY") or config.get("GROQ_API_KEY")
        model = os.getenv("GROQ_MODEL") or config.get(
            "GROQ_MODEL", "openai/gpt-oss-120b"
        )
        if not api_key:
            self.skipTest("GROQ_API_KEY is not configured.")

        tools = _tools_for_question("How many SSH sessions?")
        try:
            response = Groq(api_key=api_key, max_retries=0, timeout=30).chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": "For this synthetic test, call get_session_counts once. Do not claim actual records.",
                    },
                    {"role": "user", "content": "How many SSH sessions?"},
                ],
                tools=tools,
                tool_choice="auto",
                parallel_tool_calls=False,
                temperature=0.1,
            )
        except Exception as exc:
            status = getattr(exc, "status_code", None)
            body = getattr(exc, "body", None)
            error = body.get("error", body) if isinstance(body, dict) else {}
            raw_code = error.get("code") if isinstance(error, dict) else None
            code = (
                raw_code
                if isinstance(raw_code, str)
                and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", raw_code)
                else "[REDACTED]"
            )
            message = error.get("message") if isinstance(error, dict) else ""
            message = str(message).replace(str(api_key), "[REDACTED]")
            message = re.sub(
                r"(?i)(api[_ -]?key|authorization|token|secret)(\s*[:=]\s*)\S+",
                r"\1\2[REDACTED]",
                message,
            )[:500]
            self.fail(
                f"Groq request failed: status={status}, code={code}, "
                f"type={type(exc).__name__}, message={message}"
            )

        calls = getattr(response.choices[0].message, "tool_calls", None) or []
        self.assertTrue(calls, "Expected a synthetic tool call from Groq.")
        self.assertEqual(calls[0].function.name, "get_session_counts")


if __name__ == "__main__":
    unittest.main()
