import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.main import app


class RecordingProvider:
    def __init__(self):
        self.calls = []

    def generate(self, question: str, intent: str, evidence: dict):
        self.calls.append({"question": question, "intent": intent, "evidence": evidence})
        return "llm fallback answer"


class ChatbotTimelineRobustnessTest(unittest.TestCase):
    def setUp(self):
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def _ask(self, question: str, session_id: str | None = None):
        provider = RecordingProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            body = {"question": question}
            if session_id is not None:
                body["session_id"] = session_id
            response = client.post("/chat/query", json=body)

        self.assertEqual(response.status_code, 200)
        return response.json(), provider

    def test_show_me_the_timeline_is_deterministic(self):
        payload, provider = self._ask("Show me the timeline.", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("Session timeline:", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_show_the_session_timeline_is_deterministic(self):
        payload, provider = self._ask("Show the session timeline.", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("Session timeline:", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_what_happened_in_this_session_is_deterministic(self):
        payload, provider = self._ask("What happened in this session?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("Session timeline:", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_what_events_happened_is_deterministic(self):
        payload, provider = self._ask("What events happened?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("Session timeline:", payload["answer"])
        self.assertIn("session_started", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_what_happened_first_is_deterministic(self):
        payload, provider = self._ask("What happened first?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("Session timeline:", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_what_happened_last_is_deterministic(self):
        payload, provider = self._ask("What happened last?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("Session timeline:", payload["answer"])
        self.assertIn("session_ended", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_what_commands_were_executed_chronologically(self):
        payload, provider = self._ask("What commands were executed chronologically?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("sudo su -", payload["answer"])
        self.assertIn("sudo useradd hacker123", payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_before_privilege_escalation_is_deterministic(self):
        payload, provider = self._ask("What happened before privilege escalation?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("before the first PRIVILEGE_ESCALATION", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_after_privilege_escalation_is_deterministic(self):
        payload, provider = self._ask("What happened after privilege escalation?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("after the first PRIVILEGE_ESCALATION", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_around_privilege_escalation_is_deterministic(self):
        payload, provider = self._ask("What happened around the privilege escalation?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("Session timeline:", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_benign_session_no_fabricated_risk(self):
        payload, provider = self._ask("Show me the timeline.", self.benign_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("Overall risk: NONE", payload["answer"])
        self.assertNotIn("PRIVILEGE_ESCALATION", payload["answer"])
        self.assertNotIn("PERMISSION_MODIFICATION", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_unknown_session_timeline_question_is_safe(self):
        payload, provider = self._ask(
            "Show me the timeline.",
            "00000000-0000-0000-0000-000000000000",
        )
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("couldn't retrieve session evidence", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_cross_session_question_remains_session_search(self):
        payload, provider = self._ask("What happened in sessions involving sudo?")
        self.assertEqual(payload["intent"], "SESSION_SEARCH")
        self.assertEqual(payload["retrieval_mode"], "llm")
        self.assertGreater(len(provider.calls), 0)

    def test_first_risky_action_returns_single_entry_not_full_timeline(self):
        payload, provider = self._ask("What was the first risky action?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("First risky action:", payload["answer"])
        self.assertIn("Command: sudo su -", payload["answer"])
        self.assertIn("Risk: HIGH", payload["answer"])
        self.assertIn("Category: PRIVILEGE_ESCALATION", payload["answer"])
        self.assertNotIn("Session timeline:", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_first_risky_command_variant_is_deterministic(self):
        payload, provider = self._ask("What was the first risky command?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("First risky action:", payload["answer"])
        self.assertIn("Command: sudo su -", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_first_high_risk_action_variant_is_deterministic(self):
        payload, provider = self._ask("What was the first high-risk action?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("First risky action:", payload["answer"])
        self.assertIn("Command: sudo su -", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_first_risky_action_benign_session_has_no_findings(self):
        payload, provider = self._ask("What was the first risky action?", self.benign_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("No risky timeline entries", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_last_command_executed_is_deterministic(self):
        payload, provider = self._ask("What was the last command executed?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertEqual(payload["answer"], "Last command:\n\nhistory -c")
        self.assertEqual(provider.calls, [])

    def test_what_was_the_last_command_variant(self):
        payload, provider = self._ask("What was the last command?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertEqual(payload["answer"], "Last command:\n\nhistory -c")
        self.assertEqual(provider.calls, [])

    def test_what_command_was_executed_last_variant(self):
        payload, provider = self._ask("What command was executed last?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertEqual(payload["answer"], "Last command:\n\nhistory -c")
        self.assertEqual(provider.calls, [])

    def test_which_was_the_last_command_variant(self):
        payload, provider = self._ask("Which was the last command?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertEqual(payload["answer"], "Last command:\n\nhistory -c")
        self.assertEqual(provider.calls, [])

    def test_after_command_anchor(self):
        payload, provider = self._ask("What happened after sudo su -?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn('Entries after "sudo su -":', payload["answer"])
        self.assertIn("sudo useradd hacker123", payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])
        self.assertIn("history -c", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_before_command_anchor(self):
        payload, provider = self._ask(
            "What happened before chmod 777 /etc/passwd?", self.risky_session_id
        )
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn('Entries before "chmod 777 /etc/passwd":', payload["answer"])
        self.assertIn("session_started", payload["answer"])
        self.assertIn("sudo su -", payload["answer"])
        self.assertIn("sudo useradd hacker123", payload["answer"])
        self.assertNotIn("chmod 777 /etc/passwd", payload["answer"].split(":", 1)[-1])
        self.assertEqual(provider.calls, [])

    def test_after_command_with_arguments(self):
        payload, provider = self._ask(
            "What happened after sudo useradd hacker123?", self.risky_session_id
        )
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn('Entries after "sudo useradd hacker123":', payload["answer"])
        self.assertIn("chmod 777 /etc/passwd", payload["answer"])
        self.assertIn("history -c", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_before_first_command_anchor(self):
        payload, provider = self._ask("What happened before sudo su -?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertEqual(
            payload["answer"],
            "Entries before \"sudo su -\":\n\n"
            "1. 2026-07-30 06:01:40.043002+00:00 - session_started: Session started\n"
            "2. 2026-07-30 06:01:40.043002+00:00 - recording_attached: Recording attached to session",
        )
        self.assertEqual(provider.calls, [])

    def test_unknown_command_anchor_is_not_fabricated(self):
        payload, provider = self._ask("What happened after rm -rf /?", self.risky_session_id)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertEqual(
            payload["answer"],
            'I couldn\'t find the command "rm -rf /" in this session timeline.',
        )
        self.assertEqual(provider.calls, [])

    def test_when_privilege_escalation_happened_is_deterministic(self):
        payload, provider = self._ask(
            "When did privilege escalation happen?", self.risky_session_id
        )
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("PRIVILEGE_ESCALATION occurred at:", payload["answer"])
        self.assertIn("Command: sudo su -", payload["answer"])
        self.assertIn("Command: sudo useradd hacker123", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_when_permission_modification_happened_is_deterministic(self):
        payload, provider = self._ask(
            "When did permission modification happen?", self.risky_session_id
        )
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("PERMISSION_MODIFICATION occurred at:", payload["answer"])
        self.assertIn("Command: chmod 777 /etc/passwd", payload["answer"])
        self.assertIn("Risk: HIGH", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_when_privilege_escalation_detected_is_deterministic(self):
        payload, provider = self._ask(
            "When was privilege escalation detected?", self.risky_session_id
        )
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("PRIVILEGE_ESCALATION occurred at:", payload["answer"])
        self.assertEqual(payload["answer"].count("Category: PRIVILEGE_ESCALATION"), 2)
        self.assertEqual(provider.calls, [])

    def test_when_account_modification_happened_is_deterministic(self):
        payload, provider = self._ask(
            "When did account modification happen?", self.risky_session_id
        )
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn("ACCOUNT_MODIFICATION occurred at:", payload["answer"])
        self.assertIn("Command: sudo useradd hacker123", payload["answer"])
        self.assertIn("Risk: MEDIUM", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_when_unknown_risk_happened_does_not_fabricate(self):
        payload, provider = self._ask(
            "When did malware execution happen?", self.risky_session_id
        )
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertEqual(
            payload["answer"],
            "No MALWARE_EXECUTION findings were found in this session.",
        )
        self.assertEqual(provider.calls, [])


if __name__ == "__main__":
    unittest.main()
