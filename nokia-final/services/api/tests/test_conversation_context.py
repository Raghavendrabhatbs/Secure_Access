import sys
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.conversation_context_service import ConversationContextService


class ConversationContextServiceTest(unittest.TestCase):
    def setUp(self):
        self.service = ConversationContextService()
        self.history = [
            SimpleNamespace(
                role="user",
                content="What risky commands did admin execute?",
                metadata_json={"session_id": "session-1"},
            ),
            SimpleNamespace(
                role="assistant",
                content="`sudo -n true` and `chmod 777 test.txt` were observed.",
                metadata_json={"session_id": "session-1"},
            ),
        ]

    def test_resolves_first_reference_to_first_command(self):
        resolved = self.service.resolve("When was the first one executed?", self.history)
        self.assertEqual(resolved.command, "sudo -n true")
        self.assertIn("`sudo -n true`", resolved.question)
        self.assertEqual(resolved.session_id, "session-1")
        self.assertTrue(resolved.has_pronoun)
        self.assertEqual(resolved.followup_type, "when")

    def test_resolves_second_reference_to_second_command(self):
        resolved = self.service.resolve("Which one was the second one?", self.history)
        self.assertEqual(resolved.command, "chmod 777 test.txt")

    def test_prefers_structured_entities_for_risk_reference(self):
        history = [
            SimpleNamespace(
                role="assistant",
                content="The relevant activity was identified.",
                metadata_json={
                    "entities": {
                        "commands": [
                            {"command": "sudo -n true", "risk_categories": ["PRIVILEGE_ESCALATION"]},
                            {"command": "chmod 777 test.txt", "risk_categories": ["PERMISSION_MODIFICATION"]},
                        ]
                    },
                    "session_id": "session-1",
                },
            )
        ]
        resolved = self.service.resolve("Which one was related to privilege escalation?", history)
        self.assertEqual(resolved.command, "sudo -n true")

    def test_resolves_that_session_without_rewriting_unrelated_questions(self):
        resolved = self.service.resolve("Was that session high risk?", self.history)
        self.assertEqual(resolved.session_id, "session-1")
        self.assertIn("`session-1`", resolved.question)

        unrelated = self.service.resolve("What is SSH?", self.history)
        self.assertEqual(unrelated.question, "What is SSH?")
        self.assertIsNone(unrelated.command)
        self.assertFalse(unrelated.has_pronoun)

    def test_resolves_it_pronoun_for_command(self):
        resolved = self.service.resolve("When was it executed?", self.history)
        self.assertTrue(resolved.has_pronoun)
        self.assertEqual(resolved.followup_type, "when")
        self.assertEqual(resolved.command, "sudo -n true")
        self.assertEqual(resolved.session_id, "session-1")

    def test_resolves_that_risk_followup(self):
        resolved = self.service.resolve("Was it risky?", self.history)
        self.assertTrue(resolved.has_pronoun)
        self.assertEqual(resolved.followup_type, "risk")
        self.assertEqual(resolved.session_id, "session-1")

    def test_before_after_pronoun_followups(self):
        before = self.service.resolve("what happened before it?", self.history)
        self.assertEqual(before.followup_type, "before")
        self.assertEqual(before.command, "sudo -n true")

        after = self.service.resolve("and after it?", self.history)
        self.assertEqual(after.followup_type, "after")
        self.assertEqual(after.command, "sudo -n true")

    def test_who_pronoun_followup(self):
        resolved = self.service.resolve("who executed it?", self.history)
        self.assertEqual(resolved.followup_type, "who")
        self.assertEqual(resolved.session_id, "session-1")

    def test_last_one_reference(self):
        resolved = self.service.resolve("show me the last one", self.history)
        self.assertEqual(resolved.command, "chmod 777 test.txt")

    def test_risk_pattern_matches_ordinal_pronouns(self):
        cases = (
            "was the first one high risk?",
            "was that session dangerous?",
            "is the last one malicious?",
            "how risky was that?",
        )
        for question in cases:
            resolved = self.service.resolve(question, self.history)
            self.assertEqual(resolved.followup_type, "risk", msg=question)

    def test_no_history_still_reports_pronoun(self):
        resolved = self.service.resolve("was it risky?", [])
        self.assertTrue(resolved.has_pronoun)
        self.assertIsNone(resolved.command)
        self.assertIsNone(resolved.session_id)

    def test_ordinal_web_followup_selects_the_matching_recording(self):
        history = [
            SimpleNamespace(
                role="assistant",
                content="Found three Web recordings.",
                metadata_json={
                    "entities": {
                        "sessions": [
                            {"session_id": "session-abcdef123456", "protocol": "WEB"},
                            {"session_id": "session-bcdefa234567", "protocol": "WEB"},
                            {"session_id": "session-cdefab345678", "protocol": "WEB"},
                        ]
                    }
                },
            )
        ]
        resolved = self.service.resolve("Explain the third one", history)
        self.assertEqual(resolved.session_id, "session-cdefab345678")


if __name__ == "__main__":
    unittest.main()
