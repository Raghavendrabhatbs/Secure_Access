import sys
from pathlib import Path
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.database import SessionLocal
from app.services.chatbot_service import ChatbotQueryService


class RecordingGroundedProvider:
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
        return "grounded response"


class UnavailableGroundedProvider:
    def generate(self, question: str, intent: str, evidence: dict):
        return None


class GroundedEvidencePipelineTest(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.provider = RecordingGroundedProvider()
        self.chatbot = ChatbotQueryService(self.db, llm_provider=self.provider)

    def tearDown(self):
        self.db.close()

    def test_combined_date_command_risk_question_builds_compact_evidence(self):
        result = self.chatbot.answer_question(
            "Who logged in on 2026-08-03, what did they do, and were there any security risks?"
        )

        self.assertEqual(result["intent"], "GROUNDED_ANALYSIS")
        self.assertEqual(result["retrieval_mode"], "llm")
        self.assertTrue(result["evidence_available"])
        self.assertIn("1 session(s)", result["evidence_summary"])
        self.assertEqual(result["answer"], "grounded response")

        self.assertEqual(len(self.provider.calls), 1)
        call = self.provider.calls[0]
        self.assertEqual(call["intent"], "GROUNDED_ANALYSIS")
        evidence = call["evidence"]
        self.assertEqual(evidence["query_scope"]["date_from"], "2026-08-03")
        self.assertEqual(evidence["summary"]["session_count"], 1)
        self.assertEqual(evidence["summary"]["command_count"], 4)
        self.assertEqual(evidence["summary"]["risk_finding_count"], 0)
        self.assertEqual(evidence["sessions"][0]["username"], "admin")
        self.assertEqual(
            [command["command"] for command in evidence["sessions"][0]["commands"]],
            ["whoami", "hostname", "date", 'echo "test august 3"'],
        )

    def test_no_matching_date_does_not_call_llm(self):
        result = self.chatbot.answer_question(
            "Who logged in on 2026-08-20, what did they do, and were there any security risks?"
        )

        self.assertEqual(result["intent"], "GROUNDED_ANALYSIS")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertFalse(result["evidence_available"])
        self.assertEqual(self.provider.calls, [])
        self.assertIn("No matching SSH session evidence", result["answer"])

    def test_cross_session_risky_commands_for_user_use_grounded_pipeline(self):
        result = self.chatbot.answer_question("What risky commands did admin execute?")

        self.assertEqual(result["intent"], "GROUNDED_ANALYSIS")
        self.assertEqual(result["retrieval_mode"], "llm")
        self.assertTrue(result["evidence_available"])
        self.assertIn("risk finding", result["evidence_summary"])

        self.assertEqual(len(self.provider.calls), 1)
        evidence = self.provider.calls[0]["evidence"]
        self.assertEqual(evidence["query_scope"]["users"], ["admin"])
        self.assertGreaterEqual(evidence["summary"]["risk_finding_count"], 1)
        self.assertIn("PRIVILEGE_ESCALATION", evidence["summary"]["risk_categories"])

    def test_recent_session_command_list_question_retrieves_latest_session(self):
        result = self.chatbot.answer_question(
            "recently which ssh session was done and list all the commands that were executed in it"
        )

        self.assertEqual(result["intent"], "GROUNDED_ANALYSIS")
        self.assertTrue(result["evidence_available"])
        self.assertIn("1 session(s)", result["evidence_summary"])
        self.assertRegex(result["evidence_summary"], r"\d+ command\(s\)")
        self.assertNotIn("0 command(s)", result["evidence_summary"])

    def test_complete_audit_analysis_uses_grounded_session_evidence(self):
        result = self.chatbot.answer_question("Give me a complete audit analysis of the recorded sessions.")

        self.assertEqual(result["intent"], "GROUNDED_ANALYSIS")
        self.assertTrue(result["evidence_available"])
        self.assertNotIn("Matched 0 command row", result["evidence_summary"])
        self.assertNotIn("No matching SSH session evidence", result["answer"])

    def test_last_session_summary_fallback_is_narrative_not_command_list(self):
        chatbot = ChatbotQueryService(self.db, llm_provider=UnavailableGroundedProvider())

        result = chatbot.answer_question("Summarize the last session.")

        self.assertEqual(result["intent"], "GROUNDED_ANALYSIS")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("The latest SSH session was used by", result["answer"])
        self.assertIn("The recorded sequence was", result["answer"])
        self.assertIn("privilege or permission information", result["answer"])
        self.assertIn("Command purposes from the knowledge base", result["answer"])
        self.assertIn("does not by itself prove what changes", result["answer"])
        self.assertIn("do not establish the user's intent", result["answer"])
        self.assertNotIn("Commands executed (", result["answer"])

    def test_grounded_evidence_includes_command_descriptions(self):
        result = self.chatbot.answer_question("Summarize the last session.")

        evidence = self.provider.calls[-1]["evidence"]
        commands = evidence["sessions"][0]["commands"]
        self.assertTrue(any(command.get("description") for command in commands))

    def test_all_risky_commands_and_sessions_lists_session_ids(self):
        result = self.chatbot.answer_question(
            "what are all risky commands and sessions give me with their session id"
        )

        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Session ID:", result["answer"])
        self.assertIn("risk finding", result["evidence_summary"])
        self.assertNotIn("There are no risky commands", result["answer"])
        self.assertEqual(self.provider.calls, [])

    def test_session_id_command_list_question(self):
        result = self.chatbot.answer_question(
            "79a6a8f5-4e28-4a1d-8e85-2df716113d8b list all the commands used in this session"
        )

        self.assertEqual(result["intent"], "COMMAND_LOOKUP")
        self.assertTrue(result["evidence_available"])
        self.assertIn("79a6a8f5-4e28-4a1d-8e85-2df716113d8b", result["answer"])
        self.assertIn("whoami", result["answer"])
        self.assertNotIn("couldn't retrieve command evidence", result["answer"].lower())

    def test_who_logged_in_recently_returns_actor_listing(self):
        result = self.chatbot.answer_question(
            "who logged in recently and what all they executed?"
        )

        self.assertEqual(result["intent"], "USER_ACTIVITY")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Recent SSH sessions", result["answer"])
        self.assertRegex(result["evidence_summary"], r"Retrieved \d+ recent session\(s\)")
        self.assertNotIn("couldn't retrieve command evidence", result["answer"].lower())
        self.assertNotIn("Matched 0 command row", result["evidence_summary"])
        self.assertEqual(self.provider.calls, [])

    def test_who_just_logged_in_returns_actor_listing(self):
        result = self.chatbot.answer_question("who just logged in")

        self.assertEqual(result["intent"], "USER_ACTIVITY")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Recent SSH sessions", result["answer"])
        self.assertEqual(self.provider.calls, [])

    def test_recently_who_logged_in_and_commands_prefers_actor_listing(self):
        result = self.chatbot.answer_question(
            "recently who logged in and what all commands they executed?"
        )

        # Must return the actor listing, NOT the generic 'all commands frequency' answer.
        self.assertEqual(result["intent"], "USER_ACTIVITY")
        self.assertIn("Recent SSH sessions", result["answer"])
        self.assertNotIn("here are commands executed by count", result["answer"])
        self.assertNotIn("Listed 24 unique command(s)", result["evidence_summary"])
        self.assertEqual(self.provider.calls, [])

    def test_who_executed_command_returns_audit_listing(self):
        result = self.chatbot.answer_question("who executed whoami")

        self.assertEqual(result["intent"], "COMMAND_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Users who executed", result["answer"])
        self.assertIn("admin", result["answer"])
        # Must NOT be treated as an SSH-knowledge lookup for 'who executed'.
        self.assertNotIn("who executed", result["answer"].lower().split("users who executed")[0])
        self.assertNotIn("`who executed`", result["answer"])
        self.assertEqual(self.provider.calls, [])

    def test_who_executed_explicit_command_returns_username(self):
        result = self.chatbot.answer_question("Who executed the command hostname?")

        self.assertEqual(result["intent"], "COMMAND_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Users who executed `hostname`", result["answer"])
        self.assertIn("The recorded SSH evidence shows that `hostname` was executed", result["answer"])
        self.assertIn("admin", result["answer"])
        self.assertNotIn("`hostname` lists", result["answer"])
        self.assertEqual(self.provider.calls, [])

    def test_explicit_command_owner_question_ignores_previous_command_context(self):
        result = self.chatbot.answer_question(
            "Who executed the command ip route?",
            resolved_command="hostname",
            followup_type="who",
        )

        self.assertIn("ip route", result["answer"])
        self.assertNotIn("`hostname` was executed by", result["answer"])

    def test_direct_risk_assessment_distinguishes_benign_command(self):
        result = self.chatbot.answer_question("Is ls -la a risky command?")

        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertIn("`ls -la` is not risky", result["answer"])
        self.assertIn("No configured risk indicators", result["answer"])
        self.assertEqual(self.provider.calls, [])

    def test_direct_risk_assessment_distinguishes_high_risk_command(self):
        result = self.chatbot.answer_question("Is sudo -l a risky command?")

        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertIn("`sudo -l` is highly risky", result["answer"])
        self.assertIn("PRIVILEGE_ESCALATION (HIGH)", result["answer"])

    def test_direct_risk_assessment_handles_hostname_wording(self):
        result = self.chatbot.answer_question("Is hostname and risky command?")

        self.assertEqual(result["intent"], "RISK_ANALYSIS")
        self.assertIn("`hostname` is not risky", result["answer"])

    def test_who_executed_these_commands_with_hostname_returns_listing(self):
        result = self.chatbot.answer_question(
            "who executed these commands give me the hostname?"
        )

        self.assertEqual(result["intent"], "USER_ACTIVITY")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Recent SSH sessions", result["answer"])
        self.assertIn("host `", result["answer"])
        self.assertNotIn(
            "these commands give me the hostname",
            result["answer"].lower(),
        )
        self.assertNotIn(
            "No user has executed a command matching",
            result["answer"],
        )
        self.assertEqual(self.provider.calls, [])

    def test_who_executed_compound_and_command_splits_terms(self):
        result = self.chatbot.answer_question(
            "which user executed whoami and hostname?"
        )

        self.assertEqual(result["intent"], "COMMAND_LOOKUP")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Users who executed", result["answer"])
        self.assertIn("whoami", result["answer"])
        self.assertIn("hostname", result["answer"])
        self.assertNotIn(
            "No user has executed a command matching `whoami and hostname`",
            result["answer"],
        )

    def test_session_context_hostname_question_is_concise(self):
        result = self.chatbot.answer_question(
            "what is the hostname who is executing commands here?"
        )

        self.assertEqual(result["intent"], "COMMAND_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("admin", result["answer"])
        self.assertIn("DESKTOP-L7RS68G", result["answer"])
        self.assertLess(len(result["answer"]), 120)
        self.assertNotIn("Example:", result["answer"])
        self.assertEqual(self.provider.calls, [])

    def test_hostname_of_user_returns_recorded_hostname_and_dates(self):
        result = self.chatbot.answer_question("What is the hostname of admin?")

        self.assertEqual(result["intent"], "SESSION_LOOKUP")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("admin connected to `DESKTOP-L7RS68G`", result["answer"])
        self.assertIn("2026-08-03", result["answer"])
        self.assertNotIn("lists files", result["answer"])
        self.assertEqual(self.provider.calls, [])

    def test_hostname_audit_accepts_server_and_connect_phrasings(self):
        for question in (
            "What hostname did admin connect to?",
            "Which server did admin access?",
        ):
            with self.subTest(question=question):
                result = self.chatbot.answer_question(question)
                self.assertTrue(result["evidence_available"])
                self.assertIn("DESKTOP-L7RS68G", result["answer"])

    def test_active_session_command_query_includes_current_commands(self):
        result = self.chatbot.answer_question("What commands are running in the active session?")

        self.assertEqual(result["intent"], "USER_ACTIVITY")
        if "No SSH sessions are currently active." not in result["answer"]:
            self.assertIn("currently active SSH sessions", result["answer"].lower())
            self.assertIn("Commands recorded so far", result["answer"])

    def test_active_session_command_query_lists_ingested_commands(self):
        active_session = SimpleNamespace(
            session_id="active-session-1",
            unique_id="active-session-1",
            username="admin",
            started_at=datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc),
            target="server-1",
            remote_address=None,
            ended_at=None,
        )
        command = SimpleNamespace(command="ip route")
        with patch.object(self.chatbot._session_query_service, "list_active_sessions", return_value=[active_session]), patch.object(
            self.chatbot._session_query_service,
            "get_command_evidence",
            return_value=[command],
        ):
            result = self.chatbot.answer_question("What commands are running in the active session?")

        self.assertIn("admin", result["answer"])
        self.assertIn("Commands recorded so far: `ip route`", result["answer"])


if __name__ == "__main__":
    unittest.main()