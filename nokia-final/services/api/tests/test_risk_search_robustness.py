"""
Step 7.8 — Risk-search robustness tests.

Covers:
  - Multiple explicit phrasings for each risk category
  - Case-insensitive category extraction
  - No-match behavior remains deterministic (no LLM, no fabrication)
  - Benign sessions never appear in risk-category results
  - Command-term searches (e.g. "chmod 777") do NOT trigger the risk-category path
"""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.risk_search import extract_risk_categories
from fastapi.testclient import TestClient
from app.main import app

RISKY_SESSION_ID = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
BENIGN_SESSION_ID = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"


class RecordingProvider:
    def __init__(self):
        self.calls = []

    def generate(self, question: str, intent: str, evidence: dict):
        self.calls.append(question)
        return f"LLM would answer: {question}"


# ---------------------------------------------------------------------------
# Pure unit tests — extract_risk_categories
# ---------------------------------------------------------------------------

class ExtractRiskCategoriesTest(unittest.TestCase):
    """Verify phrase extraction without any DB or LLM dependency."""

    # --- phrase coverage ---

    def test_privilege_escalation_extracted(self):
        self.assertEqual(extract_risk_categories("find sessions with privilege escalation"), ["PRIVILEGE_ESCALATION"])

    def test_account_modification_extracted(self):
        self.assertEqual(extract_risk_categories("find sessions with account modification"), ["ACCOUNT_MODIFICATION"])

    def test_permission_modification_extracted(self):
        self.assertEqual(extract_risk_categories("which sessions had permission modification"), ["PERMISSION_MODIFICATION"])

    def test_credential_operation_extracted(self):
        self.assertEqual(extract_risk_categories("show sessions with credential operation"), ["CREDENTIAL_OPERATION"])

    def test_credential_file_access_extracted(self):
        self.assertEqual(extract_risk_categories("sessions involving credential file access"), ["CREDENTIAL_FILE_ACCESS"])

    def test_destructive_operation_extracted(self):
        self.assertEqual(extract_risk_categories("show sessions with destructive operation"), ["DESTRUCTIVE_OPERATION"])

    # --- case-insensitivity ---

    def test_uppercase_phrase_is_case_insensitive(self):
        self.assertEqual(extract_risk_categories("PRIVILEGE ESCALATION sessions"), ["PRIVILEGE_ESCALATION"])

    def test_mixed_case_phrase_is_case_insensitive(self):
        self.assertEqual(extract_risk_categories("Sessions With Account Modification"), ["ACCOUNT_MODIFICATION"])

    def test_all_caps_phrase_is_case_insensitive(self):
        self.assertEqual(extract_risk_categories("PERMISSION MODIFICATION risk"), ["PERMISSION_MODIFICATION"])

    # --- no spurious matches ---

    def test_sudo_command_does_not_trigger_category(self):
        """'sudo' alone must NOT produce a risk category — it's a command-term search."""
        result = extract_risk_categories("show sessions involving sudo")
        self.assertEqual(result, [])

    def test_chmod_command_does_not_trigger_category(self):
        result = extract_risk_categories("find sessions where chmod 777 was executed")
        self.assertEqual(result, [])

    def test_passwd_command_does_not_trigger_category(self):
        result = extract_risk_categories("show all sessions that ran passwd")
        self.assertEqual(result, [])

    def test_useradd_command_does_not_trigger_category(self):
        result = extract_risk_categories("find sessions that used useradd")
        self.assertEqual(result, [])

    def test_rm_rf_command_does_not_trigger_category(self):
        result = extract_risk_categories("sessions where rm -rf was run")
        self.assertEqual(result, [])

    def test_empty_question_returns_empty(self):
        self.assertEqual(extract_risk_categories(""), [])

    def test_whitespace_only_returns_empty(self):
        self.assertEqual(extract_risk_categories("   "), [])

    def test_generic_question_returns_empty(self):
        result = extract_risk_categories("what happened in this session?")
        self.assertEqual(result, [])

    # --- phrasing variations (sentence context) ---

    def test_phrase_embedded_in_longer_question(self):
        result = extract_risk_categories("Can you find all sessions that contain privilege escalation activity?")
        self.assertIn("PRIVILEGE_ESCALATION", result)

    def test_phrase_at_end_of_question(self):
        result = extract_risk_categories("Which sessions are flagged for account modification")
        self.assertIn("ACCOUNT_MODIFICATION", result)

    def test_phrase_at_start_of_question(self):
        result = extract_risk_categories("permission modification — which sessions?")
        self.assertIn("PERMISSION_MODIFICATION", result)

    def test_multiple_categories_in_one_question(self):
        result = extract_risk_categories(
            "find sessions with privilege escalation or account modification"
        )
        self.assertIn("PRIVILEGE_ESCALATION", result)
        self.assertIn("ACCOUNT_MODIFICATION", result)
        self.assertEqual(len(result), 2)


# ---------------------------------------------------------------------------
# Integration tests — chatbot routing and response
# ---------------------------------------------------------------------------

class RiskSearchRoutingRobustnessTest(unittest.TestCase):
    """Verify that phrase variations route correctly through the chatbot."""

    def _post(self, question: str, provider: RecordingProvider):
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post("/chat/query", json={"question": question})
        self.assertEqual(response.status_code, 200)
        return response.json()

    # --- privilege escalation variations ---

    def test_privilege_escalation_variation_1(self):
        provider = RecordingProvider()
        payload = self._post("find sessions with privilege escalation", provider)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn(RISKY_SESSION_ID, payload["answer"])
        self.assertIn("Risk: HIGH", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_privilege_escalation_variation_2(self):
        provider = RecordingProvider()
        payload = self._post(
            "Can you show me all sessions that contain privilege escalation?", provider
        )
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn(RISKY_SESSION_ID, payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_privilege_escalation_variation_3(self):
        provider = RecordingProvider()
        payload = self._post("Which sessions had privilege escalation activity?", provider)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn(RISKY_SESSION_ID, payload["answer"])
        self.assertEqual(provider.calls, [])

    # --- account modification variations ---

    def test_account_modification_variation_1(self):
        provider = RecordingProvider()
        payload = self._post("find sessions with account modification", provider)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn(RISKY_SESSION_ID, payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_account_modification_variation_2(self):
        provider = RecordingProvider()
        payload = self._post("Sessions involving account modification please", provider)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn(RISKY_SESSION_ID, payload["answer"])
        self.assertEqual(provider.calls, [])

    # --- permission modification variations ---

    def test_permission_modification_variation_1(self):
        provider = RecordingProvider()
        payload = self._post("which sessions had permission modification", provider)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn(RISKY_SESSION_ID, payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_permission_modification_variation_2(self):
        provider = RecordingProvider()
        payload = self._post("Find all sessions flagged for permission modification", provider)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertIn(RISKY_SESSION_ID, payload["answer"])
        self.assertEqual(provider.calls, [])

    # --- no-match: deterministic, no LLM, no fabrication ---

    def test_no_match_destructive_operation_is_deterministic(self):
        provider = RecordingProvider()
        payload = self._post("Which sessions contain destructive operation?", provider)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertFalse(payload["evidence_available"])
        self.assertIn("DESTRUCTIVE_OPERATION", payload["answer"])
        self.assertNotIn("sudo", payload["answer"])
        self.assertNotIn("chmod", payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_no_match_credential_file_access_is_deterministic(self):
        provider = RecordingProvider()
        payload = self._post("Show sessions with credential file access", provider)
        self.assertEqual(payload["retrieval_mode"], "rule-based")
        self.assertFalse(payload["evidence_available"])
        self.assertIn("CREDENTIAL_FILE_ACCESS", payload["answer"])
        self.assertNotIn("sudo", payload["answer"])
        self.assertEqual(provider.calls, [])

    # --- benign session isolation ---

    def test_benign_session_absent_from_privilege_escalation(self):
        provider = RecordingProvider()
        payload = self._post("find sessions with privilege escalation", provider)
        self.assertNotIn(BENIGN_SESSION_ID, payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_benign_session_absent_from_permission_modification(self):
        provider = RecordingProvider()
        payload = self._post("which sessions had permission modification", provider)
        self.assertNotIn(BENIGN_SESSION_ID, payload["answer"])
        self.assertEqual(provider.calls, [])

    def test_benign_session_absent_from_account_modification(self):
        provider = RecordingProvider()
        payload = self._post("find sessions with account modification", provider)
        self.assertNotIn(BENIGN_SESSION_ID, payload["answer"])
        self.assertEqual(provider.calls, [])

    # --- command-term searches must NOT use risk-category path ---

    def test_sudo_command_uses_llm_path_not_risk_filter(self):
        """'sudo' without an explicit risk-category phrase must reach the LLM."""
        provider = RecordingProvider()
        payload = self._post("show sessions involving sudo", provider)
        # LLM must be called because there is no risk-category phrase
        self.assertGreater(len(provider.calls), 0)

    def test_chmod_command_uses_llm_path_not_risk_filter(self):
        provider = RecordingProvider()
        payload = self._post("find sessions where chmod 777 was executed", provider)
        self.assertGreater(len(provider.calls), 0)

    def test_useradd_command_uses_llm_path_not_risk_filter(self):
        provider = RecordingProvider()
        payload = self._post("find sessions that used useradd", provider)
        self.assertGreater(len(provider.calls), 0)

    def test_passwd_command_uses_llm_path_not_risk_filter(self):
        provider = RecordingProvider()
        payload = self._post("show all sessions that ran passwd", provider)
        self.assertGreater(len(provider.calls), 0)


if __name__ == "__main__":
    unittest.main()
