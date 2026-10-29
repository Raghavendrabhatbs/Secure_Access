import sys
from datetime import datetime
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.main import app


class RecordingTimelineEvidenceProvider:
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
        return "timeline evidence captured"


class ChatbotTimelineEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def _ask_with_provider(self, session_id: str, question: str = "What commands were executed in this session?"):
        provider = RecordingTimelineEvidenceProvider()
        with patch("app.services.chatbot_service.build_llm_provider", return_value=provider):
            client = TestClient(app)
            response = client.post(
                "/chat/query",
                json={
                    "question": question,
                    "session_id": session_id,
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["retrieval_mode"], "llm")
        self.assertEqual(len(provider.calls), 1)
        return provider.calls[0]["evidence"], payload

    def test_timeline_exists_in_evidence(self):
        evidence, _ = self._ask_with_provider(self.risky_session_id)
        self.assertIn("timeline", evidence)
        self.assertTrue(evidence["timeline"])

    def test_timeline_analysis_exists_in_evidence(self):
        evidence, _ = self._ask_with_provider(self.risky_session_id)
        self.assertIn("timeline_analysis", evidence)

    def test_timeline_entries_are_chronological(self):
        evidence, _ = self._ask_with_provider(self.risky_session_id)
        timeline = evidence["timeline"]

        for i in range(len(timeline) - 1):
            current_ts = timeline[i].get("timestamp")
            next_ts = timeline[i + 1].get("timestamp")
            if current_ts is None or next_ts is None:
                continue
            self.assertLessEqual(current_ts, next_ts)
            if current_ts == next_ts:
                self.assertLessEqual(
                    timeline[i].get("sequence_number") or 10**9,
                    timeline[i + 1].get("sequence_number") or 10**9,
                )

    def test_timeline_preserves_risky_commands_and_findings(self):
        evidence, _ = self._ask_with_provider(self.risky_session_id)
        timeline = evidence["timeline"]

        command_entries = [entry for entry in timeline if entry.get("event_type") == "COMMAND"]
        commands = [entry.get("command") for entry in command_entries]

        self.assertIn("sudo su -", commands)
        self.assertIn("sudo useradd hacker123", commands)
        self.assertIn("chmod 777 /etc/passwd", commands)

        sudo_entry = next(entry for entry in command_entries if entry.get("command") == "sudo su -")
        sudo_findings = {(finding["category"], finding["severity"]) for finding in sudo_entry.get("risk_findings", [])}
        self.assertIn(("PRIVILEGE_ESCALATION", "HIGH"), sudo_findings)

        useradd_entry = next(entry for entry in command_entries if entry.get("command") == "sudo useradd hacker123")
        useradd_findings = {(finding["category"], finding["severity"]) for finding in useradd_entry.get("risk_findings", [])}
        self.assertIn(("PRIVILEGE_ESCALATION", "HIGH"), useradd_findings)
        self.assertIn(("ACCOUNT_MODIFICATION", "MEDIUM"), useradd_findings)

        chmod_entry = next(entry for entry in command_entries if entry.get("command") == "chmod 777 /etc/passwd")
        chmod_findings = {(finding["category"], finding["severity"]) for finding in chmod_entry.get("risk_findings", [])}
        self.assertIn(("PERMISSION_MODIFICATION", "HIGH"), chmod_findings)

    def test_timeline_analysis_overall_severity_is_high_for_risky_session(self):
        evidence, _ = self._ask_with_provider(self.risky_session_id)
        self.assertEqual(evidence["timeline_analysis"]["overall_severity"], "HIGH")

    def test_benign_session_has_none_severity_and_no_fabricated_risk(self):
        evidence, _ = self._ask_with_provider(self.benign_session_id)

        self.assertEqual(evidence["timeline_analysis"]["overall_severity"], "NONE")

        command_entries = [entry for entry in evidence["timeline"] if entry.get("event_type") == "COMMAND"]
        self.assertTrue(command_entries)
        for entry in command_entries:
            self.assertEqual(entry.get("risk_findings", []), [])

    def test_existing_evidence_contract_remains_present(self):
        evidence, _ = self._ask_with_provider(self.risky_session_id)

        self.assertIn("commands", evidence)
        self.assertIn("events", evidence)
        self.assertIn("risk_summary", evidence)

    def test_timeline_analysis_command_and_event_counts_are_present(self):
        evidence, _ = self._ask_with_provider(self.risky_session_id)
        analysis = evidence["timeline_analysis"]

        self.assertGreaterEqual(analysis["entry_count"], analysis["command_count"])
        self.assertGreaterEqual(analysis["entry_count"], analysis["event_count"])
        self.assertIsInstance(analysis["commands"], list)
        self.assertIsInstance(analysis["event_types"], list)


if __name__ == "__main__":
    unittest.main()
