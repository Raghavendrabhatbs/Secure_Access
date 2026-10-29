import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.risk_search import format_cross_session_risk_search


class RiskSearchResponseTest(unittest.TestCase):
    """Pure unit tests for the cross-session risk search response formatter."""

    def _make_session(self, session_id, overall_severity, commands):
        """Build a minimal session dict as the chatbot evidence layer produces it."""
        all_findings = [
            finding
            for command in commands
            for finding in command.get("risk_findings", [])
        ]
        seen: set[tuple[str, str]] = set()
        categories: list[str] = []
        for finding in all_findings:
            cat = finding.get("category", "")
            if cat and cat not in seen:
                seen.add(cat)
                categories.append(cat)
        categories.sort()
        return {
            "session_id": session_id,
            "matched_terms": [],
            "matching_commands": commands,
            "risk_summary": {
                "overall_severity": overall_severity,
                "finding_count": len(all_findings),
                "high_count": sum(1 for f in all_findings if f.get("severity", "").upper() == "HIGH"),
                "medium_count": sum(1 for f in all_findings if f.get("severity", "").upper() == "MEDIUM"),
                "low_count": sum(1 for f in all_findings if f.get("severity", "").upper() == "LOW"),
                "categories": categories,
            },
        }

    def test_no_matching_sessions_with_category(self):
        result = format_cross_session_risk_search([], ["PRIVILEGE_ESCALATION"])
        self.assertEqual(
            result,
            "No sessions with PRIVILEGE_ESCALATION were found in the retrieved session evidence.",
        )

    def test_no_matching_sessions_without_category(self):
        result = format_cross_session_risk_search([], [])
        self.assertIn("No sessions with the requested risk categories", result)
        self.assertNotIn("PRIVILEGE_ESCALATION", result)

    def test_no_fabricated_risk_in_empty_result(self):
        result = format_cross_session_risk_search([], ["CREDENTIAL_FILE_ACCESS"])
        self.assertNotIn("HIGH", result)
        self.assertNotIn("sudo", result)
        self.assertNotIn("chmod", result)
        self.assertIn("retrieved session evidence", result)

    def test_one_matching_session_privilege_escalation(self):
        session = self._make_session(
            "session-abc",
            "HIGH",
            [
                {
                    "sequence_number": 1,
                    "command": "sudo su -",
                    "risk_findings": [
                        {"category": "PRIVILEGE_ESCALATION", "severity": "HIGH", "rule": "SUDO"},
                    ],
                },
            ],
        )
        result = format_cross_session_risk_search([session], ["PRIVILEGE_ESCALATION"])
        self.assertIn("Sessions with PRIVILEGE_ESCALATION:", result)
        self.assertIn("1. session-abc", result)
        self.assertIn("Risk: HIGH", result)
        self.assertIn("Commands:", result)
        self.assertIn("- sudo su -", result)
        self.assertIn("Findings:", result)
        self.assertIn("- PRIVILEGE_ESCALATION / HIGH", result)

    def test_multiple_findings_in_one_session(self):
        session = self._make_session(
            "session-xyz",
            "HIGH",
            [
                {
                    "sequence_number": 5,
                    "command": "sudo useradd hacker123",
                    "risk_findings": [
                        {"category": "PRIVILEGE_ESCALATION", "severity": "HIGH", "rule": "SUDO"},
                        {"category": "ACCOUNT_MODIFICATION", "severity": "MEDIUM", "rule": "USERADD"},
                    ],
                },
            ],
        )
        result = format_cross_session_risk_search([session], ["PRIVILEGE_ESCALATION"])
        self.assertIn("- PRIVILEGE_ESCALATION / HIGH", result)
        self.assertIn("- ACCOUNT_MODIFICATION / MEDIUM", result)
        high_pos = result.index("PRIVILEGE_ESCALATION / HIGH")
        medium_pos = result.index("ACCOUNT_MODIFICATION / MEDIUM")
        self.assertLess(high_pos, medium_pos)

    def test_multiple_matching_sessions_ordered_by_severity(self):
        high_session = self._make_session(
            "session-high",
            "HIGH",
            [
                {
                    "sequence_number": 1,
                    "command": "sudo su -",
                    "risk_findings": [
                        {"category": "PRIVILEGE_ESCALATION", "severity": "HIGH", "rule": "SUDO"},
                    ],
                },
            ],
        )
        medium_session = self._make_session(
            "session-medium",
            "MEDIUM",
            [
                {
                    "sequence_number": 1,
                    "command": "useradd newuser",
                    "risk_findings": [
                        {"category": "ACCOUNT_MODIFICATION", "severity": "MEDIUM", "rule": "USERADD"},
                    ],
                },
            ],
        )
        result = format_cross_session_risk_search(
            [medium_session, high_session],
            ["ACCOUNT_MODIFICATION", "PRIVILEGE_ESCALATION"],
        )
        self.assertIn("1. session-high", result)
        self.assertIn("2. session-medium", result)
        high_pos = result.index("1. session-high")
        medium_pos = result.index("2. session-medium")
        self.assertLess(high_pos, medium_pos)

    def test_high_medium_low_summary_present(self):
        session = self._make_session(
            "session-abc",
            "HIGH",
            [
                {
                    "sequence_number": 1,
                    "command": "sudo su -",
                    "risk_findings": [
                        {"category": "PRIVILEGE_ESCALATION", "severity": "HIGH", "rule": "SUDO"},
                    ],
                },
                {
                    "sequence_number": 2,
                    "command": "passwd",
                    "risk_findings": [
                        {"category": "CREDENTIAL_OPERATION", "severity": "MEDIUM", "rule": "PASSWD"},
                    ],
                },
            ],
        )
        result = format_cross_session_risk_search([session], ["PRIVILEGE_ESCALATION"])
        self.assertIn("Risk: HIGH", result)
        self.assertIn("PRIVILEGE_ESCALATION / HIGH", result)
        self.assertIn("CREDENTIAL_OPERATION / MEDIUM", result)

    def test_stable_ordering_across_calls(self):
        sessions = [
            self._make_session(
                f"session-{i}",
                "HIGH",
                [
                    {
                        "sequence_number": 1,
                        "command": "sudo su -",
                        "risk_findings": [
                            {"category": "PRIVILEGE_ESCALATION", "severity": "HIGH", "rule": "SUDO"},
                        ],
                    },
                ],
            )
            for i in range(3)
        ]
        result_a = format_cross_session_risk_search(sessions, ["PRIVILEGE_ESCALATION"])
        result_b = format_cross_session_risk_search(sessions, ["PRIVILEGE_ESCALATION"])
        self.assertEqual(result_a, result_b)


if __name__ == "__main__":
    unittest.main()
