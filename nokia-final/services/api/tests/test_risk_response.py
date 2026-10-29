import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.risk_response import format_risk_summary


class RiskResponseTest(unittest.TestCase):
    def test_formats_empty_evidence(self):
        summary = {
            "overall_severity": "NONE",
            "finding_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "categories": [],
        }

        self.assertEqual(
            format_risk_summary(summary, [], []),
            "Overall risk: NONE\n\nNo risk findings were identified in the retrieved session evidence.",
        )

    def test_formats_none_summary_without_findings(self):
        self.assertEqual(
            format_risk_summary(None, [], []),
            "Overall risk: NONE\n\nNo risk findings were identified in the retrieved session evidence.",
        )

    def test_formats_low_only_summary(self):
        summary = {
            "overall_severity": "LOW",
            "finding_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 1,
            "categories": ["CONFIGURATION_CHANGE"],
        }
        findings = [
            {"category": "CONFIGURATION_CHANGE", "severity": "LOW", "rule": "WORLD_WRITABLE"},
        ]
        commands = [
            {"sequence_number": 5, "command": "chmod 644 /tmp/file", "risk_findings": findings},
        ]

        self.assertEqual(
            format_risk_summary(summary, findings, commands),
            "\n".join(
                [
                    "Overall risk: LOW",
                    "",
                    "Findings: 1",
                    "HIGH: 0",
                    "MEDIUM: 0",
                    "LOW: 1",
                    "",
                    "Risk categories:",
                    "- CONFIGURATION_CHANGE",
                    "",
                    "Risky commands:",
                    "- chmod 644 /tmp/file: CONFIGURATION_CHANGE (LOW)",
                ]
            ),
        )

    def test_formats_medium_only_summary(self):
        summary = {
            "overall_severity": "MEDIUM",
            "finding_count": 1,
            "high_count": 0,
            "medium_count": 1,
            "low_count": 0,
            "categories": ["ACCOUNT_MODIFICATION"],
        }
        findings = [
            {"category": "ACCOUNT_MODIFICATION", "severity": "MEDIUM", "rule": "USERADD"},
        ]
        commands = [
            {"sequence_number": 10, "command": "sudo useradd hacker123", "risk_findings": findings},
        ]

        self.assertEqual(
            format_risk_summary(summary, findings, commands),
            "\n".join(
                [
                    "Overall risk: MEDIUM",
                    "",
                    "Findings: 1",
                    "HIGH: 0",
                    "MEDIUM: 1",
                    "LOW: 0",
                    "",
                    "Risk categories:",
                    "- ACCOUNT_MODIFICATION",
                    "",
                    "Risky commands:",
                    "- sudo useradd hacker123: ACCOUNT_MODIFICATION (MEDIUM)",
                ]
            ),
        )

    def test_formats_high_only_summary(self):
        summary = {
            "overall_severity": "HIGH",
            "finding_count": 1,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "categories": ["PRIVILEGE_ESCALATION"],
        }
        findings = [
            {"category": "PRIVILEGE_ESCALATION", "severity": "HIGH", "rule": "SUDO"},
        ]
        commands = [
            {"sequence_number": 1, "command": "sudo su -", "risk_findings": findings},
        ]

        self.assertEqual(
            format_risk_summary(summary, findings, commands),
            "\n".join(
                [
                    "Overall risk: HIGH",
                    "",
                    "Findings: 1",
                    "HIGH: 1",
                    "MEDIUM: 0",
                    "LOW: 0",
                    "",
                    "Risk categories:",
                    "- PRIVILEGE_ESCALATION",
                    "",
                    "Risky commands:",
                    "- sudo su -: PRIVILEGE_ESCALATION (HIGH)",
                ]
            ),
        )

    def test_formats_mixed_findings_with_multiple_categories(self):
        summary = {
            "overall_severity": "HIGH",
            "finding_count": 4,
            "high_count": 3,
            "medium_count": 1,
            "low_count": 0,
            "categories": [
                "PERMISSION_MODIFICATION",
                "ACCOUNT_MODIFICATION",
                "PRIVILEGE_ESCALATION",
            ],
        }
        findings = [
            {"category": "PRIVILEGE_ESCALATION", "severity": "HIGH", "rule": "SUDO"},
            {"category": "ACCOUNT_MODIFICATION", "severity": "MEDIUM", "rule": "USERADD"},
            {"category": "PERMISSION_MODIFICATION", "severity": "HIGH", "rule": "CHMOD_777"},
            {"category": "PRIVILEGE_ESCALATION", "severity": "HIGH", "rule": "SUDO"},
        ]
        commands = [
            {
                "sequence_number": 20,
                "command": "chmod 777 /etc/passwd",
                "risk_findings": [
                    {"category": "PERMISSION_MODIFICATION", "severity": "HIGH", "rule": "CHMOD_777"},
                ],
            },
            {
                "sequence_number": 10,
                "command": "sudo useradd hacker123",
                "risk_findings": [
                    {"category": "ACCOUNT_MODIFICATION", "severity": "MEDIUM", "rule": "USERADD"},
                    {"category": "PRIVILEGE_ESCALATION", "severity": "HIGH", "rule": "SUDO"},
                ],
            },
            {
                "sequence_number": 5,
                "command": "sudo su -",
                "risk_findings": [
                    {"category": "PRIVILEGE_ESCALATION", "severity": "HIGH", "rule": "SUDO"},
                ],
            },
        ]

        self.assertEqual(
            format_risk_summary(summary, findings, commands),
            "\n".join(
                [
                    "Overall risk: HIGH",
                    "",
                    "Findings: 4",
                    "HIGH: 3",
                    "MEDIUM: 1",
                    "LOW: 0",
                    "",
                    "Risk categories:",
                    "- ACCOUNT_MODIFICATION",
                    "- PERMISSION_MODIFICATION",
                    "- PRIVILEGE_ESCALATION",
                    "",
                    "Risky commands:",
                    "- sudo su -: PRIVILEGE_ESCALATION (HIGH)",
                    "- sudo useradd hacker123: PRIVILEGE_ESCALATION (HIGH), ACCOUNT_MODIFICATION (MEDIUM)",
                    "- chmod 777 /etc/passwd: PERMISSION_MODIFICATION (HIGH)",
                ]
            ),
        )

    def test_formats_low_medium_high_in_deterministic_order(self):
        summary = {
            "overall_severity": "HIGH",
            "finding_count": 3,
            "high_count": 1,
            "medium_count": 1,
            "low_count": 1,
            "categories": ["Z_CATEGORY", "A_CATEGORY", "M_CATEGORY"],
        }
        findings = [
            {"category": "Z_CATEGORY", "severity": "LOW", "rule": "LOW_RULE"},
            {"category": "A_CATEGORY", "severity": "MEDIUM", "rule": "MED_RULE"},
            {"category": "M_CATEGORY", "severity": "HIGH", "rule": "HIGH_RULE"},
        ]
        commands = [
            {
                "sequence_number": 3,
                "command": "third",
                "risk_findings": [
                    {"category": "M_CATEGORY", "severity": "HIGH", "rule": "HIGH_RULE"},
                ],
            },
            {
                "sequence_number": 1,
                "command": "first",
                "risk_findings": [
                    {"category": "Z_CATEGORY", "severity": "LOW", "rule": "LOW_RULE"},
                ],
            },
            {
                "sequence_number": 2,
                "command": "second",
                "risk_findings": [
                    {"category": "A_CATEGORY", "severity": "MEDIUM", "rule": "MED_RULE"},
                ],
            },
        ]

        expected = "\n".join(
            [
                "Overall risk: HIGH",
                "",
                "Findings: 3",
                "HIGH: 1",
                "MEDIUM: 1",
                "LOW: 1",
                "",
                "Risk categories:",
                "- A_CATEGORY",
                "- M_CATEGORY",
                "- Z_CATEGORY",
                "",
                "Risky commands:",
                "- first: Z_CATEGORY (LOW)",
                "- second: A_CATEGORY (MEDIUM)",
                "- third: M_CATEGORY (HIGH)",
            ]
        )

        self.assertEqual(format_risk_summary(summary, findings, commands), expected)
        self.assertEqual(format_risk_summary(summary, findings, commands), expected)


if __name__ == "__main__":
    unittest.main()
