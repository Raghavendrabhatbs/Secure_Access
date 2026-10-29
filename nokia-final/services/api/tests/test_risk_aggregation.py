import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.risk_aggregator import (
    aggregate_session_risks,
    SessionRiskSummary,
)
from app.services.risk_classifier import RiskFinding


class TestRiskAggregation(unittest.TestCase):
    """Unit tests for session-level risk aggregation."""

    def test_aggregate_no_findings(self):
        """No findings should result in NONE severity."""
        findings: list[RiskFinding] = []
        summary = aggregate_session_risks(findings)

        self.assertEqual(summary.overall_severity, "NONE")
        self.assertEqual(summary.finding_count, 0)
        self.assertEqual(summary.high_count, 0)
        self.assertEqual(summary.medium_count, 0)
        self.assertEqual(summary.low_count, 0)
        self.assertEqual(summary.categories, [])

    def test_aggregate_low_only(self):
        """Only LOW findings should result in LOW severity."""
        findings = [
            RiskFinding(category="LOW_RISK_1", severity="LOW", rule="LOW_RULE_1"),
            RiskFinding(category="LOW_RISK_2", severity="LOW", rule="LOW_RULE_2"),
        ]
        summary = aggregate_session_risks(findings)

        self.assertEqual(summary.overall_severity, "LOW")
        self.assertEqual(summary.finding_count, 2)
        self.assertEqual(summary.high_count, 0)
        self.assertEqual(summary.medium_count, 0)
        self.assertEqual(summary.low_count, 2)
        self.assertEqual(sorted(summary.categories), ["LOW_RISK_1", "LOW_RISK_2"])

    def test_aggregate_medium_only(self):
        """Only MEDIUM findings should result in MEDIUM severity."""
        findings = [
            RiskFinding(
                category="CREDENTIAL_OPERATION", severity="MEDIUM", rule="PASSWD"
            ),
            RiskFinding(
                category="ACCOUNT_MODIFICATION", severity="MEDIUM", rule="USERADD"
            ),
        ]
        summary = aggregate_session_risks(findings)

        self.assertEqual(summary.overall_severity, "MEDIUM")
        self.assertEqual(summary.finding_count, 2)
        self.assertEqual(summary.high_count, 0)
        self.assertEqual(summary.medium_count, 2)
        self.assertEqual(summary.low_count, 0)
        self.assertEqual(
            sorted(summary.categories),
            ["ACCOUNT_MODIFICATION", "CREDENTIAL_OPERATION"],
        )

    def test_aggregate_high_only(self):
        """Only HIGH findings should result in HIGH severity."""
        findings = [
            RiskFinding(
                category="PRIVILEGE_ESCALATION", severity="HIGH", rule="SUDO"
            ),
            RiskFinding(
                category="PERMISSION_MODIFICATION", severity="HIGH", rule="CHMOD_777"
            ),
            RiskFinding(
                category="CREDENTIAL_FILE_ACCESS", severity="HIGH", rule="ETC_SHADOW"
            ),
        ]
        summary = aggregate_session_risks(findings)

        self.assertEqual(summary.overall_severity, "HIGH")
        self.assertEqual(summary.finding_count, 3)
        self.assertEqual(summary.high_count, 3)
        self.assertEqual(summary.medium_count, 0)
        self.assertEqual(summary.low_count, 0)
        self.assertEqual(
            sorted(summary.categories),
            [
                "CREDENTIAL_FILE_ACCESS",
                "PERMISSION_MODIFICATION",
                "PRIVILEGE_ESCALATION",
            ],
        )

    def test_aggregate_mixed_high_medium_low(self):
        """Mixed findings with HIGH should result in HIGH severity."""
        findings = [
            RiskFinding(
                category="PRIVILEGE_ESCALATION", severity="HIGH", rule="SUDO"
            ),
            RiskFinding(
                category="CREDENTIAL_OPERATION", severity="MEDIUM", rule="PASSWD"
            ),
            RiskFinding(
                category="ACCOUNT_MODIFICATION", severity="MEDIUM", rule="USERADD"
            ),
            RiskFinding(category="LOW_RISK", severity="LOW", rule="LOW_RULE"),
        ]
        summary = aggregate_session_risks(findings)

        self.assertEqual(summary.overall_severity, "HIGH")
        self.assertEqual(summary.finding_count, 4)
        self.assertEqual(summary.high_count, 1)
        self.assertEqual(summary.medium_count, 2)
        self.assertEqual(summary.low_count, 1)
        self.assertEqual(
            sorted(summary.categories),
            [
                "ACCOUNT_MODIFICATION",
                "CREDENTIAL_OPERATION",
                "LOW_RISK",
                "PRIVILEGE_ESCALATION",
            ],
        )

    def test_aggregate_duplicate_categories(self):
        """Duplicate categories should appear only once in result."""
        findings = [
            RiskFinding(
                category="PRIVILEGE_ESCALATION", severity="HIGH", rule="SUDO"
            ),
            RiskFinding(
                category="PRIVILEGE_ESCALATION",
                severity="HIGH",
                rule="SUDO_ALT",
            ),
        ]
        summary = aggregate_session_risks(findings)

        self.assertEqual(summary.overall_severity, "HIGH")
        self.assertEqual(summary.finding_count, 2)
        self.assertEqual(summary.high_count, 2)
        # Should contain each category only once
        self.assertEqual(summary.categories, ["PRIVILEGE_ESCALATION"])

    def test_aggregate_medium_without_high(self):
        """MEDIUM + LOW without HIGH should result in MEDIUM severity."""
        findings = [
            RiskFinding(
                category="CREDENTIAL_OPERATION", severity="MEDIUM", rule="PASSWD"
            ),
            RiskFinding(category="LOW_RISK", severity="LOW", rule="LOW_RULE"),
        ]
        summary = aggregate_session_risks(findings)

        self.assertEqual(summary.overall_severity, "MEDIUM")
        self.assertEqual(summary.finding_count, 2)
        self.assertEqual(summary.high_count, 0)
        self.assertEqual(summary.medium_count, 1)
        self.assertEqual(summary.low_count, 1)
        self.assertEqual(
            sorted(summary.categories),
            ["CREDENTIAL_OPERATION", "LOW_RISK"],
        )

    def test_summary_is_frozen(self):
        """SessionRiskSummary should be immutable (frozen dataclass)."""
        findings = [
            RiskFinding(
                category="PRIVILEGE_ESCALATION", severity="HIGH", rule="SUDO"
            ),
        ]
        summary = aggregate_session_risks(findings)

        # Attempting to modify should raise an error
        with self.assertRaises((AttributeError, TypeError)):
            summary.overall_severity = "LOW"


if __name__ == "__main__":
    unittest.main()
