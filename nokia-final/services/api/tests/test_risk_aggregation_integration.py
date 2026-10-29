import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.db.database import SessionLocal
from app.services.session_query_service import SessionQueryService
from app.services.risk_aggregator import aggregate_session_risks


class RiskAggregationIntegrationTest(unittest.TestCase):
    """Integration test for session-level risk aggregation with real PostgreSQL data."""

    def setUp(self):
        self.db = SessionLocal()
        self.service = SessionQueryService(self.db)
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def tearDown(self):
        self.db.close()

    def test_risky_session_aggregation_high_severity(self):
        """
        Risky session should aggregate to HIGH severity with expected categories.
        """
        # Retrieve all commands and their risk findings
        command_evidence = self.service.get_command_evidence(self.risky_session_id)

        # Collect all risk findings across all commands
        all_findings = []
        for item in command_evidence:
            all_findings.extend(item.risk_findings)

        # Aggregate
        summary = aggregate_session_risks(all_findings)

        # Verify overall severity is HIGH
        self.assertEqual(summary.overall_severity, "HIGH")

        # Verify finding count matches expected risky commands
        # sudo su - (1 finding)
        # sudo useradd hacker123 (2 findings)
        # chmod 777 /etc/passwd (1 finding)
        # = 4 total findings
        self.assertEqual(summary.finding_count, 4)

        # Verify counts by severity
        self.assertEqual(summary.high_count, 3)
        self.assertEqual(summary.medium_count, 1)
        self.assertEqual(summary.low_count, 0)

        # Verify expected categories are present
        self.assertIn("PRIVILEGE_ESCALATION", summary.categories)
        self.assertIn("ACCOUNT_MODIFICATION", summary.categories)
        self.assertIn("PERMISSION_MODIFICATION", summary.categories)

    def test_benign_session_aggregation_none_severity(self):
        """
        Benign session should aggregate to NONE severity with no findings.
        """
        # Retrieve all commands and their risk findings
        command_evidence = self.service.get_command_evidence(self.benign_session_id)

        # Collect all risk findings across all commands
        all_findings = []
        for item in command_evidence:
            all_findings.extend(item.risk_findings)

        # Aggregate
        summary = aggregate_session_risks(all_findings)

        # Verify overall severity is NONE (no findings)
        self.assertEqual(summary.overall_severity, "NONE")
        self.assertEqual(summary.finding_count, 0)
        self.assertEqual(summary.high_count, 0)
        self.assertEqual(summary.medium_count, 0)
        self.assertEqual(summary.low_count, 0)
        self.assertEqual(summary.categories, [])


if __name__ == "__main__":
    unittest.main()
