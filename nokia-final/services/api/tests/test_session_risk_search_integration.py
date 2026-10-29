import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.db.database import SessionLocal
from app.services.session_query_service import SessionQueryService


class SessionRiskSearchIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.service = SessionQueryService(self.db)
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def tearDown(self):
        self.db.close()

    def test_privilege_escalation_category_finds_risky_session(self):
        matches = self.service.search_sessions_by_risk_categories(["PRIVILEGE_ESCALATION"])

        self.assertTrue(matches)
        session_ids = [match.session_id for match in matches]
        self.assertIn(self.risky_session_id, session_ids)
        self.assertNotIn(self.benign_session_id, session_ids)

        risky = next(match for match in matches if match.session_id == self.risky_session_id)
        self.assertEqual(risky.risk_summary.overall_severity, "HIGH")
        self.assertIn("PRIVILEGE_ESCALATION", risky.risk_summary.categories)
        self.assertEqual(
            [command.command for command in risky.matching_commands],
            ["sudo su -", "sudo useradd hacker123"],
        )

    def test_permission_modification_category_finds_chmod_session(self):
        matches = self.service.search_sessions_by_risk_categories(["PERMISSION_MODIFICATION"])

        self.assertTrue(matches)
        risky = next(match for match in matches if match.session_id == self.risky_session_id)
        self.assertEqual(risky.risk_summary.overall_severity, "HIGH")
        self.assertIn("PERMISSION_MODIFICATION", risky.risk_summary.categories)
        self.assertEqual(
            [command.command for command in risky.matching_commands],
            ["chmod 777 /etc/passwd"],
        )

    def test_account_modification_category_finds_useradd_session(self):
        matches = self.service.search_sessions_by_risk_categories(["ACCOUNT_MODIFICATION"])

        self.assertTrue(matches)
        risky = next(match for match in matches if match.session_id == self.risky_session_id)
        self.assertIn("ACCOUNT_MODIFICATION", risky.risk_summary.categories)
        self.assertEqual(
            [command.command for command in risky.matching_commands],
            ["sudo useradd hacker123"],
        )
        command = risky.matching_commands[0]
        self.assertEqual(
            [(finding.category, finding.severity, finding.rule) for finding in command.risk_findings],
            [("ACCOUNT_MODIFICATION", "MEDIUM", "USERADD")],
        )

    def test_no_match_category_returns_empty(self):
        matches = self.service.search_sessions_by_risk_categories(["NON_EXISTENT_RISK_CATEGORY"])
        self.assertEqual(matches, [])

    def test_evidence_completeness_contains_session_commands_findings_and_summary(self):
        matches = self.service.search_sessions_by_risk_categories(["PRIVILEGE_ESCALATION"])
        risky = next(match for match in matches if match.session_id == self.risky_session_id)

        self.assertEqual(risky.session_id, self.risky_session_id)
        self.assertTrue(risky.matching_commands)
        self.assertIsNotNone(risky.risk_summary)

        # Commands are ordered and include findings.
        sequence_numbers = [command.sequence_number for command in risky.matching_commands]
        self.assertEqual(sequence_numbers, sorted(sequence_numbers))
        self.assertTrue(all(command.risk_findings for command in risky.matching_commands))

        # Summary is attached and consistent with findings.
        self.assertEqual(risky.risk_summary.overall_severity, "HIGH")
        self.assertEqual(risky.risk_summary.finding_count, 2)
        self.assertEqual(risky.risk_summary.high_count, 2)
        self.assertEqual(risky.risk_summary.medium_count, 0)
        self.assertEqual(risky.risk_summary.low_count, 0)
        self.assertEqual(risky.risk_summary.categories, ["PRIVILEGE_ESCALATION"])

    def test_existing_categories_only_without_new_rules(self):
        categories = ["PRIVILEGE_ESCALATION", "ACCOUNT_MODIFICATION", "PERMISSION_MODIFICATION"]
        observed_categories: set[str] = set()

        for category in categories:
            matches = self.service.search_sessions_by_risk_categories([category])
            self.assertTrue(matches)
            risky = next(match for match in matches if match.session_id == self.risky_session_id)
            observed_categories.update(
                finding.category
                for command in risky.matching_commands
                for finding in command.risk_findings
            )

        # Existing classifier categories are reused; no new rules are introduced.
        self.assertEqual(observed_categories, set(categories))


if __name__ == "__main__":
    unittest.main()
