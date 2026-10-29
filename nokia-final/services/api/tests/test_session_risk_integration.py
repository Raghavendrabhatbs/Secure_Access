import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.db.database import SessionLocal
from app.services.session_query_service import SessionQueryService


class SessionRiskIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.service = SessionQueryService(self.db)
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def tearDown(self):
        self.db.close()

    def test_risky_session_commands_include_expected_risk_findings(self):
        command_evidence = self.service.get_command_evidence(self.risky_session_id)
        by_command = {
            item.command: [(finding.category, finding.severity, finding.rule) for finding in item.risk_findings]
            for item in command_evidence
        }

        self.assertEqual(
            by_command["sudo su -"],
            [("PRIVILEGE_ESCALATION", "HIGH", "SUDO")],
        )
        self.assertEqual(
            by_command["sudo useradd hacker123"],
            [
                ("PRIVILEGE_ESCALATION", "HIGH", "SUDO"),
                ("ACCOUNT_MODIFICATION", "MEDIUM", "USERADD"),
            ],
        )
        self.assertEqual(
            by_command["chmod 777 /etc/passwd"],
            [("PERMISSION_MODIFICATION", "HIGH", "CHMOD_777")],
        )

    def test_cross_session_search_carries_risk_findings(self):
        matches = self.service.search_command_matches(["sudo", "passwd"])
        risky_matches = {match.command: match for match in matches if match.session_id == self.risky_session_id}

        self.assertEqual(
            [(finding.category, finding.severity, finding.rule) for finding in risky_matches["sudo su -"].risk_findings],
            [("PRIVILEGE_ESCALATION", "HIGH", "SUDO")],
        )
        self.assertEqual(
            [(finding.category, finding.severity, finding.rule) for finding in risky_matches["sudo useradd hacker123"].risk_findings],
            [
                ("PRIVILEGE_ESCALATION", "HIGH", "SUDO"),
                ("ACCOUNT_MODIFICATION", "MEDIUM", "USERADD"),
            ],
        )
        self.assertEqual(
            [(finding.category, finding.severity, finding.rule) for finding in risky_matches["chmod 777 /etc/passwd"].risk_findings],
            [("PERMISSION_MODIFICATION", "HIGH", "CHMOD_777")],
        )

    def test_benign_command_remains_risk_free(self):
        command_evidence = self.service.get_command_evidence(self.benign_session_id)
        by_command = {item.command: item for item in command_evidence}

        self.assertIn("whoami", by_command)
        self.assertEqual(by_command["whoami"].risk_findings, [])


if __name__ == "__main__":
    unittest.main()