import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.risk_classifier import classify_command_risks


class RiskClassifierTest(unittest.TestCase):
    def test_sudo_su_is_high_risk(self):
        findings = classify_command_risks("sudo su -")
        self.assertEqual(
            [(finding.category, finding.severity, finding.rule) for finding in findings],
            [("PRIVILEGE_ESCALATION", "HIGH", "SUDO")],
        )

    def test_sudo_i_is_high_risk(self):
        findings = classify_command_risks("sudo -i")
        self.assertEqual(
            [(finding.category, finding.severity, finding.rule) for finding in findings],
            [("PRIVILEGE_ESCALATION", "HIGH", "SUDO")],
        )

    def test_sudo_useradd_generates_two_findings(self):
        findings = classify_command_risks("sudo useradd hacker123")
        self.assertEqual(
            [(finding.category, finding.severity, finding.rule) for finding in findings],
            [
                ("PRIVILEGE_ESCALATION", "HIGH", "SUDO"),
                ("ACCOUNT_MODIFICATION", "MEDIUM", "USERADD"),
            ],
        )

    def test_chmod_777_is_high_risk(self):
        findings = classify_command_risks("chmod 777 /tmp/public")
        self.assertEqual(
            [(finding.category, finding.severity, finding.rule) for finding in findings],
            [("PERMISSION_MODIFICATION", "HIGH", "CHMOD_777")],
        )

    def test_chmod_777_on_passwd_file_triggers_both_rules(self):
        findings = classify_command_risks("chmod 777 /etc/passwd")
        self.assertEqual(
            sorted((finding.category, finding.severity, finding.rule) for finding in findings),
            sorted(
                [
                    ("CREDENTIAL_FILE_ACCESS", "HIGH", "ETC_PASSWD"),
                    ("PERMISSION_MODIFICATION", "HIGH", "CHMOD_777"),
                ]
            ),
        )

    def test_passwd_is_medium_risk(self):
        findings = classify_command_risks("passwd admin")
        self.assertEqual(
            [(finding.category, finding.severity, finding.rule) for finding in findings],
            [("CREDENTIAL_OPERATION", "MEDIUM", "PASSWD")],
        )

    def test_useradd_is_medium_risk(self):
        findings = classify_command_risks("useradd testuser")
        self.assertEqual(
            [(finding.category, finding.severity, finding.rule) for finding in findings],
            [("ACCOUNT_MODIFICATION", "MEDIUM", "USERADD")],
        )

    def test_shadow_access_is_high_risk(self):
        findings = classify_command_risks("cat /etc/shadow")
        self.assertEqual(
            [(finding.category, finding.severity, finding.rule) for finding in findings],
            [("CREDENTIAL_FILE_ACCESS", "HIGH", "ETC_SHADOW")],
        )

    def test_rm_rf_is_high_risk(self):
        findings = classify_command_risks("rm -rf /tmp/test")
        self.assertEqual(
            [(finding.category, finding.severity, finding.rule) for finding in findings],
            [("DESTRUCTIVE_OPERATION", "HIGH", "RM_RF")],
        )

    def test_benign_commands_have_no_risk(self):
        for command in ("ls -la", "pwd", "whoami", "hostname"):
            with self.subTest(command=command):
                self.assertEqual(classify_command_risks(command), [])

    def test_echo_sudo_does_not_trigger_privilege_escalation(self):
        self.assertEqual(classify_command_risks('echo "sudo"'), [])

    def test_echo_passwd_does_not_trigger_credential_operation(self):
        self.assertEqual(classify_command_risks('echo "passwd"'), [])

    def test_empty_command_has_no_risk(self):
        self.assertEqual(classify_command_risks(""), [])


if __name__ == "__main__":
    unittest.main()