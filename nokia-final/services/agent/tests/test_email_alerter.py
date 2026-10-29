import os
import unittest
from email import message_from_string
from email.policy import default
from unittest.mock import MagicMock, patch

from services.agent import email_alerter


class EmailAlerterTests(unittest.TestCase):
    def setUp(self):
        self.config = patch.multiple(
            email_alerter,
            SMTP_HOST="smtp.example.test",
            SMTP_PORT=587,
            SMTP_USER="sender@example.test",
            SMTP_PASS="test-password",
            ALERT_EMAIL="security@example.test",
        )
        self.config.start()
        self.addCleanup(self.config.stop)

    def test_missing_configuration_reports_not_configured(self):
        with patch.multiple(
            email_alerter,
            SMTP_USER="",
            SMTP_PASS="",
            ALERT_EMAIL="",
        ), patch.object(email_alerter.smtplib, "SMTP") as smtp:
            self.assertFalse(
                email_alerter.send_alert(
                    command="reboot",
                    severity="CRITICAL",
                    username="alice",
                    session_id="session-1",
                )
            )
            smtp.assert_not_called()

    def test_success_sends_both_mime_parts_and_uses_starttls(self):
        smtp = MagicMock()
        smtp.__enter__.return_value = smtp
        with patch.object(email_alerter.smtplib, "SMTP", return_value=smtp):
            sent = email_alerter.send_alert(
                command="reboot",
                severity="CRITICAL",
                username="alice",
                session_id="session-1",
                category="System Command",
                termination_requested=True,
                termination_confirmed=False,
            )

        self.assertTrue(sent)
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("sender@example.test", "test-password")
        message = smtp.send_message.call_args.args[0]
        self.assertEqual(message["To"], "security@example.test")
        parsed = message_from_string(message.as_string(), policy=default)
        self.assertEqual(
            {part.get_content_type() for part in parsed.iter_parts()},
            {"text/plain", "text/html"},
        )
        text = "\n".join(part.get_content() for part in parsed.iter_parts())
        self.assertIn("Warpgate confirmed termination: No", text)

    def test_html_escapes_attacker_controlled_values(self):
        rendered = email_alerter.build_html_email(
            command="<script>alert(1)</script>",
            severity="HIGH",
            username="<img src=x>",
            session_id="session&1",
            timestamp="now",
            category="<b>category</b>",
            reason="<script>reason</script>",
            recommended_action="<i>action</i>",
        )
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<img src=x>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("&lt;img src=x&gt;", rendered)

    def test_smtp_authentication_failure_is_reported(self):
        with patch.object(
            email_alerter.smtplib,
            "SMTP",
            side_effect=email_alerter.smtplib.SMTPAuthenticationError(535, b"denied"),
        ):
            self.assertFalse(
                email_alerter.send_alert(
                    command="reboot",
                    severity="CRITICAL",
                    username="alice",
                    session_id="session-1",
                )
            )

    def test_smtp_timeout_is_reported_without_raising(self):
        with patch.object(
            email_alerter.smtplib,
            "SMTP",
            side_effect=TimeoutError("mail server unavailable"),
        ):
            self.assertFalse(
                email_alerter.send_alert(
                    command="reboot",
                    severity="CRITICAL",
                    username="alice",
                    session_id="session-1",
                )
            )

    def test_alert_to_remains_a_supported_recipient_name(self):
        with patch.multiple(email_alerter, ALERT_EMAIL=""), patch.dict(
            os.environ,
            {"ALERT_TO": "legacy@example.test"},
        ):
            self.assertTrue(email_alerter.is_configured())


if __name__ == "__main__":
    unittest.main()
