"""
Nokia SSH Agentic AI — Email Alert System
Sends professional HTML email alerts to Nokia
security team when threats are detected.
Uses Gmail SMTP — free, reliable, no external service.
"""

import html
import logging
import os
import smtplib
import ssl
from datetime import datetime, timezone
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


def _smtp_port() -> int:
    try:
        return int(os.getenv("SMTP_PORT", "587"))
    except ValueError:
        logger.warning("Invalid SMTP_PORT; using the secure submission default.")
        return 587


SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
SMTP_PORT = _smtp_port()
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "")
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "").strip()
SMTP_TIMEOUT_SECONDS = 10


def _alert_recipient() -> str:
    return ALERT_EMAIL or os.getenv("ALERT_TO", "").strip()


def is_configured() -> bool:
    """Check if email is properly configured."""
    return bool(
        SMTP_HOST
        and 1 <= SMTP_PORT <= 65535
        and SMTP_USER
        and SMTP_PASS
        and _alert_recipient()
    )

def get_severity_color(severity: str) -> str:
    colors = {
        "CRITICAL": "#cc0000",
        "HIGH":     "#ff6600",
        "MEDIUM":   "#ffaa00",
        "LOW":      "#00aa00",
    }
    return colors.get(severity, "#666666")

def get_severity_emoji(severity: str) -> str:
    emojis = {
        "CRITICAL": "🚨",
        "HIGH":     "⚠️",
        "MEDIUM":   "🔶",
        "LOW":      "ℹ️",
    }
    return emojis.get(severity, "🔔")

def build_html_email(
    command: str,
    severity: str,
    username: str,
    session_id: str,
    timestamp: str,
    category: str = "",
    reason: str = "",
    anomaly_score: float = None,
    is_anomaly: bool = False,
    recommended_action: str = "",
    target: str = "",
    protocol: str = "",
    remote_address: str = "",
    termination_requested: bool | None = None,
    termination_confirmed: bool | None = None,
) -> str:
    color = get_severity_color(severity)
    emoji = get_severity_emoji(severity)
    command, username, session_id, reason, category, timestamp, target, protocol, remote_address, recommended_action, severity = (
        html.escape(str(v))
        for v in (
            command,
            username,
            session_id,
            reason,
            category,
            timestamp,
            target,
            protocol,
            remote_address,
            recommended_action,
            severity,
        )
    )
    anomaly_text = (
        f"YES (score: {anomaly_score:.3f})" 
        if is_anomaly and anomaly_score is not None 
        else "No"
    )
    requested_text = "Yes" if termination_requested else "No" if termination_requested is False else "Unknown"
    confirmed_text = "Yes" if termination_confirmed else "No" if termination_confirmed is False else "Not verified"

    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; background: #f4f4f4; padding: 20px; margin: 0;">

      <!-- Header -->
      <div style="background: {color}; color: white; padding: 24px;
                  border-radius: 8px 8px 0 0; text-align: center;">
        <h1 style="margin: 0; font-size: 28px;">{emoji} Nokia SSH Security Alert</h1>
        <h2 style="margin: 8px 0 0 0; font-size: 20px; font-weight: normal;">
          Severity: {severity}
        </h2>
      </div>

      <!-- Details -->
      <div style="background: white; padding: 24px; border-left: 4px solid {color};">
        <h3 style="color: {color}; margin-top: 0;">Threat Details</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 10px; font-weight: bold; width: 160px;">Command</td>
            <td style="padding: 10px;">
              <code style="background: #f0f0f0; padding: 4px 8px;
                           border-radius: 4px; font-size: 14px;">{command}</code>
            </td>
          </tr>
          <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 10px; font-weight: bold;">User</td>
            <td style="padding: 10px;">{username}</td>
          </tr>
          <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 10px; font-weight: bold;">Session ID</td>
            <td style="padding: 10px;"><code>{session_id}</code></td>
          </tr>
          <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 10px; font-weight: bold;">Time</td>
            <td style="padding: 10px;">{timestamp}</td>
          </tr>
          <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 10px; font-weight: bold;">Category</td>
            <td style="padding: 10px;">{category or "Unknown"}</td>
          </tr>
          <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 10px; font-weight: bold;">Target</td>
            <td style="padding: 10px;">{target or "Unknown"}</td>
          </tr>
          <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 10px; font-weight: bold;">Protocol</td>
            <td style="padding: 10px;">{protocol or "Unknown"}</td>
          </tr>
          <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 10px; font-weight: bold;">Remote address</td>
            <td style="padding: 10px;">{remote_address or "Unknown"}</td>
          </tr>
          <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 10px; font-weight: bold;">Reason</td>
            <td style="padding: 10px;">{reason or "See command details"}</td>
          </tr>
          <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 10px; font-weight: bold;">Termination requested</td>
            <td style="padding: 10px;">{requested_text}</td>
          </tr>
          <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 10px; font-weight: bold;">Warpgate confirmed termination</td>
            <td style="padding: 10px;">{confirmed_text}</td>
          </tr>
          <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 10px; font-weight: bold;">Anomaly Detected</td>
            <td style="padding: 10px;">{anomaly_text}</td>
          </tr>
        </table>
      </div>

      <!-- Recommended Action -->
      <div style="background: #fff3cd; padding: 16px;
                  border-left: 4px solid #ffaa00; margin-top: 4px;">
        <h3 style="margin: 0 0 8px 0; color: #856404;">
          Recommended Action
        </h3>
        <p style="margin: 0; color: #533f03;">
          {recommended_action or "Review the event and verify the session state in Warpgate."}
        </p>
      </div>

      <!-- Footer -->
      <div style="background: #333; color: #aaa; padding: 16px;
                  border-radius: 0 0 8px 8px; text-align: center;
                  font-size: 12px; margin-top: 4px;">
        Nokia SSH Session Intelligence System — Automated Security Alert<br>
        This alert was generated automatically. Do not reply to this email.
      </div>

    </body>
    </html>
    """

def build_plain_email(
    command: str,
    severity: str,
    username: str,
    session_id: str,
    timestamp: str,
    reason: str = "",
    anomaly_score: float = None,
    recommended_action: str = "",
    category: str = "",
    target: str = "",
    protocol: str = "",
    remote_address: str = "",
    termination_requested: bool | None = None,
    termination_confirmed: bool | None = None,
) -> str:
    requested_text = "Yes" if termination_requested else "No" if termination_requested is False else "Unknown"
    confirmed_text = "Yes" if termination_confirmed else "No" if termination_confirmed is False else "Not verified"
    return f"""
Nokia SSH Session Intelligence Platform - SECURITY ALERT
=========================================================

DETAILS
-------
Severity   : {severity}
User       : {username}
Session    : {session_id}
Command    : {command}
Category   : {category or "Unknown"}
Reason     : {reason or "Dangerous command detected"}
Timestamp  : {timestamp}
Target     : {target or os.getenv('PROXY_TARGET_NAME', os.getenv('PROXY_TARGET_HOST', 'unknown'))}
Protocol   : {protocol or "Unknown"}
Remote     : {remote_address or "Unknown"}
Termination requested: {requested_text}
Warpgate confirmed termination: {confirmed_text}
Anomaly    : {"YES (score: " + str(round(anomaly_score, 3)) + ")" if anomaly_score else "No"}

{recommended_action or "Review the event and verify the session state in Warpgate."}

This alert was sent automatically by the Nokia NBUC Agentic AI Security System.
    """.strip()

def send_alert(
    command: str,
    severity: str,
    username: str,
    session_id: str,
    timestamp: str = None,
    category: str = "",
    reason: str = "",
    anomaly_score: float = None,
    is_anomaly: bool = False,
    recommended_action: str = "",
    target: str = "",
    protocol: str = "",
    remote_address: str = "",
    termination_requested: bool | None = None,
    termination_confirmed: bool | None = None,
) -> bool:
    """
    Sends email alert to Nokia security team.
    Returns True if sent successfully, False otherwise.
    """
    if not is_configured():
        logger.error("Security email is not configured; set SMTP_USER, SMTP_PASS, and ALERT_EMAIL.")
        return False

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    try:
        msg = MIMEMultipart("alternative")
        subject_command = " ".join(command.replace("\r", " ").replace("\n", " ").split())[:40]
        msg["Subject"] = str(Header(f"[{severity}] Nokia SSH Security Alert — {subject_command}", "utf-8"))
        msg["From"] = f"Nokia Security System <{SMTP_USER}>"
        msg["To"] = _alert_recipient()

        plain = build_plain_email(
            command=command, severity=severity,
            username=username, session_id=session_id,
            timestamp=timestamp, reason=reason,
            anomaly_score=anomaly_score,
            recommended_action=recommended_action,
            category=category,
            target=target,
            protocol=protocol,
            remote_address=remote_address,
            termination_requested=termination_requested,
            termination_confirmed=termination_confirmed,
        )
        html = build_html_email(
            command=command, severity=severity,
            username=username, session_id=session_id,
            timestamp=timestamp, category=category,
            reason=reason, anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            recommended_action=recommended_action,
            target=target,
            protocol=protocol,
            remote_address=remote_address,
            termination_requested=termination_requested,
            termination_confirmed=termination_confirmed,
        )

        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(html, "html"))

        if SMTP_PORT == 465:
            server_context = smtplib.SMTP_SSL(
                SMTP_HOST,
                SMTP_PORT,
                timeout=SMTP_TIMEOUT_SECONDS,
                context=ssl.create_default_context(),
            )
        else:
            server_context = smtplib.SMTP(
                SMTP_HOST,
                SMTP_PORT,
                timeout=SMTP_TIMEOUT_SECONDS,
            )
        with server_context as server:
            if SMTP_PORT != 465:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        logger.info("Security email sent (severity=%s, session_id=%s).", severity, session_id)
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("Security email SMTP authentication failed; verify sender credentials.")
        return False
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        logger.error("Security email delivery failed (%s).", type(exc).__name__)
        return False
    except Exception as exc:
        logger.exception("Unexpected security email delivery failure (%s).", type(exc).__name__)
        return False

def send_test_email() -> bool:
    """Sends a test email to verify configuration."""
    logger.info("Sending a security email configuration test.")
    return send_alert(
        command="TEST — Nokia SSH Security System",
        severity="LOW",
        username="system",
        session_id="test-session",
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        category="system_test",
        reason="This is a test alert to verify email configuration",
        recommended_action="No action required; this is a test message.",
        termination_requested=False,
        termination_confirmed=False,
    )

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Nokia SSH Email Alerter - Configuration Check")

    if is_configured():
        print("SMTP sender, password, and alert recipient are configured.")
        print(f"SMTP endpoint: {SMTP_HOST}:{SMTP_PORT}")
        print()
        answer = input("Send test email? (yes/no): ").strip().lower()
        if answer == "yes":
            success = send_test_email()
            if success:
                print("✅ Test email sent successfully!")
            else:
                print("❌ Test email failed. Check configuration.")
    else:
        print("❌ Email not configured.")
        print()
        print("Add these to your .env file:")
        print("  SMTP_HOST=smtp.gmail.com")
        print("  SMTP_PORT=587")
        print("  SMTP_USER=your-gmail@gmail.com")
        print("  SMTP_PASS=your-16-char-app-password")
        print("  ALERT_EMAIL=security@nokia.com")

    print()
    print("=" * 50)
    print("Configuration check complete!")
