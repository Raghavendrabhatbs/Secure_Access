import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.risk_classifier import RiskFinding
from app.services.timeline import TimelineEntry, sort_timeline_entries


class TestTimeline(unittest.TestCase):
    """Pure unit tests for timeline DTO normalization and ordering."""

    def test_normal_command_entry(self):
        entry = TimelineEntry(
            timestamp="2026-08-10T11:00:00Z",
            sequence_number=1,
            event_type="COMMAND",
            command="whoami",
        )
        self.assertEqual(entry.event_type, "COMMAND")
        self.assertEqual(entry.command, "whoami")
        self.assertEqual(entry.output, "")
        self.assertEqual(entry.risk_findings, ())

    def test_entry_with_output(self):
        entry = TimelineEntry(
            timestamp="2026-08-10T11:00:01Z",
            sequence_number=2,
            event_type="COMMAND",
            command="hostname",
            output="nokia-lab-1",
        )
        self.assertEqual(entry.output, "nokia-lab-1")

    def test_entry_with_risk_findings(self):
        findings = (
            RiskFinding(category="PRIVILEGE_ESCALATION", severity="HIGH", rule="SUDO"),
            RiskFinding(category="ACCOUNT_MODIFICATION", severity="MEDIUM", rule="USERADD"),
        )
        entry = TimelineEntry(
            timestamp="2026-08-10T11:00:02Z",
            sequence_number=3,
            event_type="COMMAND",
            command="sudo useradd hacker123",
            risk_findings=findings,
        )
        self.assertEqual(len(entry.risk_findings), 2)
        self.assertEqual(entry.risk_findings[0].category, "PRIVILEGE_ESCALATION")
        self.assertEqual(entry.risk_findings[1].severity, "MEDIUM")

    def test_missing_output_normalizes_to_empty_string(self):
        entry = TimelineEntry(
            timestamp="2026-08-10T11:00:03Z",
            sequence_number=4,
            event_type="COMMAND",
            command="date",
            output=None,
        )
        self.assertEqual(entry.output, "")

    def test_missing_risk_findings_normalize_to_empty_tuple(self):
        entry = TimelineEntry(
            timestamp="2026-08-10T11:00:04Z",
            sequence_number=5,
            event_type="COMMAND",
            command="echo test",
            risk_findings=None,
        )
        self.assertEqual(entry.risk_findings, ())

    def test_timestamp_preservation(self):
        timestamp = "2026-08-10T11:00:05.123456Z"
        entry = TimelineEntry(
            timestamp=timestamp,
            sequence_number=6,
            event_type="COMMAND",
            command="pwd",
        )
        self.assertEqual(entry.timestamp, timestamp)

    def test_sequence_number_preservation(self):
        entry = TimelineEntry(
            timestamp="2026-08-10T11:00:06Z",
            sequence_number=42,
            event_type="COMMAND",
            command="id",
        )
        self.assertEqual(entry.sequence_number, 42)

    def test_deterministic_ordering_behavior(self):
        e3 = TimelineEntry(
            timestamp="2026-08-10T11:00:03Z",
            sequence_number=3,
            event_type="COMMAND",
            command="cmd3",
        )
        e1 = TimelineEntry(
            timestamp="2026-08-10T11:00:01Z",
            sequence_number=1,
            event_type="COMMAND",
            command="cmd1",
        )
        e2 = TimelineEntry(
            timestamp="2026-08-10T11:00:02Z",
            sequence_number=2,
            event_type="COMMAND",
            command="cmd2",
        )

        ordered = sort_timeline_entries([e3, e1, e2])
        self.assertEqual([e.command for e in ordered], ["cmd1", "cmd2", "cmd3"])

    def test_timeline_entry_is_immutable(self):
        entry = TimelineEntry(
            timestamp="2026-08-10T11:00:07Z",
            sequence_number=7,
            event_type="COMMAND",
            command="uname -a",
        )
        with self.assertRaises((AttributeError, TypeError)):
            entry.command = "changed"

    def test_multiple_entries_realistic_ssh_timeline(self):
        entries = [
            TimelineEntry(
                timestamp="2026-08-10T11:00:00Z",
                sequence_number=1,
                event_type="COMMAND",
                command="whoami",
                output="admin",
            ),
            TimelineEntry(
                timestamp="2026-08-10T11:00:01Z",
                sequence_number=2,
                event_type="COMMAND",
                command="sudo su -",
                risk_findings=(
                    RiskFinding(
                        category="PRIVILEGE_ESCALATION",
                        severity="HIGH",
                        rule="SUDO",
                    ),
                ),
            ),
            TimelineEntry(
                timestamp="2026-08-10T11:00:02Z",
                sequence_number=3,
                event_type="COMMAND",
                command="sudo useradd hacker123",
                risk_findings=(
                    RiskFinding(
                        category="PRIVILEGE_ESCALATION",
                        severity="HIGH",
                        rule="SUDO",
                    ),
                    RiskFinding(
                        category="ACCOUNT_MODIFICATION",
                        severity="MEDIUM",
                        rule="USERADD",
                    ),
                ),
            ),
            TimelineEntry(
                timestamp="2026-08-10T11:00:03Z",
                sequence_number=4,
                event_type="COMMAND",
                command="chmod 777 /etc/passwd",
                risk_findings=(
                    RiskFinding(
                        category="PERMISSION_MODIFICATION",
                        severity="HIGH",
                        rule="CHMOD_777",
                    ),
                ),
            ),
        ]

        ordered = sort_timeline_entries(entries)
        self.assertEqual(len(ordered), 4)
        self.assertEqual(ordered[0].command, "whoami")
        self.assertEqual(ordered[1].command, "sudo su -")
        self.assertEqual(ordered[2].command, "sudo useradd hacker123")
        self.assertEqual(ordered[3].command, "chmod 777 /etc/passwd")

        findings = [
            finding
            for entry in ordered
            for finding in entry.risk_findings
        ]
        self.assertEqual(len(findings), 4)


if __name__ == "__main__":
    unittest.main()
