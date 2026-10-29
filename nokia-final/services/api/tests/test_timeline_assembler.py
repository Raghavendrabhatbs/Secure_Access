import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.risk_classifier import RiskFinding
from app.services.timeline_assembler import assemble_session_timeline


@dataclass
class CommandRecord:
    executed_at: datetime | None
    sequence_number: int | None
    command: str | None
    output: str | None
    risk_findings: list[RiskFinding] | None


@dataclass
class EventRecord:
    timestamp: datetime | None
    event_type: str | None
    message: str | None
    payload: dict | None


class TestTimelineAssembler(unittest.TestCase):
    def test_empty_timeline(self):
        self.assertEqual(assemble_session_timeline([], []), [])

    def test_single_command_entry(self):
        commands = [
            CommandRecord(
                executed_at=datetime(2026, 8, 10, 10, 1, 2, tzinfo=timezone.utc),
                sequence_number=1,
                command="whoami",
                output="admin",
                risk_findings=[],
            )
        ]
        timeline = assemble_session_timeline(commands)
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0].event_type, "COMMAND")
        self.assertEqual(timeline[0].command, "whoami")

    def test_event_only_timeline(self):
        events = [
            EventRecord(
                timestamp=datetime(2026, 8, 10, 10, 1, 5, tzinfo=timezone.utc),
                event_type="LOGIN",
                message="User login accepted",
                payload={"ip": "127.0.0.1"},
            )
        ]
        timeline = assemble_session_timeline([], events)
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0].event_type, "LOGIN")
        self.assertEqual(timeline[0].command, "User login accepted")

    def test_chronological_sorting_with_reverse_input(self):
        commands = [
            CommandRecord(
                executed_at=datetime(2026, 8, 10, 10, 1, 8, tzinfo=timezone.utc),
                sequence_number=3,
                command="chmod 777 /etc/passwd",
                output="",
                risk_findings=[
                    RiskFinding(
                        category="PERMISSION_MODIFICATION",
                        severity="HIGH",
                        rule="CHMOD_777",
                    )
                ],
            ),
            CommandRecord(
                executed_at=datetime(2026, 8, 10, 10, 1, 2, tzinfo=timezone.utc),
                sequence_number=1,
                command="whoami",
                output="admin",
                risk_findings=[],
            ),
        ]
        timeline = assemble_session_timeline(commands)
        self.assertEqual([entry.sequence_number for entry in timeline], [1, 3])

    def test_same_timestamp_orders_by_sequence(self):
        ts = datetime(2026, 8, 10, 10, 1, 5, tzinfo=timezone.utc)
        commands = [
            CommandRecord(
                executed_at=ts,
                sequence_number=2,
                command="second",
                output="",
                risk_findings=[],
            ),
            CommandRecord(
                executed_at=ts,
                sequence_number=1,
                command="first",
                output="",
                risk_findings=[],
            ),
        ]
        timeline = assemble_session_timeline(commands)
        self.assertEqual([entry.command for entry in timeline], ["first", "second"])

    def test_risk_findings_remain_attached(self):
        commands = [
            CommandRecord(
                executed_at=datetime(2026, 8, 10, 10, 1, 5, tzinfo=timezone.utc),
                sequence_number=2,
                command="sudo su -",
                output="",
                risk_findings=[
                    RiskFinding(
                        category="PRIVILEGE_ESCALATION",
                        severity="HIGH",
                        rule="SUDO",
                    )
                ],
            )
        ]
        timeline = assemble_session_timeline(commands)
        self.assertEqual(timeline[0].risk_findings[0].category, "PRIVILEGE_ESCALATION")

    def test_command_and_output_preserved(self):
        commands = [
            CommandRecord(
                executed_at=datetime(2026, 8, 10, 10, 1, 2, tzinfo=timezone.utc),
                sequence_number=1,
                command="hostname",
                output="nokia-lab-1",
                risk_findings=[],
            )
        ]
        timeline = assemble_session_timeline(commands)
        self.assertEqual(timeline[0].command, "hostname")
        self.assertEqual(timeline[0].output, "nokia-lab-1")

    def test_missing_timestamp_handling(self):
        commands = [
            CommandRecord(
                executed_at=None,
                sequence_number=2,
                command="no-ts",
                output="",
                risk_findings=[],
            ),
            CommandRecord(
                executed_at=datetime(2026, 8, 10, 10, 1, 2, tzinfo=timezone.utc),
                sequence_number=1,
                command="with-ts",
                output="",
                risk_findings=[],
            ),
        ]
        timeline = assemble_session_timeline(commands)
        self.assertEqual(len(timeline), 2)
        self.assertEqual({entry.command for entry in timeline}, {"no-ts", "with-ts"})

    def test_duplicate_timestamps_are_deterministic(self):
        ts = datetime(2026, 8, 10, 10, 1, 5, tzinfo=timezone.utc)
        commands = [
            CommandRecord(ts, 1, "a", "", []),
            CommandRecord(ts, 2, "b", "", []),
        ]
        first = assemble_session_timeline(commands)
        second = assemble_session_timeline(commands)
        self.assertEqual(first, second)

    def test_commands_and_events_together(self):
        commands = [
            CommandRecord(
                executed_at=datetime(2026, 8, 10, 10, 1, 2, tzinfo=timezone.utc),
                sequence_number=1,
                command="whoami",
                output="admin",
                risk_findings=[],
            )
        ]
        events = [
            EventRecord(
                timestamp=datetime(2026, 8, 10, 10, 1, 3, tzinfo=timezone.utc),
                event_type="ALERT",
                message="Suspicious pattern",
                payload={"score": 90},
            )
        ]
        timeline = assemble_session_timeline(commands, events)
        self.assertEqual(len(timeline), 2)
        self.assertEqual(timeline[0].command, "whoami")
        self.assertEqual(timeline[1].event_type, "ALERT")

    def test_command_executed_events_are_deduplicated_against_commands(self):
        commands = [
            CommandRecord(
                executed_at=datetime(2026, 8, 10, 10, 1, 5, tzinfo=timezone.utc),
                sequence_number=1,
                command="sudo su -",
                output="",
                risk_findings=[
                    RiskFinding(category="PRIVILEGE_ESCALATION", severity="HIGH", rule="SUDO")
                ],
            )
        ]
        events = [
            EventRecord(
                timestamp=datetime(2026, 8, 10, 10, 1, 0, tzinfo=timezone.utc),
                event_type="session_started",
                message="Session started",
                payload=None,
            ),
            EventRecord(
                timestamp=datetime(2026, 8, 10, 10, 1, 5, tzinfo=timezone.utc),
                event_type="command_executed",
                message="Command executed: sudo su -",
                payload=None,
            ),
        ]
        timeline = assemble_session_timeline(commands, events)

        self.assertEqual(len(timeline), 2)
        event_types = [entry.event_type for entry in timeline]
        self.assertIn("COMMAND", event_types)
        self.assertIn("session_started", event_types)
        self.assertNotIn("command_executed", event_types)

    def test_input_objects_are_not_mutated(self):
        findings = [
            RiskFinding(
                category="PRIVILEGE_ESCALATION",
                severity="HIGH",
                rule="SUDO",
            )
        ]
        command = CommandRecord(
            executed_at=datetime(2026, 8, 10, 10, 1, 5, tzinfo=timezone.utc),
            sequence_number=2,
            command="sudo su -",
            output=None,
            risk_findings=findings,
        )
        events = [
            EventRecord(
                timestamp=datetime(2026, 8, 10, 10, 1, 6, tzinfo=timezone.utc),
                event_type="NOTICE",
                message="message",
                payload={"k": "v"},
            )
        ]

        original_command = command.command
        original_output = command.output
        original_findings = list(command.risk_findings or [])
        original_payload = dict(events[0].payload or {})

        _ = assemble_session_timeline([command], events)

        self.assertEqual(command.command, original_command)
        self.assertEqual(command.output, original_output)
        self.assertEqual(command.risk_findings, original_findings)
        self.assertEqual(events[0].payload, original_payload)


if __name__ == "__main__":
    unittest.main()
