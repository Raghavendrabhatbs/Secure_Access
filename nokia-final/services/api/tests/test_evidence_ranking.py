import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.evidence_ranking import rank_command_matches, rank_session_matches


@dataclass
class FakeCommandMatch:
    session_id: str
    sequence_number: int
    command: str
    output: str
    started_at: datetime
    matched_terms: list[str]


@dataclass
class FakeSessionMatch:
    session_id: str
    started_at: datetime
    matched_terms: list[str]
    matching_commands: list[FakeCommandMatch] = field(default_factory=list)


class EvidenceRankingTest(unittest.TestCase):
    def test_command_text_match_outranks_output_match(self):
        newer = datetime(2026, 8, 9, 10, 0, tzinfo=timezone.utc)
        older = datetime(2026, 8, 8, 10, 0, tzinfo=timezone.utc)
        command_match = FakeCommandMatch(
            session_id="session-a",
            sequence_number=1,
            command="chmod 777 /etc/passwd",
            output="",
            started_at=older,
            matched_terms=["passwd"],
        )
        output_match = FakeCommandMatch(
            session_id="session-b",
            sequence_number=1,
            command="sudo su -",
            output="/etc/passwd was referenced",
            started_at=newer,
            matched_terms=["passwd"],
        )

        ranked = rank_command_matches([output_match, command_match], ["passwd"])

        self.assertEqual([item.session_id for item in ranked], ["session-a", "session-b"])

    def test_multi_term_session_outranks_single_term_sessions(self):
        started_at = datetime(2026, 8, 9, 10, 0, tzinfo=timezone.utc)
        session_a = FakeSessionMatch(
            session_id="session-a",
            started_at=started_at,
            matched_terms=["sudo", "passwd"],
            matching_commands=[
                FakeCommandMatch("session-a", 1, "sudo useradd hacker123", "", started_at, ["sudo"]),
                FakeCommandMatch("session-a", 2, "chmod 777 /etc/passwd", "", started_at, ["passwd"]),
            ],
        )
        session_b = FakeSessionMatch(
            session_id="session-b",
            started_at=started_at,
            matched_terms=["sudo"],
            matching_commands=[
                FakeCommandMatch("session-b", 1, "sudo ls", "", started_at, ["sudo"]),
            ],
        )
        session_c = FakeSessionMatch(
            session_id="session-c",
            started_at=started_at,
            matched_terms=["passwd"],
            matching_commands=[
                FakeCommandMatch("session-c", 1, "cat /etc/passwd", "", started_at, ["passwd"]),
            ],
        )

        ranked = rank_session_matches([session_b, session_c, session_a], ["sudo", "passwd"])

        self.assertEqual([item.session_id for item in ranked], ["session-a", "session-c", "session-b"])

    def test_commands_in_multi_term_session_outrank_newer_partial_session(self):
        newer = datetime(2026, 8, 9, 10, 0, tzinfo=timezone.utc)
        older = datetime(2026, 8, 8, 10, 0, tzinfo=timezone.utc)
        partial = FakeCommandMatch("session-partial", 1, "sudo ls", "", newer, ["sudo"])
        full_sudo = FakeCommandMatch("session-full", 1, "sudo su -", "", older, ["sudo"])
        full_passwd = FakeCommandMatch("session-full", 2, "chmod 777 /etc/passwd", "", older, ["passwd"])

        ranked = rank_command_matches([partial, full_sudo, full_passwd], ["sudo", "passwd"])

        self.assertEqual([item.session_id for item in ranked], ["session-full", "session-full", "session-partial"])

    def test_newer_session_breaks_equal_score_tie(self):
        newer = datetime(2026, 8, 9, 10, 0, tzinfo=timezone.utc)
        older = datetime(2026, 8, 8, 10, 0, tzinfo=timezone.utc)
        newer_match = FakeCommandMatch("session-new", 1, "sudo ls", "", newer, ["sudo"])
        older_match = FakeCommandMatch("session-old", 1, "sudo ls", "", older, ["sudo"])

        ranked = rank_command_matches([older_match, newer_match], ["sudo"])

        self.assertEqual([item.session_id for item in ranked], ["session-new", "session-old"])

    def test_no_match_behavior_returns_empty_list(self):
        self.assertEqual(rank_command_matches([], ["sudo"]), [])
        self.assertEqual(rank_session_matches([], ["sudo"]), [])

    def test_deterministic_ordering_when_scores_are_equal(self):
        started_at = datetime(2026, 8, 9, 10, 0, tzinfo=timezone.utc)
        first = FakeCommandMatch("session-a", 1, "sudo ls", "", started_at, ["sudo"])
        second = FakeCommandMatch("session-b", 1, "sudo ls", "", started_at, ["sudo"])

        ranked = rank_command_matches([second, first], ["sudo"])

        self.assertEqual([item.session_id for item in ranked], ["session-a", "session-b"])


if __name__ == "__main__":
    unittest.main()