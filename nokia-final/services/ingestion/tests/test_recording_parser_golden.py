import sys
from datetime import datetime, timezone
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.adapters.warpgate.recording_parser import WarpgateRecordingParser


class RecordingParserGoldenTest(unittest.TestCase):
    def test_parser_matches_verified_warpgate_sample(self):
        fixture_path = (
            ROOT
            / "tests"
            / "fixtures"
            / "warpgate_recording_sample_71efcfa3.jsonl"
        )

        parser = WarpgateRecordingParser()
        commands = parser.parse_file(
            file_path=str(fixture_path),
            recording_started_at=datetime(
                2026,
                8,
                3,
                5,
                59,
                11,
                571374,
                tzinfo=timezone.utc,
            ),
        )

        self.assertEqual(len(commands), 4)
        self.assertEqual(commands[0].sequence_number, 1)
        self.assertEqual(commands[0].command, "whoami")
        self.assertEqual(commands[0].output, "sumukh_bhat")

        self.assertEqual(commands[1].sequence_number, 2)
        self.assertEqual(commands[1].command, "hostname")
        self.assertEqual(commands[1].output, "DESKTOP-L7RS68G")

        self.assertEqual(commands[2].sequence_number, 3)
        self.assertEqual(commands[2].command, "date")
        self.assertEqual(commands[2].output, "Mon Aug  3 05:59:48 UTC 2026")

        self.assertEqual(commands[3].sequence_number, 4)
        self.assertEqual(commands[3].command, "echo \"test august 3\"")
        self.assertEqual(commands[3].output, "test august 3")


if __name__ == "__main__":
    unittest.main()
