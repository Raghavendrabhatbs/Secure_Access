import sys
from datetime import datetime, timezone
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.adapters.warpgate.recording_parser import WarpgateRecordingParser


class RecordingParserSecondGoldenTest(unittest.TestCase):
    def test_parser_matches_second_verified_warpgate_sample(self):
        fixture_path = (
            ROOT
            / "tests"
            / "fixtures"
            / "warpgate_recording_sample_a9573cac.jsonl"
        )

        parser = WarpgateRecordingParser()
        commands = parser.parse_file(
            file_path=str(fixture_path),
            recording_started_at=datetime(
                2026,
                7,
                30,
                6,
                1,
                40,
                43002,
                tzinfo=timezone.utc,
            ),
        )

        self.assertEqual(len(commands), 4)

        self.assertEqual(commands[0].sequence_number, 1)
        self.assertEqual(commands[0].command, "sudo su -")
        self.assertEqual(commands[0].output, "[sudo] password for sumukh_bhat: ")

        self.assertEqual(commands[1].sequence_number, 2)
        self.assertEqual(commands[1].command, "sudo useradd hacker123")
        self.assertIsNone(commands[1].output)

        self.assertEqual(commands[2].sequence_number, 3)
        self.assertEqual(commands[2].command, "chmod 777 /etc/passwd")
        self.assertIsNone(commands[2].output)

        self.assertEqual(commands[3].sequence_number, 4)
        self.assertEqual(commands[3].command, "history -c")
        self.assertIsNone(commands[3].output)


if __name__ == "__main__":
    unittest.main()
