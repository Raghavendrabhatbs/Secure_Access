import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.adapters.warpgate.recording_parser import WarpgateRecordingParser


class RecordingParserTest(unittest.TestCase):
    def _event(self, time: float, text: str) -> str:
        return json.dumps(
            {
                "time": time,
                "stream": "Output",
                "data": base64.b64encode(text.encode("utf-8")).decode("ascii"),
            }
        )

    def _input_event(self, time: float, text: str) -> str:
        return json.dumps(
            {
                "time": time,
                "stream": "Input",
                "data": base64.b64encode(text.encode("utf-8")).decode("ascii"),
            }
        )

    def test_parser_reconstructs_commands(self):
        lines = [
            json.dumps({"time": 0.0, "cols": 80, "rows": 24}),
            self._event(0.1, "\x1b[01;32muser@host\x1b[00m:~$ "),
            self._event(1.0, "w"),
            self._event(1.1, "h"),
            self._event(1.2, "o"),
            self._event(1.3, "a"),
            self._event(1.4, "m"),
            self._event(1.5, "i"),
            self._event(1.6, "\r\n"),
            self._event(1.7, "\x1b[?2004l\r"),
            self._event(1.8, "alice\r\n"),
            self._event(2.0, "\x1b[01;32muser@host\x1b[00m:~$ "),
            self._event(2.1, "e"),
            self._event(2.2, "c"),
            self._event(2.3, "h"),
            self._event(2.4, "o"),
            self._event(2.5, " "),
            self._event(2.6, "2"),
            self._event(2.7, "\x08\x1b[K"),
            self._event(2.8, "3"),
            self._event(2.9, "\r\n"),
            self._event(3.0, "\x1b[?2004l\r"),
            self._event(3.1, "3\r\n"),
            self._event(3.2, "\x1b[01;32muser@host\x1b[00m:~$ "),
            self._event(3.3, "e"),
            self._event(3.4, "x"),
            self._event(3.5, "i"),
            self._event(3.6, "t"),
            self._event(3.7, "\r\n"),
            self._event(3.8, "logout\r\n"),
        ]

        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as file_handle:
            file_handle.write("\n".join(lines))
            file_path = file_handle.name

        parser = WarpgateRecordingParser()
        commands = parser.parse_file(
            file_path=file_path,
            recording_started_at=datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(len(commands), 3)
        self.assertEqual(commands[0].sequence_number, 1)
        self.assertEqual(commands[0].command, "whoami")
        self.assertEqual(commands[0].output, "alice")

        self.assertEqual(commands[1].sequence_number, 2)
        self.assertEqual(commands[1].command, "echo 3")
        self.assertEqual(commands[1].output, "3")
        self.assertEqual(commands[2].sequence_number, 3)
        self.assertEqual(commands[2].command, "exit")
        self.assertEqual(commands[2].output, "logout")

    def test_parser_supports_custom_prompt_suffix(self):
        lines = [
            json.dumps({"time": 0.0, "cols": 80, "rows": 24}),
            self._event(0.1, "router> "),
            self._event(0.2, "s"),
            self._event(0.3, "h"),
            self._event(0.4, "o"),
            self._event(0.5, "w"),
            self._event(0.6, "\r\n"),
            self._event(0.7, "version 1.0\r\n"),
            self._event(0.8, "router> "),
        ]

        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as file_handle:
            file_handle.write("\n".join(lines))
            file_path = file_handle.name

        parser = WarpgateRecordingParser(prompt_suffixes=("> ",))
        commands = parser.parse_file(
            file_path=file_path,
            recording_started_at=datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0].command, "show")
        self.assertEqual(commands[0].output, "version 1.0")

    def test_parser_removes_nul_bytes_from_terminal_output(self):
        lines = [
            self._event(0.1, "user@host$ "),
            self._event(0.2, "e"),
            self._event(0.3, "c"),
            self._event(0.4, "h"),
            self._event(0.5, "o"),
            self._event(0.6, " ok\r\n"),
            self._event(0.7, "ok\x00\u0000\r\n"),
            self._event(0.8, "user@host$ "),
        ]

        with tempfile.NamedTemporaryFile(
            "w", delete=False, encoding="utf-8"
        ) as file_handle:
            file_handle.write("\n".join(lines))
            file_path = file_handle.name

        commands = WarpgateRecordingParser().parse_file(
            file_path=file_path,
            recording_started_at=datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0].command, "echo ok")
        self.assertEqual(commands[0].output, "ok")

    def test_parser_uses_warpgate_input_stream_and_keeps_terminal_output(self):
        lines = [
            self._event(0.1, "user@host$ "),
            self._input_event(0.2, "p"),
            self._input_event(0.3, "w"),
            self._input_event(0.4, "d"),
            self._input_event(0.5, "\r"),
            self._event(0.6, "pwd\r\n"),
            self._event(0.7, "/home/user\r\n"),
            self._event(0.8, "user@host$ "),
            self._input_event(0.9, "w"),
            self._input_event(1.0, "h"),
            self._input_event(1.1, "o"),
            self._input_event(1.2, "a"),
            self._input_event(1.3, "m"),
            self._input_event(1.4, "i"),
            self._input_event(1.5, "\r"),
            self._event(1.6, "whoami\r\n"),
            self._event(1.7, "alice\r\n"),
        ]

        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as file_handle:
            file_handle.write("\n".join(lines))
            file_path = file_handle.name

        commands = WarpgateRecordingParser().parse_file(
            file_path=file_path,
            recording_started_at=datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(
            [(command.command, command.output) for command in commands],
            [("pwd", "/home/user"), ("whoami", "alice")],
        )


if __name__ == "__main__":
    unittest.main()
