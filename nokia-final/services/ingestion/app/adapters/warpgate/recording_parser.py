import base64
import json
import re
from datetime import datetime, timedelta

from app.domain.command import ParsedCommand


ANSI_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ANSI_OSC_RE = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)")
ANSI_SINGLE_RE = re.compile(r"\x1b[@-_]")


class WarpgateRecordingParser:
    def __init__(
        self,
        prompt_suffixes: tuple[str, ...] | None = None,
        prompt_regexes: tuple[str, ...] | None = None,
    ):
        self._prompt_suffixes = prompt_suffixes or ("$ ", "# ")
        self._prompt_regexes = tuple(
            re.compile(pattern) for pattern in (prompt_regexes or ())
        )

    def parse_file(
        self,
        file_path: str,
        recording_started_at: datetime | None,
    ) -> list[ParsedCommand]:
        input_stream_present = self._has_input_stream(file_path)
        commands: list[ParsedCommand] = []
        sequence_number = 1

        saw_prompt = False
        collecting_input = False
        current_command_chars: list[str] = []
        current_output_chunks: list[str] = []
        current_enter_time: float | None = None

        with open(file_path, "r", encoding="utf-8") as file_handle:
            for line in file_handle:
                line = line.strip()
                if not line:
                    continue

                event = json.loads(line)
                stream = event.get("stream")
                if stream not in {"Input", "Output"}:
                    continue

                decoded = self._decode_event_data(event)
                if decoded is None:
                    continue

                event_time = self._parse_event_time(event)
                if stream == "Input":
                    if not input_stream_present or not saw_prompt or not collecting_input:
                        continue
                    collecting_input, current_enter_time = self._consume_input_chunk(
                        chunk=self._strip_ansi(decoded),
                        command_chars=current_command_chars,
                        event_time=event_time,
                        current_enter_time=current_enter_time,
                    )
                    continue

                prompt_detected = self._contains_prompt(decoded)

                if prompt_detected:
                    if saw_prompt and not collecting_input and current_command_chars:
                        command = self._finalize_command(
                            sequence_number=sequence_number,
                            command_chars=current_command_chars,
                            output_chunks=current_output_chunks,
                            enter_time=current_enter_time,
                            recording_started_at=recording_started_at,
                            strip_echo=input_stream_present,
                        )
                        if command is not None:
                            commands.append(command)
                            sequence_number += 1

                    saw_prompt = True
                    collecting_input = True
                    current_command_chars = []
                    current_output_chunks = []
                    current_enter_time = None
                    continue

                if not saw_prompt:
                    continue

                cleaned = self._strip_ansi(decoded)

                if collecting_input:
                    if input_stream_present:
                        continue
                    collecting_input, current_enter_time = self._consume_input_chunk(
                        chunk=cleaned,
                        command_chars=current_command_chars,
                        event_time=event_time,
                        current_enter_time=current_enter_time,
                    )
                else:
                    current_output_chunks.append(cleaned)

        if saw_prompt and not collecting_input and current_command_chars:
            command = self._finalize_command(
                sequence_number=sequence_number,
                command_chars=current_command_chars,
                output_chunks=current_output_chunks,
                enter_time=current_enter_time,
                recording_started_at=recording_started_at,
                strip_echo=input_stream_present,
            )
            if command is not None:
                commands.append(command)

        return commands

    @staticmethod
    def _has_input_stream(file_path: str) -> bool:
        with open(file_path, "r", encoding="utf-8") as file_handle:
            for line in file_handle:
                if not line.strip():
                    continue
                if json.loads(line).get("stream") == "Input":
                    return True
        return False

    @staticmethod
    def _parse_event_time(event: dict) -> float | None:
        value = event.get("time")
        if value is None:
            return None

        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _decode_event_data(event: dict) -> str | None:
        payload = event.get("data")
        if not isinstance(payload, str):
            return None

        try:
            decoded = base64.b64decode(payload)
        except Exception:
            return None

        return decoded.decode("utf-8", errors="replace").replace("\x00", "")

    def _contains_prompt(self, text: str) -> bool:
        stripped = self._strip_ansi(text).replace("\r", "")

        for line in stripped.split("\n"):
            for suffix in self._prompt_suffixes:
                if line.endswith(suffix):
                    return True

            for pattern in self._prompt_regexes:
                if pattern.search(line):
                    return True

        return False

    @staticmethod
    def _strip_ansi(text: str) -> str:
        text = ANSI_OSC_RE.sub("", text)
        text = ANSI_CSI_RE.sub("", text)
        text = ANSI_SINGLE_RE.sub("", text)
        return text

    @staticmethod
    def _consume_input_chunk(
        chunk: str,
        command_chars: list[str],
        event_time: float | None,
        current_enter_time: float | None,
    ) -> tuple[bool, float | None]:
        collecting_input = True

        for char in chunk:
            if char in ("\x08", "\x7f"):
                if command_chars:
                    command_chars.pop()
                continue

            if char in ("\r", "\n"):
                if command_chars and collecting_input:
                    collecting_input = False
                    if current_enter_time is None:
                        current_enter_time = event_time
                continue

            if ord(char) < 32:
                continue

            if collecting_input:
                command_chars.append(char)

        return collecting_input, current_enter_time

    @staticmethod
    def _finalize_command(
        sequence_number: int,
        command_chars: list[str],
        output_chunks: list[str],
        enter_time: float | None,
        recording_started_at: datetime | None,
        strip_echo: bool = False,
    ) -> ParsedCommand | None:
        command_text = "".join(command_chars).strip()
        if not command_text:
            return None

        output_text = "".join(output_chunks).replace("\r", "")
        output_text = output_text.strip("\n")
        if strip_echo and output_text.startswith(command_text + "\n"):
            output_text = output_text[len(command_text) + 1 :]

        executed_at = None
        if recording_started_at is not None and enter_time is not None:
            executed_at = recording_started_at + timedelta(seconds=enter_time)

        return ParsedCommand(
            sequence_number=sequence_number,
            command=command_text,
            output=output_text if output_text else None,
            executed_at=executed_at,
            exit_code=None,
        )
