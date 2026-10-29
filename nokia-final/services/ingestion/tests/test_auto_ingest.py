"""Tests for the real-time ingestion watcher.

These tests exercise the debounce / dispatch logic and the poll loop without
touching a real Warpgate database. They stub the ingestion callback so no
actual DB writes happen.
"""

from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

SERVICE_ROOT = Path(__file__).resolve().parents[1]
if str(SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVICE_ROOT))

from auto_ingest import _IngestionRunner, _parse_args, _poll_paths  # noqa: E402


class IngestionRunnerTest(unittest.TestCase):
    def test_default_ingestion_limit_covers_the_full_session_archive(self):
        with patch.dict("os.environ", {}, clear=False):
            import os

            os.environ.pop("AUTO_INGEST_LIMIT", None)
            self.assertEqual(_parse_args([]).limit, 10000)

    def test_debounces_and_runs_after_events(self):
        calls: list[int] = []

        def fake_ingest(limit: int) -> dict:
            calls.append(limit)
            return {"sessions": 1, "commands": 2, "events": 3}

        runner = _IngestionRunner(
            debounce_seconds=0.2,
            limit=7,
            run_callback=fake_ingest,
        )
        thread = threading.Thread(target=runner.run_forever, daemon=True)
        thread.start()
        try:
            runner.request(reason="test1")
            time.sleep(0.05)
            runner.request(reason="test2")
            time.sleep(0.05)
            runner.request(reason="test3")
            # Wait past the debounce window + a small buffer for the run.
            time.sleep(1.0)
        finally:
            runner.stop()
            thread.join(timeout=2)

        # All three events collapse into a single ingestion run.
        self.assertEqual(calls, [7])

    def test_second_burst_after_completion_triggers_second_run(self):
        calls: list[int] = []

        def fake_ingest(limit: int) -> dict:
            calls.append(limit)
            return {"sessions": 0, "commands": 0, "events": 0}

        runner = _IngestionRunner(
            debounce_seconds=0.2,
            limit=3,
            run_callback=fake_ingest,
        )
        thread = threading.Thread(target=runner.run_forever, daemon=True)
        thread.start()
        try:
            runner.request(reason="burst1")
            time.sleep(0.7)
            runner.request(reason="burst2")
            time.sleep(0.7)
        finally:
            runner.stop()
            thread.join(timeout=2)

        self.assertEqual(calls, [3, 3])

    def test_failure_is_isolated(self):
        attempts: list[str] = []

        def fake_ingest(limit: int) -> dict:
            attempts.append("call")
            raise RuntimeError("boom")

        runner = _IngestionRunner(
            debounce_seconds=0.1,
            limit=1,
            run_callback=fake_ingest,
        )
        thread = threading.Thread(target=runner.run_forever, daemon=True)
        thread.start()
        try:
            runner.request(reason="one")
            time.sleep(0.5)
            runner.request(reason="two")
            time.sleep(0.5)
        finally:
            runner.stop()
            thread.join(timeout=2)

        # Both requests should have been attempted; the exception did not
        # crash the runner.
        self.assertEqual(attempts, ["call", "call"])

    def test_run_once_now_returns_stats(self):
        def fake_ingest(limit: int) -> dict:
            return {"sessions": 9, "commands": 8, "events": 7}

        runner = _IngestionRunner(
            debounce_seconds=1.0,
            limit=4,
            run_callback=fake_ingest,
        )
        stats = runner.run_once_now()
        self.assertEqual(stats, {"sessions": 9, "commands": 8, "events": 7})


class PollLoopTest(unittest.TestCase):
    def test_poll_detects_new_and_modified_files(self):
        import tempfile

        directory = Path(tempfile.mkdtemp(prefix="auto-ingest-test-"))
        db_file = directory / "db.sqlite3"
        db_file.write_text("initial")

        events: list[str] = []
        signal = threading.Event()
        stop_event = threading.Event()

        class DummyRunner:
            def request(self, reason: str) -> None:
                events.append(reason)
                signal.set()

        thread = threading.Thread(
            target=_poll_paths,
            args=(DummyRunner(), [db_file, directory], 0.2, stop_event),
            daemon=True,
        )
        thread.start()
        try:
            time.sleep(0.4)  # let baseline snapshot settle
            db_file.write_text("changed content")
            # New recording appears in the directory.
            (directory / "session-1.cast").write_text("record")
            self.assertTrue(signal.wait(timeout=3.0), "expected at least one poll event")
            # Give the poll loop a moment to observe both changes.
            time.sleep(0.6)
        finally:
            stop_event.set()
            thread.join(timeout=2)

        self.assertTrue(events, "polling did not surface any events")
        joined = " ".join(events)
        self.assertIn("poll:", joined)


if __name__ == "__main__":
    unittest.main()
