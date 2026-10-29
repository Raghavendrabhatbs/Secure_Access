"""Real-time Warpgate ingestion watcher.

Watches the Warpgate SQLite database and/or the recordings directory. When
either changes, it debounces briefly and then runs the ingestion pipeline in
process (much faster than shelling out a fresh subprocess for every event).

Usage examples:

    # Watch the defaults from env vars (WARPGATE_DB_PATH, WARPGATE_RECORDINGS_ROOT).
    python services/ingestion/auto_ingest.py

    # Explicit paths.
    python services/ingestion/auto_ingest.py \
        --db-path C:/warpgate/db.sqlite3 \
        --recordings-root C:/warpgate/recordings

    # Poll every 5 seconds instead of using OS-level events (useful for
    # network mounts / WSL bridges where inotify does not fire).
    python services/ingestion/auto_ingest.py --poll-interval 5

    # One-shot: just run ingestion once and exit (handy for testing).
    python services/ingestion/auto_ingest.py --once
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[2]
SERVICE_ROOT = ROOT / "services" / "ingestion"
for path in (ROOT, SERVICE_ROOT):
    text = str(path)
    if text not in sys.path:
        sys.path.insert(0, text)

from app.main import (  # noqa: E402
    _get_database_path,
    _get_recordings_host_root,
    _get_recordings_root,
    run_ingestion,
)


logger = logging.getLogger("auto_ingest")


class _IngestionRunner:
    """Serialize ingestion runs and debounce back-to-back events."""

    def __init__(
        self,
        *,
        debounce_seconds: float,
        limit: int,
        run_callback: Callable[[int], dict],
    ) -> None:
        self._debounce_seconds = max(0.1, debounce_seconds)
        self._limit = limit
        self._run_callback = run_callback

        self._lock = threading.Lock()
        self._pending = False
        self._running = False
        self._last_event_at: float | None = None
        self._last_run_at: datetime | None = None
        self._condition = threading.Condition(self._lock)
        self._stop = False

    def request(self, reason: str) -> None:
        """Signal that an ingestion cycle should run soon."""
        with self._condition:
            self._pending = True
            self._last_event_at = time.monotonic()
            logger.debug("Ingestion queued (reason=%s)", reason)
            self._condition.notify_all()

    def run_forever(self) -> None:
        """Block until stop() is called, running debounced ingestion cycles."""
        while True:
            with self._condition:
                while not self._pending and not self._stop:
                    self._condition.wait(timeout=1.0)
                if self._stop:
                    return

                # Debounce: wait until at least `debounce_seconds` have passed
                # since the last change event.
                while not self._stop:
                    now = time.monotonic()
                    last = self._last_event_at or now
                    wait_for = self._debounce_seconds - (now - last)
                    if wait_for <= 0:
                        break
                    self._condition.wait(timeout=wait_for)

                if self._stop:
                    return

                self._pending = False
                self._running = True

            try:
                self._run_once()
            finally:
                with self._condition:
                    self._running = False

    def run_once_now(self) -> dict:
        return self._run_once()

    def stop(self) -> None:
        with self._condition:
            self._stop = True
            self._condition.notify_all()

    def _run_once(self) -> dict:
        started_at = datetime.now(timezone.utc)
        logger.info("Ingestion cycle started at %s", started_at.isoformat(timespec="seconds"))
        try:
            stats = self._run_callback(self._limit)
        except Exception:
            logger.exception("Ingestion failed")
            return {"sessions": 0, "commands": 0, "events": 0, "error": True}

        finished_at = datetime.now(timezone.utc)
        duration_ms = int((finished_at - started_at).total_seconds() * 1000)
        logger.info(
            "Ingestion cycle finished in %dms: %d session(s), %d command(s), %d event(s)",
            duration_ms,
            stats.get("sessions", 0),
            stats.get("commands", 0),
            stats.get("events", 0),
        )
        self._last_run_at = finished_at
        return stats


def _resolve_targets(
    db_path: str | None,
    recordings_root: str | None,
) -> tuple[Path | None, Path | None]:
    db = Path(db_path) if db_path else Path(_get_database_path())
    host_root = _get_recordings_host_root()
    recordings_env = _get_recordings_root()
    recordings = Path(recordings_root or host_root or recordings_env)
    return (db if db.exists() or db.parent.exists() else None,
            recordings if recordings.exists() else None)


def _install_watchdog(
    runner: _IngestionRunner,
    db_path: Path | None,
    recordings_root: Path | None,
) -> object | None:
    """Install a watchdog Observer if possible. Returns the observer or None."""
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except Exception as exc:
        logger.warning("watchdog not available (%s); falling back to polling", exc)
        return None

    class _DbHandler(FileSystemEventHandler):
        def __init__(self, target: Path) -> None:
            self._target = target.resolve()

        def _matches(self, path: str) -> bool:
            try:
                resolved = Path(path).resolve()
            except OSError:
                return False
            if resolved == self._target:
                return True
            # SQLite writes to sibling -wal/-journal files during a session.
            return resolved.name.startswith(self._target.name)

        def on_any_event(self, event) -> None:  # type: ignore[override]
            if event.is_directory:
                return
            if self._matches(event.src_path):
                runner.request(reason=f"db:{event.event_type}")

    class _RecordingsHandler(FileSystemEventHandler):
        def on_created(self, event) -> None:  # type: ignore[override]
            if event.is_directory:
                return
            runner.request(reason=f"recording-created:{event.src_path}")

        def on_modified(self, event) -> None:  # type: ignore[override]
            if event.is_directory:
                return
            runner.request(reason=f"recording-modified:{event.src_path}")

        def on_moved(self, event) -> None:  # type: ignore[override]
            if event.is_directory:
                return
            runner.request(reason=f"recording-moved:{event.dest_path}")

    observer = Observer()
    scheduled_any = False

    if db_path is not None:
        watch_dir = db_path.parent
        try:
            observer.schedule(_DbHandler(db_path), path=str(watch_dir), recursive=False)
            logger.info("Watching Warpgate database at %s", db_path)
            scheduled_any = True
        except Exception as exc:
            logger.warning("Could not watch %s: %s", db_path, exc)

    if recordings_root is not None:
        try:
            observer.schedule(_RecordingsHandler(), path=str(recordings_root), recursive=True)
            logger.info("Watching Warpgate recordings under %s", recordings_root)
            scheduled_any = True
        except Exception as exc:
            logger.warning("Could not watch %s: %s", recordings_root, exc)

    if not scheduled_any:
        logger.warning("Nothing to watch; watchdog will not be started")
        return None

    observer.start()
    return observer


def _poll_paths(
    runner: _IngestionRunner,
    paths: list[Path],
    interval: float,
    stop_event: threading.Event,
) -> None:
    """Trigger ingestion whenever any watched path's mtime advances."""
    known_mtimes: dict[str, float] = {}

    def snapshot() -> dict[str, float]:
        snap: dict[str, float] = {}
        for path in paths:
            if not path.exists():
                continue
            if path.is_file():
                snap[str(path)] = path.stat().st_mtime
                continue
            for entry in path.rglob("*"):
                try:
                    if entry.is_file():
                        snap[str(entry)] = entry.stat().st_mtime
                except OSError:
                    continue
        return snap

    known_mtimes = snapshot()
    logger.info("Poll mode: baseline of %d file(s) captured", len(known_mtimes))

    while not stop_event.is_set():
        stop_event.wait(interval)
        if stop_event.is_set():
            break
        current = snapshot()
        added = set(current) - set(known_mtimes)
        changed = {key for key, value in current.items() if known_mtimes.get(key, 0) < value}
        if added or changed:
            reason = f"poll:added={len(added)},changed={len(changed - added)}"
            runner.request(reason=reason)
        known_mtimes = current


def watch(
    *,
    db_path: str | None = None,
    recordings_root: str | None = None,
    debounce_seconds: float = 1.0,
    poll_interval: float | None = None,
    limit: int = 100,
    run_callback: Callable[[int], dict] | None = None,
) -> None:
    """Run the watcher until interrupted."""
    resolved_db, resolved_recordings = _resolve_targets(db_path, recordings_root)

    if resolved_db is None and resolved_recordings is None:
        logger.error(
            "Neither the Warpgate database nor a recordings directory exists. "
            "Set WARPGATE_DB_PATH and/or WARPGATE_RECORDINGS_ROOT, or pass "
            "--db-path / --recordings-root."
        )
        raise SystemExit(2)

    callback = run_callback or run_ingestion
    runner = _IngestionRunner(
        debounce_seconds=debounce_seconds,
        limit=limit,
        run_callback=callback,
    )
    # Run once at startup so the database reflects everything that already exists.
    runner.request(reason="startup")

    observer = None
    poll_thread: threading.Thread | None = None
    stop_event = threading.Event()

    if poll_interval is None:
        observer = _install_watchdog(runner, resolved_db, resolved_recordings)

    if observer is None:
        interval = poll_interval if poll_interval is not None else 5.0
        watched_paths = [p for p in (resolved_db, resolved_recordings) if p is not None]
        logger.info(
            "Polling %d path(s) every %.1fs (watchdog unavailable or --poll-interval set)",
            len(watched_paths),
            interval,
        )
        poll_thread = threading.Thread(
            target=_poll_paths,
            args=(runner, watched_paths, interval, stop_event),
            daemon=True,
            name="ingestion-poller",
        )
        poll_thread.start()

    logger.info(
        "Auto-ingest ready (debounce=%.1fs, limit=%d). Press Ctrl-C to stop.",
        debounce_seconds,
        limit,
    )

    try:
        runner.run_forever()
    except KeyboardInterrupt:
        logger.info("Stopping auto-ingest on user request.")
    finally:
        runner.stop()
        stop_event.set()
        if observer is not None:
            observer.stop()
            observer.join(timeout=5)
        if poll_thread is not None:
            poll_thread.join(timeout=5)


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Real-time Warpgate ingestion watcher.")
    parser.add_argument(
        "--db-path",
        default=None,
        help="Path to the Warpgate SQLite database (default: $WARPGATE_DB_PATH).",
    )
    parser.add_argument(
        "--recordings-root",
        default=None,
        help="Path to the Warpgate recordings directory (default: $WARPGATE_RECORDINGS_ROOT).",
    )
    parser.add_argument(
        "--debounce",
        type=float,
        default=float(os.getenv("AUTO_INGEST_DEBOUNCE", "3.0")),
        help="Seconds to wait after the last change before running ingestion (default: 3s).",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=None,
        help=(
            "Poll every N seconds instead of using OS file events. "
            "Useful for network mounts or WSL bridges."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=int(os.getenv("AUTO_INGEST_LIMIT", "10000")),
        help="How many recent Warpgate sessions to consider per ingestion cycle.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run ingestion a single time and exit.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    _configure_logging(args.verbose)

    if args.once:
        runner = _IngestionRunner(
            debounce_seconds=0.1,
            limit=args.limit,
            run_callback=run_ingestion,
        )
        stats = runner.run_once_now()
        return 0 if not stats.get("error") else 1

    watch(
        db_path=args.db_path,
        recordings_root=args.recordings_root,
        debounce_seconds=args.debounce,
        poll_interval=args.poll_interval,
        limit=args.limit,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
