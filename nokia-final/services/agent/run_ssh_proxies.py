"""Run one inspected SSH proxy process for each Warpgate SSH target."""

import argparse
import json
import logging
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import Any

from dotenv import load_dotenv


LOGGER = logging.getLogger("ssh_proxy_supervisor")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROXY_SCRIPT = Path(__file__).with_name("ssh_proxy.py")
REQUIRED_TARGET_FIELDS = {"name", "host", "port", "listen_port"}
SUPPORTED_SESSION_MODES = {"warpgate", "direct"}


def load_targets(config_path: Path) -> list[dict[str, Any]]:
    try:
        with config_path.open(encoding="utf-8") as config_file:
            configuration = json.load(config_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read proxy target configuration: {exc}") from exc

    targets = configuration.get("targets") if isinstance(configuration, dict) else None
    if not isinstance(targets, list) or not targets:
        raise ValueError("Proxy target configuration must contain a non-empty targets list.")

    names: set[str] = set()
    listen_ports: set[int] = set()
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            raise ValueError(f"Target entry {index + 1} must be a JSON object.")
        missing = REQUIRED_TARGET_FIELDS - target.keys()
        if missing:
            raise ValueError(
                f"Target entry {index + 1} is missing fields: {', '.join(sorted(missing))}."
            )

        name = target["name"]
        host = target["host"]
        mode = target.get("mode", "warpgate")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"Target entry {index + 1} has an invalid name.")
        if not isinstance(mode, str) or mode not in SUPPORTED_SESSION_MODES:
            raise ValueError(
                f"Target {name!r} has an invalid mode; expected one of: "
                f"{', '.join(sorted(SUPPORTED_SESSION_MODES))}."
            )
        if not isinstance(host, str) or not host.strip() or any(c.isspace() for c in host):
            raise ValueError(f"Target {name!r} has an invalid host.")
        for field in ("port", "listen_port"):
            value = target[field]
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
                raise ValueError(f"Target {name!r} has an invalid {field}; expected 1-65535.")
        if name.casefold() in names:
            raise ValueError(f"Duplicate Warpgate target name: {name}.")
        if target["listen_port"] in listen_ports:
            raise ValueError(f"Duplicate proxy listener port: {target['listen_port']}.")
        names.add(name.casefold())
        listen_ports.add(target["listen_port"])

    return targets


def start_target_proxy(target: dict[str, Any]) -> subprocess.Popen:
    environment = os.environ.copy()
    environment.update(
        {
            "WARPGATE_TARGET_NAME": target["name"],
            "PROXY_TARGET_HOST": target["host"],
            "PROXY_TARGET_PORT": str(target["port"]),
            "PROXY_LISTEN_PORT": str(target["listen_port"]),
            "PROXY_SESSION_MODE": target.get("mode", "warpgate"),
        }
    )
    LOGGER.info(
        "Starting inspected SSH route %s on listener port %d",
        target["name"],
        target["listen_port"],
    )
    return subprocess.Popen(
        [sys.executable, str(PROXY_SCRIPT)],
        cwd=PROJECT_ROOT,
        env=environment,
    )


def stop_proxies(processes: list[tuple[dict[str, Any], subprocess.Popen]]) -> None:
    for target, process in processes:
        if process.poll() is None:
            LOGGER.info("Stopping proxy for target %s", target["name"])
            process.terminate()
    deadline = time.monotonic() + 5
    for target, process in processes:
        if process.poll() is None:
            try:
                process.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                LOGGER.error("Proxy for target %s did not stop; forcing shutdown", target["name"])
                process.kill()
                process.wait()


def run(config_path: Path, mode_filter: str | None = None) -> int:
    targets = load_targets(config_path)
    if mode_filter is not None:
        targets = [
            target
            for target in targets
            if target.get("mode", "warpgate") == mode_filter
        ]
        if not targets:
            raise ValueError(f"No {mode_filter!r} routes found in the proxy target configuration.")
    required_environment = ["AI_AGENT_URL", "ALERT_SECRET"]
    if any(target.get("mode", "warpgate") == "warpgate" for target in targets):
        required_environment.append("WARPGATE_TOKEN")
    missing = [name for name in required_environment if not os.getenv(name)]
    if missing:
        raise ValueError(
            "Missing required root .env settings: "
            + ", ".join(missing)
            + ". Add them before starting inspected proxy routes."
        )
    processes: list[tuple[dict[str, Any], subprocess.Popen]] = []
    stopping = False

    def request_stop(_signum, _frame) -> None:
        nonlocal stopping
        stopping = True

    previous_handlers = {
        signum: signal.signal(signum, request_stop)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        for target in targets:
            processes.append((target, start_target_proxy(target)))
        LOGGER.info("Running %d inspected SSH target route(s)", len(processes))

        while not stopping:
            for target, process in processes:
                return_code = process.poll()
                if return_code is not None:
                    LOGGER.error(
                        "Proxy for target %s exited unexpectedly (code %d); stopping all routes",
                        target["name"],
                        return_code,
                    )
                    return return_code or 1
            time.sleep(0.5)
        return 0
    finally:
        stop_proxies(processes)
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run one Secure Access SSH proxy per registered Warpgate SSH target."
    )
    parser.add_argument(
        "--config",
        type=Path,
        required=True,
        help="JSON target-route manifest; see ssh_proxy_targets.example.json.",
    )
    parser.add_argument(
        "--direct-only",
        action="store_true",
        help="Start only direct SSH routes (does not require WARPGATE_TOKEN).",
    )
    args = parser.parse_args()
    config_path = args.config
    if not config_path.is_absolute():
        config_path = PROJECT_ROOT / config_path

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [ssh_proxy_supervisor] %(levelname)s %(message)s",
    )
    load_dotenv(PROJECT_ROOT / ".env")
    try:
        return run(config_path, mode_filter="direct" if args.direct_only else None)
    except ValueError as exc:
        LOGGER.error("%s", exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
