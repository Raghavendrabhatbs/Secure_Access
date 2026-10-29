"""Verify every Warpgate SSH target is routed through its configured proxy."""

import argparse
import logging
import os
from pathlib import Path
import sys

from dotenv import load_dotenv
import requests

from run_ssh_proxies import load_targets


LOGGER = logging.getLogger("ssh_proxy_route_audit")
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def audit_routes(
    targets: list[dict],
    warpgate_targets: list[dict],
    proxy_host: str = "127.0.0.1",
) -> list[str]:
    routes = {
        target["name"].casefold(): target
        for target in targets
        if target.get("mode", "warpgate") == "warpgate"
    }
    errors: list[str] = []
    seen: set[str] = set()

    for target in warpgate_targets:
        if not isinstance(target, dict) or str(target.get("kind", "")).casefold() != "ssh":
            continue
        name = target.get("name")
        if not isinstance(name, str) or not name:
            errors.append("Warpgate returned an SSH target without a valid name.")
            continue

        key = name.casefold()
        seen.add(key)
        route = routes.get(key)
        if route is None:
            errors.append(f"SSH target {name!r} has no proxy route in the manifest.")
            continue

        options = target.get("options")
        if not isinstance(options, dict):
            options = target
        ssh_options = options.get("ssh")
        if isinstance(ssh_options, dict):
            options = ssh_options
        elif isinstance(target.get("ssh"), dict):
            options = target["ssh"]
        actual_host = options.get("host")
        actual_port = options.get("port")
        if (
            not isinstance(actual_host, str)
            or actual_host.casefold() != proxy_host.casefold()
            or actual_port != route["listen_port"]
        ):
            errors.append(
                f"SSH target {name!r} must point to "
                f"{proxy_host}:{route['listen_port']} (currently {actual_host}:{actual_port})."
            )

    for key, route in routes.items():
        if key not in seen:
            errors.append(
                f"Manifest route {route['name']!r} does not match an SSH target in Warpgate."
            )
    return errors


def fetch_warpgate_targets(
    base_url: str,
    token: str,
    verify: bool | str = True,
) -> list[dict]:
    response = requests.get(
        f"{base_url.rstrip('/')}/@warpgate/admin/api/targets",
        headers={"X-Warpgate-Token": token},
        timeout=10,
        verify=verify,
    )
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload, dict):
        payload = payload.get("items")
    if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
        raise ValueError("Warpgate returned an invalid target list.")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check that every SSH target in Warpgate uses its inspected proxy route."
    )
    parser.add_argument("--config", type=Path, required=True, help="Proxy target route manifest.")
    parser.add_argument(
        "--proxy-host",
        default="127.0.0.1",
        help="Host address used by Warpgate to reach the proxy listeners.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip Warpgate TLS verification (only for local self-signed certificates).",
    )
    args = parser.parse_args()

    load_dotenv(PROJECT_ROOT / ".env")
    token = os.getenv("WARPGATE_TOKEN", "")
    base_url = os.getenv("WARPGATE_URL", "https://localhost:8888")
    ca_bundle = os.getenv("WARPGATE_CA_BUNDLE")
    if not token:
        LOGGER.error("WARPGATE_TOKEN is missing from the project environment.")
        return 2

    config_path = args.config
    if not config_path.is_absolute():
        config_path = PROJECT_ROOT / config_path
    try:
        routes = load_targets(config_path)
        warpgate_targets = fetch_warpgate_targets(
            base_url,
            token,
            verify=False if args.insecure else (ca_bundle or True),
        )
    except (ValueError, OSError, requests.RequestException) as exc:
        LOGGER.error("Could not audit Warpgate SSH routes (%s).", type(exc).__name__)
        return 2

    errors = audit_routes(routes, warpgate_targets, args.proxy_host)
    if errors:
        for error in errors:
            LOGGER.error("%s", error)
        LOGGER.error(
            "Route audit failed: %d SSH target(s) need attention.",
            len(errors),
        )
        return 1

    ssh_count = sum(
        isinstance(target, dict) and str(target.get("kind", "")).casefold() == "ssh"
        for target in warpgate_targets
    )
    LOGGER.info("Route audit passed: all %d Warpgate SSH target(s) use their proxy listeners.", ssh_count)
    return 0


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [ssh_proxy_route_audit] %(levelname)s %(message)s",
    )
    sys.exit(main())
