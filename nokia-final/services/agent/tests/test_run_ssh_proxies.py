import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from audit_ssh_proxy_routes import audit_routes, fetch_warpgate_targets
from run_ssh_proxies import load_targets, run, start_target_proxy


class ProxyTargetConfigurationTests(unittest.TestCase):
    def load_configuration(self, configuration):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "targets.json"
        path.write_text(json.dumps(configuration), encoding="utf-8")
        return load_targets(path)

    def test_loads_multiple_unique_target_routes(self):
        targets = [
            {"name": "ssh-a", "host": "10.0.0.10", "port": 22, "listen_port": 2223},
            {"name": "ssh-b", "host": "10.0.0.11", "port": 22, "listen_port": 2224},
        ]

        self.assertEqual(self.load_configuration({"targets": targets}), targets)

    def test_rejects_duplicate_target_names(self):
        route = {"name": "ssh-a", "host": "10.0.0.10", "port": 22, "listen_port": 2223}

        with self.assertRaisesRegex(ValueError, "Duplicate Warpgate target"):
            self.load_configuration({"targets": [route, {**route, "listen_port": 2224}]})

    def test_rejects_duplicate_listener_ports(self):
        first = {"name": "ssh-a", "host": "10.0.0.10", "port": 22, "listen_port": 2223}
        second = {"name": "ssh-b", "host": "10.0.0.11", "port": 22, "listen_port": 2223}

        with self.assertRaisesRegex(ValueError, "Duplicate proxy listener"):
            self.load_configuration({"targets": [first, second]})

    def test_rejects_invalid_ports(self):
        route = {"name": "ssh-a", "host": "10.0.0.10", "port": True, "listen_port": 2223}

        with self.assertRaisesRegex(ValueError, "invalid port"):
            self.load_configuration({"targets": [route]})

    def test_rejects_invalid_session_mode(self):
        route = {
            "name": "ssh-a",
            "host": "10.0.0.10",
            "port": 22,
            "listen_port": 2223,
            "mode": "unknown",
        }

        with self.assertRaisesRegex(ValueError, "invalid mode"):
            self.load_configuration({"targets": [route]})

    def test_child_receives_route_specific_environment(self):
        route = {"name": "ssh-a", "host": "10.0.0.10", "port": 22, "listen_port": 2223}
        with patch("run_ssh_proxies.subprocess.Popen") as popen:
            start_target_proxy(route)

        environment = popen.call_args.kwargs["env"]
        self.assertEqual(environment["WARPGATE_TARGET_NAME"], "ssh-a")
        self.assertEqual(environment["PROXY_TARGET_HOST"], "10.0.0.10")
        self.assertEqual(environment["PROXY_TARGET_PORT"], "22")
        self.assertEqual(environment["PROXY_LISTEN_PORT"], "2223")
        self.assertEqual(environment["PROXY_SESSION_MODE"], "warpgate")

    def test_direct_route_does_not_require_warpgate_admin_token(self):
        process = Mock()
        process.poll.return_value = 0
        with patch.dict(
            "os.environ",
            {"AI_AGENT_URL": "http://api.local", "ALERT_SECRET": "test"},
            clear=True,
        ), patch(
            "run_ssh_proxies.load_targets",
            return_value=[
                {
                    "name": "ssh-demo",
                    "mode": "warpgate",
                    "host": "127.0.0.1",
                    "port": 22,
                    "listen_port": 2224,
                },
                {
                    "name": "direct-test",
                    "mode": "direct",
                    "host": "127.0.0.1",
                    "port": 2225,
                    "listen_port": 2226,
                }
            ],
        ), patch(
            "run_ssh_proxies.start_target_proxy", return_value=process
        ), patch("run_ssh_proxies.signal.signal"):
            self.assertEqual(run(Path("unused.json"), mode_filter="direct"), 1)

    @patch.dict(
        os.environ,
        {"AI_AGENT_URL": "http://api.local", "ALERT_SECRET": "test"},
        clear=True,
    )
    @patch(
        "run_ssh_proxies.load_targets",
        return_value=[{"mode": "warpgate"}],
    )
    def test_warpgate_routes_require_admin_token(self, _load):
        with self.assertRaisesRegex(
            ValueError,
            "WARPGATE_TOKEN",
        ):
            run(Path("unused.json"))

    def test_audit_accepts_all_routed_ssh_targets_and_ignores_other_protocols(self):
        routes = [
            {"name": "ssh-a", "host": "10.0.0.10", "port": 22, "listen_port": 2223},
        ]
        warpgate_targets = [
            {"name": "ssh-a", "kind": "ssh", "host": "127.0.0.1", "port": 2223},
            {"name": "web", "kind": "http", "url": "https://example.test"},
        ]

        self.assertEqual(audit_routes(routes, warpgate_targets), [])

    def test_audit_accepts_nested_warpgate_ssh_options(self):
        routes = [
            {"name": "ssh-a", "host": "172.16.0.10", "port": 22, "listen_port": 2223},
        ]
        warpgate_targets = [
            {
                "name": "ssh-a",
                "kind": "ssh",
                "options": {"ssh": {"host": "127.0.0.1", "port": 2223}},
            }
        ]

        self.assertEqual(audit_routes(routes, warpgate_targets), [])

    def test_warpgate_audit_ignores_direct_ssh_routes(self):
        routes = [
            {
                "name": "ssh-a",
                "host": "10.0.0.10",
                "port": 22,
                "listen_port": 2223,
                "mode": "warpgate",
            },
            {
                "name": "direct-ssh",
                "host": "127.0.0.1",
                "port": 2225,
                "listen_port": 2226,
                "mode": "direct",
            },
        ]
        warpgate_targets = [
            {"name": "ssh-a", "kind": "ssh", "host": "127.0.0.1", "port": 2223},
        ]

        self.assertEqual(audit_routes(routes, warpgate_targets), [])

    def test_audit_reports_missing_and_unproxied_ssh_targets(self):
        routes = [
            {"name": "ssh-a", "host": "10.0.0.10", "port": 22, "listen_port": 2223},
        ]
        warpgate_targets = [
            {"name": "ssh-a", "kind": "ssh", "host": "127.0.0.1", "port": 22},
            {"name": "ssh-b", "kind": "ssh", "host": "10.0.0.11", "port": 22},
        ]

        errors = audit_routes(routes, warpgate_targets)
        self.assertEqual(len(errors), 2)
        self.assertTrue(any("currently 127.0.0.1:22" in error for error in errors))
        self.assertTrue(any("ssh-b" in error and "no proxy route" in error for error in errors))

    @patch("audit_ssh_proxy_routes.requests.get")
    def test_fetch_uses_warpgate_admin_api_and_token_header(self, get):
        get.return_value.json.return_value = [
            {"name": "ssh-a", "kind": "ssh", "host": "127.0.0.1", "port": 2223}
        ]
        targets = fetch_warpgate_targets("https://warpgate.local/", "private-token")

        self.assertEqual(targets[0]["name"], "ssh-a")
        self.assertEqual(
            get.call_args.kwargs["headers"],
            {"X-Warpgate-Token": "private-token"},
        )
        get.return_value.raise_for_status.assert_called_once()


if __name__ == "__main__":
    unittest.main()
