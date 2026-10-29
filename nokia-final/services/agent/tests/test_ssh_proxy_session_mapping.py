import unittest
from unittest.mock import Mock, patch

from ssh_proxy import NokiaInterceptForwarder, _warpgate_target_name


class WarpgateTargetNameTests(unittest.TestCase):
    def test_reads_target_name_from_snapshot_object(self):
        session = {
            "target_sessions": [
                {"ended": None, "target": {"name": "ssh-demo"}},
            ]
        }

        self.assertEqual(_warpgate_target_name(session), "ssh-demo")

    def test_reads_target_name_from_direct_string(self):
        self.assertEqual(_warpgate_target_name({"target": "ssh-demo"}), "ssh-demo")

    def test_rejects_ambiguous_target_snapshots(self):
        session = {
            "target_sessions": [
                {"ended": None, "target": {"name": "ssh-demo"}},
                {"ended": None, "target": {"name": "another-target"}},
            ]
        }

        self.assertEqual(_warpgate_target_name(session), "")


class WarpgateSessionLookupTests(unittest.TestCase):
    def make_forwarder(self):
        forwarder = object.__new__(NokiaInterceptForwarder)
        forwarder._proxy_session_id = "127.0.0.1:40000"
        forwarder._warpgate_session_id = ""
        forwarder._session_username = ""
        return forwarder

    @patch("ssh_proxy.WARPGATE_TARGET_NAME", "ssh-demo")
    @patch("ssh_proxy.requests.get")
    def test_maps_unique_active_ssh_session_for_target(self, get):
        get.return_value.status_code = 200
        get.return_value.json.return_value = {
            "items": [
                {
                    "id": "warpgate-session-1",
                    "username": "alice",
                    "protocol": "SSH",
                    "ended": None,
                    "target_sessions": [
                        {"ended": None, "target": {"name": "ssh-demo"}}
                    ],
                },
                {
                    "id": "old-session",
                    "username": "bob",
                    "protocol": "SSH",
                    "ended": "2026-01-01T00:00:00Z",
                    "target_sessions": [
                        {"target": {"name": "ssh-demo"}}
                    ],
                },
            ]
        }
        forwarder = self.make_forwarder()

        self.assertEqual(forwarder._find_warpgate_session(), "warpgate-session-1")
        self.assertEqual(forwarder._session_username, "alice")

    @patch("ssh_proxy.WARPGATE_TARGET_NAME", "ssh-demo")
    @patch("ssh_proxy.requests.get")
    def test_refuses_to_guess_between_concurrent_sessions(self, get):
        get.return_value.status_code = 200
        get.return_value.json.return_value = {
            "items": [
                {
                    "id": f"warpgate-session-{username}",
                    "username": username,
                    "protocol": "SSH",
                    "ended": None,
                    "target_sessions": [
                        {"ended": None, "target": {"name": "ssh-demo"}}
                    ],
                }
                for username in ("alice", "bob")
            ]
        }
        forwarder = self.make_forwarder()

        self.assertEqual(forwarder._find_warpgate_session(), "")
        self.assertEqual(forwarder._session_username, "")

    @patch("ssh_proxy.PROXY_SESSION_MODE", "direct")
    def test_direct_session_uses_client_login_and_skips_warpgate_lookup(self):
        forwarder = self.make_forwarder()
        forwarder._proxy_session_id = ""
        forwarder.session = Mock()
        forwarder.session.remote.socket_address = ("192.0.2.10", 40000)
        forwarder.session.auth.username_provided = "alice"

        with patch.object(forwarder, "_find_warpgate_session") as lookup:
            forwarder._get_session_ids()

        lookup.assert_not_called()
        self.assertEqual(forwarder._session_username, "alice")
        self.assertEqual(forwarder._warpgate_session_id, "")


if __name__ == "__main__":
    unittest.main()
