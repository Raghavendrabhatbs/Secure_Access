from __future__ import annotations

import unittest
from uuid import uuid4

import httpx

from app.services.warpgate_admin_client import (
    WarpgateAdminClient,
    WarpgateAdminError,
)


SESSION_ID = "94e34c21-156c-4a41-9cf2-ccedc1520669"


def session_payload(session_id: str = SESSION_ID, ended=None):
    return {
        "id": session_id,
        "username": "alice",
        "target": {"name": "ssh-demo"},
        "protocol": "SSH",
        "started": "2026-10-25T10:00:00Z",
        "ended": ended,
        "node_hostname": "wsl-host",
    }


class WarpgateAdminClientTests(unittest.TestCase):
    def client(self, handler):
        return WarpgateAdminClient(
            base_url="https://warpgate.test",
            transport=httpx.MockTransport(handler),
        )

    def test_lists_only_active_sessions_from_all_pages(self):
        def handler(request):
            self.assertEqual(request.url.path, "/@warpgate/admin/api/sessions")
            self.assertEqual(request.url.params["active_only"], "true")
            self.assertEqual(request.headers["cookie"], "warpgate-http-session=secret-cookie")
            offset = int(request.url.params["offset"])
            if offset == 0:
                return httpx.Response(
                    200,
                    json={
                        "items": [
                            session_payload(str(uuid4()))
                            for _ in range(100)
                        ],
                        "offset": 0,
                        "total": 101,
                    },
                )
            return httpx.Response(
                200,
                json={
                    "items": [session_payload(str(uuid4()))],
                    "offset": offset,
                    "total": 101,
                },
            )

        client = self.client(handler)
        client.PAGE_SIZE = 100
        self.assertEqual(
            len(client.list_active_sessions("warpgate-http-session=secret-cookie")),
            101,
        )

    def test_empty_active_session_list(self):
        client = self.client(
            lambda _request: httpx.Response(
                200,
                json={"items": [], "offset": 0, "total": 0},
            )
        )
        self.assertEqual(client.list_active_sessions("session=cookie"), [])

    def test_api_timeout_is_reported(self):
        def handler(_request):
            raise httpx.ReadTimeout("timed out")

        client = self.client(handler)
        with self.assertRaises(WarpgateAdminError) as raised:
            client.list_active_sessions("session=cookie")
        self.assertEqual(raised.exception.status_code, 503)

    def test_authentication_and_permission_errors_are_not_hidden(self):
        for status_code in (401, 403):
            with self.subTest(status_code=status_code):
                client = self.client(
                    lambda _request, status_code=status_code: httpx.Response(status_code)
                )
                with self.assertRaises(WarpgateAdminError) as raised:
                    client.list_active_sessions("session=cookie")
                self.assertEqual(raised.exception.status_code, status_code)

    def test_invalid_session_id_is_rejected_without_request(self):
        requested = False

        def handler(_request):
            nonlocal requested
            requested = True
            return httpx.Response(200, json={})

        client = self.client(handler)
        with self.assertRaises(WarpgateAdminError) as raised:
            client.terminate_session("session=cookie", "not-a-uuid")
        self.assertEqual(raised.exception.status_code, 422)
        self.assertFalse(requested)

    def test_successful_termination_is_verified_by_reading_session_state(self):
        calls = []

        def handler(request):
            calls.append((request.method, request.url.path))
            if request.method == "GET":
                ended = None if len(calls) == 1 else "2026-10-25T10:05:00Z"
                return httpx.Response(200, json=session_payload(ended=ended))
            return httpx.Response(201)

        result = self.client(handler).terminate_session("session=cookie", SESSION_ID)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(
            [method for method, _path in calls],
            ["GET", "POST", "GET"],
        )

    def test_already_ended_session_is_not_terminated_again(self):
        calls = []

        def handler(request):
            calls.append(request.method)
            return httpx.Response(
                200,
                json=session_payload(ended="2026-10-25T10:05:00Z"),
            )

        result = self.client(handler).terminate_session("session=cookie", SESSION_ID)
        self.assertEqual(result["status"], "already_ended")
        self.assertEqual(calls, ["GET"])

    def test_unexpected_close_status_is_reported_unverified(self):
        def handler(request):
            if request.method == "POST":
                return httpx.Response(500)
            return httpx.Response(200, json=session_payload())

        result = self.client(handler).terminate_session("session=cookie", SESSION_ID)
        self.assertEqual(result["status"], "unverified")

    def test_session_state_must_match_requested_id(self):
        post_called = False

        def handler(request):
            nonlocal post_called
            if request.method == "POST":
                post_called = True
                return httpx.Response(201)
            return httpx.Response(200, json=session_payload(str(uuid4())))

        with self.assertRaises(WarpgateAdminError):
            self.client(handler).terminate_session("session=cookie", SESSION_ID)
        self.assertFalse(post_called)

    def test_session_state_remaining_active_after_close_is_unverified(self):
        call_count = 0

        def handler(request):
            nonlocal call_count
            if request.method == "GET":
                call_count += 1
                return httpx.Response(200, json=session_payload())
            return httpx.Response(201)

        result = self.client(handler).terminate_session("session=cookie", SESSION_ID)
        self.assertEqual(result["status"], "unverified")

    def test_missing_session_cookie_is_rejected(self):
        client = self.client(lambda _request: httpx.Response(200, json={}))
        with self.assertRaises(WarpgateAdminError) as raised:
            client.list_active_sessions("")
        self.assertEqual(raised.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main()
