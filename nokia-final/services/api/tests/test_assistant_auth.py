import os
import unittest
from unittest.mock import patch

import httpx
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.core.assistant_auth import require_assistant_user
from app.db.database import get_db
from app.main import app


def _request(cookie: str | None = None) -> Request:
    headers = [] if cookie is None else [(b"cookie", cookie.encode("ascii"))]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers})


class AssistantAuthenticationTest(unittest.TestCase):
    def test_rejects_request_without_warpgate_cookie(self):
        with patch("app.core.assistant_auth.httpx.get") as get_identity:
            with self.assertRaises(HTTPException) as raised:
                require_assistant_user(_request())

        self.assertEqual(raised.exception.status_code, 401)
        get_identity.assert_not_called()

    def test_uses_warpgate_verified_role_and_username(self):
        response = type(
            "IdentityResponse",
            (),
            {"status_code": 200, "json": lambda self: {"username": "analyst", "application_role": "auditor_viewer"}},
        )()
        with patch.dict(os.environ, {"WARPGATE_URL": "https://identity.example"}), patch(
            "app.core.assistant_auth.httpx.get", return_value=response
        ) as get_identity:
            identity = require_assistant_user(_request("warpgate-http-session=signed-cookie"))

        self.assertEqual(identity.username, "analyst")
        self.assertEqual(identity.role, "auditor_viewer")
        self.assertEqual(get_identity.call_args.args[0], "https://identity.example/@warpgate/api/info")
        self.assertEqual(
            get_identity.call_args.kwargs["headers"],
            {"Cookie": "warpgate-http-session=signed-cookie"},
        )
        self.assertTrue(get_identity.call_args.kwargs["verify"])

    def test_uses_local_warpgate_default_when_url_is_not_set(self):
        response = type(
            "IdentityResponse",
            (),
            {"status_code": 200, "json": lambda self: {"username": "analyst", "application_role": "admin"}},
        )()
        with patch.dict(os.environ, {"WARPGATE_URL": "", "WARPGATE_CA_BUNDLE": ""}), patch(
            "app.core.assistant_auth.httpx.get",
            return_value=response,
        ) as get_identity:
            identity = require_assistant_user(_request("warpgate-http-session=signed-cookie"))

        self.assertEqual(identity.username, "analyst")
        self.assertEqual(
            get_identity.call_args.args[0],
            "https://localhost:8888/@warpgate/api/info",
        )

    def test_forwards_only_the_warpgate_session_cookie(self):
        response = type(
            "IdentityResponse",
            (),
            {"status_code": 200, "json": lambda self: {"username": "analyst", "application_role": "admin"}},
        )()
        with patch.dict(os.environ, {"WARPGATE_URL": "https://identity.example"}), patch(
            "app.core.assistant_auth.httpx.get", return_value=response
        ) as get_identity:
            require_assistant_user(
                _request("app-state=private; warpgate-http-session=signed-cookie; other=value")
            )

        self.assertEqual(
            get_identity.call_args.kwargs["headers"],
            {"Cookie": "warpgate-http-session=signed-cookie"},
        )

    def test_rejects_unapproved_role(self):
        response = type(
            "IdentityResponse",
            (),
            {"status_code": 200, "json": lambda self: {"username": "user", "application_role": "viewer"}},
        )()
        with patch.dict(os.environ, {"WARPGATE_URL": "https://identity.example"}), patch(
            "app.core.assistant_auth.httpx.get", return_value=response
        ):
            with self.assertRaises(HTTPException) as raised:
                require_assistant_user(_request("warpgate-http-session=signed-cookie"))

        self.assertEqual(raised.exception.status_code, 403)

    def test_rejects_malformed_role_from_identity_service(self):
        response = type(
            "IdentityResponse",
            (),
            {"status_code": 200, "json": lambda self: {"username": "user", "application_role": []}},
        )()
        with patch.dict(os.environ, {"WARPGATE_URL": "https://identity.example"}), patch(
            "app.core.assistant_auth.httpx.get", return_value=response
        ):
            with self.assertRaises(HTTPException) as raised:
                require_assistant_user(_request("warpgate-http-session=signed-cookie"))

        self.assertEqual(raised.exception.status_code, 403)

    def test_hides_identity_service_failure_details(self):
        with patch.dict(os.environ, {"WARPGATE_URL": "https://identity.example"}), patch(
            "app.core.assistant_auth.httpx.get",
            side_effect=httpx.ConnectError("secret host and credential details"),
        ):
            with self.assertRaises(HTTPException) as raised:
                require_assistant_user(_request("warpgate-http-session=signed-cookie"))

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(raised.exception.detail, "Identity service is unavailable.")
        self.assertNotIn("secret", raised.exception.detail)

    def test_session_api_rejects_anonymous_access(self):
        app.dependency_overrides[get_db] = lambda: iter((object(),))
        try:
            response = TestClient(app).get("/sessions")
        finally:
            app.dependency_overrides.clear()

        self.assertEqual(response.status_code, 401)

    def test_chat_api_rejects_blank_or_oversized_questions(self):
        from app.core.assistant_auth import AssistantUser

        app.dependency_overrides[require_assistant_user] = lambda: AssistantUser("test-analyst", "admin")
        try:
            client = TestClient(app)
            blank = client.post("/chat/query", json={"message": "   "})
            oversized = client.post("/chat/query", json={"message": "x" * 4001})
        finally:
            app.dependency_overrides.clear()

        self.assertEqual(blank.status_code, 422)
        self.assertEqual(oversized.status_code, 422)


if __name__ == "__main__":
    unittest.main()
