import sys
from datetime import date, datetime, timezone
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from sqlalchemy.exc import OperationalError

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.web_session_query_service import (
    WebSessionAccessDenied,
    WebSessionQueryError,
    WebSessionQueryService,
)
from app.core.assistant_auth import AssistantUser, require_assistant_user
from app.db.database import get_db
from app.main import app


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self.payload = payload

    def json(self):
        return self.payload


class WebSessionQueryServiceTest(unittest.TestCase):
    def setUp(self):
        def override_get_db():
            yield object()

        app.dependency_overrides[get_db] = override_get_db

    def tearDown(self):
        app.dependency_overrides.clear()

    def test_listing_filters_paginates_and_forwards_only_warpgate_cookie(self):
        records = [
            {
                "sessionId": "session-one",
                "username": "alice",
                "target": "prod-web",
                "startedAt": "2026-10-23T12:00:00Z",
                "firstPageUrl": "https://example.test/",
                "eventCount": 7,
                "hasRecording": True,
                "privateField": "must not escape",
            },
            {
                "sessionId": "session-two",
                "username": "bob",
                "target": "test-web",
                "startedAt": "2026-10-22T12:00:00Z",
                "eventCount": 2,
            },
            {
                "sessionId": "session-three",
                "username": "alice",
                "target": "prod-web",
                "startedAt": "2026-10-20T12:00:00Z",
                "eventCount": 3,
            },
        ]
        service = WebSessionQueryService(
            "theme=dark; warpgate-http-session=signed-cookie; unrelated=private",
            warpgate_url="https://warpgate.test",
        )
        with patch(
            "app.services.web_session_query_service.httpx.get",
            return_value=FakeResponse(200, records),
        ) as get:
            page = service.list_sessions(
                limit=1,
                offset=1,
                username="ALICE",
                target="prod",
                start_date=date(2026, 10, 20),
                end_date=date(2026, 10, 23),
            )

        self.assertEqual(page["protocol"], "WEB")
        self.assertEqual(page["total"], 2)
        self.assertEqual(page["offset"], 1)
        self.assertEqual(page["items"][0]["sessionId"], "session-three")
        self.assertNotIn("privateField", page["items"][0])
        self.assertEqual(get.call_args.args[0], "https://warpgate.test/@warpgate/rrweb/api/sessions")
        self.assertEqual(get.call_args.kwargs["headers"], {"Cookie": "warpgate-http-session=signed-cookie"})

    def test_detail_validates_recording_id_and_limits_metadata_fields(self):
        payload = {
            "sessionId": "session-abcdef123456",
            "username": "alice",
            "target": "prod-web",
            "pageVisits": [{"url": "https://example.test/", "timestamp": "2026-10-23T12:00:00Z"}],
            "rawEvents": [{"type": "full-snapshot"}],
        }
        service = WebSessionQueryService(
            "warpgate-http-session=signed-cookie",
            warpgate_url="https://warpgate.test",
        )
        with patch(
            "app.services.web_session_query_service.httpx.get",
            return_value=FakeResponse(200, payload),
        ) as get:
            result = service.get_session("session-abcdef123456")
        self.assertEqual(result["sessionId"], "session-abcdef123456")
        self.assertNotIn("rawEvents", result)
        self.assertTrue(get.call_args.args[0].endswith("/session-metadata/session-abcdef123456"))

        with self.assertRaises(ValueError):
            service.get_session("../recordings.json")

    def test_missing_cookie_and_upstream_denial_fail_closed(self):
        service = WebSessionQueryService("other-cookie=ignored", warpgate_url="https://warpgate.test")
        with self.assertRaises(WebSessionAccessDenied):
            service.list_sessions()

        service = WebSessionQueryService(
            "warpgate-http-session=signed-cookie",
            warpgate_url="https://warpgate.test",
        )
        with patch(
            "app.services.web_session_query_service.httpx.get",
            return_value=FakeResponse(403, {}),
        ):
            with self.assertRaises(WebSessionAccessDenied):
                service.list_sessions()

    def test_web_query_uses_the_configured_local_warpgate_default(self):
        service = WebSessionQueryService(
            "warpgate-http-session=signed-cookie",
            warpgate_url="",
        )

        self.assertEqual(service._base_url, "https://localhost:8888")
        self.assertIsNot(service._verify, False)

    def test_web_listing_filters_recording_availability_and_future_timestamps(self):
        service = WebSessionQueryService(
            "warpgate-http-session=signed-cookie",
            warpgate_url="https://warpgate.test",
        )
        records = [
            {
                "sessionId": "session-recorded-0001",
                "username": "alice",
                "startedAt": "2026-10-24T10:00:00Z",
                "hasRecording": True,
            },
            {
                "sessionId": "session-no-record-0001",
                "username": "alice",
                "startedAt": "2026-10-24T09:00:00Z",
                "hasRecording": False,
            },
            {
                "sessionId": "session-future-00001",
                "username": "alice",
                "startedAt": "2026-10-25T09:00:00Z",
                "hasRecording": True,
            },
        ]
        with patch(
            "app.services.web_session_query_service.httpx.get",
            return_value=FakeResponse(200, records),
        ):
            page = service.list_sessions(
                limit=1,
                has_recording=True,
                occurred_before=datetime(2026, 10, 24, 12, tzinfo=timezone.utc),
            )

        self.assertEqual(page["total"], 1)
        self.assertEqual(page["items"][0]["sessionId"], "session-recorded-0001")

    def test_upstream_failures_are_generic_and_page_bounds_are_limited(self):
        service = WebSessionQueryService(
            "warpgate-http-session=signed-cookie",
            warpgate_url="https://warpgate.test",
        )
        with self.assertRaises(ValueError):
            service.list_sessions(limit=101)
        with patch(
            "app.services.web_session_query_service.httpx.get",
            return_value=FakeResponse(502, {"detail": "private host information"}),
        ):
            with self.assertRaisesRegex(WebSessionQueryError, "returned an error") as context:
                service.list_sessions()
        self.assertNotIn("private host information", str(context.exception))

    def test_chat_answers_web_count_from_authorized_metadata(self):
        service = WebSessionQueryService(
            "warpgate-http-session=signed-cookie",
            warpgate_url="https://warpgate.test",
        )
        with patch(
            "app.services.web_session_query_service.httpx.get",
            return_value=FakeResponse(200, [
                {"sessionId": "session-abcdef123456", "username": "alice"},
                {"sessionId": "session-bcdefa234567", "username": "bob"},
            ]),
        ):
            answer = service.answer_question("How many web sessions are recorded?")
        self.assertIn("2 distinct Web recording session(s)", answer["answer"])
        self.assertEqual(answer["intent"], "SESSION_COUNT")
        self.assertEqual(answer["retrieval_mode"], "rule-based")
        self.assertTrue(answer["evidence_available"])

    def test_web_recording_listing_uses_recording_search_intent(self):
        service = WebSessionQueryService(
            "warpgate-http-session=signed-cookie",
            warpgate_url="https://warpgate.test",
        )
        with patch(
            "app.services.web_session_query_service.httpx.get",
            return_value=FakeResponse(
                200,
                [{"sessionId": "session-abcdef123456", "username": "alice"}],
            ),
        ):
            answer = service.answer_question("Show all web recordings")

        self.assertEqual(answer["intent"], "RECORDING_SEARCH")
        self.assertIn("Found 1 authorized Web recording session", answer["answer"])

    def test_web_chat_applies_user_and_relative_date_filters(self):
        service = WebSessionQueryService(
            "warpgate-http-session=signed-cookie",
            warpgate_url="https://warpgate.test",
        )
        with patch.object(service, "list_sessions", return_value={"items": [], "total": 0}) as listing:
            answer = service.answer_question("How many web sessions for username alice yesterday?")
        self.assertIn("0 distinct Web recording", answer["answer"])
        self.assertEqual(listing.call_args.kwargs["username"], "alice")
        self.assertEqual(listing.call_args.kwargs["start_date"], date(2026, 10, 23))
        self.assertEqual(listing.call_args.kwargs["end_date"], date(2026, 10, 23))

    def test_developer_web_chat_is_scoped_to_authenticated_username(self):
        service = WebSessionQueryService(
            "warpgate-http-session=signed-cookie",
            warpgate_url="https://warpgate.test",
        )
        with patch.object(service, "list_sessions", return_value={"items": [], "total": 0}) as listing:
            service.answer_question(
                "How many web sessions for username bob?",
                username_scope="alice",
            )

        self.assertEqual(listing.call_args.kwargs["username"], "alice")

    def test_web_detail_sends_bounded_metadata_to_existing_llm(self):
        service = WebSessionQueryService(
            "warpgate-http-session=signed-cookie",
            warpgate_url="https://warpgate.test",
        )
        metadata = {
            "sessionId": "session-abcdef123456",
            "username": "alice",
            "target": "prod-web",
            "eventCount": 12,
            "pageVisits": [{"url": "https://example.test/", "timestamp": "2026-10-23T12:00:00Z"}],
            "rawEvents": [{"type": "unbounded event payload"}],
        }
        with patch(
            "app.services.web_session_query_service.httpx.get",
            return_value=FakeResponse(200, metadata),
        ), patch("app.services.llm.ollama_provider.OllamaProvider.generate", return_value="Grounded summary.") as generate:
            answer = service.answer_question(
                "Summarize this web session",
                session_id="session-abcdef123456",
            )
        self.assertEqual(answer["answer"], "Grounded summary.")
        self.assertEqual(answer["retrieval_mode"], "llm")
        evidence = generate.call_args.args[2]
        self.assertIn("pageVisits", evidence["records"][0])
        self.assertNotIn("rawEvents", evidence["records"][0])

    def test_web_proxy_architecture_question_does_not_query_recordings(self):
        self.assertFalse(WebSessionQueryService.is_web_session_question(
            "Explain how the Secure Access web proxy works"
        ))
        self.assertTrue(WebSessionQueryService.is_web_session_question(
            "Show me all browser sessions"
        ))

    def test_empty_web_results_are_explicit_and_do_not_call_llm(self):
        service = WebSessionQueryService(
            "warpgate-http-session=signed-cookie",
            warpgate_url="https://warpgate.test",
        )
        with patch(
            "app.services.web_session_query_service.httpx.get",
            return_value=FakeResponse(200, []),
        ), patch("app.services.llm.ollama_provider.OllamaProvider.generate") as generate:
            answer = service.answer_question("Summarize web activity")
        self.assertIn("No Web recording metadata", answer["answer"])
        self.assertTrue(answer["evidence_available"])
        generate.assert_not_called()

    def test_chat_route_dispatches_web_question_to_web_query_service(self):
        app.dependency_overrides[require_assistant_user] = lambda: AssistantUser("analyst", "admin")
        expected = {
            "answer": "There are 2 distinct Web recording session(s) visible to your account.",
            "intent": "SESSION_COUNT",
            "retrieval_mode": "rule-based",
            "evidence_available": True,
            "evidence_summary": "Counted authorized Web recording metadata records.",
        }
        with patch("app.api.routes.WebSessionQueryService") as service_type:
            service_type.return_value.answer_question.return_value = expected
            response = TestClient(app).post(
                "/chat/query",
                headers={"cookie": "theme=dark; warpgate-http-session=signed-cookie"},
                json={"message": "How many web sessions?"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["answer"], expected["answer"])
        service_type.assert_called_once_with("theme=dark; warpgate-http-session=signed-cookie")

    def test_web_question_still_answers_when_optional_conversation_database_is_down(self):
        db = Mock()

        def override_get_db():
            yield db

        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[require_assistant_user] = lambda: AssistantUser("analyst", "admin")
        expected = {
            "answer": "There is one current web recording.",
            "intent": "SESSION_COUNT",
            "retrieval_mode": "rule-based",
            "evidence_available": True,
            "evidence_summary": "Counted current web recordings.",
        }
        with patch("app.api.routes.ConversationService") as conversation_type, patch(
            "app.api.routes.WebSessionQueryService"
        ) as web_service_type:
            conversation_type.return_value.get_or_create.side_effect = OperationalError(
                "INSERT",
                {},
                ConnectionError("database unavailable"),
            )
            web_service_type.return_value.answer_question.return_value = expected
            response = TestClient(app).post(
                "/chat/query",
                headers={"cookie": "warpgate-http-session=signed-cookie"},
                json={
                    "message": "How many web sessions?",
                    "conversation_id": "c9a16957-9e67-4b37-a870-904f7e77b9e8",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["answer"], expected["answer"])
        db.rollback.assert_called_once()

    def test_web_session_api_requires_auth_and_maps_upstream_failure(self):
        client = TestClient(app)
        unauthorized = client.get("/web-sessions")
        self.assertEqual(unauthorized.status_code, 401)

        app.dependency_overrides[require_assistant_user] = lambda: AssistantUser("analyst", "admin")
        with patch("app.api.routes.WebSessionQueryService") as service_type:
            service_type.return_value.list_sessions.side_effect = WebSessionQueryError(
                "Web session service is unavailable."
            )
            failed = client.get("/web-sessions?limit=10")
        self.assertEqual(failed.status_code, 503)
        self.assertEqual(failed.json()["detail"], "Web session service is unavailable.")

    def test_web_session_api_rejects_invalid_date_order(self):
        app.dependency_overrides[require_assistant_user] = lambda: AssistantUser("analyst", "admin")
        response = TestClient(app).get(
            "/web-sessions?start_date=2026-10-24&end_date=2026-10-23"
        )
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
