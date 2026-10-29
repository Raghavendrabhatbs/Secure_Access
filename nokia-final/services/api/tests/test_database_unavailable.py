import sys
from pathlib import Path
import unittest
from unittest.mock import Mock

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.assistant_auth import AssistantUser, require_assistant_user
from app.db.database import get_db
from app.main import app


class DatabaseUnavailableTest(unittest.TestCase):
    def tearDown(self):
        app.dependency_overrides.clear()

    def test_session_api_returns_service_unavailable_on_database_failure(self):
        db = Mock()
        db.scalars.side_effect = OperationalError("SELECT", {}, ConnectionError("unavailable"))

        def override_get_db():
            yield db

        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[require_assistant_user] = lambda: AssistantUser(
            "test-admin",
            "admin",
        )

        response = TestClient(app).get("/sessions")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json(),
            {"detail": "Database is unavailable. Please retry shortly."},
        )


if __name__ == "__main__":
    unittest.main()
