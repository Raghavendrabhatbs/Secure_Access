import sys
import types
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.database import SessionLocal
from app.services.chatbot_service import ChatbotQueryService
from app.services.llm.ollama_provider import OllamaProvider


class FakeImportFailureModule:
    def __getattr__(self, name):
        raise ImportError("ollama unavailable")


class FakeConnectionFailureClient:
    def __init__(self, host=None):
        self.host = host

    def generate(self, model, prompt, stream=False):
        raise ConnectionError("Ollama unavailable")


class FakeTimeoutClient:
    def __init__(self, host=None):
        self.host = host

    def generate(self, model, prompt, stream=False):
        raise TimeoutError("Ollama request timed out")


class FakeGenericFailureClient:
    def __init__(self, host=None):
        self.host = host

    def generate(self, model, prompt, stream=False):
        raise RuntimeError("provider failure")


class FakeEmptyResponseClient:
    response_payload = {"response": ""}

    def __init__(self, host=None):
        self.host = host

    def generate(self, model, prompt, stream=False):
        return self.__class__.response_payload


class FailingProvider:
    def generate(self, question, intent, evidence):
        raise RuntimeError("Ollama unavailable")


class WorkingProvider:
    def generate(self, question, intent, evidence):
        return "Mocked Ollama answer"


class OllamaFailureFallbackTest(unittest.TestCase):
    def setUp(self):
        self.provider = OllamaProvider()
        self.db = SessionLocal()
        self.chatbot = ChatbotQueryService(self.db, llm_provider=None)
        self.risky_session_id = "f9ba2142-8680-40e9-bebe-cc7ba5806af8"
        self.benign_session_id = "d21a4035-7ecc-4e42-9feb-b9bf7f343d43"

    def tearDown(self):
        self.db.close()

    def test_provider_import_failure_returns_none(self):
        with patch.dict(sys.modules, {"ollama": FakeImportFailureModule()}):
            result = self.provider.generate("question", "intent", {})
        self.assertIsNone(result)

    def test_provider_connection_failure_returns_none(self):
        fake_module = types.SimpleNamespace(Client=FakeConnectionFailureClient)
        with patch.dict(sys.modules, {"ollama": fake_module}):
            result = self.provider.generate("question", "intent", {})
        self.assertIsNone(result)

    def test_provider_timeout_returns_none(self):
        fake_module = types.SimpleNamespace(Client=FakeTimeoutClient)
        with patch.dict(sys.modules, {"ollama": fake_module}):
            result = self.provider.generate("question", "intent", {})
        self.assertIsNone(result)

    def test_provider_generic_failure_returns_none(self):
        fake_module = types.SimpleNamespace(Client=FakeGenericFailureClient)
        with patch.dict(sys.modules, {"ollama": fake_module}):
            result = self.provider.generate("question", "intent", {})
        self.assertIsNone(result)

    def test_provider_empty_and_malformed_responses_return_none(self):
        fake_module = types.SimpleNamespace(Client=FakeEmptyResponseClient)
        with patch.dict(sys.modules, {"ollama": fake_module}):
            FakeEmptyResponseClient.response_payload = {"response": ""}
            self.assertIsNone(self.provider.generate("question", "intent", {}))

            FakeEmptyResponseClient.response_payload = {"response": "   "}
            self.assertIsNone(self.provider.generate("question", "intent", {}))

            FakeEmptyResponseClient.response_payload = {"response": None}
            self.assertIsNone(self.provider.generate("question", "intent", {}))

            FakeEmptyResponseClient.response_payload = {"unexpected": "shape"}
            self.assertIsNone(self.provider.generate("question", "intent", {}))

    def test_chatbot_risky_session_falls_back_safely_when_provider_raises(self):
        chatbot = ChatbotQueryService(self.db, llm_provider=FailingProvider())
        result = chatbot.answer_question(
            "Explain why this session was considered high risk.",
            session_id=self.risky_session_id,
        )

        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["answer"])
        self.assertIn("PRIVILEGE_ESCALATION", result["answer"])
        self.assertIn("chmod 777 /etc/passwd", result["answer"])
        self.assertNotIn("database deleted", result["answer"].lower())

    def test_chatbot_benign_session_fallback_does_not_fabricate_risk(self):
        chatbot = ChatbotQueryService(self.db, llm_provider=FailingProvider())
        result = chatbot.answer_question(
            "What is the risk in this session?",
            session_id=self.benign_session_id,
        )

        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["answer"])
        self.assertIn("No risk findings were identified", result["answer"])
        self.assertNotIn("HIGH", result["answer"])
        self.assertNotIn("MEDIUM", result["answer"])

    def test_chatbot_negative_question_fallback_does_not_invent_action(self):
        chatbot = ChatbotQueryService(self.db, llm_provider=FailingProvider())
        result = chatbot.answer_question(
            "Did the user delete the database?",
            session_id=self.risky_session_id,
        )

        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["answer"])
        self.assertNotIn("yes", result["answer"].lower())
        self.assertNotIn("deleted the database", result["answer"].lower())

    def test_chatbot_successful_provider_still_returns_llm_answer(self):
        chatbot = ChatbotQueryService(self.db, llm_provider=WorkingProvider())
        result = chatbot.answer_question(
            "Explain why this session was considered high risk.",
            session_id=self.risky_session_id,
        )

        self.assertEqual(result["retrieval_mode"], "llm")
        self.assertEqual(result["answer"], "Mocked Ollama answer")


if __name__ == "__main__":
    unittest.main()
