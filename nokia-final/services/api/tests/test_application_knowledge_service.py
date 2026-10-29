import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.chatbot_service import ChatbotQueryService
from app.services.application_knowledge_service import ApplicationKnowledgeService


class ApplicationKnowledgeServiceTest(unittest.TestCase):
    def test_chatbot_uses_project_docs_for_application_architecture_questions(self):
        class EmptyDatabase:
            def scalars(self, *_args, **_kwargs):
                raise AssertionError("general app questions must not query session data")

            def get(self, *_args, **_kwargs):
                raise AssertionError("general app questions must not query session data")

        service = ChatbotQueryService(EmptyDatabase())
        context = {
            "source": "repository documentation",
            "documents": [{"path": "nokia-final/SETUP_GUIDE.md", "text": "FastAPI and Ollama."}],
        }
        with patch.object(service._application_knowledge_service, "context_for", return_value=context), patch.object(
            service,
            "_generate_llm_answer",
            return_value="The app uses FastAPI and Ollama.",
        ) as generate:
            result = service.answer_question("Explain Secure Access architecture")

        self.assertEqual(result["answer"], "The app uses FastAPI and Ollama.")
        self.assertTrue(result["evidence_available"])
        self.assertIn("repository documentation", result["evidence_summary"])
        self.assertEqual(generate.call_args.args[2], context)

    def test_application_question_retrieves_bounded_relevant_docs(self):
        with tempfile.TemporaryDirectory() as directory:
            project_root = Path(directory) / "nokia-final"
            rrweb_root = Path(directory) / "rrweb"
            project_root.mkdir()
            rrweb_root.mkdir()
            (project_root / "SETUP_GUIDE.md").write_text(
                "## Architecture\nBackend flow evidence.\n### API\nAPI flow evidence.\n## Other architecture\nIgnore this section.\n"
                "## Part 2\n### 2.1 What runs\nOllama model evidence.\n### 2.2 Other\nIgnore this too.\n",
                encoding="utf-8",
            )
            (project_root / "README.md").write_text("Nokia assistant overview.\n", encoding="utf-8")
            (rrweb_root / "README.md").write_text(
                "## Recording persistence\nMetadata and event files.\n"
                "## Recording continuity and navigation\nPage visits and retries.\n"
                "## Other\nDo not include.\n",
                encoding="utf-8",
            )
            service = ApplicationKnowledgeService(project_root)

            context = service.context_for("Explain Secure Access web recording architecture")

        self.assertEqual(context["source"], "repository documentation")
        self.assertLessEqual(sum(len(doc["text"]) for doc in context["documents"]), service.MAX_CONTEXT_CHARS)
        texts = " ".join(doc["text"] for doc in context["documents"])
        self.assertIn("Backend flow evidence", texts)
        self.assertIn("API flow evidence", texts)
        self.assertIn("Ollama model evidence", texts)
        self.assertIn("Metadata and event files", texts)
        self.assertNotIn("Ignore this section", texts)
        self.assertNotIn("Do not include", texts)

    def test_general_technical_question_does_not_load_application_docs(self):
        service = ApplicationKnowledgeService(Path("missing-project-root"))
        self.assertIsNone(service.context_for("What does the grep command do?"))

    def test_application_question_reports_missing_docs_as_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            service = ApplicationKnowledgeService(Path(directory))
            self.assertIsNone(service.context_for("Explain the Secure Access architecture"))


if __name__ == "__main__":
    unittest.main()
