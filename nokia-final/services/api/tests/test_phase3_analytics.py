import sys
from pathlib import Path
import unittest
from datetime import date

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.database import SessionLocal
from app.services.anomaly_detection_service import AnomalyDetectionService
from app.services.audit_report_service import AuditReportService
from app.services.chatbot_service import ChatbotQueryService
from app.services.phase3_query_service import Phase3QueryService
from app.services.ssh_knowledge_service import SSHKnowledgeService
from app.services.session_query_service import SessionQueryService


KNOWN_DATE = date(2026, 8, 20)


class Phase3AnalyticsTest(unittest.TestCase):
    def setUp(self):
        self.db = SessionLocal()
        self.sessions = SessionQueryService(self.db)
        self.audit = AuditReportService(self.sessions)
        self.anomaly = AnomalyDetectionService(self.sessions)
        self.phase3 = Phase3QueryService(self.sessions)
        self.knowledge = SSHKnowledgeService()
        self.chatbot = ChatbotQueryService(self.db, llm_provider=None)

    def tearDown(self):
        self.db.close()

    def test_expanded_knowledge_base(self):
        self.assertGreater(len(self.knowledge.known_commands()), 20)
        self.assertIsNotNone(self.knowledge.lookup("scp"))
        self.assertIsNotNone(self.knowledge.lookup("systemctl"))

    def test_ssh_knowledge_question(self):
        result = self.chatbot.answer_question("What is scp?")
        self.assertEqual(result["intent"], "COMMAND_EXPLANATION")
        self.assertTrue(result["evidence_available"])
        self.assertIn("scp", result["answer"].lower())

    def test_mkdir_os_explanation_question(self):
        result = self.chatbot.answer_question("explain me the command mkdir os does")
        self.assertEqual(result["intent"], "COMMAND_EXPLANATION")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("mkdir os", result["answer"].lower())
        self.assertIn("os", result["answer"].lower())
        self.assertNotIn("Ollama was unavailable", result["answer"])
        self.assertNotIn("Ollama was unavailable", result["evidence_summary"])

    def test_mkdir_os_knowledge_extraction(self):
        command = self.knowledge.extract_command_from_question("explain me the command mkdir os does")
        self.assertEqual(command, "mkdir os")
        answer = self.knowledge.explain(command)
        self.assertIsNotNone(answer)
        self.assertIn("directory named `os`", answer)

    def test_sudo_n_true_explanation(self):
        result = self.chatbot.answer_question("explain me the command sudo -n true")
        self.assertEqual(result["intent"], "COMMAND_EXPLANATION")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertIn("non-interactive", result["answer"].lower())
        self.assertIn("password", result["answer"].lower())
        self.assertNotIn("runs `-n true` with elevated privileges", result["answer"])

    def test_ssh_in_detail_does_not_treat_filler_as_arguments(self):
        command = self.knowledge.extract_command_from_question("what is ssh explain me indetail")
        self.assertEqual(command, "ssh")
        result = self.chatbot.answer_question("what is ssh explain me indetail")
        self.assertEqual(result["intent"], "COMMAND_EXPLANATION")
        self.assertTrue(
            "encrypt" in result["answer"].lower() or "secure" in result["answer"].lower()
        )
        self.assertNotIn("explain me indetail", result["answer"].lower())
        self.assertNotIn("argument is", result["answer"].lower())

    def test_audit_report_markdown(self):
        report = self.audit.build_report(KNOWN_DATE, KNOWN_DATE)
        self.assertEqual(report.session_count, 4)
        markdown = self.audit.format_markdown(report)
        self.assertIn("# SSH Security Audit Report", markdown)
        self.assertIn("Executive Summary", markdown)

    def test_export_audit_report_question(self):
        result = self.chatbot.answer_question("Generate audit report for 2026-08-20")
        self.assertEqual(result["intent"], "AUDIT_EXPORT")
        self.assertTrue(result["evidence_available"])
        self.assertIn("SSH Security Audit Report", result["answer"])

    def test_export_audit_report_json(self):
        result = self.chatbot.answer_question("Export audit report for 2026-08-20 as json")
        self.assertEqual(result["intent"], "AUDIT_EXPORT")
        self.assertIn('"session_count": 4', result["answer"])

    def test_weekly_audit_report(self):
        result = self.phase3.try_answer("Generate weekly audit report for this week")
        self.assertIsNotNone(result)
        self.assertEqual(result["intent"], "AUDIT_EXPORT")

    def test_anomaly_detection(self):
        baseline = self.anomaly.build_baseline(KNOWN_DATE - __import__("datetime").timedelta(days=1))
        findings = self.anomaly.detect_anomalies(KNOWN_DATE, baseline)
        self.assertIsInstance(findings, list)

        result = self.chatbot.answer_question("Detect anomalies on 2026-08-20")
        self.assertEqual(result["intent"], "CROSS_SESSION_ANALYSIS")

    def test_baseline_comparison(self):
        result = self.chatbot.answer_question("How does 2026-08-20 compare to baseline?")
        self.assertEqual(result["intent"], "CROSS_SESSION_ANALYSIS")
        self.assertIn("Baseline comparison", result["answer"])

    def test_current_datetime_question(self):
        result = self.chatbot.answer_question("what is todays date and day?")
        self.assertEqual(result["intent"], "GENERAL_KNOWLEDGE")
        self.assertEqual(result["retrieval_mode"], "rule-based")
        self.assertTrue(result["evidence_available"])
        self.assertIn("Today is", result["answer"])
        self.assertNotIn("current time", result["answer"].lower())
        self.assertNotIn("format is", result["answer"].lower())

    def test_current_time_question(self):
        result = self.chatbot.answer_question("what is the time?")
        self.assertEqual(result["intent"], "GENERAL_KNOWLEDGE")
        self.assertIn("current time is", result["answer"].lower())
        self.assertNotIn("Today is", result["answer"])

    def test_date_command_still_explained(self):
        result = self.chatbot.answer_question("What is the date command?")
        self.assertEqual(result["intent"], "COMMAND_EXPLANATION")
        self.assertIn("date", result["answer"].lower())


if __name__ == "__main__":
    unittest.main()
