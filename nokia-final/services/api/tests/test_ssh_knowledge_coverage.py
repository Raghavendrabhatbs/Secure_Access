"""Coverage tests ensuring the SSH knowledge base handles many natural-language phrasings."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.db.database import SessionLocal
from app.services.chatbot_service import ChatbotQueryService
from app.services.ssh_knowledge_service import SSHKnowledgeService


class SSHKnowledgeCoverageTest(unittest.TestCase):
    """Every reasonable SSH/Linux command phrasing should get an explanation."""

    @classmethod
    def setUpClass(cls):
        cls.knowledge = SSHKnowledgeService()

    def setUp(self):
        self.db = SessionLocal()
        # Deliberately pass no LLM provider so we exercise the offline path.
        self.chatbot = ChatbotQueryService(self.db, llm_provider=None)

    def tearDown(self):
        self.db.close()

    def _assert_command_answer(self, question: str, must_contain: tuple[str, ...]):
        result = self.chatbot.answer_question(question)
        self.assertEqual(
            result["intent"],
            "COMMAND_EXPLANATION",
            msg=f"Question `{question}` was not classified as COMMAND_EXPLANATION: {result}",
        )
        for needle in must_contain:
            self.assertIn(
                needle,
                result["answer"],
                msg=f"Question `{question}` -> missing `{needle}` in `{result['answer']}`",
            )

    def test_extract_ps_aux(self):
        self.assertEqual(self.knowledge.extract_command_from_question("explain me the command ps aux"), "ps aux")

    def test_extract_sudo_n_true(self):
        self.assertEqual(
            self.knowledge.extract_command_from_question("briefly explain the command sudo -n true"),
            "sudo -n true",
        )

    def test_extract_history_c_with_mean_trailing(self):
        self.assertEqual(
            self.knowledge.extract_command_from_question("what does history -c mean"),
            "history -c",
        )

    def test_extract_ip_a_from_the_command_phrasing(self):
        self.assertEqual(
            self.knowledge.extract_command_from_question("what does the ip a command do"),
            "ip a",
        )

    def test_extract_unknown_command(self):
        # Unknown to the KB, but should still surface as a candidate so LLM/fallback can handle it.
        self.assertEqual(
            self.knowledge.extract_command_from_question("tell me what jq does"),
            "jq",
        )

    def test_extract_trailing_the_x_command(self):
        self.assertEqual(
            self.knowledge.extract_command_from_question("tell me about the netcat command"),
            "netcat",
        )

    def test_ps_aux_explanation_is_compound(self):
        self._assert_command_answer(
            "explain me the command ps aux",
            ("ps aux", "processes", "every user"),
        )

    def test_sudo_n_true_brief_is_short(self):
        result = self.chatbot.answer_question("briefly explain the command sudo -n true")
        self.assertEqual(result["intent"], "COMMAND_EXPLANATION")
        # Brief mode should return a single sentence, not the multi-line breakdown.
        self.assertLess(result["answer"].count("\n"), 2)
        self.assertIn("sudo -n true", result["answer"])

    def test_ls_la_compound(self):
        self._assert_command_answer(
            "what does ls -la do",
            ("ls -la", "hidden", "long"),
        )

    def test_rm_rf_decomposes_flags(self):
        self._assert_command_answer(
            "explain rm -rf /tmp/x",
            ("rm -rf /tmp/x", "recursive", "force", "/tmp/x"),
        )

    def test_grep_r_with_target(self):
        self._assert_command_answer(
            "what is grep -r foo",
            ("grep -r foo", "recursive", "foo"),
        )

    def test_netcat_offline_answer(self):
        self._assert_command_answer(
            "tell me about the netcat command",
            ("netcat", "network"),
        )

    def test_kubectl_subcommand(self):
        self._assert_command_answer(
            "explain kubectl get pods",
            ("kubectl", "get", "pods"),
        )

    def test_uname_a_compound(self):
        self._assert_command_answer(
            "what is uname -a",
            ("uname -a", "kernel"),
        )

    def test_ip_a_compound(self):
        self._assert_command_answer(
            "what does the ip a command do",
            ("ip a", "addresses"),
        )

    def test_chmod_plus_x_with_target(self):
        self._assert_command_answer(
            "what does chmod +x script.sh do",
            ("chmod +x script.sh", "script.sh"),
        )

    def test_mkdir_p_compound(self):
        self._assert_command_answer(
            "what does mkdir -p do",
            ("mkdir -p", "parent"),
        )

    def test_docker_exec_subcommand(self):
        self._assert_command_answer(
            "what is docker exec",
            ("docker exec", "container"),
        )

    def test_apt_install_subcommand(self):
        self._assert_command_answer(
            "explain me apt install",
            ("apt install", "install"),
        )

    def test_briefly_returns_first_sentence(self):
        result = self.chatbot.answer_question("briefly explain awk")
        self.assertEqual(result["intent"], "COMMAND_EXPLANATION")
        self.assertLess(result["answer"].count(". "), 2)

    def test_kill_9_compound(self):
        self._assert_command_answer(
            "what is kill -9",
            ("kill -9", "SIGKILL"),
        )

    def test_history_c_compound_via_mean(self):
        self._assert_command_answer(
            "what does history -c mean",
            ("history -c", "anti-forensics"),
        )


class SSHKnowledgeFallbackTest(unittest.TestCase):
    """When Ollama is unavailable and the command is unknown, we still respond gracefully."""

    def setUp(self):
        self.db = SessionLocal()
        self.chatbot = ChatbotQueryService(self.db, llm_provider=None)

    def tearDown(self):
        self.db.close()

    def test_unknown_command_falls_through_to_llm_or_fallback(self):
        result = self.chatbot.answer_question("what is somecompletelyfakecmd_12345")
        # Intent should be an explanation-family value, not COMMAND_SEARCH.
        self.assertIn(
            result["intent"],
            ("COMMAND_EXPLANATION", "GENERAL_KNOWLEDGE"),
            msg=result,
        )


if __name__ == "__main__":
    unittest.main()
