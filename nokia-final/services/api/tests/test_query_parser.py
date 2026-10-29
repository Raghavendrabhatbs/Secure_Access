import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.query_parser import extract_search_terms


class QueryParserTest(unittest.TestCase):
    def test_single_term(self):
        self.assertEqual(
            extract_search_terms("Which sessions used sudo?"),
            ["sudo"],
        )

    def test_multiple_terms(self):
        self.assertEqual(
            extract_search_terms(
                "Which sessions used sudo to modify passwd?"
            ),
            ["sudo", "passwd"],
        )

    def test_path_and_command(self):
        self.assertEqual(
            extract_search_terms(
                "Show commands using chmod and /etc/passwd"
            ),
            ["chmod", "/etc/passwd"],
        )

    def test_duplicate_terms_are_removed(self):
        self.assertEqual(
            extract_search_terms(
                "sudo sudo passwd passwd"
            ),
            ["sudo", "passwd"],
        )

    def test_empty_question(self):
        self.assertEqual(
            extract_search_terms(""),
            [],
        )

    def test_no_useful_terms_returns_empty_list(self):
        self.assertEqual(
            extract_search_terms("show me everything"),
            [],
        )

    def test_timeline_question_does_not_expand_into_search(self):
        self.assertEqual(
            extract_search_terms("What happened in this session?"),
            [],
        )


if __name__ == "__main__":
    unittest.main()