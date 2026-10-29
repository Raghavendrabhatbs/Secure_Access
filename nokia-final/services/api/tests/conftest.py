"""Ensures the entire integration test suite runs against a dedicated,
deterministic test database (nokia_ssh_test) instead of the live development
database (nokia_ssh).

This module MUST set the POSTGRES_DB environment variable before any test
module imports app.core.config / app.db.database, since Settings() is
constructed once at import time. Pytest guarantees conftest.py in this
directory is imported before any test_*.py file within it, so this works
without needing per-test changes.

Run `python tests/seed_test_fixtures.py` (with POSTGRES_DB=nokia_ssh_test)
once to (re)create the deterministic fixture data this suite depends on.
"""
import os

os.environ["POSTGRES_DB"] = "nokia_ssh_test"
