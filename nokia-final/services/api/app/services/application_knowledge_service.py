from __future__ import annotations

from pathlib import Path
import re
from typing import Any


class ApplicationKnowledgeService:
    MAX_CONTEXT_CHARS = 7000
    APPLICATION_TERMS = re.compile(
        r"\b(secure\s*access|nokia|architecture|web\s+session|"
        r"recording\s+pipeline|assistant\s+service|project|what\s+can\s+you\s+do|"
        r"your\s+capabilities)\b",
        re.IGNORECASE,
    )

    def __init__(self, project_root: Path | None = None):
        self._project_root = project_root or Path(__file__).resolve().parents[4]

    @classmethod
    def is_application_question(cls, question: str) -> bool:
        return bool(cls.APPLICATION_TERMS.search(question or ""))

    @staticmethod
    def _section(path: Path, heading: str) -> str | None:
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            return None
        lines = content.splitlines()
        start = next(
            (index for index, line in enumerate(lines) if line.strip() == heading),
            None,
        )
        if start is None:
            return None
        level = len(heading) - len(heading.lstrip("#"))
        body: list[str] = []
        for line in lines[start + 1 :]:
            if line.startswith("#"):
                next_level = len(line) - len(line.lstrip("#"))
                if next_level <= level:
                    break
            body.append(line)
        excerpt = "\n".join(body).strip()
        return excerpt or None

    def context_for(self, question: str) -> dict[str, Any] | None:
        if not self.APPLICATION_TERMS.search(question or ""):
            return None

        docs: list[dict[str, str]] = []
        setup = self._project_root / "SETUP_GUIDE.md"
        readme = self._project_root / "README.md"
        sections = (
            (setup, "## Architecture"),
            (setup, "### 2.1 What runs"),
        )
        if re.search(r"\b(web|browser|rrweb|recording)\b", question, re.IGNORECASE):
            sections += (
                (self._project_root.parent / "rrweb" / "README.md", "## Recording persistence"),
                (self._project_root.parent / "rrweb" / "README.md", "## Recording continuity and navigation"),
            )
        for path, heading in sections:
            excerpt = self._section(path, heading)
            if excerpt:
                docs.append({"_path": path, "section": heading.lstrip("# "), "text": excerpt})
        if not docs:
            try:
                excerpt = "\n".join(readme.read_text(encoding="utf-8").splitlines()[:35]).strip()
            except OSError:
                excerpt = ""
            if excerpt:
                docs.append({"_path": readme, "section": "project overview", "text": excerpt})
        if not docs:
            return None

        remaining = self.MAX_CONTEXT_CHARS
        bounded_docs = []
        for doc in docs:
            if remaining <= 0:
                break
            bounded_text = doc["text"][:remaining]
            doc_path = doc.pop("_path")
            relative_path = doc_path.resolve().relative_to(self._project_root.parent.resolve())
            bounded_docs.append({**doc, "path": relative_path.as_posix(), "text": bounded_text})
            remaining -= len(bounded_text)
        return {"source": "repository documentation", "documents": bounded_docs}
