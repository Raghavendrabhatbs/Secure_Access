from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, question: str, intent: str, evidence: dict[str, Any]) -> str | None:
        raise NotImplementedError