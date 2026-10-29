from __future__ import annotations

from datetime import datetime, timezone
import logging
import os
import re
from typing import Any
from urllib.parse import urlparse

import httpx


logger = logging.getLogger(__name__)

BRAVE_SEARCH_URL = "https://api.search.brave.com/res/v1/web/search"
PUBLIC_INFORMATION_TERMS = re.compile(
    r"\b(world|worldwide|india|nokia|technology|tech|cybersecurity|cyber security|"
    r"security|artificial intelligence|ai|current affairs|news|developments|"
    r"conference|conferences|events|event|launch|launches|weather|vulnerabilities)\b",
    re.IGNORECASE,
)
PRIVATE_DATA_TERMS = re.compile(
    r"\b(session|ssh|warpgate|recording|command|commands|"
    r"username|password|credential|target host|database|audit log)\b",
    re.IGNORECASE,
)
UPCOMING_TERMS = re.compile(
    r"\b(upcoming|coming up|scheduled|next week|next month|next year|"
    r"will happen|will be held)\b",
    re.IGNORECASE,
)
CURRENT_TERMS = re.compile(
    r"\b(today|current|currently|latest|recent|recently|this week|"
    r"this month|what happened|developments|news)\b",
    re.IGNORECASE,
)
SESSION_ID_PATTERN = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


class LiveInformationError(RuntimeError):
    pass


class LiveInformationNotConfigured(LiveInformationError):
    pass


class BraveSearchProvider:
    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 8.0,
        client: Any = httpx,
    ):
        self._api_key = api_key if api_key is not None else os.getenv("BRAVE_SEARCH_API_KEY", "")
        self._timeout = timeout
        self._client = client

    def search(self, query: str, *, upcoming: bool = False) -> list[dict[str, str | None]]:
        if not self._api_key:
            raise LiveInformationNotConfigured(
                "Live search is not configured. Set BRAVE_SEARCH_API_KEY in the API environment."
            )

        search_query = query.strip()[:512]
        params: dict[str, Any] = {"q": search_query, "count": 8}
        if upcoming:
            search_query = (
                f"{search_query} official event schedule after "
                f"{datetime.now(timezone.utc).date().isoformat()}"
            )
            params["q"] = search_query
        else:
            query_lower = query.casefold()
            params["freshness"] = (
                "pd"
                if "today" in query_lower
                else "pw"
                if "this week" in query_lower
                else "pm"
            )
        try:
            response = self._client.get(
                BRAVE_SEARCH_URL,
                headers={"X-Subscription-Token": self._api_key, "Accept": "application/json"},
                params=params,
                timeout=self._timeout,
                follow_redirects=False,
            )
        except httpx.TimeoutException as exc:
            raise LiveInformationError("The live search provider timed out.") from exc
        except httpx.RequestError as exc:
            raise LiveInformationError("The live search provider is unavailable.") from exc

        if response.status_code in {401, 403}:
            raise LiveInformationError("The live search provider rejected its configured credentials.")
        if response.status_code != 200:
            raise LiveInformationError("The live search provider returned an error.")
        try:
            payload = response.json()
        except ValueError as exc:
            raise LiveInformationError("The live search provider returned invalid data.") from exc

        web_payload = payload.get("web") if isinstance(payload, dict) else None
        web_results = web_payload.get("results") if isinstance(web_payload, dict) else None
        if not isinstance(web_results, list):
            raise LiveInformationError("The live search provider returned invalid results.")

        sources: list[dict[str, str | None]] = []
        for result in web_results:
            if not isinstance(result, dict):
                continue
            title = result.get("title")
            url = result.get("url")
            description = result.get("description")
            if not isinstance(title, str) or not isinstance(url, str):
                continue
            try:
                parsed_url = urlparse(url)
            except ValueError:
                continue
            if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname or parsed_url.username:
                continue
            sources.append(
                {
                    "title": title[:300],
                    "url": url[:2048],
                    "description": description[:1200] if isinstance(description, str) else None,
                    "published_at": self._publication_date(result),
                }
            )
        return sources

    @staticmethod
    def _publication_date(result: dict[str, Any]) -> str | None:
        for field in ("page_age", "published_at", "date"):
            value = result.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()[:80]
        return None


def classify_live_information_intent(question: str) -> str | None:
    question = (question or "").strip()
    if (
        not question
        or PRIVATE_DATA_TERMS.search(question)
        or SESSION_ID_PATTERN.search(question)
        or not PUBLIC_INFORMATION_TERMS.search(question)
    ):
        return None
    if UPCOMING_TERMS.search(question):
        return "UPCOMING_EVENTS"
    if re.search(r"\bweather\b", question, re.IGNORECASE):
        return "CURRENT_WEATHER_OR_TIME"
    if CURRENT_TERMS.search(question):
        return "CURRENT_EVENTS"
    return None


class LiveInformationService:
    def __init__(self, search_provider: BraveSearchProvider | None = None, llm_provider=None):
        self._search = search_provider or BraveSearchProvider()
        self._llm_provider = llm_provider

    def answer_question(self, question: str, intent: str | None = None) -> dict[str, Any] | None:
        resolved_intent = intent or classify_live_information_intent(question)
        if resolved_intent is None:
            return None

        try:
            sources = self._search.search(
                question,
                upcoming=resolved_intent == "UPCOMING_EVENTS",
            )
        except LiveInformationNotConfigured as exc:
            return self._unavailable(resolved_intent, str(exc))
        except LiveInformationError as exc:
            logger.warning("Live information retrieval failed (%s)", type(exc).__name__)
            return self._unavailable(
                resolved_intent,
                "Live sources could not be retrieved right now. Please try again later.",
            )

        if not sources:
            return {
                "answer": "The live search completed but returned no usable sources for this question.",
                "intent": resolved_intent,
                "retrieval_mode": "rule-based",
                "evidence_available": False,
                "evidence_summary": "No usable public information sources were returned.",
                "sources": [],
            }

        evidence = {
            "source": "live public web search",
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "upcoming_events": resolved_intent == "UPCOMING_EVENTS",
            "results": sources,
        }
        answer = self._generate_answer(question, resolved_intent, evidence)
        retrieval_mode = "rule-based"
        if answer:
            retrieval_mode = "llm"
        else:
            answer = self._format_source_summaries(sources)

        return {
            "answer": answer,
            "intent": resolved_intent,
            "retrieval_mode": retrieval_mode,
            "evidence_available": True,
            "evidence_summary": f"Retrieved {len(sources)} public search result(s) at request time.",
            "sources": [
                {
                    "title": source["title"],
                    "url": source["url"],
                    "published_at": source["published_at"],
                }
                for source in sources
            ],
        }

    def _generate_answer(
        self,
        question: str,
        intent: str,
        evidence: dict[str, Any],
    ) -> str | None:
        if self._llm_provider is None:
            from app.services.llm.ollama_provider import OllamaProvider

            provider = OllamaProvider()
        else:
            provider = self._llm_provider
        try:
            return provider.generate(question, intent, evidence)
        except Exception as exc:
            logger.warning("Live information synthesis failed (%s)", type(exc).__name__)
            return None

    @staticmethod
    def _format_source_summaries(sources: list[dict[str, str | None]]) -> str:
        lines = ["I found these live results; use the linked sources to verify the details:"]
        for source in sources[:5]:
            description = source.get("description")
            if description:
                lines.append(f"- {description}")
        return "\n".join(lines)

    @staticmethod
    def _unavailable(intent: str, message: str) -> dict[str, Any]:
        return {
            "answer": message,
            "intent": intent,
            "retrieval_mode": "rule-based",
            "evidence_available": False,
            "evidence_summary": "No live public information was retrieved.",
            "sources": [],
        }
