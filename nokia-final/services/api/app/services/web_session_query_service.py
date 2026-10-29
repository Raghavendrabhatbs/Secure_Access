from __future__ import annotations

from datetime import date, datetime, timezone
import os
import re
from http.cookies import SimpleCookie
from typing import Any

import httpx

from app.core.config import settings
from app.services.query_understanding_service import date_range_utc_bounds, extract_date_range


class WebSessionQueryError(RuntimeError):
    pass


class WebSessionAccessDenied(WebSessionQueryError):
    pass


class WebSessionNotFound(WebSessionQueryError):
    pass


class WebSessionQueryService:
    WEB_QUERY_PATTERN = re.compile(
        r"\bweb[ -]sessions?\b|\bbrowser[ -]sessions?\b|\brrweb\b|\bpage visits?\b|\bweb recordings?\b",
        re.IGNORECASE,
    )

    def __init__(
        self,
        cookie_header: str,
        warpgate_url: str | None = None,
        ca_bundle: str | None = None,
        timeout: float = 8.0,
    ):
        self._base_url = (warpgate_url or os.getenv("WARPGATE_URL") or settings.warpgate_url).rstrip("/")
        self._verify: bool | str = (
            ca_bundle
            or os.getenv("WARPGATE_CA_BUNDLE")
            or settings.warpgate_ca_bundle
            or True
        )
        self._timeout = timeout
        cookies = SimpleCookie()
        cookies.load(cookie_header or "")
        session_cookie = cookies.get("warpgate-http-session")
        self._cookie = session_cookie.OutputString() if session_cookie else None

    def _get_json(self, path: str) -> Any:
        if not self._cookie:
            raise WebSessionAccessDenied("Authentication required.")
        if not self._base_url:
            raise WebSessionQueryError("Web session service is unavailable.")
        try:
            response = httpx.get(
                f"{self._base_url}/@warpgate/rrweb/api/{path.lstrip('/')}",
                headers={"Cookie": self._cookie},
                timeout=self._timeout,
                verify=self._verify,
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            raise WebSessionQueryError("Web session service is unavailable.") from exc

        if response.status_code in {401, 403}:
            raise WebSessionAccessDenied("Web session access is not permitted.")
        if response.status_code == 404:
            raise WebSessionNotFound("Web recording was not found.")
        if response.status_code != 200:
            raise WebSessionQueryError("Web session service returned an error.")
        try:
            return response.json()
        except ValueError as exc:
            raise WebSessionQueryError("Web session service returned invalid data.") from exc

    @staticmethod
    def _safe_session(record: dict[str, Any]) -> dict[str, Any]:
        fields = (
            "sessionId",
            "username",
            "target",
            "startedAt",
            "lastSeenAt",
            "firstPageUrl",
            "lastPageUrl",
            "eventCount",
            "durationMs",
            "recordingStatus",
            "recordingFinalized",
            "hasRecording",
            "warpgateSessionId",
            "lastFailure",
            "recordingFailures",
        )
        safe = {field: record.get(field) for field in fields if field in record}
        targets = record.get("targets")
        if isinstance(targets, list):
            safe["targets"] = [value for value in targets[:10] if isinstance(value, str)]
        visits = record.get("pageVisits")
        if isinstance(visits, list):
            safe["pageVisits"] = [
                {
                    key: visit[key]
                    for key in ("url", "timestamp", "target")
                    if isinstance(visit.get(key), str)
                }
                for visit in visits[-20:]
                if isinstance(visit, dict)
            ]
        return safe

    @classmethod
    def is_web_session_question(cls, question: str, session_id: str | None = None) -> bool:
        return bool(
            cls.WEB_QUERY_PATTERN.search(question or "")
            or (session_id and re.fullmatch(r"session-[A-Za-z0-9_-]{8,120}", session_id))
        )

    @staticmethod
    def _is_count_question(question: str) -> bool:
        normalized = question.casefold()
        return any(
            phrase in normalized
            for phrase in ("how many", "count", "total number", "number of")
        )

    @staticmethod
    def _is_listing_question(question: str) -> bool:
        normalized = question.casefold()
        return any(
            phrase in normalized
            for phrase in ("show", "list", "which", "all", "recent", "latest")
        )

    def answer_question(
        self,
        question: str,
        session_id: str | None = None,
        username_scope: str | None = None,
    ) -> dict[str, Any]:
        requested_id = session_id
        if not requested_id:
            match = re.search(r"\bsession-[A-Za-z0-9_-]{1,120}\b", question or "")
            requested_id = match.group(0) if match else None

        if requested_id and requested_id.startswith("session-"):
            record = self.get_session(requested_id)
            if (
                username_scope
                and str(record.get("username") or "").casefold() != username_scope.casefold()
            ):
                raise WebSessionNotFound("Web recording was not found.")
            records = [record]
            intent = "RECORDING_SEARCH" if re.search(r"\b(?:recordings?|replay|rrweb)\b", question, re.IGNORECASE) else "SESSION_LOOKUP"
            evidence_summary = "Retrieved authorized Web recording metadata."
        else:
            date_range = extract_date_range(question)
            normalized_question = (question or "").casefold()
            username_match = re.search(
                r"\buser(?:name)?\s+([A-Za-z0-9_.-]{1,128})\b",
                question or "",
                re.IGNORECASE,
            )
            target_match = re.search(
                r"\b(?:target|host)\s+([A-Za-z0-9_.-]{1,256})\b",
                question or "",
                re.IGNORECASE,
            )
            page_match = re.search(r"\bpage\s+(\d{1,6})\b", question or "", re.IGNORECASE)
            page = max(1, int(page_match.group(1))) if page_match else 1
            has_recording = None
            if re.search(r"\b(?:have|has|with|without)\s+(?:a\s+)?recordings?\b", normalized_question):
                has_recording = not bool(
                    re.search(r"\b(?:without|do not|don't)\b", normalized_question)
                )
            listing = self.list_sessions(
                limit=25,
                offset=(page - 1) * 25,
                username=username_scope or (username_match.group(1) if username_match else None),
                target=target_match.group(1) if target_match else None,
                start_date=date_range[0] if date_range else None,
                end_date=date_range[1] if date_range else None,
                has_recording=has_recording,
                occurred_before=datetime.now(timezone.utc),
            )
            records = listing["items"]
            total = listing["total"]
            if self._is_count_question(question):
                return {
                    "answer": f"There are {total} distinct Web recording session(s) visible to your account.",
                    "intent": "SESSION_COUNT",
                    "retrieval_mode": "rule-based",
                    "evidence_available": True,
                    "evidence_summary": "Counted authorized Web recording metadata records.",
                    "conversation_entities": {"sessions": []},
                }
            intent = (
                "RECORDING_SEARCH"
                if re.search(r"\b(?:recordings?|replay|rrweb)\b", question, re.IGNORECASE)
                else "SESSION_SEARCH"
            )
            evidence_summary = (
                f"Retrieved {len(records)} of {total} authorized Web recording metadata records."
            )

        if self._is_listing_question(question) and not requested_id:
            lines = [
                f"Found {total} authorized Web recording session(s). "
                f"Showing page {page} ({len(records)} session(s)):"
            ]
            for record in records:
                lines.append(
                    "- {sessionId}: user {username}; target {target}; started {startedAt}; "
                    "recording {status}; {events} event(s)".format(
                        sessionId=record.get("sessionId", "unknown ID"),
                        username=record.get("username", "unknown"),
                        target=record.get("target", "unknown"),
                        startedAt=record.get("startedAt", "unknown time"),
                        status=record.get("recordingStatus", "status unavailable"),
                        events=record.get("eventCount", "unknown count"),
                    )
                )
            if total > page * 25:
                lines.append(f"More results are available. Ask for page {page + 1} to continue.")
            return {
                "answer": "\n".join(lines),
                "intent": intent,
                "retrieval_mode": "rule-based",
                "evidence_available": True,
                "evidence_summary": evidence_summary,
                "conversation_entities": {
                    "sessions": [{"session_id": item.get("sessionId"), "protocol": "WEB"} for item in records],
                },
            }

        if not records:
            return {
                "answer": "No Web recording metadata is available to your account for this query.",
                "intent": intent,
                "retrieval_mode": "rule-based",
                "evidence_available": True,
                "evidence_summary": "The authorized Web recording query completed with no matching records.",
                "conversation_entities": {"sessions": []},
            }

        evidence = {
            "source": "authorized rrweb recording metadata",
            "protocol": "WEB",
            "records": records[:8],
            "record_count": len(records),
            "risk_findings": "not present in the rrweb metadata source",
            "event_payloads": "not retrieved by this assistant query",
        }
        retrieval_mode = "rule-based"
        try:
            from app.services.llm.ollama_provider import OllamaProvider

            answer = OllamaProvider().generate(question, "GROUNDED_ANALYSIS", evidence)
            if answer:
                retrieval_mode = "llm"
        except Exception:
            answer = None
        if not answer:
            record = records[0]
            pages = record.get("pageVisits", [])
            page_summary = "; ".join(
                visit.get("url", "") for visit in pages if visit.get("url")
            ) or "page-visit details are unavailable"
            answer = (
                f"Web recording {record.get('sessionId', 'unknown ID')} belongs to "
                f"{record.get('username', 'unknown')} on target {record.get('target', 'unknown')}. "
                f"It contains {record.get('eventCount', 'an unknown number of')} recorded event(s); "
                f"captured page visits: {page_summary}."
            )
        return {
            "answer": answer,
            "intent": intent,
            "retrieval_mode": retrieval_mode,
            "evidence_available": bool(records),
            "evidence_summary": evidence_summary,
            "session_id": records[0].get("sessionId") if len(records) == 1 else None,
            "conversation_entities": {
                "sessions": [{"session_id": item.get("sessionId"), "protocol": "WEB"} for item in records[:10]],
            },
        }

    @staticmethod
    def _is_in_date_range(record: dict[str, Any], start_date: date | None, end_date: date | None) -> bool:
        if start_date is None and end_date is None:
            return True
        value = record.get("startedAt")
        if not isinstance(value, str):
            return False
        try:
            started_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        lower, upper = (
            date_range_utc_bounds(start_date, end_date)
            if start_date is not None and end_date is not None
            else (None, None)
        )
        if start_date is not None and lower is None:
            lower = date_range_utc_bounds(start_date, start_date)[0]
        if end_date is not None and upper is None:
            upper = date_range_utc_bounds(end_date, end_date)[1]
        return (lower is None or started_at >= lower) and (upper is None or started_at < upper)

    @staticmethod
    def _recording_available(record: dict[str, Any]) -> bool | None:
        has_recording = record.get("hasRecording")
        if isinstance(has_recording, bool):
            return has_recording
        status = record.get("recordingStatus")
        if isinstance(status, str):
            normalized = status.casefold()
            if normalized in {"available", "recording", "finalized", "complete", "completed"}:
                return True
            if normalized in {"missing", "failed", "unavailable", "none"}:
                return False
        return None

    @staticmethod
    def _started_at_utc(record: dict[str, Any]) -> datetime | None:
        value = record.get("startedAt")
        if not isinstance(value, str):
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def list_sessions(
        self,
        *,
        limit: int = 25,
        offset: int = 0,
        username: str | None = None,
        target: str | None = None,
        start_date: date | None = None,
        end_date: date | None = None,
        has_recording: bool | None = None,
        occurred_before: datetime | None = None,
    ) -> dict[str, Any]:
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError("Invalid web session page bounds.")
        records = self._get_json("sessions")
        if not isinstance(records, list):
            raise WebSessionQueryError("Web session service returned invalid data.")

        filtered = [record for record in records if isinstance(record, dict)]
        if username:
            filtered = [record for record in filtered if str(record.get("username", "")).casefold() == username.casefold()]
        if target:
            filtered = [record for record in filtered if target.casefold() in str(record.get("target", "")).casefold()]
        filtered = [
            record for record in filtered
            if self._is_in_date_range(record, start_date, end_date)
        ]
        if has_recording is not None:
            filtered = [
                record
                for record in filtered
                if self._recording_available(record) is has_recording
            ]
        if occurred_before is not None:
            cutoff = occurred_before
            if cutoff.tzinfo is None:
                cutoff = cutoff.replace(tzinfo=timezone.utc)
            cutoff = cutoff.astimezone(timezone.utc)
            filtered = [
                record
                for record in filtered
                if (started := self._started_at_utc(record)) is None or started <= cutoff
            ]
        filtered.sort(
            key=lambda record: self._started_at_utc(record) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        return {
            "protocol": "WEB",
            "items": [self._safe_session(record) for record in filtered[offset : offset + limit]],
            "total": len(filtered),
            "limit": limit,
            "offset": offset,
        }

    def get_session(self, session_id: str) -> dict[str, Any]:
        if not re.fullmatch(r"session-[A-Za-z0-9_-]{8,120}", session_id or ""):
            raise ValueError("Invalid web recording ID.")
        metadata = self._get_json(f"session-metadata/{session_id}")
        if not isinstance(metadata, dict) or metadata.get("sessionId") != session_id:
            raise WebSessionQueryError("Web session service returned invalid data.")
        return self._safe_session(metadata)