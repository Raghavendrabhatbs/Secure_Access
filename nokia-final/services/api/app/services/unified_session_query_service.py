from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import re
from typing import Any

from app.core.assistant_auth import AssistantUser
from app.services.query_understanding_service import (
    configured_today,
    extract_date_range,
)
from app.services.session_query_service import SessionQueryService
from app.services.web_session_query_service import WebSessionQueryService


SESSION_WORDS = re.compile(r"\bsessions?\b", re.IGNORECASE)
SESSION_ID = re.compile(
    r"\b(?:session-[A-Za-z0-9_-]{8,120}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b",
    re.IGNORECASE,
)
COMMAND_SEARCH = re.compile(
    r"\b(?:which|find|show)\s+sessions?\s+(?:that\s+)?(?:executed|ran|used|contained)\b",
    re.IGNORECASE,
)
SCHEDULED_SESSION = re.compile(
    r"\b(?:scheduled|planned|expected|forecast)\b|\b(?:sessions?)\s+(?:for|on)\s+(?:tomorrow|next week|next month)\b",
    re.IGNORECASE,
)
COUNT_QUESTION = re.compile(
    r"\b(?:how many|count|number of|total number)\b",
    re.IGNORECASE,
)
ACTIVE_QUESTION = re.compile(
    r"\b(?:currently active|active sessions?|online now|logged in now|still connected)\b",
    re.IGNORECASE,
)
RECORDING_QUESTION = re.compile(
    r"\b(?:have|has|with|without)\s+(?:a\s+)?recordings?\b|"
    r"\b(?:do not|don't)\s+have\s+(?:a\s+)?recordings?\b|"
    r"\brecording availability\b",
    re.IGNORECASE,
)
PAGE_QUESTION = re.compile(r"\bpage\s+(\d{1,6})\b", re.IGNORECASE)
DATE_OR_SCOPE = re.compile(
    r"\b(?:today|yesterday|tomorrow|this week|last week|previous week|"
    r"this month|last month|previous month|historical|history|"
    r"till now|until now|up to now|so far|between|since|until|through|"
    r"all time|all sessions|all ssh|all web)\b",
    re.IGNORECASE,
)
SESSION_OVERVIEW_ACTION = re.compile(
    r"\b(?:show|list|display|what|which|how many|count|total|occurred|"
    r"happened|recorded|performed|captured|accessed|sessions?)\b",
    re.IGNORECASE,
)
NON_OVERVIEW = re.compile(
    r"\b(?:command|commands|event|events|timeline|risk|risky|anomal(?:y|ous)|"
    r"suspicious|summarize|summary|details?|explain|executed|ran)\b",
    re.IGNORECASE,
)


class UnifiedSessionQueryService:
    PAGE_SIZE = 25

    def __init__(
        self,
        ssh_sessions: SessionQueryService,
        web_sessions: WebSessionQueryService,
    ):
        self._ssh_sessions = ssh_sessions
        self._web_sessions = web_sessions

    @classmethod
    def should_answer(cls, question: str) -> bool:
        normalized = (question or "").strip()
        if not SESSION_WORDS.search(normalized) or SESSION_ID.search(normalized):
            return False
        if SCHEDULED_SESSION.search(normalized):
            return True
        if re.search(r"\b(?:web|browser|http)\b", normalized, re.IGNORECASE) and not re.search(
            r"\bssh\b",
            normalized,
            re.IGNORECASE,
        ):
            return False
        if (
            re.search(r"\bsession\b", normalized, re.IGNORECASE)
            and not re.search(r"\bsessions\b", normalized, re.IGNORECASE)
            and not COUNT_QUESTION.search(normalized)
            and not ACTIVE_QUESTION.search(normalized)
            and not DATE_OR_SCOPE.search(normalized)
        ):
            return False
        if COMMAND_SEARCH.search(normalized) or NON_OVERVIEW.search(normalized):
            return False
        if not SESSION_OVERVIEW_ACTION.search(normalized):
            return False
        return bool(
            COUNT_QUESTION.search(normalized)
            or ACTIVE_QUESTION.search(normalized)
            or RECORDING_QUESTION.search(normalized)
            or DATE_OR_SCOPE.search(normalized)
            or re.search(r"\b(?:ssh|web|browser|user|username|target|host)\b", normalized, re.I)
            or re.search(r"\b(?:show|list|display|what|which|occurred|happened|recorded|performed|captured)\b", normalized, re.I)
        )

    @staticmethod
    def _started_at(value: Any) -> datetime | None:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None
        else:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _filters(question: str) -> tuple[str | None, str | None, str | None]:
        username_match = re.search(
            r"\b(?:user|username)\s+([a-z0-9_.-]{1,128})\b|"
            r"\b(?:by|for)\s+(?!today\b|yesterday\b|tomorrow\b|this\b|last\b|"
            r"previous\b|all\b|ssh\b|web\b|browser\b)([a-z0-9_.-]{1,128})\b",
            question,
            re.IGNORECASE,
        )
        username = None
        if username_match:
            username = next(
                (value for value in username_match.groups() if value),
                None,
            )
        target_match = re.search(
            r"\b(?:target|host)\s+([a-z0-9_.-]{1,256})\b",
            question,
            re.IGNORECASE,
        )
        normalized = question.casefold()
        if re.search(r"\bssh\b", normalized) and not re.search(r"\b(?:web|browser)\b", normalized):
            protocol = "SSH"
        elif re.search(r"\b(?:web|browser|http)\b", normalized) and not re.search(r"\bssh\b", normalized):
            protocol = "WEB"
        else:
            protocol = None
        return username, target_match.group(1) if target_match else None, protocol

    @staticmethod
    def _scheduled_source_unavailable() -> dict[str, Any]:
        return {
            "answer": (
                "I can't confirm scheduled or planned future sessions: the available "
                "session sources contain recorded activity, not a scheduled-session register."
            ),
            "intent": "SESSION_LIST",
            "retrieval_mode": "rule-based",
            "evidence_available": False,
            "evidence_summary": "No reliable scheduled-session data source is configured.",
            "conversation_entities": {"sessions": []},
        }

    def answer_question(self, question: str, user: AssistantUser) -> dict[str, Any]:
        normalized = (question or "").strip()
        if SCHEDULED_SESSION.search(normalized):
            return self._scheduled_source_unavailable()

        if (
            re.search(r"\bcompare\b|\bversus\b|\bvs\.?\b", normalized, re.IGNORECASE)
            and re.search(r"\btoday\b", normalized, re.IGNORECASE)
            and re.search(r"\byesterday\b", normalized, re.IGNORECASE)
        ):
            username, target, protocol = self._filters(normalized)
            if user.role == "developer":
                username = user.username
            today = configured_today()
            today_count = self._count_range(
                today,
                today,
                username=username,
                target=target,
                protocol=protocol,
            )
            yesterday = today - timedelta(days=1)
            yesterday_count = self._count_range(
                yesterday,
                yesterday,
                username=username,
                target=target,
                protocol=protocol,
            )
            return {
                "answer": (
                    f"Recorded sessions today ({today.isoformat()}): {today_count}. "
                    f"Yesterday ({yesterday.isoformat()}): {yesterday_count}."
                ),
                "intent": "SESSION_STATS",
                "retrieval_mode": "rule-based",
                "evidence_available": True,
                "evidence_summary": "Compared timestamp-filtered counts from available SSH and Web sources.",
                "conversation_entities": {"sessions": []},
            }

        date_range = extract_date_range(normalized)
        today = configured_today()
        if date_range and date_range[0] > today:
            return {
                "answer": (
                    f"No recorded sessions are available for {date_range[0].isoformat()} "
                    "or later. Scheduled future sessions cannot be verified because no "
                    "scheduled-session source is configured."
                ),
                "intent": "SESSION_LIST",
                "retrieval_mode": "rule-based",
                "evidence_available": True,
                "evidence_summary": "Queried recorded-session sources; future schedules are not available.",
                "conversation_entities": {"sessions": []},
            }

        username, target, protocol = self._filters(normalized)
        if user.role == "developer":
            username = user.username
        start_date, end_date = date_range if date_range else (None, None)
        now = datetime.now(timezone.utc)
        active_question = bool(ACTIVE_QUESTION.search(normalized))
        recording_match = RECORDING_QUESTION.search(normalized)
        has_recording = None
        if recording_match:
            has_recording = not bool(
                re.search(r"\b(?:without|do not|don't)\b", normalized, re.IGNORECASE)
            )
        page_match = PAGE_QUESTION.search(normalized)
        page = max(1, int(page_match.group(1))) if page_match else 1
        offset = (page - 1) * self.PAGE_SIZE

        ssh_items: list[Any] = []
        ssh_total = 0
        if protocol != "WEB":
            ssh_items, ssh_total = self._ssh_sessions.query_sessions(
                limit=self.PAGE_SIZE,
                offset=offset,
                username=username,
                target=target,
                protocol="SSH",
                start_date=start_date,
                end_date=end_date,
                active=True if active_question else None,
                has_recording=has_recording,
                occurred_before=now,
            )

        web_items: list[dict[str, Any]] = []
        web_total = 0
        web_status_unavailable = active_question and protocol != "SSH"
        if protocol != "SSH" and not active_question:
            web_listing = self._web_sessions.list_sessions(
                limit=self.PAGE_SIZE,
                offset=offset,
                username=username,
                target=target,
                start_date=start_date,
                end_date=end_date,
                has_recording=has_recording,
                occurred_before=now,
            )
            web_items = web_listing["items"]
            web_total = web_listing["total"]

        records: list[dict[str, Any]] = []
        for session in ssh_items:
            started_at = session.started_at or session.login_time
            ended_at = getattr(session, "ended_at", None) or getattr(session, "logout_time", None)
            records.append(
                {
                    "session_id": session.session_id or session.unique_id,
                    "username": session.username or "unknown",
                    "target": session.target or "unknown",
                    "started_at": started_at.isoformat() if started_at else None,
                    "ended_at": ended_at.isoformat() if ended_at else None,
                    "protocol": "SSH",
                    "remote_address": getattr(session, "remote_address", None),
                    "total_commands": getattr(session, "total_commands", None),
                    "recording": bool(
                        getattr(session, "recording_id", None)
                        or getattr(session, "recording_path", None)
                    ),
                    "risk": getattr(session, "risk", None),
                }
            )
        for item in web_items:
            records.append(
                {
                    "session_id": item.get("sessionId") or "unknown",
                    "username": item.get("username") or "unknown",
                    "target": item.get("target") or "unknown",
                    "started_at": item.get("startedAt"),
                    "protocol": "WEB",
                    "event_count": item.get("eventCount"),
                    "recording": WebSessionQueryService._recording_available(item),
                }
            )
        records.sort(
            key=lambda item: self._started_at(item["started_at"])
            or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

        total = ssh_total + web_total
        is_count = bool(COUNT_QUESTION.search(normalized))
        if is_count:
            answer = (
                f"Found {ssh_total} SSH session(s) and {web_total} web session(s) "
                f"({total} total) in the requested scope."
            )
            intent = "SESSION_COUNT"
        elif not records:
            if active_question:
                answer = "No SSH sessions with a current start lifecycle event and no end event were found."
            elif has_recording is True:
                answer = "No SSH or web sessions with confirmed recording metadata were found in the requested scope."
            else:
                answer = "No recorded SSH or web sessions were found in the requested scope."
            intent = "SESSION_LIST"
        else:
            query_kind = "active session" if active_question else "session"
            lines = [
                f"Found {ssh_total} SSH and {web_total} web {query_kind}(s) in the requested scope "
                f"({total} total). Showing page {page}:"
            ]
            for record in records:
                line = (
                    f"- [{record['protocol']}] `{record['session_id']}` | "
                    f"user: {record['username']} | target: {record['target']} | "
                    f"started: {record['started_at'] or 'unknown'}"
                )
                if record["protocol"] == "SSH":
                    if record.get("ended_at"):
                        line += f" | ended: {record['ended_at']}"
                    line += (
                        f" | commands: {record['total_commands'] if record['total_commands'] is not None else 'unknown'}"
                        f" | recording: {'available' if record['recording'] else 'not recorded'}"
                    )
                    if record.get("remote_address"):
                        line += f" | remote: {record['remote_address']}"
                else:
                    line += (
                        f" | events: {record['event_count'] if record['event_count'] is not None else 'unknown'}"
                        f" | recording: {record['recording'] if record['recording'] is not None else 'status unavailable'}"
                    )
                lines.append(line)
            if total > page * self.PAGE_SIZE:
                lines.append(
                    f"More results are available. Ask for page {page + 1} to continue."
                )
            answer = "\n".join(lines)
            intent = "SESSION_LIST"
        if web_status_unavailable:
            answer += (
                "\nThe Web metadata source does not expose a reliable active-session "
                "lifecycle status, so Web sessions are not classified as active."
            )

        return {
            "answer": answer,
            "intent": intent,
            "retrieval_mode": "rule-based",
            "evidence_available": True,
            "evidence_summary": (
                f"Queried PostgreSQL logical SSH sessions ({ssh_total}) and authenticated "
                f"Warpgate Web recording metadata ({web_total}); records after the current "
                "time were excluded."
            ),
            "conversation_entities": {
                "sessions": [
                    {"session_id": item["session_id"], "protocol": item["protocol"]}
                    for item in records
                ]
            },
        }

    def _count_range(
        self,
        start_date: date,
        end_date: date,
        *,
        username: str | None,
        target: str | None,
        protocol: str | None,
    ) -> int:
        now = datetime.now(timezone.utc)
        total = 0
        if protocol != "WEB":
            _, ssh_count = self._ssh_sessions.query_sessions(
                limit=1,
                offset=0,
                username=username,
                target=target,
                protocol="SSH",
                start_date=start_date,
                end_date=end_date,
                occurred_before=now,
            )
            total += ssh_count
        if protocol != "SSH":
            web_count = self._web_sessions.list_sessions(
                limit=1,
                offset=0,
                username=username,
                target=target,
                start_date=start_date,
                end_date=end_date,
                occurred_before=now,
            )["total"]
            total += web_count
        return total
