from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.config import Settings
from backend.security import AssistantIdentity
from backend.secure_access_client import DataSourceError, SecureAccessClient
from backend.time_ranges import date_range_from_question, time_bounds_from_question


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ListSessionsArguments(ToolArguments):
    protocol: str = Field(default="all", pattern="^(all|ssh|web)$")
    username: str | None = Field(default=None, max_length=128)
    target: str | None = Field(default=None, max_length=256)
    start_date: date | None = None
    end_date: date | None = None
    limit: int = Field(default=25, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=100000)
    active_only: bool = False

    @field_validator("start_date", "end_date", mode="before")
    @classmethod
    def normalize_datetime_date_bound(cls, value: Any) -> Any:
        return _date_only(value)

    @model_validator(mode="after")
    def validate_dates(self):
        if self.start_date and self.end_date and self.start_date > self.end_date:
            raise ValueError("start_date must be before or equal to end_date")
        return self


class SessionIdArguments(ToolArguments):
    session_id: str = Field(min_length=1, max_length=255)


class SessionCommandsArguments(SessionIdArguments):
    limit: int = Field(default=5, ge=1, le=25)
    offset: int = Field(default=0, ge=0, le=100000)
    output_offset: int = Field(default=0, ge=0, le=10000000)
    output_limit: int = Field(default=4000, ge=1, le=4000)


class CommandArchiveArguments(ToolArguments):
    search: str | None = Field(default=None, min_length=1, max_length=200)
    risky_only: bool = False
    limit: int = Field(default=25, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=100000)
    session_limit: int = Field(default=25, ge=1, le=100)
    session_offset: int = Field(default=0, ge=0, le=100000)

class AnalyzeWebRecordingsArguments(ToolArguments):
    start_date: date | None = None
    end_date: date | None = None
    limit: int = Field(default=10, ge=1, le=10)
    offset: int = Field(default=0, ge=0, le=10000)

    @field_validator("start_date", "end_date", mode="before")
    @classmethod
    def normalize_datetime_date_bound(cls, value: Any) -> Any:
        return _date_only(value)

    @model_validator(mode="after")
    def validate_dates(self):
        if self.start_date and self.end_date and self.start_date > self.end_date:
            raise ValueError("start_date must be before or equal to end_date")
        return self


class IncidentArguments(ToolArguments):
    username: str | None = Field(default=None, max_length=128)
    start_date: date | None = None
    end_date: date | None = None
    limit: int = Field(default=25, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=100000)

    @field_validator("start_date", "end_date", mode="before")
    @classmethod
    def normalize_datetime_date_bound(cls, value: Any) -> Any:
        return _date_only(value)

    @model_validator(mode="after")
    def validate_dates(self):
        if self.start_date and self.end_date and self.start_date > self.end_date:
            raise ValueError("start_date must be before or equal to end_date")
        return self


class AuditLogArguments(ToolArguments):
    search: str | None = Field(default=None, max_length=200)
    limit: int = Field(default=500, ge=1, le=500)


def _date_only(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str) and "T" in value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
        except ValueError:
            return value
    return value


TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "get_session_counts",
            "description": "Count persisted, deduplicated SSH and/or Web sessions in an optional scope.",
            "parameters": {
                "type": "object",
                "properties": {
                    "protocol": {"type": "string", "enum": ["all", "ssh", "web"], "default": "all"},
                    "username": {"type": ["string", "null"]},
                    "target": {"type": ["string", "null"]},
                    "start_date": {"type": ["string", "null"], "description": "Inclusive ISO date"},
                    "end_date": {"type": ["string", "null"], "description": "Inclusive ISO date"},
                    "active_only": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_sessions",
            "description": "List current or historical SSH/Web sessions from the live data sources.",
            "parameters": {
                "type": "object",
                "properties": {
                    "protocol": {"type": "string", "enum": ["all", "ssh", "web"], "default": "all"},
                    "username": {"type": ["string", "null"]},
                    "target": {"type": ["string", "null"]},
                    "start_date": {"type": ["string", "null"], "description": "Inclusive ISO date"},
                    "end_date": {"type": ["string", "null"], "description": "Inclusive ISO date"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                    "offset": {"type": "integer", "minimum": 0, "maximum": 100000},
                    "active_only": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_session_details",
            "description": "Retrieve verified metadata for an authorized SSH session or Web recording.",
            "parameters": {
                "type": "object",
                "properties": {"session_id": {"type": "string", "minLength": 1, "maxLength": 255}},
                "required": ["session_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_web_recording_activity",
            "description": (
                "Retrieve bounded, privacy-preserving activity statistics from one "
                "authorized finalized Web recording. Use this for questions about "
                "what happened inside a specific browser recording; DOM text and input "
                "values are never returned."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "minLength": 1, "maxLength": 255},
                },
                "required": ["session_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_web_recordings",
            "description": (
                "Analyze a page of authorized Web recording activity summaries. "
                "Use this when asked to review all or multiple recordings. Page through "
                "the results with the returned next_offset until complete, and report any "
                "recordings that are still in progress or unavailable. DOM text and input "
                "values are never returned."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "start_date": {"type": ["string", "null"], "description": "Inclusive ISO date"},
                    "end_date": {"type": ["string", "null"], "description": "Inclusive ISO date"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 10},
                    "offset": {"type": "integer", "minimum": 0, "maximum": 10000},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_ssh_command_archive",
            "description": (
                "Search the full PostgreSQL SSH command archive, or scan every "
                "recorded SSH command for the platform's risk rules. Use this for "
                "questions about risky commands across sessions and for summaries "
                "of stored SSH command activity. Returns archive-wide session and "
                "command totals, a paged list of per-session command/risk summaries, "
                "and a bounded page of matching command evidence. Continue pages using "
                "next_session_offset when summarizing all sessions. Call without search "
                "or risky_only for an archive-wide summary."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {"type": ["string", "null"], "maxLength": 200},
                    "risky_only": {"type": "boolean"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                    "offset": {"type": "integer", "minimum": 0, "maximum": 100000},
                    "session_limit": {"type": "integer", "minimum": 1, "maximum": 100},
                    "session_offset": {"type": "integer", "minimum": 0, "maximum": 100000},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_session_commands",
            "description": (
                "Retrieve a page of the complete stored command log for one authorized "
                "SSH session, including recorded terminal output. Use the returned "
                "next_offset to continue until complete when the question requires the "
                "full session history. If output_complete is false, request the same "
                "command page again with output_offset set to output_next_offset."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "minLength": 1, "maxLength": 255},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 25},
                    "offset": {"type": "integer", "minimum": 0, "maximum": 100000},
                    "output_offset": {"type": "integer", "minimum": 0, "maximum": 10000000},
                    "output_limit": {"type": "integer", "minimum": 1, "maximum": 4000},
                },
                "required": ["session_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_session_events",
            "description": "Retrieve events recorded for one authorized SSH session.",
            "parameters": {
                "type": "object",
                "properties": {"session_id": {"type": "string", "minLength": 1, "maxLength": 255}},
                "required": ["session_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_audit_logs",
            "description": "Search the authenticated Secure Access UI audit events and Warpgate audit events. Available to admins and auditors, up to 500 latest events per source.",
            "parameters": {
                "type": "object",
                "properties": {
                    "search": {"type": ["string", "null"], "maxLength": 200},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_security_incidents",
            "description": "Search recorded agent incidents/alerts, only when the optional read-only incidents source is configured.",
            "parameters": {
                "type": "object",
                "properties": {
                    "username": {"type": ["string", "null"]},
                    "start_date": {"type": ["string", "null"], "description": "Inclusive ISO date"},
                    "end_date": {"type": ["string", "null"], "description": "Inclusive ISO date"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                    "offset": {"type": "integer", "minimum": 0, "maximum": 100000},
                },
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_data_source_status",
            "description": "Report which verified Secure Access session, recording, incident, and log sources are available.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_application_knowledge",
            "description": "Return verified architecture and integration facts about this Secure Access installation.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        },
    },
]


class ToolRegistry:
    def __init__(
        self,
        settings: Settings,
        client: SecureAccessClient,
        identity: AssistantIdentity,
        incidents_reader: Any = None,
    ):
        self._settings = settings
        self._client = client
        self._identity = identity
        self._incidents_reader = incidents_reader

    def execute(self, name: str, raw_arguments: str, question: str) -> dict[str, Any]:
        try:
            arguments = json.loads(raw_arguments or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError("Tool arguments were not valid JSON.") from exc
        if not isinstance(arguments, dict):
            raise ValueError("Tool arguments must be a JSON object.")

        handlers = {
            "get_session_counts": (ListSessionsArguments, self._count_sessions),
            "list_sessions": (ListSessionsArguments, self._list_sessions),
            "get_session_details": (SessionIdArguments, self._get_session_details),
            "get_web_recording_activity": (
                SessionIdArguments,
                self._get_web_recording_activity,
            ),
            "analyze_ssh_command_archive": (
                CommandArchiveArguments,
                self._analyze_ssh_command_archive,
            ),
            "analyze_web_recordings": (
                AnalyzeWebRecordingsArguments,
                self._analyze_web_recordings,
            ),
            "get_session_commands": (
                SessionCommandsArguments,
                self._get_session_commands,
            ),
            "get_session_events": (SessionIdArguments, self._get_session_events),
            "list_audit_logs": (AuditLogArguments, self._list_audit_logs),
            "list_security_incidents": (IncidentArguments, self._list_incidents),
            "get_data_source_status": (ToolArguments, self._source_status),
            "get_application_knowledge": (ToolArguments, self._application_knowledge),
        }
        entry = handlers.get(name)
        if entry is None:
            raise ValueError("The requested tool is not permitted.")
        argument_type, handler = entry
        validated = argument_type.model_validate(arguments)
        validated = self._apply_question_constraints(name, validated, question)
        return handler(validated, question)

    def _apply_question_constraints(self, name: str, args: Any, question: str) -> Any:
        if name not in {"get_session_counts", "list_sessions"}:
            return args
        normalized = question.casefold()
        has_ssh = bool(re.search(r"\bssh\b", normalized))
        has_web = bool(re.search(r"\b(?:web|browser|rrweb)\b", normalized))
        updates: dict[str, Any] = {}
        if has_ssh != has_web:
            updates["protocol"] = "ssh" if has_ssh else "web"
        username_match = re.search(
            r"\b(?:user|username)\s+([a-z0-9_.-]{1,128})\b|"
            r"\b(?:by|for)\s+(?!today\b|yesterday\b|tomorrow\b|this\b|last\b|"
            r"previous\b|all\b|ssh\b|web\b|browser\b)([a-z0-9_.-]{1,128})\b",
            normalized,
        )
        if username_match:
            updates["username"] = next(
                value for value in username_match.groups() if value
            )
        target_match = re.search(
            r"\b(?:target|host)\s+([a-z0-9_.-]{1,256})\b",
            normalized,
        )
        if target_match:
            updates["target"] = target_match.group(1)
        if re.search(r"\b(?:active|currently connected|still connected|logged in now)\b", normalized):
            updates["active_only"] = True
        parsed_dates = date_range_from_question(question, self._settings.app_timezone)
        if parsed_dates:
            updates["start_date"], updates["end_date"] = parsed_dates
        return args.model_copy(update=updates) if updates else args

    def _date_bounds(self, args: Any, question: str) -> tuple[date | None, date | None]:
        if args.start_date or args.end_date:
            return args.start_date, args.end_date
        parsed = date_range_from_question(question, self._settings.app_timezone)
        return parsed if parsed else (None, None)

    def _time_bounds(
        self,
        question: str,
    ) -> tuple[datetime | None, datetime | None]:
        return time_bounds_from_question(question, self._settings.app_timezone)

    def _count_sessions(self, args: ListSessionsArguments, question: str) -> dict[str, Any]:
        start_date, end_date = self._date_bounds(args, question)
        since, before = self._time_bounds(question)
        ssh = (
            self._client.list_ssh_sessions(
                username=args.username,
                target=args.target,
                start_date=start_date,
                end_date=end_date,
                before=before or datetime.now(timezone.utc),
                since=since,
            )
            if args.protocol in {"all", "ssh"}
            else {"total": 0, "complete": True}
        )
        active_complete = True
        if args.active_only and args.protocol in {"all", "ssh"}:
            active_records, active_complete = self._filter_active_ssh(
                [{**item, "protocol": "SSH"} for item in ssh["items"]]
            )
            ssh = {
                **ssh,
                "total": len(active_records),
                "complete": ssh["complete"] and active_complete,
            }
        web_active_unavailable = args.active_only and args.protocol in {"all", "web"}
        web = (
            {"total": None, "complete": False}
            if web_active_unavailable
            else self._client.list_web_sessions(
                username=args.username,
                target=args.target,
                start_date=start_date,
                end_date=end_date,
                limit=1,
                since=since,
                before=before or datetime.now(timezone.utc),
            )
            if args.protocol in {"all", "web"}
            else {"total": 0, "complete": True}
        )
        total = (
            ssh["total"] + web["total"]
            if ssh["total"] is not None and web["total"] is not None
            else None
        )
        return {
            "ssh_count": ssh["total"],
            "web_count": web["total"],
            "total": total,
            "scope": _scope(
                args,
                start_date,
                end_date,
                self._identity.username if self._identity.is_developer else args.username,
            ),
            "complete": ssh.get("complete", True) and web.get("complete", True),
            "warnings": ssh.get("warnings", []),
            "web_active_status": (
                "not exposed by the Web metadata source"
                if web_active_unavailable
                else None
            ),
        }

    def _list_sessions(self, args: ListSessionsArguments, question: str) -> dict[str, Any]:
        start_date, end_date = self._date_bounds(args, question)
        since, before = self._time_bounds(question)
        sessions: list[dict[str, Any]] = []
        complete = True
        warnings: list[str] = []
        if args.protocol in {"all", "ssh"}:
            ssh = self._client.list_ssh_sessions(
                username=args.username,
                target=args.target,
                start_date=start_date,
                end_date=end_date,
                before=before or datetime.now(timezone.utc),
                since=since,
            )
            sessions.extend({**item, "protocol": "SSH"} for item in ssh["items"])
            complete = complete and ssh["complete"]
            warnings.extend(ssh.get("warnings", []))
        if args.protocol in {"all", "web"} and not args.active_only:
            web = self._client.list_web_sessions(
                username=args.username,
                target=args.target,
                start_date=start_date,
                end_date=end_date,
                limit=100,
                since=since,
                before=before or datetime.now(timezone.utc),
            )
            sessions.extend({**item, "protocol": "WEB"} for item in web["items"])
            complete = complete and web["complete"]
        if args.active_only:
            sessions, active_complete = self._filter_active_ssh(sessions)
            complete = complete and active_complete
        web_active_unavailable = args.active_only and args.protocol in {"all", "web"}
        if web_active_unavailable:
            complete = False
        sessions.sort(key=lambda item: _sort_key(item), reverse=True)
        known_ssh_active_count = len(sessions) if args.active_only else None
        page = sessions[args.offset : args.offset + args.limit]
        ssh_page = [item for item in page if item.get("protocol") == "SSH"]
        enriched_ssh = iter(self._client.enrich_ssh_sessions(ssh_page))
        page = [
            next(enriched_ssh) if item.get("protocol") == "SSH" else item
            for item in page
        ]
        return {
            "items": page,
            "total": None if web_active_unavailable else len(sessions),
            "known_ssh_active_count": known_ssh_active_count,
            "offset": args.offset,
            "limit": args.limit,
            "scope": _scope(
                args,
                start_date,
                end_date,
                self._identity.username if self._identity.is_developer else args.username,
            ),
            "complete": complete,
            "warnings": list(dict.fromkeys(warnings)),
            "note": (
                "Active status is based only on SSH lifecycle events; Web metadata does not establish active status."
                if args.active_only
                else None
            ),
        }

    def _filter_active_ssh(self, sessions: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
        candidates = [
            item for item in sessions
            if item.get("protocol") == "SSH" and not item.get("ended_at")
        ]
        active: list[dict[str, Any]] = []
        complete = len(candidates) <= 25
        for session in candidates[:25]:
            if session.get("live_source") == "Warpgate":
                active.append(session)
                continue
            session_id = session.get("session_id") or session.get("unique_id")
            events = self._client.get_session_related(str(session_id), "events")
            starts = [
                _event_time(event)
                for event in events
                if event.get("event_type") == "session_started"
            ]
            ends = [
                _event_time(event)
                for event in events
                if event.get("event_type") == "session_ended"
            ]
            starts = [value for value in starts if value is not None]
            ends = [value for value in ends if value is not None]
            if starts and not any(end >= max(starts) for end in ends):
                active.append(session)
        return active, complete

    def _get_session_details(self, args: SessionIdArguments, _question: str) -> dict[str, Any]:
        if args.session_id.startswith("session-"):
            return self._client.get_web_session(args.session_id)
        return self._client.get_session_detail(args.session_id)

    def _get_web_recording_activity(
        self,
        args: SessionIdArguments,
        _question: str,
    ) -> dict[str, Any]:
        return self._client.get_web_recording_activity(args.session_id)

    def _analyze_web_recordings(
        self,
        args: AnalyzeWebRecordingsArguments,
        _question: str,
    ) -> dict[str, Any]:
        start_date, end_date = self._date_bounds(args, _question)
        recordings = self._client.list_web_sessions(
            start_date=start_date,
            end_date=end_date,
            limit=args.limit,
            offset=args.offset,
        )
        items: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []
        for recording in recordings["items"]:
            session_id = recording["sessionId"]
            try:
                activity = self._client.get_web_recording_activity(session_id)
            except DataSourceError as exc:
                failures.append({"session_id": session_id, "error": str(exc)})
                continue
            items.append(
                {
                    "session_id": session_id,
                    "username": activity.get("username"),
                    "started_at": activity.get("started_at"),
                    "activity": {
                        **{
                            key: activity["activity"][key]
                            for key in (
                                "event_count",
                                "analyzed_event_count",
                                "truncated",
                                "event_types",
                                "activity_types",
                                "first_event_at",
                                "last_event_at",
                            )
                            if key in activity.get("activity", {})
                        },
                        "page_origins": activity.get("activity", {}).get(
                            "page_origins", []
                        )[:5],
                        "dom_text_included": False,
                        "input_values_included": False,
                    },
                }
            )
        next_offset = args.offset + len(recordings["items"])
        has_more = next_offset < recordings["total"]
        complete = (
            recordings["complete"]
            and not has_more
            and not failures
        )
        return {
            "items": items,
            "recordings_total": recordings["total"],
            "analyzed_count": len(items),
            "unavailable_count": len(failures),
            "unavailable": failures,
            "offset": args.offset,
            "next_offset": next_offset if has_more else None,
            "complete": complete,
            "source": recordings["source"],
        }

    def _get_session_commands(
        self,
        args: SessionCommandsArguments,
        _question: str,
    ) -> dict[str, Any]:
        return self._client.get_session_command_log(
            args.session_id,
            limit=args.limit,
            offset=args.offset,
            output_offset=args.output_offset,
            output_limit=args.output_limit,
        )

    def _analyze_ssh_command_archive(
        self,
        args: CommandArchiveArguments,
        _question: str,
    ) -> dict[str, Any]:
        return self._client.analyze_ssh_command_archive(
            search=args.search,
            risky_only=args.risky_only,
            limit=args.limit,
            offset=args.offset,
            session_limit=args.session_limit,
            session_offset=args.session_offset,
        )

    def _get_session_events(self, args: SessionIdArguments, _question: str) -> dict[str, Any]:
        return {
            "session_id": args.session_id,
            "events": self._client.get_session_related(args.session_id, "events"),
        }

    def _list_audit_logs(
        self,
        args: AuditLogArguments,
        _question: str,
    ) -> dict[str, Any]:
        return self._client.list_audit_logs(
            search=args.search,
            limit=args.limit,
        )

    def _list_incidents(self, args: IncidentArguments, question: str) -> dict[str, Any]:
        if not self._settings.audit_database_url:
            return {
                "available": False,
                "source": "agent incidents table",
                "reason": "AUDIT_DATABASE_URL is not configured with a dedicated read-only connection.",
            }
        reader = self._incidents_reader or IncidentReader(self._settings)
        start_date, end_date = self._date_bounds(args, question)
        username = self._identity.username if self._identity.is_developer else args.username
        return reader.list_incidents(
            username=username,
            start_date=start_date,
            end_date=end_date,
            limit=args.limit,
            offset=args.offset,
        )

    def _source_status(self, _args: ToolArguments, _question: str) -> dict[str, Any]:
        return {
            "ssh_sessions": (
                "available through the authenticated role-scoped Warpgate session "
                "feed, combined with the Secure Access PostgreSQL archive"
            ),
            "ssh_commands": (
                "available from the authenticated PostgreSQL command archive; "
                "Warpgate's live session feed does not provide terminal command lists"
            ),
            "ssh_session_events": (
                "available from the authenticated PostgreSQL session-event archive"
            ),
            "web_sessions_and_recording_metadata": "available through authenticated Warpgate-backed API",
            "web_recording_activity": (
                "authorized Web recordings can be analyzed in live pages of up to "
                "ten recordings; event text and input values are excluded"
            ),
            "secure_access_audit_events": (
                "available through the authenticated Warpgate audit API for admins and auditors"
            ),
            "warpgate_audit_events": (
                "available through the authenticated Warpgate audit API for admins and auditors"
            ),
            "agent_incidents_and_alerts": (
                "available through a dedicated read-only database connection"
                if self._settings.audit_database_url
                else "source exists in the project, but no dedicated read-only connection is configured"
            ),
            "audit_log": (
                "Secure Access UI events and Warpgate gateway events are available "
                "through authenticated APIs, up to 500 recent events per source"
            ),
            "universal_log": (
                "the audit page combines Secure Access UI events and Warpgate gateway "
                "events; no separate third universal-log source was found"
            ),
            "active_ssh": "only verifiable when session_started/session_ended events are recorded",
            "web_active_status": "unavailable; Web metadata has no reliable active lifecycle indicator",
        }

    def _application_knowledge(
        self,
        _args: ToolArguments,
        _question: str,
    ) -> dict[str, Any]:
        return {
            "frontend": "The existing Secure Access UI uses React and Vite.",
            "backend": "The existing HTTP API and assistant use FastAPI.",
            "session_identity": (
                "Logical SSH session identity is COALESCE(session_id, unique_id); "
                "commands and events are associated with the persisted session row."
            ),
            "authentication": (
                "The API validates the signed warpgate-http-session cookie against "
                "Warpgate and permits admin, developer, and auditor_viewer roles."
            ),
            "session_storage": (
                "Current SSH sessions are retrieved live from Warpgate through its "
                "authenticated role-scoped session feed. The Secure Access PostgreSQL "
                "sessions, commands, and events tables provide the historical archive."
            ),
            "web_recordings": (
                "Web recording metadata and bounded activity statistics are retrieved "
                "in live, paginated queries through authenticated Warpgate rrweb APIs. "
                "DOM text and input values are excluded from assistant evidence; "
                "recordings are not ingested for model training."
            ),
            "audit_logs": (
                "The Warpgate-backed API provides Secure Access UI audit events and "
                "Warpgate gateway audit events to admin and auditor_viewer roles. "
                "Each endpoint exposes up to 500 latest matching events."
            ),
            "existing_assistant": (
                "The existing assistant has a configurable Ollama provider. This "
                "Groq addon is separate and does not replace or configure it."
            ),
            "incident_logs": (
                "Agent code defines an incidents table for security alerts, separate "
                "from Secure Access UI and Warpgate audit events."
            ),
            "freshness": (
                "The addon queries Warpgate and Secure Access APIs on each request "
                "and does not cache session records; newly persisted sessions and "
                "finalized Web recordings can appear on the next query."
            ),
            "limitations": (
                "There is no scheduled-session source. Web metadata does not provide "
                "reliable active status. No public live-search provider is configured."
            ),
        }


class IncidentReader:
    def __init__(self, settings: Settings):
        self._settings = settings

    def list_incidents(
        self,
        *,
        username: str | None,
        start_date: date | None,
        end_date: date | None,
        limit: int,
        offset: int,
    ) -> dict[str, Any]:
        try:
            import psycopg
            from psycopg.rows import dict_row

            with psycopg.connect(
                self._settings.audit_database_url,
                connect_timeout=max(1, int(self._settings.audit_query_timeout_seconds)),
                row_factory=dict_row,
            ) as connection:
                connection.execute("SET TRANSACTION READ ONLY")
                connection.execute(
                    "SELECT set_config('statement_timeout', %s, true)",
                    (f"{int(self._settings.audit_query_timeout_seconds * 1000)}ms",),
                )
                clauses: list[str] = []
                parameters: list[Any] = []
                if username:
                    clauses.append("username = %s")
                    parameters.append(username)
                if start_date:
                    clauses.append("detected_at >= %s")
                    parameters.append(start_date)
                if end_date:
                    clauses.append("detected_at < %s")
                    parameters.append(end_date + timedelta(days=1))
                where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
                rows = connection.execute(
                    "SELECT id, command, severity, username, session_id, detected_at, "
                    "anomaly_score, is_anomaly, action_taken, notes "
                    f"FROM incidents {where} ORDER BY detected_at DESC NULLS LAST "
                    "LIMIT %s OFFSET %s",
                    (*parameters, limit, offset),
                ).fetchall()
                count = connection.execute(
                    f"SELECT count(*) AS total FROM incidents {where}",
                    parameters,
                ).fetchone()
            return {
                "items": [dict(row) for row in rows],
                "total": int(count["total"]),
                "source": "incidents table (read-only transaction)",
                "complete": True,
            }
        except Exception as exc:
            raise DataSourceError(
                "Agent incidents",
                "The optional read-only agent incidents source is unavailable.",
            ) from exc


def _scope(
    args: Any,
    start_date: date | None,
    end_date: date | None,
    username: str | None,
) -> dict[str, Any]:
    return {
        "username": username,
        "target": args.target if hasattr(args, "target") else None,
        "start_date": start_date.isoformat() if start_date else None,
        "end_date": end_date.isoformat() if end_date else None,
    }


def _event_time(event: dict[str, Any]) -> datetime | None:
    value = event.get("timestamp")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _sort_key(item: dict[str, Any]) -> float:
    value = item.get("started_at") or item.get("startedAt") or item.get("login_time")
    if not isinstance(value, str):
        return float("-inf")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return float("-inf")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()
