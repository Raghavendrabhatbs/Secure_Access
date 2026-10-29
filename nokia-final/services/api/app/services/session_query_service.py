from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from sqlalchemy import Select, and_, case, cast, func, or_, select
from sqlalchemy.orm import Session

from app.services.evidence_ranking import rank_command_matches, rank_session_matches
from app.services.risk_aggregator import SessionRiskSummary, aggregate_session_risks
from app.services.risk_classifier import RiskFinding, classify_command_risks
from app.services.query_understanding_service import date_range_utc_bounds
from app.services.timeline import TimelineEntry
from app.services.timeline_assembler import assemble_session_timeline
from shared.models.command import Command
from shared.models.event import Event
from shared.models.session import Session as SessionModel


@dataclass
class CommandSearchMatch:
    session_id: str
    username: str | None
    protocol: str | None
    started_at: datetime | None
    ended_at: datetime | None
    sequence_number: int | None
    command: str | None
    output: str | None
    executed_at: datetime | None
    matched_terms: list[str]
    risk_findings: list[RiskFinding]


@dataclass
class SessionCommandEvidence:
    session_id: str
    sequence_number: int | None
    command: str | None
    output: str | None
    executed_at: datetime | None
    exit_code: int | None
    risk_findings: list[RiskFinding]


@dataclass
class EventSearchMatch:
    event_id: str
    session_id: str
    username: str | None
    protocol: str | None
    timestamp: datetime
    event_type: str
    severity: str | None
    message: str | None


@dataclass
class SessionSearchMatch:
    session_id: str
    username: str | None
    protocol: str | None
    started_at: datetime | None
    ended_at: datetime | None
    matched_terms: list[str]
    matching_commands: list[CommandSearchMatch]
    risk_summary: SessionRiskSummary | None = None


def filter_sessions_by_risk_category(
    candidates: list[SessionSearchMatch],
    category: str,
) -> list[SessionSearchMatch]:
    """Filter pre-ranked session candidates to those containing a specific risk category."""
    normalized_category = (category or "").strip().upper()
    if not normalized_category:
        return []

    results: list[SessionSearchMatch] = []
    for candidate in candidates:
        matching_commands = []
        for command in candidate.matching_commands:
            matching_findings = [
                finding
                for finding in command.risk_findings
                if finding.category == normalized_category
            ]
            if not matching_findings:
                continue
            matching_commands.append(
                CommandSearchMatch(
                    session_id=command.session_id,
                    username=command.username,
                    protocol=command.protocol,
                    started_at=command.started_at,
                    ended_at=command.ended_at,
                    sequence_number=command.sequence_number,
                    command=command.command,
                    output=command.output,
                    executed_at=command.executed_at,
                    matched_terms=[normalized_category.lower()],
                    risk_findings=matching_findings,
                )
            )

        if not matching_commands:
            continue

        risk_summary = aggregate_session_risks(
            [finding for command in matching_commands for finding in command.risk_findings]
        )
        results.append(
            SessionSearchMatch(
                session_id=candidate.session_id,
                username=candidate.username,
                protocol=candidate.protocol,
                started_at=candidate.started_at,
                ended_at=candidate.ended_at,
                matched_terms=[normalized_category.lower()],
                matching_commands=matching_commands,
                risk_summary=risk_summary,
            )
        )

    return results


class SessionQueryService:
    def __init__(self, db: Session):
        self._db = db

    def count_unique_sessions(self, limit: int = 10000) -> int:
        logical_id = func.coalesce(SessionModel.session_id, SessionModel.unique_id)
        return int(self._db.scalar(select(func.count(func.distinct(logical_id)))) or 0)

    def sum_total_commands(self) -> int:
        logical_id = func.coalesce(SessionModel.session_id, SessionModel.unique_id)
        session_totals = (
            select(
                logical_id.label("logical_id"),
                func.max(SessionModel.total_commands).label("total_commands"),
            )
            .group_by(logical_id)
            .subquery()
        )
        return int(
            self._db.scalar(
                select(func.coalesce(func.sum(session_totals.c.total_commands), 0))
            )
            or 0
        )

    @staticmethod
    def _merged_started_at(logical_id):
        started_at = func.coalesce(
            SessionModel.started_at,
            func.timezone("UTC", SessionModel.login_time),
        )
        return func.coalesce(
            func.max(
                case(
                    (SessionModel.unique_id == logical_id, started_at),
                )
            ),
            func.max(started_at),
        )

    @staticmethod
    def _merged_ended_at(logical_id):
        ended_at = func.coalesce(
            SessionModel.ended_at,
            func.timezone("UTC", SessionModel.logout_time),
        )
        return func.coalesce(
            func.max(
                case(
                    (SessionModel.unique_id == logical_id, ended_at),
                )
            ),
            func.max(ended_at),
        )

    @staticmethod
    def _merged_field(logical_id, field):
        return func.coalesce(
            func.max(case((SessionModel.unique_id == logical_id, field))),
            func.max(field),
        )

    def query_sessions(
        self,
        *,
        limit: int = 25,
        offset: int = 0,
        username: str | None = None,
        target: str | None = None,
        protocol: str | None = None,
        start_date: date | None = None,
        end_date: date | None = None,
        session_id: str | None = None,
        active: bool | None = None,
        has_recording: bool | None = None,
        occurred_before: datetime | None = None,
    ) -> tuple[list[SessionModel], int]:
        if not 1 <= limit <= 1000 or offset < 0:
            raise ValueError("Invalid session page bounds.")
        if start_date and end_date and start_date > end_date:
            raise ValueError("start_date must not be after end_date.")

        logical_id = func.coalesce(SessionModel.session_id, SessionModel.unique_id)
        sessions = (
            select(
                logical_id.label("logical_id"),
                self._merged_started_at(logical_id).label("started_at"),
                self._merged_ended_at(logical_id).label("ended_at"),
                self._merged_field(logical_id, SessionModel.username).label("username"),
                self._merged_field(logical_id, SessionModel.target).label("target"),
                func.upper(
                    self._merged_field(
                        logical_id,
                        func.coalesce(SessionModel.protocol, SessionModel.session_type),
                    )
                ).label("protocol"),
                func.bool_or(
                    or_(
                        SessionModel.recording_id.is_not(None),
                        SessionModel.recording_path.is_not(None),
                    )
                ).label("has_recording"),
            )
            .group_by(logical_id)
            .subquery()
        )

        conditions = []
        if start_date is not None:
            start_at, _ = date_range_utc_bounds(start_date, start_date)
            conditions.append(sessions.c.started_at >= start_at)
        if end_date is not None:
            _, end_at = date_range_utc_bounds(end_date, end_date)
            conditions.append(sessions.c.started_at < end_at)
        if occurred_before is not None:
            conditions.append(
                or_(
                    sessions.c.started_at.is_(None),
                    sessions.c.started_at <= occurred_before,
                )
            )
        if username:
            conditions.append(func.lower(sessions.c.username) == username.strip().casefold())
        if target:
            conditions.append(sessions.c.target.ilike(f"%{target.strip()}%"))
        if session_id:
            conditions.append(func.lower(sessions.c.logical_id) == session_id.casefold())
        if protocol:
            normalized_protocol = protocol.strip().upper()
            accepted_protocols = (
                ("WEB", "HTTP", "BROWSER")
                if normalized_protocol in {"WEB", "HTTP", "BROWSER"}
                else (normalized_protocol,)
            )
            conditions.append(sessions.c.protocol.in_(accepted_protocols))
        if active is False:
            conditions.append(sessions.c.ended_at.is_not(None))
        elif active is True:
            lifecycle = (
                select(
                    logical_id.label("logical_id"),
                    func.max(
                        case(
                            (
                                func.lower(Event.event_type).in_(
                                    ("session_started", "session_start", "connected")
                                ),
                                Event.timestamp,
                            )
                        )
                    ).label("last_started_at"),
                    func.max(
                        case(
                            (
                                func.lower(Event.event_type).in_(
                                    ("session_ended", "session_stopped", "disconnected")
                                ),
                                Event.timestamp,
                            )
                        )
                    ).label("last_ended_at"),
                )
                .select_from(Event)
                .join(SessionModel, SessionModel.unique_id == Event.session_id)
                .group_by(logical_id)
                .subquery()
            )
            conditions.extend(
                (
                    sessions.c.ended_at.is_(None),
                    lifecycle.c.last_started_at.is_not(None),
                    or_(
                        lifecycle.c.last_ended_at.is_(None),
                        lifecycle.c.last_started_at > lifecycle.c.last_ended_at,
                    ),
                )
            )
        if has_recording is not None:
            conditions.append(sessions.c.has_recording.is_(has_recording))

        query = select(sessions.c.logical_id).select_from(sessions)
        if active is True:
            query = query.join(
                lifecycle,
                lifecycle.c.logical_id == sessions.c.logical_id,
            )
        if conditions:
            query = query.where(*conditions)
        total = int(
            self._db.scalar(
                select(func.count()).select_from(query.order_by(None).subquery())
            )
            or 0
        )
        logical_ids = list(
            self._db.scalars(
                query.order_by(
                    sessions.c.started_at.desc().nullslast(),
                    sessions.c.logical_id.desc(),
                )
                .limit(limit)
                .offset(offset)
            ).all()
        )
        return self._load_merged_sessions(logical_ids), total

    def count_sessions_started_between(self, start_date: date, end_date: date) -> int:
        start_at, end_at = date_range_utc_bounds(start_date, end_date)
        logical_id = func.coalesce(SessionModel.session_id, SessionModel.unique_id)
        session_starts = (
            select(
                logical_id.label("logical_id"),
                self._merged_started_at(logical_id).label("started_at"),
            )
            .group_by(logical_id)
            .subquery()
        )
        statement = (
            select(func.count())
            .select_from(session_starts)
            .where(
                session_starts.c.started_at >= start_at,
                session_starts.c.started_at < end_at,
            )
        )
        return int(self._db.scalar(statement) or 0)

    def list_sessions(self, limit: int = 100, offset: int = 0) -> list[SessionModel]:
        if limit > 1000:
            if offset < 0:
                raise ValueError("offset must not be negative")
            return self.list_all_sessions()[offset:]
        logical_id = func.coalesce(SessionModel.session_id, SessionModel.unique_id)
        sessions_by_id = (
            select(
                logical_id.label("logical_id"),
                self._merged_started_at(logical_id).label("started_at"),
            )
            .group_by(logical_id)
            .subquery()
        )
        statement = (
            select(sessions_by_id.c.logical_id)
            .order_by(sessions_by_id.c.started_at.desc().nullslast(), sessions_by_id.c.logical_id.desc())
            .limit(limit)
            .offset(offset)
        )
        return self._load_merged_sessions(list(self._db.scalars(statement).all()))

    def list_all_sessions(self, page_size: int = 1000) -> list[SessionModel]:
        if not 1 <= page_size <= 1000:
            raise ValueError("page_size must be between 1 and 1000")
        sessions: list[SessionModel] = []
        offset = 0
        while True:
            page = self.list_sessions(limit=page_size, offset=offset)
            sessions.extend(page)
            if len(page) < page_size:
                return sessions
            offset += len(page)

    def list_sessions_started_between(
        self,
        start_date: date,
        end_date: date,
        limit: int = 10000,
        offset: int = 0,
    ) -> list[SessionModel]:
        if limit > 1000:
            if offset < 0:
                raise ValueError("offset must not be negative")
            return self.list_all_sessions_started_between(start_date, end_date)[offset:]
        start_at, end_at = date_range_utc_bounds(start_date, end_date)
        logical_id = func.coalesce(SessionModel.session_id, SessionModel.unique_id)
        sessions_by_id = (
            select(
                logical_id.label("logical_id"),
                self._merged_started_at(logical_id).label("started_at"),
            )
            .group_by(logical_id)
            .subquery()
        )
        statement = (
            select(sessions_by_id.c.logical_id)
            .where(
                sessions_by_id.c.started_at >= start_at,
                sessions_by_id.c.started_at < end_at,
            )
            .order_by(sessions_by_id.c.started_at.desc(), sessions_by_id.c.logical_id.desc())
            .limit(limit)
            .offset(offset)
        )
        return self._load_merged_sessions(list(self._db.scalars(statement).all()))

    def list_all_sessions_started_between(
        self,
        start_date: date,
        end_date: date,
        page_size: int = 1000,
    ) -> list[SessionModel]:
        if not 1 <= page_size <= 1000:
            raise ValueError("page_size must be between 1 and 1000")
        sessions: list[SessionModel] = []
        offset = 0
        while True:
            page = self.list_sessions_started_between(
                start_date,
                end_date,
                limit=page_size,
                offset=offset,
            )
            sessions.extend(page)
            if len(page) < page_size:
                return sessions
            offset += len(page)

    def _load_merged_sessions(self, logical_ids: list[str]) -> list[SessionModel]:
        if not logical_ids:
            return []

        logical_id = func.coalesce(SessionModel.session_id, SessionModel.unique_id)
        rows = self._db.scalars(
            select(SessionModel).where(logical_id.in_(logical_ids))
        ).all()
        grouped: dict[str, list[SessionModel]] = {}
        for row in rows:
            grouped.setdefault(row.session_id or row.unique_id, []).append(row)

        merged: list[SessionModel] = []
        for session_id in logical_ids:
            representations = grouped.get(session_id, [])
            if not representations:
                continue
            representations.sort(key=lambda row: row.unique_id != session_id)
            values = {}
            for column in SessionModel.__table__.columns:
                name = column.name
                candidates = [getattr(row, name) for row in representations]
                present = [value for value in candidates if value is not None]
                if not present:
                    values[name] = None
                elif name in {"commands", "flagged"}:
                    combined = []
                    for value in present:
                        if isinstance(value, list):
                            combined.extend(item for item in value if item not in combined)
                    values[name] = combined or present[0]
                elif name == "total_commands":
                    values[name] = max(present)
                else:
                    values[name] = present[0]
            values["unique_id"] = session_id
            merged.append(SessionModel(**values))
        return merged

    def list_active_sessions(self, limit: int = 100) -> list[SessionModel]:
        """Return open sessions whose latest recorded lifecycle event is a start."""
        sessions, _ = self.query_sessions(limit=limit, active=True)
        return sessions

    def get_latest_session_for_user(self, username: str) -> SessionModel | None:
        normalized_username = (username or "").strip().lower()
        if not normalized_username:
            return None

        logical_id = func.coalesce(SessionModel.session_id, SessionModel.unique_id)
        statement = (
            select(logical_id.label("logical_id"))
            .where(
                SessionModel.username.is_not(None),
                SessionModel.started_at.is_not(None),
                SessionModel.username.ilike(normalized_username),
            )
            .group_by(logical_id)
            .order_by(self._merged_started_at(logical_id).desc(), logical_id.desc())
            .limit(1)
        )
        latest_id = self._db.scalars(statement).first()
        return self._load_merged_sessions([latest_id])[0] if latest_id else None

    def get_session(self, session_id: str) -> SessionModel | None:
        session = self._db.get(SessionModel, session_id)
        if session is None:
            statement = select(SessionModel).where(SessionModel.session_id == session_id)
            session = self._db.scalars(statement).first()
        if session is None:
            return None
        logical_id = session.session_id or session.unique_id
        merged = self._load_merged_sessions([logical_id])
        return merged[0] if merged else None

    def get_commands(self, session_id: str) -> list[Command]:
        statement = (
            select(Command)
            .where(Command.session_id == session_id)
            .order_by(Command.sequence_number.asc())
        )
        return list(self._db.scalars(statement).all())

    def get_commands_page(
        self,
        session_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Command], int]:
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError("Invalid command log page bounds.")

        filtered = select(Command).where(Command.session_id == session_id)
        total = int(
            self._db.scalar(
                select(func.count()).select_from(filtered.subquery())
            )
            or 0
        )
        commands = self._db.scalars(
            filtered.order_by(
                Command.sequence_number.asc(),
                Command.id.asc(),
            )
            .limit(limit)
            .offset(offset)
        ).all()
        return list(commands), total

    def analyze_command_archive(
        self,
        *,
        search: str | None = None,
        risky_only: bool = False,
        username: str | None = None,
        limit: int = 25,
        offset: int = 0,
        session_limit: int = 25,
        session_offset: int = 0,
    ) -> dict[str, object]:
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError("Invalid command archive page bounds.")
        if not 1 <= session_limit <= 100 or session_offset < 0:
            raise ValueError("Invalid session summary page bounds.")

        sessions = self.list_all_sessions()
        sessions = [
            session
            for session in sessions
            if (session.protocol or session.session_type or "SSH").upper() == "SSH"
        ]
        if username:
            sessions = [
                session
                for session in sessions
                if (session.username or "").casefold() == username.casefold()
            ]
        session_by_id = {
            session.session_id or session.unique_id: session
            for session in sessions
        }
        if not session_by_id:
            return {
                "scope": "postgresql",
                "session_count": 0,
                "command_count": 0,
                "risky_command_count": 0,
                "risk_categories": {},
                "sessions": [],
                "session_summaries": [],
                "session_summaries_total": 0,
                "session_offset": session_offset,
                "session_limit": session_limit,
                "next_session_offset": None,
                "session_summaries_complete": True,
                "matches": [],
                "match_count": 0,
                "offset": offset,
                "limit": limit,
                "matches_complete": True,
                "complete": True,
            }

        statement = (
            select(Command, SessionModel)
            .join(SessionModel, SessionModel.unique_id == Command.session_id)
            .where(SessionModel.unique_id.in_(session_by_id))
            .order_by(
                SessionModel.started_at.desc().nullslast(),
                Command.sequence_number.asc().nullslast(),
                Command.id.asc(),
            )
        )
        rows = self._db.execute(statement).all()
        query = (search or "").strip().casefold()
        command_count = 0
        risky_command_count = 0
        risk_categories: dict[str, int] = {}
        session_command_counts: dict[str, int] = {}
        session_summaries: dict[str, dict[str, Any]] = {
            session_id: {
                "session_id": session_id,
                "username": session.username,
                "protocol": session.protocol or session.session_type,
                "started_at": session.started_at,
                "command_count": 0,
                "risky_command_count": 0,
                "risk_categories": {},
                "commands": [],
            }
            for session_id, session in session_by_id.items()
        }
        matches: list[dict] = []

        for command, session in rows:
            session_id = command.session_id
            if session_id not in session_by_id:
                continue
            command_count += 1
            session_command_counts[session_id] = (
                session_command_counts.get(session_id, 0) + 1
            )
            findings = classify_command_risks(command.command or "")
            session_summary = session_summaries[session_id]
            session_summary["command_count"] += 1
            if len(session_summary["commands"]) < 5:
                session_summary["commands"].append(command.command or "")
            if findings:
                risky_command_count += 1
                session_summary["risky_command_count"] += 1
                for finding in findings:
                    risk_categories[finding.category] = (
                        risk_categories.get(finding.category, 0) + 1
                    )
                    categories = session_summary["risk_categories"]
                    categories[finding.category] = categories.get(finding.category, 0) + 1

            command_text = command.command or ""
            output_text = command.output or ""
            if risky_only and not findings:
                continue
            if query and query not in command_text.casefold() and query not in output_text.casefold():
                continue

            matches.append(
                {
                    "session_id": session_id,
                    "username": session.username,
                    "protocol": session.protocol,
                    "started_at": session.started_at,
                    "sequence_number": command.sequence_number,
                    "command": command_text,
                    "output": output_text[:4000],
                    "output_truncated": len(output_text) > 4000,
                    "executed_at": command.executed_at,
                    "risk_findings": [
                        {
                            "category": finding.category,
                            "severity": finding.severity,
                            "rule": finding.rule,
                        }
                        for finding in findings
                    ],
                }
            )

        ordered_session_summaries = list(session_summaries.values())
        session_summaries_page = ordered_session_summaries[
            session_offset : session_offset + session_limit
        ]
        next_session_offset = (
            session_offset + len(session_summaries_page)
            if session_offset + len(session_summaries_page) < len(ordered_session_summaries)
            else None
        )

        return {
            "scope": "postgresql",
            "session_count": len(sessions),
            "command_count": command_count,
            "risky_command_count": risky_command_count,
            "risk_categories": risk_categories,
            "sessions": [
                {
                    "session_id": session.session_id or session.unique_id,
                    "username": session.username,
                    "protocol": session.protocol,
                    "started_at": session.started_at,
                    "command_count": session_command_counts.get(
                        session.session_id or session.unique_id,
                        0,
                    ),
                    "risk": session.risk,
                }
                for session in sessions[:10]
            ],
            "session_summaries": session_summaries_page,
            "session_summaries_total": len(ordered_session_summaries),
            "session_offset": session_offset,
            "session_limit": session_limit,
            "next_session_offset": next_session_offset,
            "session_summaries_complete": next_session_offset is None,
            "matches": matches[offset : offset + limit],
            "match_count": len(matches),
            "offset": offset,
            "limit": limit,
            "matches_complete": offset + limit >= len(matches),
            "complete": True,
        }

    def get_command_evidence(self, session_id: str) -> list[SessionCommandEvidence]:
        commands = self.get_commands(session_id)
        return [self._build_session_command_evidence(command) for command in commands]

    def get_session_timeline(self, session_id: str) -> list[TimelineEntry]:
        commands = self.get_command_evidence(session_id)
        events = self.get_events(session_id)
        return assemble_session_timeline(commands, events)

    def query_session_timeline(
        self,
        session_id: str,
        command_contains: str | None = None,
        event_type: str | None = None,
        include_commands: bool = True,
        include_events: bool = True,
    ) -> list[TimelineEntry]:
        """Retrieve a deterministic timeline with optional command/event filters."""
        if not include_commands and not include_events:
            return []

        timeline = self.get_session_timeline(session_id)
        if not timeline:
            return []

        command_filter = (command_contains or "").strip().lower()
        event_type_filter = (event_type or "").strip().upper()

        filtered: list[TimelineEntry] = []
        for entry in timeline:
            is_command = entry.event_type == "COMMAND"
            if is_command and not include_commands:
                continue
            if not is_command and not include_events:
                continue

            if command_filter and command_filter not in (entry.command or "").lower():
                continue

            if event_type_filter and entry.event_type.upper() != event_type_filter:
                continue

            filtered.append(entry)

        return filtered

    def get_events(self, session_id: str) -> list[Event]:
        statement = (
            select(Event)
            .where(Event.session_id == session_id)
            .order_by(Event.timestamp.asc(), Event.id.asc())
        )
        return list(self._db.scalars(statement).all())

    def search_event_matches(
        self,
        search_terms: list[str],
        *,
        limit: int = 20,
        offset: int = 0,
        start_date: date | None = None,
        end_date: date | None = None,
    ) -> tuple[list[EventSearchMatch], int]:
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError("Invalid event search page bounds.")
        terms = self._normalize_search_terms(search_terms)[:5]
        if not terms:
            return [], 0

        conditions = []
        for term in terms:
            escaped_term = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = f"%{escaped_term}%"
            conditions.append(
                or_(
                    Event.event_type.ilike(pattern, escape="\\"),
                    Event.message.ilike(pattern, escape="\\"),
                    cast(Event.payload, Text).ilike(pattern, escape="\\"),
                )
            )
        filters = [and_(*conditions)]
        if start_date is not None or end_date is not None:
            lower, upper = date_range_utc_bounds(
                start_date or end_date,
                end_date or start_date,
            )
            if start_date is not None:
                filters.append(Event.timestamp >= lower)
            if end_date is not None:
                filters.append(Event.timestamp < upper)

        join = select(Event, SessionModel).join(
            SessionModel,
            SessionModel.unique_id == Event.session_id,
        )
        count_statement = (
            select(func.count())
            .select_from(Event)
            .join(SessionModel, SessionModel.unique_id == Event.session_id)
            .where(*filters)
        )
        total = int(self._db.scalar(count_statement) or 0)
        statement = (
            join.where(*filters)
            .order_by(Event.timestamp.desc(), Event.id.desc())
            .limit(limit)
            .offset(offset)
        )
        results = self._db.execute(statement).all()
        return [
            EventSearchMatch(
                event_id=str(event.id),
                session_id=event.session_id,
                username=session.username,
                protocol=session.protocol,
                timestamp=event.timestamp,
                event_type=event.event_type,
                severity=event.severity,
                message=event.message,
            )
            for event, session in results
        ], total

    def search_command_matches(self, search_terms: list[str], limit: int = 20) -> list[CommandSearchMatch]:
        normalized_terms = self._normalize_search_terms(search_terms)
        if not normalized_terms:
            return []

        statement = (
            select(Command, SessionModel)
            .join(SessionModel, SessionModel.unique_id == Command.session_id)
            .where(
                or_(
                    *[
                        clause
                        for term in normalized_terms
                        for clause in (
                            Command.command.ilike(f"%{term}%"),
                            Command.output.ilike(f"%{term}%"),
                        )
                    ]
                )
            )
            .order_by(
                SessionModel.started_at.desc().nullslast(),
                Command.sequence_number.asc().nullslast(),
                Command.id.asc(),
            )
        )
        rows = self._db.execute(statement).all()

        matches: list[CommandSearchMatch] = []
        for command, session in rows:
            matched_terms = self._matched_terms(command, normalized_terms)
            if not matched_terms:
                continue

            matches.append(
                CommandSearchMatch(
                    session_id=command.session_id,
                    username=session.username,
                    protocol=session.protocol,
                    started_at=session.started_at,
                    ended_at=session.ended_at,
                    sequence_number=command.sequence_number,
                    command=command.command,
                    output=command.output,
                    executed_at=command.executed_at,
                    matched_terms=matched_terms,
                    risk_findings=classify_command_risks(command.command or ""),
                )
            )

        return rank_command_matches(matches, normalized_terms, limit=limit)

    def search_sessions_by_command_terms(self, search_terms: list[str], limit: int = 20) -> list[SessionSearchMatch]:
        command_matches = self.search_command_matches(search_terms, limit=max(limit * 10, limit))
        if not command_matches:
            return []

        sessions_by_id: dict[str, SessionSearchMatch] = {}
        for match in command_matches:
            existing = sessions_by_id.get(match.session_id)
            if existing is None:
                existing = SessionSearchMatch(
                    session_id=match.session_id,
                    username=match.username,
                    protocol=match.protocol,
                    started_at=match.started_at,
                    ended_at=match.ended_at,
                    matched_terms=[],
                    matching_commands=[],
                )
                sessions_by_id[match.session_id] = existing

            for term in match.matched_terms:
                if term not in existing.matched_terms:
                    existing.matched_terms.append(term)

            existing.matching_commands.append(match)

        results = list(sessions_by_id.values())
        return rank_session_matches(results, self._normalize_search_terms(search_terms), limit=limit)

    def _build_all_session_candidates(self, limit: int) -> list[SessionSearchMatch]:
        sessions = self.list_sessions(limit=max(limit * 10, limit))
        candidates_by_id: dict[str, SessionSearchMatch] = {}

        for session in sessions:
            session_identifier = session.session_id or session.unique_id
            if session_identifier in candidates_by_id:
                continue

            commands = self.get_commands(session_identifier)
            command_evidence = [self._build_command_search_match(command, session) for command in commands]
            if not command_evidence:
                continue

            candidates_by_id[session_identifier] = SessionSearchMatch(
                session_id=session_identifier,
                username=session.username,
                protocol=session.protocol,
                started_at=session.started_at,
                ended_at=session.ended_at,
                matched_terms=[],
                matching_commands=command_evidence,
            )

        return list(candidates_by_id.values())

    def search_sessions_by_risk_categories(self, risk_categories: list[str], limit: int = 20) -> list[SessionSearchMatch]:
        normalized_categories = self._normalize_risk_categories(risk_categories)
        if not normalized_categories:
            return []

        candidates = self._build_all_session_candidates(limit)

        if len(normalized_categories) == 1:
            filtered: list[SessionSearchMatch] = filter_sessions_by_risk_category(
                candidates, normalized_categories[0]
            )
        else:
            filtered = []
            for match in candidates:
                categories_present = {
                    finding.category
                    for command in match.matching_commands
                    for finding in command.risk_findings
                }
                if not all(category in categories_present for category in normalized_categories):
                    continue

                relevant_commands = [
                    command
                    for command in match.matching_commands
                    if any(finding.category in normalized_categories for finding in command.risk_findings)
                ]

                filtered.append(
                    SessionSearchMatch(
                        session_id=match.session_id,
                        username=match.username,
                        protocol=match.protocol,
                        started_at=match.started_at,
                        ended_at=match.ended_at,
                        matched_terms=[],
                        matching_commands=relevant_commands,
                    )
                )

        if not filtered:
            return []

        ranked = rank_session_matches(filtered, normalized_categories, limit=limit)
        for match in ranked:
            if match.risk_summary is None:
                match.risk_summary = aggregate_session_risks(
                    [finding for command in match.matching_commands for finding in command.risk_findings]
                )
        return ranked

    def search_sessions_by_risk_severity(self, severity: str, limit: int = 20) -> list[SessionSearchMatch]:
        normalized_severity = (severity or "").strip().upper()
        if normalized_severity not in {"HIGH", "MEDIUM", "LOW"}:
            return []

        candidates = self._build_all_session_candidates(limit)

        matches: list[SessionSearchMatch] = []
        for candidate in candidates:
            findings = [finding for command in candidate.matching_commands for finding in command.risk_findings]
            risk_summary = aggregate_session_risks(findings)
            if risk_summary.overall_severity != normalized_severity:
                continue

            candidate.risk_summary = risk_summary
            candidate.matched_terms = [normalized_severity.lower()]
            matches.append(candidate)

        matches.sort(key=lambda match: (match.started_at is None, match.started_at, match.session_id))
        return matches[:limit]

    def search_sessions_with_risk_findings(self, limit: int = 20) -> list[SessionSearchMatch]:
        candidates = self._build_all_session_candidates(limit)

        matched: list[SessionSearchMatch] = []
        for match in candidates:
            risk_summary = match.risk_summary
            if risk_summary is None:
                findings = [finding for command in match.matching_commands for finding in command.risk_findings]
                risk_summary = aggregate_session_risks(findings)
                match.risk_summary = risk_summary

            if risk_summary.finding_count > 0:
                matched.append(match)

        matched.sort(key=lambda match: (match.started_at is None, match.started_at, match.session_id))
        return matched[:limit]

    def _normalize_search_terms(self, search_terms: list[str]) -> list[str]:
        normalized_terms: list[str] = []
        for term in search_terms:
            normalized_term = term.strip().lower()
            if normalized_term and normalized_term not in normalized_terms:
                normalized_terms.append(normalized_term)
        return normalized_terms

    def _normalize_risk_categories(self, risk_categories: list[str]) -> list[str]:
        normalized_categories: list[str] = []
        for category in risk_categories:
            normalized_category = category.strip().upper()
            if normalized_category and normalized_category not in normalized_categories:
                normalized_categories.append(normalized_category)
        return normalized_categories

    def _matched_terms(self, command: Command, search_terms: list[str]) -> list[str]:
        command_text = (command.command or "").lower()
        output_text = (command.output or "").lower()
        return [
            term
            for term in search_terms
            if term in command_text or term in output_text
        ]

    def _build_session_command_evidence(self, command: Command) -> SessionCommandEvidence:
        return SessionCommandEvidence(
            session_id=command.session_id,
            sequence_number=command.sequence_number,
            command=command.command,
            output=command.output,
            executed_at=command.executed_at,
            exit_code=command.exit_code,
            risk_findings=classify_command_risks(command.command or ""),
        )

    def _build_command_search_match(self, command: Command, session: SessionModel) -> CommandSearchMatch:
        return CommandSearchMatch(
            session_id=command.session_id,
            username=session.username,
            protocol=session.protocol,
            started_at=session.started_at,
            ended_at=session.ended_at,
            sequence_number=command.sequence_number,
            command=command.command,
            output=command.output,
            executed_at=command.executed_at,
            matched_terms=[],
            risk_findings=classify_command_risks(command.command or ""),
        )
