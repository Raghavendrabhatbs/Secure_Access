from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.query_understanding_service import COMMAND_STOP_WORDS, QueryPlan
from app.services.risk_aggregator import aggregate_session_risks
from app.services.session_query_service import SessionQueryService


@dataclass
class RetrievedEvidence:
    plan: QueryPlan
    sessions: list[Any] = field(default_factory=list)
    commands_by_session: dict[str, list[Any]] = field(default_factory=dict)
    events_by_session: dict[str, list[Any]] = field(default_factory=dict)

    @property
    def evidence_available(self) -> bool:
        return bool(self.sessions or self.commands_by_session or self.events_by_session)


class EvidenceRetrievalService:
    def __init__(self, session_query_service: SessionQueryService):
        self._session_query_service = session_query_service

    def retrieve(self, plan: QueryPlan, limit: int = 20) -> RetrievedEvidence:
        sessions = self._resolve_sessions(plan, limit=limit)
        if plan.users:
            allowed_users = {user.lower() for user in plan.users}
            sessions = [
                session
                for session in sessions
                if (session.username or "").lower() in allowed_users
            ]
        if plan.risk_severity:
            sessions = self._filter_sessions_by_risk_severity(sessions, plan.risk_severity)

        evidence = RetrievedEvidence(plan=plan, sessions=sessions)

        for session in sessions:
            session_identifier = session.session_id or session.unique_id
            if "commands" in plan.needs or "risk_findings" in plan.needs:
                commands = (
                    self._session_query_service.get_command_evidence(session_identifier)
                )
                if plan.command:
                    command_text = plan.command.lower()
                    commands = [
                        command for command in commands
                        if command_text in (command.command or "").lower()
                    ]
                evidence.commands_by_session[session_identifier] = commands
            if "events" in plan.needs or "timeline" in plan.needs:
                evidence.events_by_session[session_identifier] = (
                    self._session_query_service.get_events(session_identifier)
                )

        return evidence

    def _resolve_sessions(self, plan: QueryPlan, limit: int) -> list[Any]:
        if plan.session_id:
            session = self._session_query_service.get_session(plan.session_id)
            return [session] if session is not None else []

        if plan.scope == "latest_session":
            sessions = self._session_query_service.list_sessions(limit=limit)
            return sessions[:1]

        if plan.date_range is not None:
            start_date, end_date = plan.date_range
            return self._session_query_service.list_sessions_started_between(
                start_date,
                end_date,
                limit=limit,
            )

        if plan.risk_categories:
            return self._sessions_from_matches(
                self._session_query_service.search_sessions_by_risk_categories(plan.risk_categories, limit=limit)
            )

        if plan.risk_severity:
            return self._sessions_from_matches(
                self._session_query_service.search_sessions_by_risk_severity(plan.risk_severity, limit=limit)
            )

        if plan.command:
            normalized_command = plan.command.strip().lower()
            if normalized_command in COMMAND_STOP_WORDS:
                if plan.risk_domain_query and "risk_findings" in plan.needs:
                    return self._sessions_from_matches(
                        self._session_query_service.search_sessions_with_risk_findings(limit=limit)
                    )
                fallback_plan = QueryPlan(
                    question=plan.question,
                    query_type=plan.query_type,
                    date_range=plan.date_range,
                    session_id=plan.session_id,
                    command=None,
                    users=plan.users,
                    scope="latest_session" if plan.scope == "all" else plan.scope,
                    needs=plan.needs,
                    risk_categories=plan.risk_categories,
                    risk_severity=plan.risk_severity,
                    risk_domain_query=plan.risk_domain_query,
                    analysis=plan.analysis,
                )
                return self._resolve_sessions(fallback_plan, limit=limit)

            matches = self._session_query_service.search_sessions_by_command_terms(
                [plan.command], limit=limit
            )
            return self._sessions_from_matches(matches)

        if plan.risk_domain_query and "risk_findings" in plan.needs:
            return self._sessions_from_matches(
                self._session_query_service.search_sessions_with_risk_findings(limit=limit)
            )

        return self._session_query_service.list_sessions(limit=limit)

    def _sessions_from_matches(self, matches: list[Any]) -> list[Any]:
        sessions = []
        for match in matches:
            session = self._session_query_service.get_session(match.session_id)
            if session is not None:
                sessions.append(session)
        return sessions

    def _filter_sessions_by_risk_severity(self, sessions: list[Any], severity: str) -> list[Any]:
        normalized_severity = (severity or "").strip().upper()
        if normalized_severity not in {"HIGH", "MEDIUM", "LOW"}:
            return sessions

        filtered: list[Any] = []
        for session in sessions:
            session_identifier = session.session_id or session.unique_id
            commands = self._session_query_service.get_command_evidence(session_identifier)
            findings = [
                finding
                for command in commands
                for finding in getattr(command, "risk_findings", [])
            ]
            if not findings and normalized_severity == "LOW":
                if (session.risk or "NONE").upper() in {"NONE", "LOW", ""}:
                    filtered.append(session)
                continue
            risk_summary = aggregate_session_risks(findings)
            if risk_summary.overall_severity == normalized_severity:
                filtered.append(session)
        return filtered