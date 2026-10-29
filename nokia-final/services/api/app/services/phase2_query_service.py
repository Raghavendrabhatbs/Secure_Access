from __future__ import annotations

import re
from datetime import date
from typing import Any

from app.services.analytics_query_service import AnalyticsQueryService, DailySummary
from app.services.query_understanding_service import (
    configured_today,
    extract_comparison_dates,
    extract_date_range,
    extract_hour_range,
)
from app.services.risk_search import extract_risk_categories
from app.services.session_query_service import SessionQueryService
from app.services.timeline_analyzer import analyze_timeline
from app.services.timeline_response import format_timeline_summary

SESSION_ID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


class Phase2QueryService:
    """Deterministic handlers for Phase 2 timeline and security-depth questions."""

    def __init__(self, session_query_service: SessionQueryService):
        self._sessions = session_query_service
        self._analytics = AnalyticsQueryService(session_query_service)

    def try_answer(self, question: str, session_id: str | None = None) -> dict[str, Any] | None:
        question_text = (question or "").strip()
        if not question_text:
            return None

        question_lower = question_text.lower()
        embedded_session_id = session_id or self._extract_session_id(question_text)
        date_range = extract_date_range(question_text)
        hour_range = extract_hour_range(question_text)
        comparison_dates = extract_comparison_dates(question_text)

        handlers = (
            self._try_compare_periods,
            self._try_hour_window_activity,
            self._try_first_privilege_escalation,
            self._try_most_dangerous_user,
            self._try_step_by_step_walkthrough,
            self._try_first_command_after_login,
        )

        for handler in handlers:
            result = handler(
                question_text=question_text,
                question_lower=question_lower,
                session_id=embedded_session_id,
                date_range=date_range,
                hour_range=hour_range,
                comparison_dates=comparison_dates,
            )
            if result is not None:
                return result
        return None

    def _try_hour_window_activity(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
        hour_range: tuple[int, int] | None,
        comparison_dates: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if hour_range is None:
            return None
        if not any(
            term in question_lower
            for term in ("between", "from", "activity", "session", "command", "access", "happened")
        ):
            return None

        start_hour, end_hour = hour_range
        target_date = None
        if date_range is not None:
            start_date, end_date = date_range
            if start_date == end_date:
                target_date = start_date
        if target_date is None:
            if "today" in question_lower:
                target_date = configured_today()
            else:
                return None

        sessions = self._analytics.sessions_in_hour_window(target_date, start_hour, end_hour)
        commands = self._analytics.commands_in_hour_window(target_date, start_hour, end_hour)
        label = target_date.isoformat()
        window_label = f"{start_hour:02d}:00–{end_hour:02d}:59 UTC"

        if not sessions and not commands:
            return self._result(
                f"No SSH activity was recorded between {window_label} on {label}.",
                intent="TEMPORAL_ACCESS",
                evidence_available=False,
                evidence_summary=f"No activity in hour window on {label}.",
            )

        users = sorted({session.username or "unknown" for session in sessions})
        lines = [
            f"Activity between {window_label} on {label}:",
            f"- {len(sessions)} session(s) started",
            f"- {len(commands)} command(s) executed",
        ]
        if users:
            lines.append(f"- Users: {', '.join(users)}")
        if commands:
            lines.append("")
            lines.append("Commands:")
            for index, (session, item) in enumerate(commands[:10], start=1):
                when = item.executed_at.isoformat() if item.executed_at else "unknown time"
                lines.append(
                    f"{index}. {when} | {session.username or 'unknown'} | `{item.command}`"
                )
        return self._result(
            "\n".join(lines),
            intent="TEMPORAL_ACCESS",
            evidence_available=True,
            evidence_summary=(
                f"Matched {len(sessions)} session(s) and {len(commands)} command(s) "
                f"between {window_label} on {label}."
            ),
        )

    def _try_first_privilege_escalation(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
        hour_range: tuple[int, int] | None,
        comparison_dates: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if "first" not in question_lower:
            return None
        if not any(
            term in question_lower
            for term in ("privilege escalation", "priv esc", "priv-esc", "sudo")
        ):
            categories = extract_risk_categories(question_text)
            if "PRIVILEGE_ESCALATION" not in categories:
                return None

        target_date = None
        if date_range is not None:
            start_date, end_date = date_range
            if start_date == end_date:
                target_date = start_date
        if target_date is None:
            if "today" in question_lower:
                target_date = configured_today()
            else:
                return None

        record = self._analytics.first_risk_finding_on_date(target_date, "PRIVILEGE_ESCALATION")
        label = target_date.isoformat()
        if record is None:
            return self._result(
                f"No privilege escalation was recorded on {label}.",
                intent="RISK_ANALYSIS",
                evidence_available=False,
                evidence_summary=f"No PRIVILEGE_ESCALATION findings on {label}.",
            )

        when = record.executed_at.isoformat() if record.executed_at else "unknown time"
        return self._result(
            f"The first privilege escalation on {label} was at {when}: "
            f"user `{record.username or 'unknown'}` ran `{record.command}` "
            f"in session {record.session_id} ({record.severity}).",
            intent="RISK_ANALYSIS",
            evidence_available=True,
            evidence_summary=f"First PRIVILEGE_ESCALATION on {label} at {when}.",
            session_id=record.session_id,
        )

    def _try_most_dangerous_user(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
        hour_range: tuple[int, int] | None,
        comparison_dates: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not any(
            phrase in question_lower
            for phrase in (
                "most dangerous user",
                "riskiest user",
                "most risky user",
                "dangerous user",
                "rank users by risk",
                "user risk ranking",
            )
        ):
            return None

        if not date_range:
            date_range = extract_date_range("this week")

        start_date, end_date = date_range or (configured_today(), configured_today())
        ranked = self._analytics.rank_users_by_risk(start_date, end_date, limit=10)
        label = (
            start_date.isoformat()
            if start_date == end_date
            else f"{start_date.isoformat()} to {end_date.isoformat()}"
        )

        if not ranked:
            return self._result(
                f"No risky activity was recorded for any user during {label}.",
                intent="CROSS_SESSION_ANALYSIS",
                evidence_available=False,
                evidence_summary=f"No user risk scores for {label}.",
            )

        lines = [f"Most dangerous users for {label} (by risk score):"]
        for index, entry in enumerate(ranked, start=1):
            lines.append(
                f"{index}. `{entry.username}` — score {entry.score} "
                f"({entry.high_findings} HIGH, {entry.medium_findings} MEDIUM, "
                f"{entry.low_findings} LOW across {entry.session_count} session(s))"
            )
        return self._result(
            "\n".join(lines),
            intent="CROSS_SESSION_ANALYSIS",
            evidence_available=True,
            evidence_summary=f"Ranked {len(ranked)} user(s) by risk for {label}.",
        )

    def _try_step_by_step_walkthrough(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
        hour_range: tuple[int, int] | None,
        comparison_dates: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not any(
            phrase in question_lower
            for phrase in (
                "step by step",
                "step-by-step",
                "walk me through",
                "walkthrough",
                "walk through",
            )
        ):
            return None

        if not session_id:
            latest = self._sessions.list_sessions(limit=1)
            if latest and any(term in question_lower for term in ("latest", "recent", "last session")):
                session_id = latest[0].session_id or latest[0].unique_id
            else:
                return self._result(
                    "Provide a session UUID to walk through step by step, "
                    "or ask for the latest session walkthrough.",
                    intent="TIMELINE_QUERY",
                    evidence_available=False,
                    evidence_summary="Session ID required for walkthrough.",
                )

        session = self._sessions.get_session(session_id)
        if session is None:
            return self._result(
                f"Session `{session_id}` was not found in PostgreSQL.",
                intent="TIMELINE_QUERY",
                evidence_available=False,
                evidence_summary=f"Session {session_id} not found.",
                session_id=session_id,
            )

        entries = self._sessions.get_session_timeline(session_id)
        analysis = analyze_timeline(entries)
        timeline = [
            {
                "timestamp": entry.timestamp,
                "sequence_number": entry.sequence_number,
                "event_type": entry.event_type,
                "command": entry.command,
                "output": entry.output,
                "risk_findings": [
                    {"category": finding.category, "severity": finding.severity, "rule": finding.rule}
                    for finding in entry.risk_findings
                ],
            }
            for entry in entries
        ]
        analysis_dict = {
            "entry_count": analysis.entry_count,
            "command_count": analysis.command_count,
            "event_count": analysis.event_count,
            "overall_severity": analysis.overall_severity,
            "risk_categories": list(analysis.risk_categories),
        }
        answer = format_timeline_summary(timeline, analysis_dict)
        return self._result(
            answer,
            intent="TIMELINE_QUERY",
            evidence_available=bool(entries),
            evidence_summary=f"Step-by-step walkthrough for session {session_id}.",
            session_id=session_id,
        )

    def _try_first_command_after_login(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
        hour_range: tuple[int, int] | None,
        comparison_dates: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not any(
            phrase in question_lower
            for phrase in (
                "first command after login",
                "first action after login",
                "first thing after login",
                "first command after logging in",
            )
        ):
            return None
        if not session_id:
            return None

        session = self._sessions.get_session(session_id)
        if session is None:
            return self._result(
                f"Session `{session_id}` was not found in PostgreSQL.",
                intent="COMMAND_LOOKUP",
                evidence_available=False,
                evidence_summary=f"Session {session_id} not found.",
                session_id=session_id,
            )

        item = self._analytics.first_command_after_login(session_id)
        if item is None or not item.command:
            return self._result(
                f"No command was recorded after login for session `{session_id}`.",
                intent="COMMAND_LOOKUP",
                evidence_available=False,
                evidence_summary=f"No post-login command for session {session_id}.",
                session_id=session_id,
            )

        when = item.executed_at.isoformat() if item.executed_at else "unknown time"
        return self._result(
            f"The first command after login in session `{session_id}` "
            f"({session.username or 'unknown'}) was `{item.command}` at {when}.",
            intent="COMMAND_LOOKUP",
            evidence_available=True,
            evidence_summary=f"First post-login command for session {session_id}.",
            session_id=session_id,
        )

    def _try_compare_periods(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
        hour_range: tuple[int, int] | None,
        comparison_dates: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if comparison_dates is None:
            return None
        if "baseline" in question_lower:
            return None

        date_a, date_b = comparison_dates
        comparison = self._analytics.compare_daily_summaries(date_a, date_b)
        answer = self._format_daily_comparison(comparison.summary_a, comparison.summary_b)
        has_evidence = comparison.summary_a.session_count > 0 or comparison.summary_b.session_count > 0
        return self._result(
            answer,
            intent="CROSS_SESSION_ANALYSIS",
            evidence_available=has_evidence,
            evidence_summary=f"Compared {comparison.date_a} vs {comparison.date_b}.",
        )

    def _format_daily_comparison(self, summary_a: DailySummary, summary_b: DailySummary) -> str:
        def line(label: str, left: int | str, right: int | str) -> str:
            return f"- {label}: {left} vs {right}"

        lines = [
            f"Comparison: {summary_a.date_label} vs {summary_b.date_label}",
            "",
            line("Sessions", summary_a.session_count, summary_b.session_count),
            line("Users", len(summary_a.users), len(summary_b.users)),
            line("Commands", summary_a.command_count, summary_b.command_count),
            line("HIGH-risk sessions", summary_a.high_risk_sessions, summary_b.high_risk_sessions),
            line("MEDIUM-risk sessions", summary_a.medium_risk_sessions, summary_b.medium_risk_sessions),
            line("LOW-risk sessions", summary_a.low_risk_sessions, summary_b.low_risk_sessions),
        ]

        delta_sessions = summary_a.session_count - summary_b.session_count
        delta_high = summary_a.high_risk_sessions - summary_b.high_risk_sessions
        if delta_sessions or delta_high:
            lines.append("")
            if delta_sessions > 0:
                lines.append(f"{summary_a.date_label} had {delta_sessions} more session(s).")
            elif delta_sessions < 0:
                lines.append(f"{summary_b.date_label} had {-delta_sessions} more session(s).")
            else:
                lines.append("Session count was unchanged.")

            if delta_high > 0:
                lines.append(f"{summary_a.date_label} had {delta_high} more HIGH-risk session(s).")
            elif delta_high < 0:
                lines.append(f"{summary_b.date_label} had {-delta_high} more HIGH-risk session(s).")

        return "\n".join(lines)

    def _extract_session_id(self, question: str) -> str | None:
        match = SESSION_ID_RE.search(question or "")
        return match.group(0) if match else None

    def _result(
        self,
        answer: str,
        *,
        intent: str,
        evidence_available: bool,
        evidence_summary: str,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "answer": answer,
            "intent": intent,
            "retrieval_mode": "rule-based",
            "session_id": session_id,
            "evidence_available": evidence_available,
            "evidence_summary": evidence_summary,
        }
