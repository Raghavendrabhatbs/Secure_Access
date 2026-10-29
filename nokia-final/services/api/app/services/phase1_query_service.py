from __future__ import annotations

import re
from datetime import date, datetime, timedelta
from collections import Counter
from typing import Any

from app.services.analytics_query_service import AnalyticsQueryService
from app.services.query_understanding_service import (
    COMMAND_STOP_WORDS,
    QueryUnderstandingService,
    configured_today,
    extract_date_range,
)
from app.services.session_query_service import SessionQueryService

LAST_N_USERS_RE = re.compile(r"\blast\s+(\d+)\s+users?\b", re.IGNORECASE)
COMMAND_TERM_RE = re.compile(
    r"\b(?:run|ran|execute|executed|use|used)\s+[`']?([/\w.-]+)[`']?",
    re.IGNORECASE,
)
WAS_COMMAND_RUN_PATTERNS = (
    re.compile(r"\bwas\s+(.+?)\s+command\s+run\b", re.IGNORECASE),
    re.compile(r"\bwere\s+(.+?)\s+command\s+run\b", re.IGNORECASE),
    re.compile(r"\bwas\s+(.+?)\s+run\s+recently\b", re.IGNORECASE),
    re.compile(r"\bwere\s+(.+?)\s+run\s+recently\b", re.IGNORECASE),
    re.compile(r"\bwas\s+(.+?)\s+executed\s+recently\b", re.IGNORECASE),
    re.compile(r"\bwere\s+(.+?)\s+executed\s+recently\b", re.IGNORECASE),
)
SESSION_ID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
DATE_COMMAND_PHRASES = (
    "what is the date command",
    "what does the date command",
    "explain the date command",
    "date command do",
    "date command mean",
)


def _is_list_all_session_ids_query(question_lower: str) -> bool:
    """Detects: 'give me all session ids', 'list all session ids', 'show me the 63 session ids', etc."""
    if any(phrase in question_lower for phrase in DATE_COMMAND_PHRASES):
        return False
    if "risk" in question_lower or "risky" in question_lower or "important" in question_lower:
        return False
    # Definitional questions ('what is a session id', 'what does session id mean') are not listings.
    if any(
        phrase in question_lower
        for phrase in (
            "what is a session id",
            "what is session id",
            "what does session id",
            "what's a session id",
            "whats a session id",
            "meaning of session id",
            "session id mean",
        )
    ):
        return False
    # Must mention session(s)
    if "session" not in question_lower:
        return False
    # Must mention id / ids / uuid / uuids (either separate word or joined phrase).
    mentions_id = any(
        marker in question_lower
        for marker in (
            " id", " ids", "session id", "session ids", "sessions id", "sessions ids",
            "session-id", "session-ids", "uuid", "uuids", "identifier",
        )
    )
    # A bare "sessions id" (no separator) or trailing "id"/"ids" also counts.
    if question_lower.rstrip(" ?.!").endswith((" id", " ids")):
        mentions_id = True
    if not mentions_id:
        return False
    # Must be a listing / retrieval request, or a short bare phrase like "session ids".
    listing_intent = any(
        term in question_lower
        for term in (
            "give me", "list", "show", "show me", "display", "print", "get",
            "all", "every", "available", "please", "kindly", "need",
        )
    )
    word_count = len(question_lower.split())
    if not listing_intent and word_count > 4:
        return False
    # Avoid overlap with the command-list / command-explanation handlers.
    if "command" in question_lower or "commands" in question_lower:
        return False
    if "executed" in question_lower and "session" not in question_lower:
        return False
    return True


def _is_sessions_with_dates_query(question_lower: str) -> bool:
    if "session" not in question_lower:
        return False
    if any(phrase in question_lower for phrase in DATE_COMMAND_PHRASES):
        return False
    if any(
        term in question_lower
        for term in ("important", "notable", "critical", "significant", "risky", "risk", "dangerous")
    ):
        return False
    if any(
        phrase in question_lower
        for phrase in (
            "sessions with date",
            "sessions with dates",
            "session with date",
            "sessions and date",
            "sessions and dates",
            "dates of the session",
            "dates of sessions",
            "date of the session",
            "date of sessions",
            "session dates",
            "sessions with their date",
            "sessions with their dates",
            "list sessions with date",
            "give me the sessions with date",
        )
    ):
        return True
    if "dates of" in question_lower:
        return True
    if ("with date" in question_lower or "with dates" in question_lower) and "command" not in question_lower:
        return True
    if any(
        phrase in question_lower
        for phrase in (
            "sessions with start time",
            "sessions with their start time",
            "sessions with start times",
            "sessions with their start times",
            "session start times",
            "start time of the session",
            "start times of sessions",
            "list sessions with start time",
        )
    ):
        return True
    if ("with start time" in question_lower or "with their start time" in question_lower) and "command" not in question_lower:
        return True
    if "start time" in question_lower and "command" not in question_lower:
        return True
    return False


def _is_user_sessions_by_date_query(question_lower: str) -> bool:
    return (
        "session" in question_lower
        and any(term in question_lower for term in ("list", "show", "give", "display", "how many"))
        and any(term in question_lower for term in ("by date", "date wise", "date-wise", "per day", "each day", "daily", "with date", "with dates"))
    )


def _is_user_today_timing_query(question_lower: str) -> bool:
    return (
        "today" in question_lower
        and any(term in question_lower for term in ("logged in", "log in", "login", "session", "sessions"))
        and any(term in question_lower for term in ("what time", "from what time", "time to", "when"))
    )


def _is_session_status_query(question_lower: str) -> bool:
    return "session" in question_lower and any(
        term in question_lower
        for term in ("active", "inactive", "running", "ongoing", "open", "live", "closed", "ended", "completed", "finished")
    )


def _is_user_total_sessions_query(question_lower: str) -> bool:
    return (
        "session" in question_lower
        and any(term in question_lower for term in ("total", "how many", "how much", "times"))
        and any(term in question_lower for term in (" does ", " did ", "'s session", " by ", "admin"))
        and "active" not in question_lower
        and "inactive" not in question_lower
        and not any(term in question_lower for term in ("today", "yesterday", "this week", "this month", "last week", "last month"))
        and not _is_user_sessions_by_date_query(question_lower)
    )


def _is_remaining_sessions_by_user_query(question_lower: str) -> bool:
    return (
        "session" in question_lower
        and any(term in question_lower for term in ("rest", "remaining", "other"))
        and any(term in question_lower for term in ("by whom", "who", "executed by", "user", "users"))
    )


def _is_busiest_date_query(question_lower: str) -> bool:
    return "session" in question_lower and any(
        phrase in question_lower
        for phrase in ("most sessions", "busiest", "highest sessions", "most active day", "which date had")
    )


def _is_session_timing_query(question_lower: str) -> bool:
    has_timing_phrase = any(
        term in question_lower
        for term in ("what time", "login time", "logout time", "login and logout", "from what time", "timing", "login to logout", "start time", "end time")
    )
    return has_timing_phrase and (
        "session" in question_lower
        or "login" in question_lower
        or "logout" in question_lower
    )


def _is_duration_query(question_lower: str) -> bool:
    return any(
        phrase in question_lower
        for phrase in (
            "longest session",
            "which session was longest",
            "session was the longest",
            "shortest session",
            "which session was shortest",
            "session was the shortest",
            "average duration",
            "average session duration",
        )
    )


def _is_last_login_query(question_lower: str) -> bool:
    return (
        "logged in" in question_lower
        and any(term in question_lower for term in ("last", "latest", "most recent", "recently"))
    ) or question_lower in {"last login", "latest login", "who logged in last"}


def _is_privilege_escalation_presence_query(question_lower: str) -> bool:
    return (
        any(
            phrase in question_lower
            for phrase in ("privilege escalation", "privilage escalation", "priviledge escalation")
        )
        and any(term in question_lower for term in ("any", "were there", "did", "attempt", "attempts", "occurred"))
        and "first" not in question_lower
    )


def _is_highest_risk_session_query(question_lower: str) -> bool:
    return "session" in question_lower and "which user" not in question_lower and any(
        phrase in question_lower
        for phrase in ("most risk", "highest risk", "riskiest session", "most risky")
    )


def _is_session_date_lookup_query(question_lower: str, session_id: str | None) -> bool:
    if not session_id:
        return False
    if any(phrase in question_lower for phrase in DATE_COMMAND_PHRASES):
        return False
    if "first command" in question_lower or "last command" in question_lower:
        return False
    if any(
        phrase in question_lower
        for phrase in (
            "when was session",
            "when was this session",
            "when did session",
            "when did this session",
            "what date was session",
            "what date was this session",
            "date of session",
            "date of this session",
            "on which date was session",
            "on what date was session",
            "which date was session",
        )
    ):
        return True
    session_id_lower = session_id.lower()
    if session_id_lower not in question_lower:
        return False
    if any(term in question_lower for term in ("when", "what date", "which date", "on what date", "on which date")):
        if "command" in question_lower and "session" not in question_lower:
            return False
        return True
    if "executed" in question_lower and "command" not in question_lower:
        return True
    return False


class Phase1QueryService:
    """Deterministic handlers for Phase 1 analyst questions."""

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

        handlers = (
            self._try_last_login,
            self._try_privilege_escalation_presence,
            self._try_highest_risk_session,
            self._try_session_status,
            self._try_remaining_sessions_by_user,
            self._try_user_total_sessions,
            self._try_busiest_date,
            self._try_broad_session_analytics,
            self._try_session_timings,
            self._try_user_session_duration,
            self._try_duration_query,
            self._try_daily_summary,
            self._try_last_n_users,
            self._try_last_hour_access,
            self._try_user_today_timing,
            self._try_session_count,
            self._try_list_sessions_for_date,
            self._try_list_all_session_ids,
            self._try_user_sessions_by_date,
            self._try_list_sessions_with_dates,
            self._try_session_date_lookup,
            self._try_most_frequent_user,
            self._try_busiest_hour,
            self._try_high_risk_percentage,
            self._try_high_risk_count,
            self._try_all_commands_frequency,
            self._try_command_frequency,
            self._try_command_run_recently,
            self._try_sudo_or_command_on_date,
            self._try_session_timing,
            self._try_first_or_last_command,
        )

        for handler in handlers:
            result = handler(
                question_text=question_text,
                question_lower=question_lower,
                session_id=embedded_session_id,
                date_range=date_range,
            )
            if result is not None:
                return result
        return None

    def _try_broad_session_analytics(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if session_id or (
            "command" in question_lower
            and "most commands" not in question_lower
            and "total commands" not in question_lower
            and not any(
            term in question_lower for term in ("session", "accessed", "logged", "login")
            )
        ):
            return None
        if any(term in question_lower for term in ("risk", "risky", "dangerous", "suspicious")):
            return None

        sessions = self._analytics.all_unique_sessions()
        period_sessions = (
            self._analytics.sessions_for_dates(*date_range) if date_range else sessions
        )
        is_count = "how many" in question_lower or "count" in question_lower or "number of" in question_lower
        is_listing = any(term in question_lower for term in ("show me", "show", "list", "sessions from"))
        label = (
            date_range[0].isoformat()
            if date_range and date_range[0] == date_range[1]
            else f"{date_range[0].isoformat()} to {date_range[1].isoformat()}"
            if date_range
            else "all recorded time"
        )

        if "zero command" in question_lower:
            zero = [session for session in sessions if self._analytics.command_count(session) == 0]
            return self._result(
                f"{len(zero)} session(s) have zero recorded commands.",
                intent="SESSION_COUNT", evidence_available=True,
                evidence_summary=f"Counted zero-command sessions across all recorded sessions.",
            )

        if "most active user" in question_lower or "most commands" in question_lower or "most total commands" in question_lower:
            command_counts: Counter[str] = Counter()
            for session in sessions:
                command_counts[session.username or "unknown"] += self._analytics.command_count(session)
            if "most active user" in question_lower:
                session_counts = Counter(session.username or "unknown" for session in period_sessions)
                username, count = session_counts.most_common(1)[0] if session_counts else ("unknown", 0)
                return self._result(f"Most active user for {label}: {username} with {count} session(s).", intent="CROSS_SESSION_ANALYSIS", evidence_available=bool(session_counts), evidence_summary=f"Ranked users by session count for {label}.")
            username, count = command_counts.most_common(1)[0] if command_counts else ("unknown", 0)
            return self._result(f"User with the most commands: {username} with {count} command(s).", intent="CROSS_SESSION_ANALYSIS", evidence_available=bool(command_counts), evidence_summary="Ranked users by recorded command count.")

        if "highest risk sessions" in question_lower or "highest risk session" in question_lower or "most dangerous user" in question_lower:
            scores: Counter[str] = Counter()
            for session in sessions:
                findings = [finding for command in self._sessions.get_command_evidence(session.session_id or session.unique_id) for finding in command.risk_findings]
                scores[session.username or "unknown"] += sum({"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(finding.severity, 0) for finding in findings)
            username, score = scores.most_common(1)[0] if scores else ("unknown", 0)
            return self._result(f"User with the highest-risk sessions: {username} (risk score {score}).", intent="RISK_ANALYSIS", evidence_available=bool(scores), evidence_summary="Ranked users by aggregated session risk.")

        if "first ever log in" in question_lower or "first ever login" in question_lower or "last log in" in question_lower or "last login" in question_lower:
            username = "admin" if "admin" in question_lower else None
            candidates = [session for session in sessions if not username or (session.username or '').lower() == username]
            candidates = [session for session in candidates if session.started_at or session.login_time]
            if candidates:
                first = "first" in question_lower
                selected = (min if first else max)(candidates, key=lambda item: (item.started_at or item.login_time).isoformat())
                timestamp = selected.started_at or selected.login_time
                boundary = "first" if first else "last"
                return self._result(f"{selected.username or 'unknown'} {boundary} login was at {timestamp.isoformat()} in session {selected.session_id or selected.unique_id}.", intent="TEMPORAL_ACCESS", evidence_available=True, evidence_summary="Retrieved user login boundary.")

        if "more than once today" in question_lower or "only user" in question_lower or question_lower.startswith("did anyone access") or question_lower.startswith("did admin access"):
            today_sessions = self._analytics.sessions_for_dates(configured_today(), configured_today())
            if "admin" in question_lower:
                admin_count = sum(1 for session in today_sessions if (session.username or '').lower() == 'admin')
                if "more than once" in question_lower:
                    answer = f"Yes, admin logged in {admin_count} time(s) today." if admin_count > 1 else f"No, admin logged in {admin_count} time(s) today."
                else:
                    answer = f"Yes, admin accessed the system today ({admin_count} session(s))." if admin_count else "No, admin did not access the system today."
            else:
                users = sorted({session.username or 'unknown' for session in today_sessions})
                answer = f"Yes, only admin accessed the system today." if users == ['admin'] else f"Users accessing today: {', '.join(users) or 'none'}."
            return self._result(answer, intent="TEMPORAL_ACCESS", evidence_available=bool(today_sessions), evidence_summary="Checked today's access records.")

        if "most recently" in question_lower and "user" in question_lower:
            latest = self._analytics.latest_user_login()
            answer = f"The most recent user was {latest.username or 'unknown'} at {(latest.started_at or latest.login_time).isoformat()}." if latest else "No login records were found."
            return self._result(answer, intent="TEMPORAL_ACCESS", evidence_available=latest is not None, evidence_summary="Retrieved the latest user login.")

        if any(term in question_lower for term in ("earliest login", "latest login", "earliest logout", "latest logout", "first session start", "last session end", "started earliest", "ended latest", "all login times", "all logout times", "login and logout times")):
            target_sessions = period_sessions
            use_logout = "logout" in question_lower or "ended" in question_lower or "end" in question_lower
            values = [(session, session.ended_at or session.logout_time if use_logout else session.started_at or session.login_time) for session in target_sessions]
            values = [(session, value) for session, value in values if value]
            if values:
                if "all " in question_lower or "all sessions" in question_lower or "login and logout times" in question_lower:
                    lines = [f"All sessions on {label} with {'logout' if use_logout else 'login'} times:"]
                    lines.extend(f"- {session.session_id or session.unique_id}: {value.isoformat()}" for session, value in sorted(values, key=lambda pair: pair[1]))
                    answer = "\n".join(lines)
                else:
                    first = "earliest" in question_lower or "first" in question_lower
                    selected = (min if first else max)(values, key=lambda pair: pair[1])
                    answer = f"{'Earliest' if first else 'Latest'} {'logout' if use_logout else 'login'}: {selected[1].isoformat()} (session {selected[0].session_id or selected[0].unique_id})."
                return self._result(answer, intent="SESSION_TIMING", evidence_available=True, evidence_summary=f"Retrieved session {'logout' if use_logout else 'login'} times for {label}.")

            if any(term in question_lower for term in ("login", "logout", "earliest", "latest", "started", "ended")):
                return self._result(
                    f"No sessions with recorded {'logout' if use_logout else 'login'} times were found for {label}.",
                    intent="SESSION_TIMING", evidence_available=False,
                    evidence_summary=f"No session times found for {label}.",
                )

        duration_match = re.search(r"(?:more|less) than\s+(\d+)\s+minute", question_lower)
        if duration_match:
            threshold = int(duration_match.group(1)) * 60
            longer = "more than" in question_lower
            matched = [session for session in sessions if self._analytics._duration_seconds(session) is not None and ((self._analytics._duration_seconds(session) or 0) > threshold if longer else (self._analytics._duration_seconds(session) or 0) < threshold)]
            return self._result(f"{len(matched)} session(s) lasted {'more' if longer else 'less'} than {duration_match.group(1)} minute(s).", intent="SESSION_COUNT", evidence_available=True, evidence_summary="Filtered sessions by duration.")

        if "hours was the system accessed" in question_lower or "how long was the system accessed" in question_lower:
            total_seconds = sum(self._analytics._duration_seconds(session) or 0 for session in period_sessions)
            return self._result(f"The system was accessed for approximately {round(total_seconds / 3600, 2)} hour(s) during {label}.", intent="SESSION_STATS", evidence_available=bool(period_sessions), evidence_summary=f"Summed session durations for {label}.")

        if "unique user" in question_lower or "unique users" in question_lower:
            users = sorted({(session.username or "unknown").strip() for session in period_sessions})
            return self._result(
                f"{len(users)} unique user(s) accessed the system for {label}: {', '.join(users) or 'none'}.",
                intent="CROSS_SESSION_ANALYSIS", evidence_available=bool(users),
                evidence_summary=f"Counted {len(users)} unique user(s) for {label}.",
            )

        if "weekend" in question_lower or "weekday" in question_lower:
            weekend = sum(1 for session in sessions if (session.started_at or session.login_time).weekday() >= 5)
            value = weekend if "weekend" in question_lower else len(sessions) - weekend
            kind = "weekend" if "weekend" in question_lower else "weekday"
            return self._result(
                f"{value} session(s) occurred on {kind}s.", intent="SESSION_COUNT",
                evidence_available=True, evidence_summary=f"Counted {kind} sessions.",
            )

        if any(term in question_lower for term in ("oldest session", "first session ever", "first session")):
            candidates = [session for session in sessions if session.started_at or session.login_time]
            oldest = min(candidates, key=lambda session: (session.started_at or session.login_time).isoformat(), default=None)
            if oldest is None:
                return self._result("No dated sessions were found.", intent="SESSION_LOOKUP", evidence_available=False, evidence_summary="No dated sessions.")
            started = oldest.started_at or oldest.login_time
            return self._result(
                f"Oldest session: {oldest.session_id or oldest.unique_id} by {oldest.username or 'unknown'} at {started.isoformat()}.",
                intent="SESSION_LOOKUP", evidence_available=True, evidence_summary="Retrieved the oldest recorded session.",
            )

        if "quietest day" in question_lower or "busiest week" in question_lower or "week had the most" in question_lower or "month had the most" in question_lower:
            buckets: Counter[str] = Counter()
            for session in sessions:
                timestamp = session.started_at or session.login_time
                if not timestamp:
                    continue
                local_date = timestamp.astimezone(__import__("app.services.query_understanding_service", fromlist=["configured_timezone"]).configured_timezone()).date()
                if "week" in question_lower:
                    key = f"{local_date.isocalendar().year}-W{local_date.isocalendar().week:02d}"
                elif "month" in question_lower:
                    key = local_date.strftime("%Y-%m")
                else:
                    key = local_date.isoformat()
                buckets[key] += 1
            if not buckets:
                return self._result("No dated session data is available.", intent="SESSION_STATS", evidence_available=False, evidence_summary="No dated sessions.")
            choose_min = "quietest" in question_lower
            key, count = (min if choose_min else max)(buckets.items(), key=lambda item: (item[1], item[0]))
            return self._result(
                f"{'Quietest' if choose_min else 'Busiest'} period: {key} with {count} session(s).",
                intent="SESSION_STATS", evidence_available=True, evidence_summary=f"Ranked session {('days' if not ('week' in question_lower or 'month' in question_lower) else 'periods')}.",
            )

        if "admin" in question_lower and any(term in question_lower for term in ("today", "this week", "this month", "yesterday")) and is_count:
            admin_sessions = [session for session in period_sessions if (session.username or '').lower() == 'admin']
            return self._result(
                f"admin had {len(admin_sessions)} session(s) for {label}.", intent="SESSION_COUNT", evidence_available=True,
                evidence_summary=f"Counted {len(admin_sessions)} admin session(s) for {label}.",
            )

        if "who accessed" in question_lower or "who accessed the system" in question_lower:
            users = sorted({session.username or "unknown" for session in period_sessions})
            return self._result(
                f"Users who accessed the system for {label}: {', '.join(users) or 'none'}.", intent="CROSS_SESSION_ANALYSIS",
                evidence_available=bool(users), evidence_summary=f"Listed users for {label}.",
            )

        if is_listing and date_range:
            lines = [f"Sessions for {label} ({len(period_sessions)}):"]
            for session in sorted(period_sessions, key=lambda item: (item.started_at or item.login_time).isoformat()):
                started = session.started_at or session.login_time
                lines.append(f"- {session.session_id or session.unique_id} | {session.username or 'unknown'} | {started.isoformat() if started else 'unknown'}")
            return self._result("\n".join(lines), intent="SESSION_LOOKUP", evidence_available=bool(period_sessions), evidence_summary=f"Listed {len(period_sessions)} session(s) for {label}.")

        if is_count and (date_range or any(term in question_lower for term in ("total", "ever", "database", "in total"))):
            return self._result(
                f"{len(period_sessions)} session(s) were recorded for {label}.", intent="SESSION_COUNT", evidence_available=True,
                evidence_summary=f"Counted {len(period_sessions)} session(s) for {label}.",
            )

        if "summary" in question_lower or "overview" in question_lower:
            users = sorted({session.username or "unknown" for session in period_sessions})
            commands = sum(self._analytics.command_count(session) for session in period_sessions)
            return self._result(
                f"Session summary for {label}: {len(period_sessions)} session(s), {len(users)} user(s), {commands} command(s). Users: {', '.join(users) or 'none'}.",
                intent="SESSION_SUMMARY", evidence_available=bool(period_sessions), evidence_summary=f"Summarized {len(period_sessions)} session(s) for {label}.",
            )
        return None

    def _try_daily_summary(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not any(
            phrase in question_lower
            for phrase in (
                "daily summary",
                "summarize",
                "summary for",
                "security audit",
                "audit report",
                "overview of",
                "overall risk level",
            )
        ):
            return None
        if any(
            phrase in question_lower
            for phrase in (
                "export",
                "download",
                "generate audit",
                "generate security",
                "full audit",
                "weekly audit",
                "audit export",
                "as json",
                "audit report for",
                "security audit report",
            )
        ):
            return None
        if not date_range:
            if "today" in question_lower:
                date_range = extract_date_range("today")
            else:
                return None

        start_date, end_date = date_range
        if start_date != end_date:
            return None

        summary = self._analytics.build_daily_summary(start_date)
        if summary.session_count == 0:
            latest = self._sessions.list_sessions(limit=1)
            hint = ""
            if latest:
                latest_date = latest[0].started_at.date().isoformat() if latest[0].started_at else "unknown"
                hint = f" The most recent session date in PostgreSQL is {latest_date}."
            return self._result(
                f"No SSH sessions were recorded on {summary.date_label}.{hint}",
                intent="SESSION_SUMMARY",
                evidence_available=False,
                evidence_summary=f"Matched 0 session(s) on {summary.date_label}.",
            )

        top_commands = ", ".join(f"{item.command} ({item.count})" for item in summary.top_commands)
        risky = ", ".join(summary.risky_commands) if summary.risky_commands else "none"
        answer = (
            f"Summary for {summary.date_label}: {summary.session_count} session(s), "
            f"{len(summary.users)} user(s) ({', '.join(summary.users)}), "
            f"{summary.command_count} command(s). "
            f"Risk: {summary.high_risk_sessions} HIGH, {summary.medium_risk_sessions} MEDIUM, "
            f"{summary.low_risk_sessions} LOW. "
            f"Top commands: {top_commands or 'none'}. "
            f"Risky commands: {risky}."
        )
        return self._result(
            answer,
            intent="SESSION_SUMMARY",
            evidence_available=True,
            evidence_summary=f"Daily summary for {summary.date_label} with {summary.session_count} session(s).",
        )

    def _try_session_status(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_session_status_query(question_lower):
            return None

        wants_active = (
            "active and inactive" in question_lower
            or "inactive and active" in question_lower
            or (
                "inactive" not in question_lower
                and any(term in question_lower for term in ("active", "running", "ongoing", "open", "live"))
            )
        )
        wants_inactive = any(term in question_lower for term in ("inactive", "closed", "ended", "completed", "finished"))
        active, inactive = self._analytics.session_status_counts()
        if wants_active and not wants_inactive:
            answer = f"{active} active session(s) right now."
        elif wants_inactive and not wants_active:
            answer = f"{inactive} inactive/completed session(s) in total."
        else:
            answer = f"Session summary:\n- Active (running now): {active}\n- Inactive (completed): {inactive}\n- Total: {active + inactive}"
        return self._result(
            answer,
            intent="SESSION_STATUS",
            evidence_available=True,
            evidence_summary=f"Counted {active} active and {inactive} inactive session(s).",
        )

    def _try_last_login(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_last_login_query(question_lower):
            return None
        session = self._analytics.latest_user_login()
        if session is None:
            return self._result(
                "No recorded logins were found.",
                intent="TEMPORAL_ACCESS",
                evidence_available=False,
                evidence_summary="No session login timestamps were found.",
            )
        login = session.started_at or session.login_time
        identifier = session.session_id or session.unique_id
        return self._result(
            f"The last login was by {session.username or 'unknown'} at {login.isoformat()} "
            f"in session `{identifier}`.",
            intent="TEMPORAL_ACCESS",
            evidence_available=True,
            evidence_summary="Retrieved the most recent session login.",
            session_id=identifier,
        )

    def _try_privilege_escalation_presence(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_privilege_escalation_presence_query(question_lower):
            return None
        sessions = self._analytics.sessions_with_risk_category("PRIVILEGE_ESCALATION")
        if not sessions:
            return self._result(
                "No privilege escalation attempts were recorded.",
                intent="RISK_ANALYSIS",
                evidence_available=False,
                evidence_summary="No PRIVILEGE_ESCALATION findings were found.",
            )
        lines = [f"Yes, privilege escalation activity was found in {len(sessions)} session(s):"]
        for session in sessions[:10]:
            lines.append(
                f"- {session.username or 'unknown'} | session `{session.session_id or session.unique_id}`"
            )
        return self._result(
            "\n".join(lines),
            intent="RISK_ANALYSIS",
            evidence_available=True,
            evidence_summary=f"Found PRIVILEGE_ESCALATION findings in {len(sessions)} session(s).",
        )

    def _try_highest_risk_session(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_highest_risk_session_query(question_lower):
            return None
        result = self._analytics.highest_risk_session()
        if result is None:
            return self._result(
                "No risk findings were recorded in any session.",
                intent="RISK_ANALYSIS",
                evidence_available=False,
                evidence_summary="No session risk findings were found.",
            )
        session, summary = result
        identifier = session.session_id or session.unique_id
        started = session.started_at or session.login_time
        return self._result(
            f"The highest-risk session was `{identifier}` by {session.username or 'unknown'} "
            f"with {summary.finding_count} finding(s), overall severity {summary.overall_severity}. "
            f"Categories: {', '.join(summary.categories) or 'none'}.",
            intent="RISK_ANALYSIS",
            evidence_available=True,
            evidence_summary=f"Ranked session {identifier} as the highest-risk session.",
            session_id=identifier,
        )

    def _try_remaining_sessions_by_user(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_remaining_sessions_by_user_query(question_lower):
            return None

        counts = self._analytics.session_counts_by_user()
        if not counts:
            return self._result(
                "No sessions were recorded.",
                intent="CROSS_SESSION_ANALYSIS",
                evidence_available=False,
                evidence_summary="No logical sessions were found.",
            )

        excluded_user = "admin" if "admin" in question_lower else None
        remaining = {
            username: count
            for username, count in counts.items()
            if username.lower() != excluded_user
        }
        remaining_total = sum(remaining.values())
        if not remaining:
            answer = "No sessions were found for users other than admin."
        else:
            lines = [f"The remaining {remaining_total} session(s) were executed by:"]
            lines.extend(
                f"- {username}: {count} session(s)"
                for username, count in sorted(remaining.items(), key=lambda item: (-item[1], item[0].lower()))
            )
            answer = "\n".join(lines)
        return self._result(
            answer,
            intent="CROSS_SESSION_ANALYSIS",
            evidence_available=True,
            evidence_summary=f"Counted {remaining_total} session(s) for users other than {excluded_user or 'the referenced user'}.",
        )

    def _try_duration_query(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_duration_query(question_lower):
            return None

        if "average" in question_lower:
            average_seconds = self._analytics.average_duration_seconds()
            if average_seconds is None:
                return self._result(
                    "No session duration data available.",
                    intent="SESSION_STATS",
                    evidence_available=False,
                    evidence_summary="No session durations were found.",
                )
            return self._result(
                f"Average session duration: {round(average_seconds / 60, 1)} minutes.",
                intent="SESSION_STATS",
                evidence_available=True,
                evidence_summary="Calculated average duration across recorded sessions.",
            )

        longest = "longest" in question_lower
        session = self._analytics.duration_extreme(longest=longest)
        label = "Longest" if longest else "Shortest"
        if session is None:
            return self._result(
                "No session duration data available.",
                intent="SESSION_STATS",
                evidence_available=False,
                evidence_summary="No session durations were found.",
            )
        started = session.started_at or session.login_time
        date_label = started.date().isoformat() if started else "unknown"
        duration = session.duration or self._analytics.format_duration(session) or "unknown"
        return self._result(
            f"{label} session:\n- User: {session.username or 'unknown'}\n"
            f"- Date: {date_label}\n- Duration: {duration}\n"
            f"- Session: {session.session_id or session.unique_id}",
            intent="SESSION_STATS",
            evidence_available=True,
            evidence_summary=f"Retrieved the {label.lower()} session by duration.",
        )

    def _try_user_session_duration(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not any(phrase in question_lower for phrase in ("how long was", "how long is", "session duration for")):
            return None
        username = self._extract_username(question_lower)
        if username is None:
            return None

        session = self._sessions.get_latest_session_for_user(username)
        if session is None:
            return self._result(
                f"No sessions found for {username}.",
                intent="USER_ACTIVITY",
                evidence_available=False,
                evidence_summary=f"Found no sessions for user {username}.",
            )

        started = getattr(session, "started_at", None) or getattr(session, "login_time", None)
        ended = getattr(session, "ended_at", None) or getattr(session, "logout_time", None)
        if ended is None:
            if started is None:
                answer = f"{username}'s session is active, but its start time is unknown."
            else:
                elapsed_minutes = max(int((datetime.now(started.tzinfo) - started).total_seconds() // 60), 0)
                answer = f"{username}'s session is still active; running for {elapsed_minutes} minute(s)."
        else:
            duration_seconds = self._analytics._duration_seconds(session)
            if duration_seconds is None:
                answer = f"No duration was recorded for {username}'s latest session."
            elif duration_seconds % 60 == 0:
                minutes = int(duration_seconds // 60)
                unit = "minute" if minutes == 1 else "minutes"
                answer = f"{username}'s session lasted {minutes} {unit}."
            else:
                answer = f"{username}'s session lasted {round(duration_seconds / 60, 1)} minutes."

        identifier = session.session_id or session.unique_id
        return self._result(
            answer,
            intent="USER_ACTIVITY",
            evidence_available=True,
            evidence_summary=f"Retrieved the latest session duration for {username}.",
            session_id=identifier,
        )

    def _try_user_total_sessions(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_user_total_sessions_query(question_lower):
            return None
        username = self._extract_username(question_lower)
        if username is None:
            return None
        count = len(self._analytics.list_user_sessions(username))
        answer = f"{username} has {count} total session(s) recorded." if count else f"No sessions found for {username}."
        return self._result(
            answer,
            intent="SESSION_COUNT",
            evidence_available=count > 0,
            evidence_summary=f"Counted {count} session(s) for {username}.",
        )

    def _try_busiest_date(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_busiest_date_query(question_lower) or "week" in question_lower or "month" in question_lower:
            return None
        result = self._analytics.busiest_date()
        if result is None:
            return self._result(
                "No session data available.",
                intent="SESSION_STATS",
                evidence_available=False,
                evidence_summary="No dated sessions were found.",
            )
        busiest, count = result
        return self._result(
            f"Busiest day: {busiest.isoformat()} with {count} session(s).",
            intent="SESSION_STATS",
            evidence_available=True,
            evidence_summary=f"Busiest day was {busiest.isoformat()} with {count} session(s).",
        )

    def _try_session_timings(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_session_timing_query(question_lower):
            return None
        username = self._extract_username(question_lower)
        target_date = (
            configured_today()
            if "today" in question_lower
            else date_range[0] if date_range and date_range[0] == date_range[1] else None
        )
        if target_date is not None:
            sessions = (
                self._analytics.list_user_sessions_between(username, target_date, target_date)
                if username
                else self._analytics.list_sessions_between(target_date, target_date)
            )
        else:
            sessions = self._sessions.list_all_sessions()
        timing_intent = (
            "TEMPORAL_ACCESS"
            if "from what time" in question_lower or "log in today" in question_lower
            else "SESSION_TIMING"
        )
        if not sessions:
            scope = f"{username} on {target_date.isoformat()}" if username and target_date else "the requested period"
            return self._result(
                f"No sessions found for {scope}.",
                intent=timing_intent,
                evidence_available=False,
                evidence_summary=f"No sessions found for {scope}.",
            )
        sessions.sort(
            key=lambda session: (session.started_at or session.login_time or datetime.min).isoformat()
        )
        is_temporal_today = "today" in question_lower and "from what time" in question_lower
        if is_temporal_today:
            lines = [f"{(username or 'All users').title()} login/session times for today ({target_date.isoformat()}):"]
            first_start = next((session.started_at or session.login_time for session in sessions), None)
            last_end = max(
                (session.ended_at or session.logout_time or session.started_at or session.login_time for session in sessions),
                default=None,
            )
            if first_start and last_end:
                lines.append(f"Overall: {first_start.isoformat()} to {last_end.isoformat()}")
        else:
            scope_label = username or "all users"
            date_label = target_date.isoformat() if target_date else "all recorded dates"
            lines = [f"{scope_label} sessions on {date_label}:"]
        for index, session in enumerate(sessions, start=1):
            login = session.started_at or session.login_time
            logout = session.ended_at or session.logout_time
            duration = session.duration or "unknown"
            lines.append(
                f"- Session {index}: {login.isoformat() if login else 'unknown'} to "
                f"{logout.isoformat() if logout else 'still active'} ({duration})"
            )
        return self._result(
            "\n".join(lines),
            intent=timing_intent,
            evidence_available=True,
            evidence_summary=(
                f"Listed {len(sessions)} {username or 'all-user'} session timing(s)"
                f"{f' for {target_date.isoformat()}' if target_date else ''}."
            ),
        )

    def _try_last_n_users(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        match = LAST_N_USERS_RE.search(question_lower)
        if not match and "last users" not in question_lower:
            return None
        limit = int(match.group(1)) if match else 5
        records = self._analytics.last_n_users(limit=limit)
        if not records:
            return self._result(
                "No user login records were found in PostgreSQL.",
                intent="TEMPORAL_ACCESS",
                evidence_available=False,
                evidence_summary="Matched 0 user login record(s).",
            )

        lines = [f"Last {len(records)} user(s) to access SSH:"]
        for index, record in enumerate(records, start=1):
            started = record.started_at.isoformat() if record.started_at else "unknown time"
            lines.append(f"{index}. {record.username} at {started} (session {record.session_id})")
        return self._result(
            "\n".join(lines),
            intent="TEMPORAL_ACCESS",
            evidence_available=True,
            evidence_summary=f"Retrieved {len(records)} recent user login record(s).",
        )

    def _try_last_hour_access(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if "last hour" not in question_lower and "past hour" not in question_lower:
            return None
        sessions = self._analytics.sessions_in_last_hours(hours=1.0)
        if not sessions:
            return self._result(
                "No SSH sessions were recorded in the last hour.",
                intent="TEMPORAL_ACCESS",
                evidence_available=False,
                evidence_summary="Matched 0 session(s) in the last hour.",
            )
        users = sorted({session.username or "unknown" for session in sessions})
        return self._result(
            f"{len(sessions)} SSH session(s) in the last hour by {len(users)} user(s): {', '.join(users)}.",
            intent="TEMPORAL_ACCESS",
            evidence_available=True,
            evidence_summary=f"Matched {len(sessions)} session(s) in the last hour.",
        )

    def _try_session_count(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not any(
            phrase in question_lower
            for phrase in ("how many session", "number of session", "count session", "sessions were there")
        ):
            return None
        if not date_range:
            return None

        start_date, end_date = date_range
        count = self._analytics.count_sessions_between(start_date, end_date)
        label = start_date.isoformat() if start_date == end_date else f"{start_date.isoformat()} to {end_date.isoformat()}"
        if count == 0:
            return self._result(
                f"No SSH sessions were recorded for {label}.",
                intent="SESSION_COUNT",
                evidence_available=False,
                evidence_summary=f"Counted 0 session(s) for {label}.",
            )
        return self._result(
            f"{count} SSH session(s) were recorded for {label}.",
            intent="SESSION_COUNT",
            evidence_available=True,
            evidence_summary=f"Counted {count} session(s) for {label}.",
        )

    def _try_list_sessions_for_date(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not (
            any(term in question_lower for term in ("list", "show", "display", "give"))
            and "session" in question_lower
            and date_range is not None
            and session_id is None
            and not any(term in question_lower for term in ("risk", "risky", "dangerous", "suspicious"))
        ):
            return None
        if any(term in question_lower for term in ("login", "logout", "start time", "end time", "earliest", "latest")):
            return None

        start_date, end_date = date_range
        sessions = self._analytics.list_sessions_between(start_date, end_date, limit=50)
        label = start_date.isoformat() if start_date == end_date else f"{start_date.isoformat()} to {end_date.isoformat()}"
        if not sessions:
            return self._result(
                f"No SSH sessions were recorded for {label}.",
                intent="SESSION_LOOKUP",
                evidence_available=False,
                evidence_summary=f"Matched 0 session(s) for {label}.",
            )

        lines = [f"Sessions for {label}:"]
        for index, session in enumerate(sessions, start=1):
            sid = session.session_id or session.unique_id
            started = session.started_at.isoformat() if session.started_at else "unknown"
            lines.append(f"{index}. {sid} | {session.username or 'unknown'} | started {started}")
        return self._result(
            "\n".join(lines),
            intent="SESSION_LOOKUP",
            evidence_available=True,
            evidence_summary=f"Listed {len(sessions)} session(s) for {label}.",
        )

    def _try_user_sessions_by_date(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_user_sessions_by_date_query(question_lower):
            return None

        username = self._extract_username(question_lower)
        if username is None:
            return None

        sessions = [
            session
            for session in self._sessions.list_all_sessions()
            if (session.username or "").strip().lower() == username.lower()
        ]
        if not sessions:
            return self._result(
                f"No sessions were recorded for {username}.",
                intent="SESSION_LOOKUP",
                evidence_available=False,
                evidence_summary=f"Matched 0 session(s) for {username}.",
            )

        sessions.sort(
            key=lambda session: (session.started_at or session.login_time or datetime.min).isoformat()
        )
        if "how many" in question_lower:
            sessions_by_date: dict[str, list[str]] = {}
            for session in sessions:
                started = session.started_at or session.login_time
                date_label = started.date().isoformat() if started else "unknown date"
                sessions_by_date.setdefault(date_label, []).append(
                    session.session_id or session.unique_id
                )
            lines = [f"{username.title()} sessions by date ({len(sessions)} total):"]
            for date_label, session_ids in sorted(sessions_by_date.items()):
                lines.append(f"- {date_label}: {len(session_ids)} session(s)")
                lines.append(f"  Session IDs: {', '.join(session_ids)}")
            return self._result(
                "\n".join(lines),
                intent="SESSION_COUNT",
                evidence_available=True,
                evidence_summary=f"Counted {len(sessions)} session(s) for {username} by date.",
            )

        lines = [f"{username.title()} sessions by date ({len(sessions)}):"]
        for index, session in enumerate(sessions, start=1):
            sid = session.session_id or session.unique_id
            started = session.started_at or session.login_time
            date_label = started.date().isoformat() if started else "unknown date"
            time_label = started.isoformat() if started else "unknown time"
            lines.append(f"{index}. {date_label} | {time_label} | session {sid}")
        return self._result(
            "\n".join(lines),
            intent="SESSION_LOOKUP",
            evidence_available=True,
            evidence_summary=f"Listed {len(sessions)} session(s) for {username} by date.",
        )

    def _try_user_today_timing(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_user_today_timing_query(question_lower):
            return None

        username = self._extract_username(question_lower)
        if username is None:
            return None

        target_date = (
            date_range[0]
            if date_range is not None and date_range[0] == date_range[1]
            else configured_today()
        )
        sessions = [
            session
            for session in self._sessions.list_all_sessions_started_between(target_date, target_date)
            if (session.username or "").strip().lower() == username.lower()
        ]
        sessions.sort(
            key=lambda session: (session.started_at or session.login_time or datetime.min).isoformat()
        )
        if not sessions:
            return self._result(
                f"No sessions or logins were recorded for {username} today ({target_date.isoformat()}).",
                intent="TEMPORAL_ACCESS",
                evidence_available=False,
                evidence_summary=f"Matched 0 {username} session(s) for {target_date.isoformat()}.",
            )

        first_start = next((session.started_at or session.login_time for session in sessions), None)
        last_end = max(
            (session.ended_at or session.logout_time or session.started_at or session.login_time for session in sessions),
            default=None,
        )
        lines = [f"{username.title()} login/session times for today ({target_date.isoformat()}):"]
        if first_start and last_end:
            lines.append(f"Overall: {first_start.isoformat()} to {last_end.isoformat()}")
        for index, session in enumerate(sessions, start=1):
            started = session.started_at or session.login_time
            ended = session.ended_at or session.logout_time
            lines.append(
                f"{index}. {started.isoformat() if started else 'unknown start'}"
                f" to {ended.isoformat() if ended else 'still active'}"
                f" | session {session.session_id or session.unique_id}"
            )
        return self._result(
            "\n".join(lines),
            intent="TEMPORAL_ACCESS",
            evidence_available=True,
            evidence_summary=f"Retrieved {len(sessions)} {username} session time(s) for {target_date.isoformat()}.",
        )

    def _try_list_all_session_ids(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_list_all_session_ids_query(question_lower):
            return None

        sessions = self._sessions.list_all_sessions()
        if not sessions:
            return self._result(
                "No SSH sessions were recorded.",
                intent="SESSION_LOOKUP",
                evidence_available=False,
                evidence_summary="Matched 0 session(s).",
            )

        lines = [f"Session IDs ({len(sessions)}):"]
        for index, session in enumerate(sessions, start=1):
            sid = session.session_id or session.unique_id
            username = session.username or "unknown"
            date_label = (
                session.started_at.date().isoformat() if session.started_at else "unknown"
            )
            lines.append(f"{index}. `{sid}` | {username} | {date_label}")
        return self._result(
            "\n".join(lines),
            intent="SESSION_LOOKUP",
            evidence_available=True,
            evidence_summary=f"Listed {len(sessions)} session ID(s).",
        )

    def _try_list_sessions_with_dates(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_sessions_with_dates_query(question_lower):
            return None

        sessions = self._sessions.list_all_sessions()
        if not sessions:
            return self._result(
                "No SSH sessions were recorded.",
                intent="SESSION_LOOKUP",
                evidence_available=False,
                evidence_summary="Matched 0 session(s).",
            )

        lines = [f"Sessions with dates ({len(sessions)}):"]
        for index, session in enumerate(sessions, start=1):
            sid = session.session_id or session.unique_id
            if session.started_at:
                date_label = session.started_at.date().isoformat()
                started = session.started_at.isoformat()
            else:
                date_label = "unknown"
                started = "unknown"
            lines.append(f"{index}. {sid} | {session.username or 'unknown'} | {date_label} (started {started})")
        return self._result(
            "\n".join(lines),
            intent="SESSION_LOOKUP",
            evidence_available=True,
            evidence_summary=f"Listed {len(sessions)} session(s) with dates.",
        )

    def _try_session_date_lookup(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not _is_session_date_lookup_query(question_lower, session_id):
            return None

        session = self._sessions.get_session(session_id)
        if session is None:
            return self._result(
                f"Session `{session_id}` was not found in PostgreSQL.",
                intent="SESSION_LOOKUP",
                evidence_available=False,
                evidence_summary=f"Session {session_id} not found.",
                session_id=session_id,
            )

        if session.started_at:
            date_label = session.started_at.date().isoformat()
            started = session.started_at.isoformat()
            answer = (
                f"Session `{session_id}` ({session.username or 'unknown'}) was executed on "
                f"{date_label} (started at {started})."
            )
        else:
            answer = f"Session `{session_id}` ({session.username or 'unknown'}) has no recorded start date."
        return self._result(
            answer,
            intent="SESSION_LOOKUP",
            evidence_available=session.started_at is not None,
            evidence_summary=f"Retrieved execution date for session {session_id}.",
            session_id=session_id,
        )

    def _try_most_frequent_user(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if "most frequent user" not in question_lower and "accessed the system most" not in question_lower:
            return None
        if not date_range:
            date_range = extract_date_range("this week")

        start_date, end_date = date_range or (configured_today(), configured_today())
        result = self._analytics.most_frequent_user_between(start_date, end_date)
        label = start_date.isoformat() if start_date == end_date else f"{start_date.isoformat()} to {end_date.isoformat()}"
        if result is None:
            return self._result(
                f"No SSH sessions were recorded for {label}.",
                intent="CROSS_SESSION_ANALYSIS",
                evidence_available=False,
                evidence_summary=f"No users found for {label}.",
            )
        username, count = result
        return self._result(
            f"User `{username}` accessed the system most often for {label}: {count} session(s).",
            intent="CROSS_SESSION_ANALYSIS",
            evidence_available=True,
            evidence_summary=f"Most frequent user for {label}: {username}.",
        )

    def _try_busiest_hour(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        peak_login_query = "peak" in question_lower and "login" in question_lower and "hour" in question_lower
        if "busiest hour" not in question_lower and "most ssh activity" not in question_lower and not peak_login_query:
            return None
        if not date_range:
            date_range = extract_date_range("today")

        start_date, end_date = date_range or (configured_today(), configured_today())
        result = self._analytics.busiest_hour_between(start_date, end_date)
        label = start_date.isoformat() if start_date == end_date else f"{start_date.isoformat()} to {end_date.isoformat()}"
        if result is None:
            return self._result(
                f"No SSH sessions were recorded for {label}.",
                intent="CROSS_SESSION_ANALYSIS",
                evidence_available=False,
                evidence_summary=f"No hour activity for {label}.",
            )
        hour, count = result
        answer_prefix = "Peak login hour" if peak_login_query else "The busiest hour"
        return self._result(
            f"{answer_prefix} for {label} was {hour:02d}:00 UTC with {count} session(s).",
            intent="CROSS_SESSION_ANALYSIS",
            evidence_available=True,
            evidence_summary=f"Busiest hour for {label}: {hour:02d}:00.",
        )

    def _try_high_risk_percentage(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if "percentage" not in question_lower and "%" not in question_lower:
            return None
        if "risk" not in question_lower:
            return None
        if not date_range:
            date_range = extract_date_range("today")

        start_date, end_date = date_range or (configured_today(), configured_today())
        high_risk, total, percentage = self._analytics.high_risk_percentage_between(start_date, end_date)
        label = start_date.isoformat() if start_date == end_date else f"{start_date.isoformat()} to {end_date.isoformat()}"
        if total == 0:
            return self._result(
                f"No SSH sessions were recorded for {label}.",
                intent="RISK_ANALYSIS",
                evidence_available=False,
                evidence_summary=f"Counted 0 session(s) for {label}.",
            )
        return self._result(
            f"{percentage}% of sessions were HIGH risk for {label} ({high_risk} of {total}).",
            intent="RISK_ANALYSIS",
            evidence_available=True,
            evidence_summary=f"HIGH risk percentage for {label}: {percentage}%.",
        )

    def _try_high_risk_count(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not any(phrase in question_lower for phrase in ("high risk session", "high-risk session")):
            return None
        if "how many" not in question_lower and "were there" not in question_lower:
            return None
        if not date_range:
            date_range = extract_date_range("this week")

        start_date, end_date = date_range or (configured_today(), configured_today())
        count = self._analytics.count_sessions_by_risk_between(start_date, end_date, "HIGH")
        label = start_date.isoformat() if start_date == end_date else f"{start_date.isoformat()} to {end_date.isoformat()}"
        return self._result(
            f"{count} HIGH-risk SSH session(s) were recorded for {label}.",
            intent="RISK_ANALYSIS",
            evidence_available=count > 0,
            evidence_summary=f"Counted {count} HIGH-risk session(s) for {label}.",
        )

    def _try_all_commands_frequency(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if session_id is not None or self._extract_session_id(question_text):
            return None
        if not any(term in question_lower for term in ("command", "commands", "executed", "execute")):
            return None
        if not any(
            phrase in question_lower
            for phrase in (
                "how many times",
                "which all commands",
                "which commands",
                "all commands",
                "every command",
                "commands were executed",
                "command count",
                "command frequency",
            )
        ):
            return None

        if date_range is not None:
            start_date, end_date = date_range
            sessions_label = (
                start_date.isoformat()
                if start_date == end_date
                else f"{start_date.isoformat()} to {end_date.isoformat()}"
            )
            total_sessions = self._analytics.count_sessions_between(start_date, end_date)
            frequencies = self._analytics.command_frequency_between(start_date, end_date, limit=50)
            scope_label = f"on {sessions_label}"
        else:
            total_sessions = self._sessions.count_unique_sessions()
            frequencies = self._analytics.command_frequency_all(limit=50)
            scope_label = "across all recorded dates"
        if not frequencies:
            return self._result(
                f"No commands were recorded {scope_label} across {total_sessions} SSH session(s) in PostgreSQL.",
                intent="COMMAND_SEARCH",
                evidence_available=False,
                evidence_summary=f"No command frequency data {scope_label} across {total_sessions} session(s).",
            )

        total_executions = sum(item.count for item in frequencies)
        lines = [
            f"{scope_label.capitalize()}, {total_sessions} SSH session(s) recorded these commands:",
        ]
        for index, item in enumerate(frequencies, start=1):
            lines.append(f"{index}. `{item.command}` — {item.count} time(s)")
        lines.append(
            f"Total: {len(frequencies)} unique command(s), {total_executions} execution(s)."
        )
        return self._result(
            "\n".join(lines),
            intent="COMMAND_SEARCH",
            evidence_available=True,
            evidence_summary=(
                f"Listed {len(frequencies)} unique command(s) across {total_sessions} session(s)."
            ),
        )

    def _try_command_frequency(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if "most frequently" not in question_lower and "most frequent command" not in question_lower:
            return None
        if not date_range:
            date_range = extract_date_range("this week")

        start_date, end_date = date_range or (configured_today(), configured_today())
        frequencies = self._analytics.command_frequency_between(start_date, end_date, limit=10)
        label = start_date.isoformat() if start_date == end_date else f"{start_date.isoformat()} to {end_date.isoformat()}"
        if not frequencies:
            return self._result(
                f"No commands were recorded for {label}.",
                intent="COMMAND_SEARCH",
                evidence_available=False,
                evidence_summary=f"No command frequency data for {label}.",
            )
        lines = [f"Most frequently executed commands for {label}:"]
        for index, item in enumerate(frequencies, start=1):
            lines.append(f"{index}. `{item.command}` — {item.count} time(s)")
        return self._result(
            "\n".join(lines),
            intent="COMMAND_SEARCH",
            evidence_available=True,
            evidence_summary=f"Top {len(frequencies)} command frequency result(s) for {label}.",
        )

    def _try_command_run_recently(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not any(term in question_lower for term in ("was ", "were ")):
            return None
        if not any(term in question_lower for term in ("run", "executed", "recently", "recent")):
            return None
        if date_range is not None and not any(
            term in question_lower for term in ("recently", "recent")
        ):
            return None

        command_term = self._extract_was_command_run_term(question_text)
        if not command_term:
            return None

        usages = self._analytics.find_command_usages_recent(command_term)
        if not usages:
            return self._result(
                f"No, `{command_term}` was not recorded in any SSH session in PostgreSQL.",
                intent="COMMAND_LOOKUP",
                evidence_available=False,
                evidence_summary=f"Matched 0 `{command_term}` command occurrence(s) recently.",
            )

        if len(usages) == 1:
            session, item = usages[0]
            when = item.executed_at.isoformat() if item.executed_at else "unknown time"
            sid = session.session_id or session.unique_id
            return self._result(
                f"Yes, `{command_term}` was run by {session.username or 'unknown'} "
                f"in session {sid} at {when}.",
                intent="COMMAND_LOOKUP",
                evidence_available=True,
                evidence_summary=f"Matched 1 recent `{command_term}` command occurrence.",
                session_id=sid,
            )

        lines = [f"Yes, `{command_term}` was recorded {len(usages)} time(s) recently:"]
        for session, item in usages[:5]:
            when = item.executed_at.isoformat() if item.executed_at else "unknown time"
            sid = session.session_id or session.unique_id
            lines.append(
                f"- {session.username or 'unknown'} in session {sid} at {when}: `{item.command}`"
            )
        return self._result(
            "\n".join(lines),
            intent="COMMAND_LOOKUP",
            evidence_available=True,
            evidence_summary=f"Matched {len(usages)} recent `{command_term}` command occurrence(s).",
            session_id=usages[0][0].session_id or usages[0][0].unique_id,
        )

    def _try_sudo_or_command_on_date(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not any(term in question_lower for term in ("did anyone", "did ", "was ", "were ", "anyone run")):
            return None

        command_term = None
        if "sudo" in question_lower:
            command_term = "sudo"
        else:
            match = COMMAND_TERM_RE.search(question_text)
            if match:
                command_term = match.group(1)

        if not command_term:
            return None
        if not date_range:
            if "today" in question_lower:
                date_range = extract_date_range("today")
            else:
                return None

        username = None
        user_match = re.search(r"\bdid\s+([\w.-]+)\s+", question_lower)
        if user_match:
            username = user_match.group(1)
            if username in {"anyone", "someone", "they"}:
                username = None

        start_date, end_date = date_range
        usages = self._analytics.find_command_usages_between(
            command_term,
            start_date,
            end_date,
            username=username,
        )
        label = start_date.isoformat() if start_date == end_date else f"{start_date.isoformat()} to {end_date.isoformat()}"
        if not usages:
            subject = f"user `{username}`" if username else "anyone"
            return self._result(
                f"No, `{command_term}` was not recorded for {subject} on {label}.",
                intent="COMMAND_LOOKUP",
                evidence_available=False,
                evidence_summary=f"Matched 0 `{command_term}` command(s) for {label}.",
            )

        lines = [f"Yes, `{command_term}` was recorded {len(usages)} time(s) for {label}:"]
        for session, item in usages[:10]:
            when = item.executed_at.isoformat() if item.executed_at else "unknown time"
            lines.append(
                f"- {session.username or 'unknown'} in session {session.session_id or session.unique_id} at {when}"
            )
        return self._result(
            "\n".join(lines),
            intent="COMMAND_LOOKUP",
            evidence_available=True,
            evidence_summary=f"Matched {len(usages)} `{command_term}` command occurrence(s) for {label}.",
        )

    def _try_session_timing(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not session_id:
            return None
        if not any(
            term in question_lower
            for term in ("log in", "log out", "login", "logout", "duration", "how long", "start", "end")
        ):
            return None
        if any(
            phrase in question_lower
            for phrase in ("first command after login", "first action after login", "first thing after login")
        ):
            return None

        session = self._sessions.get_session(session_id)
        if session is None:
            return self._result(
                f"Session `{session_id}` was not found in PostgreSQL.",
                intent="SESSION_LOOKUP",
                evidence_available=False,
                evidence_summary=f"Session {session_id} not found.",
                session_id=session_id,
            )
        return self._result(
            f"Session `{session_id}` ({session.username or 'unknown'}): "
            f"{self._analytics.format_session_timing(session)}.",
            intent="SESSION_LOOKUP",
            evidence_available=True,
            evidence_summary=f"Retrieved timing for session {session_id}.",
            session_id=session_id,
        )

    def _try_first_or_last_command(
        self,
        *,
        question_text: str,
        question_lower: str,
        session_id: str | None,
        date_range: tuple[date, date] | None,
    ) -> dict[str, Any] | None:
        if not session_id:
            return None
        if "first command" not in question_lower and "last command" not in question_lower:
            return None

        if "first command" in question_lower:
            item = self._analytics.first_command(session_id)
            label = "first"
        else:
            item = self._analytics.last_command(session_id)
            label = "last"

        if item is None or not item.command:
            return self._result(
                f"No {label} command was recorded for session `{session_id}`.",
                intent="COMMAND_LOOKUP",
                evidence_available=False,
                evidence_summary=f"No {label} command for session {session_id}.",
                session_id=session_id,
            )

        when = item.executed_at.isoformat() if item.executed_at else "unknown time"
        return self._result(
            f"The {label} command in session `{session_id}` was `{item.command}` at {when}.",
            intent="COMMAND_LOOKUP",
            evidence_available=True,
            evidence_summary=f"Retrieved {label} command for session {session_id}.",
            session_id=session_id,
        )

    def _extract_session_id(self, question: str) -> str | None:
        match = SESSION_ID_RE.search(question or "")
        return match.group(0) if match else None

    def _extract_username(self, question_lower: str) -> str | None:
        users = QueryUnderstandingService()._extract_users(question_lower)
        if users:
            return users[0]
        recorded_users = {
            (session.username or "").strip()
            for session in self._sessions.list_all_sessions()
            if (session.username or "").strip()
        }
        for recorded_user in sorted(recorded_users, key=len, reverse=True):
            if re.search(rf"(?<![\w.-]){re.escape(recorded_user)}(?![\w.-])", question_lower, re.IGNORECASE):
                return recorded_user
        return None

    def _extract_was_command_run_term(self, question: str) -> str | None:
        question_text = (question or "").strip()
        if not question_text:
            return None

        for pattern in WAS_COMMAND_RUN_PATTERNS:
            match = pattern.search(question_text)
            if match is None:
                continue
            command_term = match.group(1).strip().strip("`'\"")
            command_term = re.sub(r"\s+command$", "", command_term, flags=re.IGNORECASE).strip()
            if command_term and command_term.lower() not in COMMAND_STOP_WORDS:
                return command_term
        return None

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
