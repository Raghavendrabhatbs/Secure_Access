from __future__ import annotations

import re
import os
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
import calendar
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.core.config import settings
from app.services.risk_search import (
    extract_risk_categories,
    extract_risk_severity,
    is_risk_domain_query,
)


DATE_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
NUMERIC_DATE_RE = re.compile(r"\b(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})\b")
MONTH_DATE_RE = re.compile(
    r"\b(january|february|march|april|may|june|july|august|september|october|november|december)\s+(\d{1,2})(?:,\s*(\d{4}))?\b",
    re.IGNORECASE,
)
SESSION_ID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
MONTHS = {
    "january": 1,
    "february": 2,
    "march": 3,
    "april": 4,
    "may": 5,
    "june": 6,
    "july": 7,
    "august": 8,
    "september": 9,
    "october": 10,
    "november": 11,
    "december": 12,
}


def configured_timezone() -> ZoneInfo:
    timezone_name = (
        os.getenv("CHATBOT_TIMEZONE")
        or os.getenv("APP_TIMEZONE")
        or settings.app_timezone
    )
    try:
        return ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"Invalid configured application timezone: {timezone_name}") from exc


def configured_today() -> date:
    return datetime.now(configured_timezone()).date()


def date_range_utc_bounds(start_date: date, end_date: date) -> tuple[datetime, datetime]:
    local_timezone = configured_timezone()
    local_start = datetime.combine(start_date, time.min, tzinfo=local_timezone)
    local_end = datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=local_timezone)
    return local_start.astimezone(timezone.utc), local_end.astimezone(timezone.utc)
LATEST_SESSION_PATTERNS = (
    r"\blatest\s+(?:ssh\s+)?session\b",
    r"\blast\s+(?:ssh\s+)?session\b",
    r"\bmost\s+recent\s+(?:ssh\s+)?session\b",
    r"\brecent(?:ly)?\b.*\b(?:ssh\s+)?session\b",
    r"\b(?:ssh\s+)?session\b.*\brecent(?:ly)?\b",
)
COMMAND_STOP_WORDS = {
    "command", "commands", "risky", "dangerous", "suspicious", "high-risk", "high",
    "that", "which", "all", "the", "in", "it", "they", "any", "some", "every", "each",
    "what", "when", "where", "how", "who", "were", "was", "are", "is", "did", "do",
    "list", "show", "tell", "give", "executed", "execute", "ran", "run",
    "and", "or", "with", "their", "session", "sessions", "id", "ids", "me", "my",
    "here", "there", "this", "that",
}
def _is_excluded_datetime_context(question_lower: str) -> bool:
    if any(
        term in question_lower
        for term in ("session", "logged", "warpgate", "postgresql", "executed", "ssh session")
    ):
        return True
    if re.search(r"[`'\"]\s*date\s*[`'\"]", question_lower) or "date command" in question_lower:
        return True
    if "command" in question_lower and not any(
        term in question_lower for term in ("today", "what time is it", "what day is it")
    ):
        return True
    return False


def classify_current_datetime_question(question: str) -> str | None:
    """Return 'date', 'time', or 'both' for current clock questions."""
    question_lower = (question or "").strip().lower()
    if not question_lower or _is_excluded_datetime_context(question_lower):
        return None

    wants_time = any(
        pattern.search(question_lower)
        for pattern in (
            re.compile(r"\bwhat(?:'s| is)\s+(?:the\s+)?time\b", re.IGNORECASE),
            re.compile(r"\bwhat\s+time\s+is\s+it\b", re.IGNORECASE),
            re.compile(r"\bcurrent\s+time\b", re.IGNORECASE),
            re.compile(r"\btoday'?s?\s+time\b", re.IGNORECASE),
        )
    )
    wants_date = any(
        pattern.search(question_lower)
        for pattern in (
            re.compile(r"\bdate\b", re.IGNORECASE),
            re.compile(r"\bday\b", re.IGNORECASE),
            re.compile(r"\bwhat\s+day\s+is\s+(?:it|today)\b", re.IGNORECASE),
            re.compile(r"\bwhat\s+(?:day|date)\s+(?:is\s+)?today\b", re.IGNORECASE),
            re.compile(r"\btoday'?s?\s+(?:date|day)\b", re.IGNORECASE),
            re.compile(r"\bwhat(?:'s| is)\s+today\b", re.IGNORECASE),
            re.compile(r"\bcurrent\s+date\b", re.IGNORECASE),
        )
    )

    if wants_time and wants_date:
        return "both"
    if wants_time:
        return "time"
    if wants_date:
        return "date"
    return None


def is_current_datetime_question(question: str) -> bool:
    """True when the user wants the actual current date/time, not the `date` command."""
    return classify_current_datetime_question(question) is not None


def format_current_datetime_answer(question: str, now=None) -> str:
    from datetime import datetime

    kind = classify_current_datetime_question(question)
    if kind is None:
        kind = "both"

    current = now or datetime.now().astimezone()
    day_name = current.strftime("%A")
    date_label = current.strftime("%d %B %Y")
    time_label = current.strftime("%H:%M:%S")
    timezone_label = current.tzname() or "local time"
    utc_label = current.astimezone(__import__("datetime").timezone.utc).strftime("%H:%M:%S UTC")

    if kind == "time":
        return f"The current time is {time_label} {timezone_label} ({utc_label})."
    if kind == "date":
        return f"Today is {day_name}, {date_label}."
    return (
        f"Today is {day_name}, {date_label}. "
        f"The current time is {time_label} {timezone_label} ({utc_label})."
    )


def extract_date_range(question: str, today: date | None = None) -> tuple[date, date] | None:
    question_lower = (question or "").strip().lower()
    if not question_lower:
        return None

    current_date = today or configured_today()
    if re.search(r"\btoday\b", question_lower):
        return current_date, current_date
    if re.search(r"\b(?:yesterday|previous day|day before)\b", question_lower):
        yesterday = current_date - timedelta(days=1)
        return yesterday, yesterday
    if re.search(r"\b(?:this|current) week\b", question_lower):
        start_of_week = current_date - timedelta(days=current_date.weekday())
        return start_of_week, current_date
    if re.search(r"\b(?:last|previous) week\b", question_lower):
        start_of_last_week = current_date - timedelta(days=current_date.weekday() + 7)
        return start_of_last_week, start_of_last_week + timedelta(days=6)
    if re.search(r"\b(?:this|current) month\b", question_lower):
        start_of_month = current_date.replace(day=1)
        return start_of_month, current_date
    if re.search(r"\b(?:last|previous) month\b", question_lower):
        last_month_end = current_date.replace(day=1) - timedelta(days=1)
        return last_month_end.replace(day=1), last_month_end
    last_days_match = re.search(r"last\s+(\d+)\s+days?", question_lower)
    if last_days_match:
        days = int(last_days_match.group(1))
        return current_date - timedelta(days=max(days - 1, 0)), current_date

    month_dates = list(MONTH_DATE_RE.finditer(question_lower))
    if len(month_dates) >= 2 and any(term in question_lower for term in ("between", "and", "to", "through", "until")):
        first, second = month_dates[0], month_dates[1]
        first_date = date(
            int(first.group(3) or current_date.year),
            MONTHS[first.group(1).lower()],
            int(first.group(2)),
        )
        second_date = date(
            int(second.group(3) or current_date.year),
            MONTHS[second.group(1).lower()],
            int(second.group(2)),
        )
        return min(first_date, second_date), max(first_date, second_date)

    iso_dates = list(DATE_RE.finditer(question_lower))
    if len(iso_dates) >= 2 and any(
        term in question_lower for term in ("between", "and", "to", "through", "until")
    ):
        try:
            first_date = date.fromisoformat(iso_dates[0].group(1))
            second_date = date.fromisoformat(iso_dates[1].group(1))
        except ValueError:
            return None
        return min(first_date, second_date), max(first_date, second_date)

    match = iso_dates[0] if iso_dates else None
    if match is not None:
        try:
            parsed_date = date.fromisoformat(match.group(1))
        except ValueError:
            return None
        if "since" in question_lower[:match.start()]:
            return parsed_date, current_date
        return parsed_date, parsed_date

    numeric_dates = list(NUMERIC_DATE_RE.finditer(question_lower))
    parsed_numeric_dates: list[date] = []
    for numeric_match in numeric_dates:
        try:
            parsed_numeric_dates.append(
                date(
                    int(numeric_match.group(3)),
                    int(numeric_match.group(2)),
                    int(numeric_match.group(1)),
                )
            )
        except ValueError:
            continue
    if len(parsed_numeric_dates) >= 2 and any(
        term in question_lower for term in ("between", "and", "to", "through", "until")
    ):
        return min(parsed_numeric_dates[:2]), max(parsed_numeric_dates[:2])
    if parsed_numeric_dates:
        parsed_date = parsed_numeric_dates[0]
        numeric_match = numeric_dates[0]
        if "since" in question_lower[:numeric_match.start()]:
            return parsed_date, current_date
        return parsed_date, parsed_date

    month_match = MONTH_DATE_RE.search(question_lower)
    if month_match is None:
        for month_name, month_number in MONTHS.items():
            if re.search(rf"\b{month_name}\b", question_lower):
                start_of_month = date(current_date.year, month_number, 1)
                end_of_month = date(
                    current_date.year,
                    month_number,
                    calendar.monthrange(current_date.year, month_number)[1],
                )
                return start_of_month, end_of_month
        return None

    month = MONTHS[month_match.group(1).lower()]
    day = int(month_match.group(2))
    year = int(month_match.group(3) or current_date.year)
    parsed_date = date(year, month, day)
    if "since" in question_lower[:month_match.start()]:
        return parsed_date, current_date
    return parsed_date, parsed_date


BETWEEN_HOURS_RE = re.compile(
    r"\b(?:between|from)\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\s+(?:and|to|-)\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b",
    re.IGNORECASE,
)
DASH_HOURS_RE = re.compile(
    r"\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\s*-\s*(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b",
    re.IGNORECASE,
)


def _parse_hour_token(hour_text: str, minute_text: str | None, meridiem: str | None) -> int:
    hour = int(hour_text)
    if meridiem:
        meridiem_lower = meridiem.lower()
        if meridiem_lower == "pm" and hour != 12:
            hour += 12
        elif meridiem_lower == "am" and hour == 12:
            hour = 0
    elif 1 <= hour <= 11:
        # Bare small numbers in "between 9 and 11" are treated as morning hours.
        pass
    return hour % 24


def extract_hour_range(question: str) -> tuple[int, int] | None:
    """Return inclusive (start_hour, end_hour) in 24h UTC for phrases like 9am-11am."""
    question_text = (question or "").strip()
    if not question_text:
        return None

    # ISO dates such as 2026-08-25 contain hyphens but are not hour ranges.
    date_matches = [
        match
        for match in (DATE_RE.search(question_text), NUMERIC_DATE_RE.search(question_text))
        if match is not None
    ]
    candidates = [match for match in (
        BETWEEN_HOURS_RE.search(question_text),
        DASH_HOURS_RE.search(question_text),
    ) if match is not None]
    match = next(
        (
            candidate
            for candidate in candidates
            if not any(date_match.span()[0] <= candidate.start() <= date_match.span()[1] for date_match in date_matches)
        ),
        None,
    )
    if match is None:
        return None

    start_hour = _parse_hour_token(match.group(1), match.group(2), match.group(3))
    end_hour = _parse_hour_token(match.group(4), match.group(5), match.group(6))
    if start_hour > end_hour:
        start_hour, end_hour = end_hour, start_hour
    return start_hour, end_hour


def extract_comparison_dates(question: str, today: date | None = None) -> tuple[date, date] | None:
    """Return (period_a, period_b) for today-vs-yesterday style comparisons."""
    question_lower = (question or "").strip().lower()
    if not question_lower:
        return None

    has_compare = any(term in question_lower for term in ("compare", " vs ", " versus ", "compared to"))
    if not has_compare:
        return None

    current_date = today or configured_today()
    if "today" in question_lower and "yesterday" in question_lower:
        return current_date, current_date - timedelta(days=1)

    iso_match = DATE_RE.search(question_lower)
    if iso_match is not None and "yesterday" in question_lower:
        anchor_date = date.fromisoformat(iso_match.group(1))
        return anchor_date, anchor_date - timedelta(days=1)

    date_range = extract_date_range(question_lower, today=current_date)
    if date_range is None:
        return None

    start_date, end_date = date_range
    if start_date != end_date:
        return None

    previous_date = start_date - timedelta(days=1)
    return start_date, previous_date


@dataclass(frozen=True)
class QueryPlan:
    question: str
    query_type: str = "GENERAL_KNOWLEDGE"
    date_range: tuple[date, date] | None = None
    session_id: str | None = None
    command: str | None = None
    users: list[str] = field(default_factory=list)
    scope: str = "all"
    needs: set[str] = field(default_factory=set)
    risk_categories: list[str] = field(default_factory=list)
    risk_severity: str | None = None
    risk_domain_query: bool = False
    analysis: str | None = None

    def needs_only_temporal_access(self) -> bool:
        return self.date_range is not None and self.needs <= {"sessions"}

    def requires_grounded_retrieval(self) -> bool:
        if self.query_type in {"GENERAL_KNOWLEDGE", "COMMAND_EXPLANATION"}:
            return False
        if self.scope == "latest_session":
            return True
        if self.date_range is not None and bool(self.needs - {"sessions"}):
            return True
        if self.session_id and self.query_type == "RISK_ANALYSIS":
            return False
        if self.session_id and self.query_type == "TIMELINE_QUERY":
            return False
        if self.query_type in {"COMMAND_LOOKUP", "MIXED_QUERY"} and self.session_id is None:
            return True
        if self.command and "Conversation context:" in self.question:
            return True
        if self.query_type == "TIMELINE_QUERY" and self.command:
            return True
        if self.query_type == "CROSS_SESSION_ANALYSIS":
            return True
        if self.analysis is not None:
            return True
        question_lower = self.question.lower()
        command_question = any(
            term in question_lower
            for term in ("command", "commands", "execute", "executed", "ran", "run")
        )
        if self.risk_domain_query and command_question and "commands" in self.needs:
            return True
        if self.session_id and "commands" in self.needs:
            return True
        if self.risk_domain_query and self.users and "risk_findings" in self.needs:
            return True
        if self.risk_severity and "risk_findings" in self.needs:
            return True
        return False


class QueryUnderstandingService:
    def understand(self, question: str, session_id: str | None = None) -> QueryPlan:
        question_text = (question or "").strip()
        question_lower = question_text.lower()

        explicit_session_id = session_id or self._extract_session_id(question_text)
        session_evidence_question = self._is_session_evidence_question(question_lower)
        scope = "specific_session" if explicit_session_id else "all"
        if any(re.search(pattern, question_lower) for pattern in LATEST_SESSION_PATTERNS):
            scope = "latest_session"
        elif session_evidence_question and any(
            term in question_lower for term in ("here", "this session", "executing command", "executing commands")
        ):
            scope = "latest_session"

        needs: set[str] = set()
        command = self._extract_command(question_text)
        command_explanation_question = bool(
            re.search(
                r"\b(?:what\s+does|what\s+is|what'?s|explain(?:\s+me)?|meaning\s+of|"
                r"purpose\s+of|what\s+is\s+the\s+purpose\s+of|"
                r"tell\s+me\s+(?:about|what)|describe|"
                r"briefly\s+explain|brief\s+(?:me\s+)?on|give\s+me\s+(?:a\s+)?brief|"
                r"how\s+(?:does|to\s+use|do\s+i\s+use))\b",
                question_lower,
            )
        ) and not session_evidence_question
        if session_evidence_question:
            needs.update({"sessions", "commands"})
            if "hostname" in question_lower:
                command = command or "hostname"
            elif "whoami" in question_lower:
                command = command or "whoami"
            elif "date" in question_lower and "update" not in question_lower:
                command = command or "date"
            elif "pwd" in question_lower:
                command = command or "pwd"

        if any(term in question_lower for term in ("who", "logged in", "accessed", "user", "users")):
            needs.add("sessions")
        if (
            not command_explanation_question
            and any(term in question_lower for term in ("command", "commands", "what did", "do today", "did they do", "ran", "execute", "executed"))
        ):
            needs.update({"sessions", "commands"})
        if command and not command_explanation_question and any(
            term in question_lower
            for term in ("run", "ran", "executed", "execute", "output", "session", "latest", "recent")
        ):
            needs.update({"sessions", "commands"})
        if any(term in question_lower for term in ("event", "events", "timeline", "what happened", "summary", "summarize")):
            needs.update({"sessions", "commands", "events"})
        if (
            not command_explanation_question
            and any(term in question_lower for term in ("risk", "risky", "dangerous", "suspicious", "privilege", "sudo", "root", "permission"))
        ):
            needs.update({"sessions", "commands", "risk_findings"})
        if any(term in question_lower for term in ("risk finding", "risk findings")):
            needs.update({"sessions", "commands", "risk_findings"})

        risk_categories = extract_risk_categories(question_text)
        if "modified permissions" in question_lower or "modify permissions" in question_lower:
            risk_categories.append("PERMISSION_MODIFICATION")
        risk_severity = extract_risk_severity(question_text)
        risk_domain_query = (
            is_risk_domain_query(question_text)
            or bool(risk_categories or risk_severity)
            or any(term in question_lower for term in ("suspicious", "dangerous"))
        )
        if risk_domain_query or "risk_findings" in needs:
            needs.update({"sessions", "commands", "risk_findings"})

        analysis = None
        if "root" in question_lower:
            analysis = "root_access"
        elif (
            not command_explanation_question
            and any(term in question_lower for term in ("why", "explain", "summarize", "summary", "assess"))
        ):
            analysis = "security_summary"

        if not needs:
            if explicit_session_id:
                needs.add("sessions")
            elif "session" in question_lower:
                needs.add("sessions")

        query_type = self._classify_query_type(
            question_lower,
            command=command,
            explicit_session_id=explicit_session_id,
            needs=needs,
            risk_domain_query=risk_domain_query,
            session_evidence_question=session_evidence_question,
        )
        if command and query_type in {"COMMAND_LOOKUP", "MIXED_QUERY"}:
            needs.update({"sessions", "commands"})
        if query_type == "SESSION_SEARCH" and "commands" in needs:
            needs.update({"sessions", "commands"})
        if query_type in {"SESSION_SUMMARY", "SECURITY_SUMMARY", "CROSS_SESSION_ANALYSIS"}:
            needs.update({"sessions", "commands", "events", "timeline"})
        if query_type in {"RISK_ANALYSIS", "SECURITY_SUMMARY", "CROSS_SESSION_ANALYSIS"}:
            needs.update({"sessions", "commands", "risk_findings"})
        if analysis is not None and explicit_session_id:
            needs.update({"sessions", "commands", "events", "timeline"})

        return QueryPlan(
            question=question_text,
            query_type=query_type,
            date_range=extract_date_range(question_text),
            session_id=explicit_session_id,
            command=command,
            users=self._extract_users(question_lower),
            scope=scope,
            needs=needs,
            risk_categories=risk_categories,
            risk_severity=risk_severity,
            risk_domain_query=risk_domain_query,
            analysis=analysis,
        )

    def _classify_query_type(
        self,
        question_lower: str,
        *,
        command: str | None,
        explicit_session_id: str | None,
        needs: set[str],
        risk_domain_query: bool,
        session_evidence_question: bool = False,
    ) -> str:
        if "sessions" in question_lower and any(
            term in question_lower for term in ("which", "find", "show", "search", "contain", "containing")
        ):
            return "SESSION_SEARCH"
        if command and any(term in question_lower for term in ("before", "after")):
            return "TIMELINE_QUERY"
        if command and any(term in question_lower for term in ("when", "what time", "output")):
            return "COMMAND_LOOKUP"
        if "compare" in question_lower:
            return "CROSS_SESSION_ANALYSIS"
        if command and not (risk_domain_query or "risk_findings" in needs) and any(
            term in question_lower
            for term in (
                "what does", "what is", "what's", "whats",
                "explain", "meaning", "difference",
                "tell me about", "tell me what", "describe",
                "briefly", "brief on", "purpose of",
                "how does", "how do i", "how to use",
            )
        ):
            if session_evidence_question:
                return "COMMAND_LOOKUP" if command else "SESSION_LOOKUP"
            if any(term in question_lower for term in ("did", "use", "execute", "ran")):
                return "MIXED_QUERY"
            return "COMMAND_EXPLANATION"
        if risk_domain_query or "risk_findings" in needs:
            if "across" in question_lower or "which user" in question_lower:
                return "CROSS_SESSION_ANALYSIS"
            return "RISK_ANALYSIS"
        if any(term in question_lower for term in ("summarize", "summary", "complete summary")):
            return "SECURITY_SUMMARY" if "security" in question_lower else "SESSION_SUMMARY"
        if any(term in question_lower for term in ("timeline", "chronological", "before", "after", "what happened")):
            return "TIMELINE_QUERY"
        if any(term in question_lower for term in ("who accessed", "who logged", "which users", "user activity")):
            return "USER_ACTIVITY"
        if command and "commands" in needs and any(
            term in question_lower for term in ("did", "when", "what output", "output", "execute", "executed")
        ):
            return "COMMAND_LOOKUP"
        if "commands" in needs and any(
            term in question_lower for term in ("did", "execute", "executed", "ran", "run")
        ):
            return "COMMAND_LOOKUP"
        if command and (explicit_session_id or any(term in question_lower for term in ("did", "when", "what time", "output"))):
            return "COMMAND_LOOKUP"
        if explicit_session_id:
            return "SESSION_LOOKUP"
        if not needs:
            return "GENERAL_KNOWLEDGE"
        return "SESSION_LOOKUP"

    def _is_session_evidence_question(self, question_lower: str) -> bool:
        if any(
            phrase in question_lower
            for phrase in (
                "executing commands here",
                "executing command here",
                "commands here",
                "in this session",
                "this session",
                "from the session",
                "in the session",
                "who is executing",
                "who was executing",
                "who executed",
                "who ran commands",
            )
        ):
            return True
        if "here" in question_lower and any(
            term in question_lower for term in ("hostname", "whoami", "date", "pwd", "who", "command")
        ):
            return True
        if "hostname" in question_lower and "who" in question_lower and "execut" in question_lower:
            return True
        if any(
            phrase in question_lower
            for phrase in (
                "what is the hostname",
                "what was the hostname",
                "what hostname",
                "hostname output",
                "output of hostname",
            )
        ) and any(term in question_lower for term in ("session", "execut", "here", "who", "ran", "run")):
            return True
        return False

    def _extract_command(self, question: str) -> str | None:
        if is_current_datetime_question(question):
            return None
        backtick_match = re.search(r"`([^`]+)`", question or "")
        if backtick_match:
            return backtick_match.group(1).strip()
        patterns = (
            r"\b(?:command|commands)\s+(?!(?:did|was|were|are|is|that|which|all|the|any|in|it|and|or|with|their|session|sessions)\b)(.+?)(?:\s+does|\?|\.|$)",
            r"\b(?:command|commands)\s+(?!(?:did|was|were|are|is|that|which|all|the|any|in|it|and|or|with|their|session|sessions)\b)([/\w.-]+)",
            r"\b(?:what\s+)?([/\w.-]+)\s+was\s+(?:run|executed)\b",
            r"\b(?:was|were)\s+([/\w.-]+)\s+(?:run|executed)\b",
            r"\bwhat\s+does\s+([/\w.-]+)\b",
            r"\bwhat\s+is\s+([/\w.-]+)\b",
            r"\bexplain\s+([/\w.-]+(?:\s+[-/\w.]+)*)",
            r"\b(?:when\s+(?:did|was)\s+\w+\s+)?(?:execute|executed|run|ran)\s+([/\w.-]+)",
            r"\b(?:when\s+(?:did|was)|(?:at\s+)?what\s+time\s+was)\s+([/\w.-]+)\s+(?:run|executed)",
            r"\bwhat\s+was\s+the\s+output\s+of\s+([/\w.-]+)",
            r"\b([/\w.-]+)\s+(?:was|were)\s+executed\b",
            r"\b(?:before|after)\s+([/\w.-]+(?:\s+[-/\w.]+)*)\s*\??$",
        )
        candidate = None
        for pattern in patterns:
            match = re.search(pattern, question or "", re.IGNORECASE)
            if match:
                candidate = re.sub(
                    r"^the\s+", "", match.group(1).strip().rstrip("?.!,"), flags=re.IGNORECASE
                )
                break
        if candidate is None:
            return None
        if candidate.lower() in COMMAND_STOP_WORDS:
            return None
        if candidate.lower() in {
            "privilege escalation",
            "permission modification",
            "account modification",
        }:
            return None
        return candidate

    def _extract_session_id(self, question: str) -> str | None:
        match = SESSION_ID_RE.search(question or "")
        if match is None:
            return None
        return match.group(0)

    def _extract_users(self, question_lower: str) -> list[str]:
        users: list[str] = []
        ignored_user_tokens = {
            "anyone", "they", "he", "she", "the", "user", "users", "do", "did",
            "deleted", "restarted", "accessed", "executed", "ran", "had", "privilege",
        }
        for pattern in (
            r"\buser\s+([\w.-]+)",
            r"\bwhat did\s+([\w.-]+)\s+do",
            r"\b(?:did|does|has)\s+([\w.-]+)\s+",
            r"\bsessions?\s+(?:does|did)\s+([\w.-]+)\s+have\b",
            r"\b([\w.-]+)'s\s+sessions?\b",
            r"\bsessions?\s+(?:executed|created|run)\s+by\s+([\w.-]+)\b",
        ):
            for match in re.finditer(pattern, question_lower):
                username = match.group(1)
                if username not in ignored_user_tokens and username not in users:
                    users.append(username)
        if "admin" in question_lower and "admin" not in users:
            users.append("admin")
        return users