from __future__ import annotations

import logging
import json
import re
from dataclasses import replace
from collections import Counter
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import text

from app.services.phase1_query_service import Phase1QueryService
from app.services.phase2_query_service import Phase2QueryService
from app.services.phase3_query_service import Phase3QueryService
from app.services.ssh_knowledge_service import SSHKnowledgeService
from app.services.application_knowledge_service import ApplicationKnowledgeService
from app.services.evidence_context_service import EvidenceContextService
from app.services.evidence_retrieval_service import EvidenceRetrievalService
from app.services.llm.base import LLMProvider
from app.services.llm.ollama_provider import OllamaProvider
from app.services.live_information_service import (
    LiveInformationService,
    classify_live_information_intent,
)
from app.services.query_understanding_service import (
    COMMAND_STOP_WORDS,
    QueryUnderstandingService,
    classify_current_datetime_question,
    extract_date_range,
)
from app.services.risk_aggregator import aggregate_session_risks
from app.services.risk_response import format_risk_summary
from app.services.risk_search import (
    extract_risk_categories,
    extract_risk_severity,
    format_cross_session_risk_search,
    is_risk_domain_query,
)
from app.services.timeline_analyzer import analyze_timeline
from app.services.timeline_response import (
    format_first_risky_timeline_entry,
    format_last_command_entry,
    format_timeline_relative_to_command,
    format_timeline_relative_to_risk,
    format_timeline_summary,
    format_when_risk_occurred,
)
from app.services.query_parser import extract_search_terms
from app.services.session_query_service import SessionQueryService


from datetime import date, datetime, timezone

logger = logging.getLogger(__name__)

COMMAND_KNOWLEDGE = {
    "ls": "`ls` lists files and directories in the current working directory.",
    "ssh": "SSH (Secure Shell) is a protocol for securely connecting to and operating remote systems over an encrypted channel.",
    "hostname": "`hostname` displays or sets the system's host name. In sessions it is often used to identify which server you are connected to.",
    "date": "`date` displays or sets the system date and time. It is commonly used to verify server clock and session timing.",
    "whoami": "`whoami` prints the effective username of the current user.",
    "pwd": "`pwd` prints the current working directory path.",
    "sudo": "`sudo` runs a command with elevated (root) privileges. It is a high-risk command in production environments.",
    "chmod": "`chmod` changes file or directory permissions. Dangerous forms like `chmod 777` make files world-writable.",
    "chown": "`chown` changes file or directory ownership.",
    "cat": "`cat` concatenates and displays file contents.",
    "grep": "`grep` searches for text patterns inside files or command output.",
    "cd": "`cd` changes the current working directory.",
    "mkdir": "`mkdir` creates a new directory.",
    "rm": "`rm` removes files or directories. `rm -rf` is destructive and high-risk.",
    "passwd": "`passwd` changes user passwords and is treated as a credential operation.",
    "useradd": "`useradd` creates new user accounts.",
    "history": "`history` shows previously executed shell commands.",
    "echo": "`echo` prints text to the terminal or redirects it to files.",
    "curl": "`curl` transfers data from or to a server. Piping curl to a shell is high-risk.",
    "wget": "`wget` downloads files from the network.",
}

def _is_recent_session_command_list_query(question: str) -> bool:
    question_lower = (question or "").strip().lower()
    wants_recent = any(
        term in question_lower
        for term in (
            "recent", "recently", "latest", "last session", "most recent",
            "newest", "just now", "just logged in", "current session",
        )
    )
    if not wants_recent:
        return False
    wants_commands = any(
        term in question_lower
        for term in ("command", "commands", "executed", "execute", "run", "ran", "list", "activity")
    )
    if wants_commands and ("session" in question_lower or _mentions_actors(question_lower)):
        return True
    # "Who logged in recently" alone (no commands term) is handled by _wants_recent_actor_listing.
    return False


def _mentions_actors(question_lower: str) -> bool:
    return any(
        term in question_lower
        for term in (
            "who", "user", "users", "logged in", "log in", "login", "logins",
            "they", "them", "everyone", "anyone",
        )
    )


def _wants_recent_actor_listing(question: str) -> bool:
    """True for questions like 'who logged in recently and what did they execute?'.

    Requires an explicit actor reference (who/users/they/logged in) — not merely 'all'
    or 'session', because those phrasings usually mean a single-session lookup.
    """
    question_lower = (question or "").strip().lower()
    if not any(
        term in question_lower
        for term in ("recent", "recently", "latest", "just now", "just logged in", "newest")
    ):
        return False
    if _mentions_actors(question_lower):
        return True
    # "show me recent activity" — no explicit actor but implies session listing.
    if "activity" in question_lower and "session" not in question_lower:
        return True
    return False


def _is_latest_session_risk_query(question: str) -> bool:
    question_lower = (question or "").strip().lower()
    if not any(
        term in question_lower
        for term in ("risk finding", "risk findings", "risky", "risk level", "overall risk")
    ):
        return False
    return re.search(
        r"\b(?:latest|last|most recent|recent)\s+(?:ssh\s+)?session\b",
        question_lower,
    ) is not None


def _format_session_duration(started: datetime | None, ended: datetime | None, duration: Any) -> str:
    if duration is not None:
        return str(duration)
    if started is None or ended is None:
        return "unknown"
    if started.tzinfo is None and ended.tzinfo is not None:
        started = started.replace(tzinfo=timezone.utc)
    elif ended.tzinfo is None and started.tzinfo is not None:
        ended = ended.replace(tzinfo=timezone.utc)
    seconds = int((ended - started).total_seconds())
    if seconds < 0:
        return "unknown"
    minutes, remaining_seconds = divmod(seconds, 60)
    if minutes:
        return f"{minutes}m {remaining_seconds}s"
    return f"{remaining_seconds}s"


def _format_command_log(command_evidence: list[Any]) -> list[str]:
    lines = ["Recorded command log (outputs are previews, capped at 1,000 characters each):"]
    output_budget = 4000
    for index, item in enumerate(command_evidence[:10], start=1):
        lines.append(f"{index}. `{item.command or '[command not recorded]'}`")
        output = (item.output or "").strip()
        if not output:
            lines.append("   Output: [no output recorded]")
        elif output_budget > 0:
            display_output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
            display_output = display_output.replace("\r", "")
            display_output = "".join(
                char for char in display_output
                if char in "\n\t" or ord(char) >= 32
            )
            preview = display_output[: min(1000, output_budget)]
            output_budget -= len(preview)
            fence_length = max(3, max((len(run) for run in re.findall(r"`+", preview)), default=0) + 1)
            fence = "`" * fence_length
            lines.append("   Output preview:")
            lines.append(f"   {fence}text")
            lines.extend(f"   {line}" for line in preview.splitlines())
            lines.append(f"   {fence}")
            if len(display_output) > len(preview):
                lines.append("   [output truncated; the complete output remains in the session log]")
        else:
            lines.append("   Output omitted from this response to keep it concise.")
        if item.exit_code is not None:
            lines.append(f"   Exit code: {item.exit_code}")
        elif item.output is not None:
            lines.append("   Exit code: not recorded")
    if len(command_evidence) > 10:
        lines.append(f"[Showing 10 of {len(command_evidence)} recorded commands.]")
    return lines


def _format_command_execution_time(executed_at: datetime | None) -> str:
    if executed_at is None:
        return "execution time not recorded"
    if executed_at.tzinfo is None:
        return f"executed at {executed_at.strftime('%Y-%m-%d %H:%M:%S')} (timezone unknown)"
    return f"executed at {executed_at.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"


def _sanitize_question_for_understanding(question: str) -> str:
    """Strip conversation-context suffixes that can confuse command extraction."""
    marker = "\n\nConversation context:"
    if marker in question:
        return question.split(marker, 1)[0].strip()
    return question.strip()


def _is_important_sessions_query(question: str) -> bool:
    question_lower = (question or "").strip().lower()
    return any(
        phrase in question_lower
        for phrase in (
            "important session",
            "important sessions",
            "notable session",
            "notable sessions",
            "critical session",
            "critical sessions",
            "significant session",
            "significant sessions",
        )
    )


def _wants_session_timing_details(question: str) -> bool:
    question_lower = (question or "").strip().lower()
    if any(
        phrase in question_lower
        for phrase in (
            "with date",
            "with dates",
            "with their date",
            "with their dates",
            "with time",
            "with their time",
            "when where",
            "when and where",
            "at what time",
            "what time",
            "when were",
            "when was",
            "where were",
            "where was",
            "where these",
            "when these",
            "conducted",
            "executed on",
            "on which date",
        )
    ):
        return True
    if "session" in question_lower and any(term in question_lower for term in ("date", "time", "where")):
        return True
    return False


def _format_session_datetime(started_at) -> tuple[str, str]:
    if started_at is None:
        return "unknown date", "unknown time"
    date_label = started_at.strftime("%d-%m-%y")
    time_label = started_at.strftime("%H:%M:%S")
    tz_name = started_at.tzname()
    if tz_name:
        time_label = f"{time_label} {tz_name}"
    return date_label, time_label


def _resolve_session_location(session, commands) -> str:
    if session is not None:
        target = getattr(session, "target", None)
        if target and str(target).strip():
            return str(target).strip()
        remote_address = getattr(session, "remote_address", None)
        if remote_address and str(remote_address).strip():
            return str(remote_address).strip()
    for command in commands:
        command_text = (getattr(command, "command", None) or "").strip().lower()
        if command_text != "hostname":
            continue
        output = (getattr(command, "output", None) or "").strip()
        if output:
            return output
    return "unknown"


def _is_risk_count_query(question: str) -> bool:
    """True when the user just wants a NUMBER of risky sessions, not a full listing."""
    question_lower = (question or "").strip().lower()
    if not any(term in question_lower for term in ("risky", "risk", "dangerous", "suspicious", "high-risk", "high risk")):
        return False
    if not any(phrase in question_lower for phrase in COUNT_TERMS):
        return False
    return "session" in question_lower or "sessions" in question_lower


def _is_all_risk_overview_query(question: str) -> bool:
    question_lower = (question or "").strip().lower()
    if not any(term in question_lower for term in ("risky", "risk", "dangerous", "suspicious", "high-risk", "high risk")):
        return False
    # Precision guard: bare count questions should NOT get a full listing.
    if _is_risk_count_query(question):
        return False
    return any(
        term in question_lower
        for term in (
            "all risky",
            "risky command",
            "risky commands",
            "risky session",
            "risky sessions",
            "risk findings",
            "risk session",
            "session id",
            "with their session",
            "give me",
            "list",
            "what are",
            "show",
        )
    )


def _is_risk_follow_up_query(question: str) -> bool:
    question_lower = (question or "").strip().lower()
    return (
        "retrieved" in question_lower
        and "session(s)" in question_lower
        and any(term in question_lower for term in ("risk", "risky", "said", "but"))
    )


SESSION_ID_IN_QUESTION_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


def _extract_session_id_from_question(question: str) -> str | None:
    match = SESSION_ID_IN_QUESTION_RE.search(question or "")
    if match is None:
        return None
    return match.group(0)


def _is_session_context_query(question: str) -> bool:
    return QueryUnderstandingService()._is_session_evidence_question((question or "").strip().lower())


def _is_session_command_list_query(question: str) -> bool:
    question_lower = (question or "").strip().lower()
    if _extract_session_id_from_question(question) is None:
        return False
    # Time-oriented follow-ups such as "when was session <uuid> executed?" ask
    # for a date, not a command listing; let Phase 1 handle them.
    if any(
        phrase in question_lower
        for phrase in (
            "when was session",
            "when did session",
            "when was this session",
            "when did this session",
            "date of session",
            "date of this session",
            "on what date",
            "on which date",
            "what date was session",
        )
    ):
        return False
    if any(
        phrase in question_lower
        for phrase in ("what time", "at what time", "how long", "duration of", "login time", "logout time")
    ):
        return False
    return any(
        term in question_lower
        for term in (
            "command", "commands", "executed", "execute", "run", "ran", "used",
            "list", "show", "description", "details", "detail", "what happened",
            "information", "activity",
        )
    )


_PLACEHOLDER_COMMAND_PHRASES = {
    "commands", "the commands", "these commands", "those commands", "the command",
    "these", "those", "them", "it", "all", "all commands",
    "some commands", "all of them", "any", "any command",
}


def _is_placeholder_command_phrase(term: str) -> bool:
    lowered = (term or "").strip().lower().rstrip(" ?.!,")
    if not lowered:
        return True
    if lowered in _PLACEHOLDER_COMMAND_PHRASES:
        return True
    words = [w for w in lowered.replace("`", "").split() if w]
    if not words:
        return True
    filler_only = {
        "the", "these", "those", "them", "it", "all", "any", "some",
        "commands", "command", "one", "ones",
    }
    if all(w in filler_only for w in words):
        return True
    # Garbled compound phrases like "these commands give me the hostname" that mix
    # pronouns with imperative fragments — treat as vague, not a literal command name.
    if any(w in {"these", "those", "them", "the"} for w in words[:2]) and any(
        marker in lowered
        for marker in (
            " give me", " show me", " tell me", " list ", " and ", " also ",
            " hostname", " host name", " host ", " who ", " which ",
            " what ", " when ", " where ", " ?", "?",
        )
    ):
        return True
    # If the phrase contains an English interrogative or contains a natural-language
    # connective it is almost certainly not a real command name.
    if any(
        marker in f" {lowered} "
        for marker in (
            " give me ", " show me ", " tell me ", " and give ", " and show ",
            " who ", " which ", " when ", " where ", " why ",
        )
    ):
        return True
    return False


def _mentions_hostname(question_lower: str) -> bool:
    return any(
        term in question_lower
        for term in (
            "hostname", "host name", "which host", "what host", "on which host",
            "target host", "which machine", "what machine",
        )
    )


def _is_command_audit_query(question_lower: str) -> bool:
    """Detects: 'who executed the command X?', 'which user ran X?', 'who ran ip addr?'."""
    if not any(
        marker in question_lower
        for marker in (
            "who executed", "who ran", "who used",
            "which user ran", "which user executed", "which user used",
            "what user ran", "what user executed",
            "who has executed", "who has run",
        )
    ):
        return False
    # "Who executed commands here" (no specific command) is a session-scoped question.
    if "here" in question_lower or "in this session" in question_lower:
        return False
    # Analytical/aggregation questions ("most", "least", "top") aren't a single-command
    # lookup — e.g. "which user ran the most commands this week" should NOT be treated
    # as auditing a literal command called "the most commands this week".
    if any(
        marker in question_lower
        for marker in (
            "most", "least", "fewest", "top", "highest", "lowest",
            "average", "most often", "most frequently",
        )
    ):
        return False
    return True


def _is_active_sessions_query(question_lower: str) -> bool:
    """Detect questions asking which sessions are currently still open."""
    if "inactive" in question_lower or "active and inactive" in question_lower:
        return False
    return any(
        marker in question_lower
        for marker in (
            "currently logged in",
            "currently online",
            "currently active",
            "who is online",
            "who's online",
            "who is active",
            "who's active",
            "active sessions",
            "active session",
            "logged in right now",
            "logged in now",
            "who is logged in",
            "who's logged in",
        )
    )


def _is_admin_session_date_query(question: str) -> bool:
    question_lower = (question or "").strip().lower()
    return (
        "admin" in question_lower
        and "session" in question_lower
        and any(term in question_lower for term in ("list", "show", "give", "display"))
        and any(term in question_lower for term in ("by date", "date wise", "date-wise", "with date", "with dates"))
    )


def _is_logout_time_query(question_lower: str) -> bool:
    has_temporal_marker = "when" in question_lower or "what time" in question_lower
    has_logout_marker = any(
        marker in question_lower
        for marker in ("log out", "logged out", "logout", "sign out", "end session", "disconnect")
    )
    return has_temporal_marker and has_logout_marker


def _is_command_explanation_query(question: str) -> bool:
    question_lower = (question or "").strip().lower()
    if _extract_session_id_from_question(question):
        return False
    if any(
        phrase in question_lower
        for phrase in (
            "who accessed",
            "who logged in",
            "who is logged in",
            "who was logged in",
            "user activity",
            "accessed the system",
        )
    ):
        return False
    if any(term in question_lower for term in ("session", "warpgate", "postgresql", "logged in")):
        return False
    # Actor-audit questions ("who executed X", "who ran X", "which user ran X") are
    # NOT explanation questions — they ask which user executed a command.
    if _is_command_audit_query(question_lower):
        return False
    return any(
        term in question_lower
        for term in (
            "explain",
            "what does",
            "what is",
            "what's",
            "whats",
            "tell me about",
            "tell me what",
            "how does",
            "how do i",
            "how to use",
            "meaning of",
            "purpose of",
            "describe",
            "briefly explain",
            "brief on",
            "give me a brief",
            "one liner",
            "one-liner",
            " command do",
        )
    )


def build_llm_provider() -> LLMProvider:
    return OllamaProvider()


RISK_TERMS = (
    "suspicious",
    "risk",
    "anomalous",
    "malicious",
    "dangerous",
    "risky",
    "privilege escalation",
    "permission modification",
)
TIMELINE_TERMS = ("timeline", "events", "event", "chronological")
SESSION_SEARCH_PATTERNS = (
    r"\bfind\s+(all\s+)?sessions\b",
    r"\bwhich\s+sessions\b",
    r"\bshow\s+(me\s+)?sessions\b",
    r"\bsearch\s+sessions\b",
    r"\bsessions\s+where\b",
    r"\bsessions\s+(with|using|involving|containing|that)\b",
    r"\bacross\s+sessions\b",
    r"\bother\s+sessions\b",
    r"\bany\s+sessions\b",
    r"\bwhat\s+happened\s+in\s+sessions\b",
    r"\bsessions\s+contain\b",
)
SESSION_LIST_PATTERNS = (
    r"\b(?:what|which)\s+(?:were|are)\s+(?:the\s+)?(?:ssh\s+|web\s+)?sessions?\b",
    r"\b(?:show|list|display|retrieve|fetch)\s+(?:me\s+)?(?:all\s+)?(?:ssh\s+|web\s+)?sessions?\b",
    r"\b(?:all\s+)?(?:ssh\s+|web\s+)?sessions?\s+(?:till|until|up to)\s+(?:now|today)\b",
    r"\b(?:ssh\s+|web\s+)?sessions?\s+(?:so far|up to now)\b",
    r"\b(?:what|which)\s+sessions?\s+(?:occurred|happened|were recorded|were performed|were captured)\b",
    r"\b(?:all\s+)?historical\s+(?:ssh\s+|web\s+)?sessions?\b",
)
SCHEDULED_SESSION_QUERY = re.compile(
    r"\bsessions?\b.*\b(?:scheduled|planned|expected|forecast)\b|"
    r"\b(?:scheduled|planned|expected|forecast)\b.*\bsessions?\b",
    re.IGNORECASE,
)
EVENT_SEARCH_PATTERNS = (
    r"\b(?:search|find|look up)\s+(?:the\s+)?(?:audit\s+)?events?\b",
    r"\b(?:search|find)\s+event\s+log\b",
    r"\b(?:show|list)\s+(?:audit\s+)?events?\s+(?:for|about|containing|with)\b",
)
COMMAND_TERMS = ("command", "commands", "ran", "run", "executed", "execute")
SESSION_LOOKUP_TERMS = (
    "what happened",
    "who used",
    "who was",
    "details",
    "summary",
    "summarize",
    "summarise",
    "overview",
)
SESSION_TIME_TERMS = ("when did", "start", "end", "started", "ended", "login", "logout")
COUNT_TERMS = ("how many", "number of", "how much", "total number", "count of")
ANALYST_QUERY_TERMS = (
    "analyze",
    "analysis",
    "explain",
    "why is",
    "why was",
    "security significance",
    "security impact",
    "security concern",
    "security concerns",
    "summarize",
    "summary",
    "give me an assessment",
    "assess",
    "interpret",
)


def classify_chat_intent(question: str, session_id: str | None = None) -> str:
    question_lower = (question or "").strip().lower()
    session_id = session_id or _extract_session_id_from_question(question)
    if not question_lower:
        return "UNKNOWN"

    if _is_session_count_query(question_lower, session_id):
        return "SESSION_COUNT"

    if _is_session_listing_question(question_lower):
        return "SESSION_LIST"

    if SCHEDULED_SESSION_QUERY.search(question_lower):
        return "SESSION_LIST"

    if _is_active_sessions_query(question_lower):
        return "USER_ACTIVITY"

    if re.search(r"\bcompare\b.*\bsessions?\b", question_lower):
        return "SESSION_STATS"

    live_information_intent = classify_live_information_intent(question)
    if live_information_intent is not None:
        return live_information_intent

    if classify_current_datetime_question(question) is not None:
        return "CURRENT_WEATHER_OR_TIME"

    if (
        session_id is None
        and any(re.search(pattern, question_lower) for pattern in EVENT_SEARCH_PATTERNS)
    ):
        return "EVENT_SEARCH"

    if re.search(r"\b(?:web|browser|rrweb)\b.*\b(?:recordings?|replay)\b", question_lower):
        return "RECORDING_SEARCH"

    if re.search(
        r"\b(?:which|what)\s+sessions?\b.*\b(?:have|has)\s+(?:a\s+)?recordings?\b",
        question_lower,
    ):
        return "RECORDING_SEARCH"

    risk_severity = extract_risk_severity(question_lower)
    if risk_severity and session_id is None and "sessions" in question_lower:
        return "SESSION_SEARCH"

    if _has_session_search_signal(question_lower):
        return "SESSION_SEARCH"

    if any(term in question_lower for term in RISK_TERMS):
        return "RISK_ANALYSIS"

    if "permission" in question_lower and "modif" in question_lower:
        return "RISK_ANALYSIS"

    if any(term in question_lower for term in TIMELINE_TERMS):
        return "TIMELINE_SUMMARY"

    if _is_command_explanation_query(question) and (
        "command" in question_lower
        or any(
            re.search(rf"\b{re.escape(command)}\b", question_lower)
            for command in COMMAND_KNOWLEDGE
        )
    ):
        return "COMMAND_EXPLANATION"

    if session_id and any(term in question_lower for term in SESSION_TIME_TERMS):
        return "SESSION_LOOKUP"

    if session_id and _has_session_command_signal(question_lower):
        return "COMMAND_LOOKUP"

    if session_id and any(term in question_lower for term in SESSION_LOOKUP_TERMS):
        return "SESSION_LOOKUP"

    if session_id and extract_search_terms(question_lower):
        return "COMMAND_LOOKUP"

    if any(term in question_lower for term in COMMAND_TERMS):
        return "COMMAND_SEARCH"

    if any(term in question_lower for term in SESSION_TIME_TERMS):
        return "SESSION_SEARCH"

    if any(term in question_lower for term in SESSION_LOOKUP_TERMS):
        return "SESSION_LOOKUP" if session_id else "UNKNOWN"

    if extract_search_terms(question_lower) and any(
        term in question_lower for term in ("search", "find", "look for", "which command")
    ):
        return "COMMAND_SEARCH"

    return "GENERAL_QUESTION"


def _has_session_search_signal(question_lower: str) -> bool:
    return any(re.search(pattern, question_lower) for pattern in SESSION_SEARCH_PATTERNS)


def _is_session_listing_question(question: str) -> bool:
    question_lower = (question or "").strip().lower()
    if not re.search(r"\bsessions?\b", question_lower):
        return False
    if re.search(r"\b(?:which|find)\s+sessions?\s+(?:that\s+)?(?:executed|ran|used)\b", question_lower):
        return False
    if re.search(r"\bsessions?\s+(?:where|with|using|involving|containing|that)\b", question_lower):
        return False
    if any(phrase in question_lower for phrase in ("till now", "until now", "up to now", "so far")):
        return True
    if re.search(
        r"\b(?:what|which)\s+sessions?\s+(?:occurred|happened|were recorded|were performed|were captured)\b",
        question_lower,
    ):
        return not any(term in question_lower for term in ("command", "commands"))
    if re.search(r"\b(?:all\s+)?historical\s+(?:ssh\s+|web\s+)?sessions?\b", question_lower):
        return not any(term in question_lower for term in ("command", "commands"))
    if re.search(r"\bsessions?\s+(?:performed|recorded|seen|captured)\s+(?:till|until|up to)\s+(?:now|today)\b", question_lower):
        return True
    if any(re.search(pattern, question_lower) for pattern in SESSION_LIST_PATTERNS):
        return not any(term in question_lower for term in ("command", "commands"))
    if extract_date_range(question_lower) is not None and any(
        phrase in question_lower for phrase in ("what were", "what are", "show", "list")
    ):
        return not any(term in question_lower for term in ("command", "commands"))
    return False


def _is_analyst_query(question_lower: str) -> bool:
    """Return True for questions that benefit from LLM-based analysis."""
    return any(term in question_lower for term in ANALYST_QUERY_TERMS)


FIRST_RISKY_TERMS = ("first risky", "first high-risk", "first high risk")


def _is_first_risky_query(question_lower: str) -> bool:
    return any(term in question_lower for term in FIRST_RISKY_TERMS)


LAST_COMMAND_TERMS = ("last command", "command was executed last", "command executed last")


def _is_last_command_query(question_lower: str) -> bool:
    return any(term in question_lower for term in LAST_COMMAND_TERMS)


_COMMAND_ANCHOR_RE = re.compile(
    r"(?:what happened|what did the user do)\s+(before|after)\s+(.+?)\s*\??$",
    re.IGNORECASE,
)


def _extract_command_anchor(question: str) -> tuple[str, str] | None:
    """Extract (direction, literal command text) from phrasing like
    'what happened after <command>' / 'what did the user do before <command>'."""
    match = _COMMAND_ANCHOR_RE.search((question or "").strip())
    if not match:
        context_match = re.search(
            r"\b(before|after)\s+(?:that\s+command|it)\b.*?referenced command is `([^`]+)`",
            question or "",
            re.IGNORECASE | re.DOTALL,
        )
        if context_match:
            return context_match.group(1).lower(), context_match.group(2).strip()
    if not match:
        return None

    direction = match.group(1).lower()
    command_text = match.group(2).strip()
    if not command_text:
        return None

    return direction, command_text


WHEN_DID_TERMS = ("when did", "when was")


def _is_when_risk_query(question_lower: str) -> bool:
    return any(term in question_lower for term in WHEN_DID_TERMS)


_WHEN_RISK_RE = re.compile(
    r"when (?:did|was)\s+(.+?)\s+(?:happen|happened|occur|occurred|detected)\b",
    re.IGNORECASE,
)


def _extract_when_risk_category_label(question: str) -> str | None:
    """Fallback label for risk phrases not in the recognized category vocabulary,
    so unsupported categories deterministically report 'no findings' instead of
    falling through to the generic timeline summary."""
    match = _WHEN_RISK_RE.search((question or "").strip())
    if not match:
        return None

    phrase = match.group(1).strip()
    if not phrase:
        return None

    return phrase.upper().replace(" ", "_").replace("-", "_")


def _is_session_count_query(question_lower: str, session_id: str | None) -> bool:
    if session_id is not None:
        return False
    if not any(term in question_lower for term in COUNT_TERMS):
        return False
    return "session" in question_lower or "sessions" in question_lower


def _has_session_command_signal(question_lower: str) -> bool:
    if any(term in question_lower for term in COMMAND_TERMS):
        return True
    return bool(re.search(r"\bwas\b.*\bused\b", question_lower))


def _serialize_risk_findings(findings: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "category": finding.category,
            "severity": finding.severity,
            "rule": finding.rule,
        }
        for finding in findings
    ]


def _serialize_session_risk_summary(commands: list[Any]) -> dict[str, Any]:
    findings = [
        finding
        for command in commands
        for finding in getattr(command, "risk_findings", [])
    ]
    risk_summary = aggregate_session_risks(findings)
    return {
        "overall_severity": risk_summary.overall_severity,
        "finding_count": risk_summary.finding_count,
        "high_count": risk_summary.high_count,
        "medium_count": risk_summary.medium_count,
        "low_count": risk_summary.low_count,
        "categories": risk_summary.categories,
    }


def _serialize_timeline_entries(entries: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "timestamp": entry.timestamp,
            "sequence_number": entry.sequence_number,
            "event_type": entry.event_type,
            "command": entry.command,
            "output": entry.output,
            "risk_findings": _serialize_risk_findings(list(getattr(entry, "risk_findings", ()) or ())),
        }
        for entry in entries
    ]


def _serialize_timeline_analysis(analysis: Any) -> dict[str, Any]:
    return {
        "entry_count": analysis.entry_count,
        "command_count": analysis.command_count,
        "event_count": analysis.event_count,
        "first_timestamp": analysis.first_timestamp,
        "last_timestamp": analysis.last_timestamp,
        "overall_severity": analysis.overall_severity,
        "high_count": analysis.high_count,
        "medium_count": analysis.medium_count,
        "low_count": analysis.low_count,
        "risk_categories": list(analysis.risk_categories),
        "commands": list(analysis.commands),
        "event_types": list(analysis.event_types),
        "significant_events": list(analysis.significant_events),
    }


def _conversation_entities(evidence: dict[str, Any]) -> dict[str, Any]:
    command_entities: list[dict[str, Any]] = []
    sessions: list[str] = []
    users: set[str] = set()
    findings: list[dict[str, Any]] = []

    def serialize_timestamp(value: Any) -> str | None:
        return value.isoformat() if hasattr(value, "isoformat") else value

    for session in evidence.get("sessions", []):
        session_id = session.get("session_id")
        if session_id and session_id not in sessions:
            sessions.append(session_id)
        if session.get("username"):
            users.add(session["username"])
        for command in session.get("commands", []):
            if command.get("command"):
                risk_findings = command.get("risk_findings", [])
                command_entities.append(
                    {
                        "command": command["command"],
                        "session_id": session_id,
                        "executed_at": serialize_timestamp(command.get("executed_at")),
                        "output": command.get("output"),
                        "risk_categories": [item.get("category") for item in risk_findings if item.get("category")],
                    }
                )
                findings.extend(risk_findings)

    for command in evidence.get("commands", []) + evidence.get("matched_commands", []):
        if command.get("command") and not any(item["command"] == command["command"] for item in command_entities):
            command_entities.append(
                {
                    "command": command["command"],
                    "session_id": command.get("session_id"),
                    "executed_at": serialize_timestamp(command.get("executed_at")),
                    "output": command.get("output"),
                    "risk_categories": [item.get("category") for item in command.get("risk_findings", []) if item.get("category")],
                }
            )
        if command.get("username"):
            users.add(command["username"])

    for session in evidence.get("matched_sessions", []):
        if session.get("session_id") and session["session_id"] not in sessions:
            sessions.append(session["session_id"])
        if session.get("username"):
            users.add(session["username"])

    return {
        "commands": command_entities,
        "sessions": sessions,
        "users": sorted(users),
        "risk_findings": findings + evidence.get("findings", []),
    }


def _uses_deterministic_risk_response(question: str) -> bool:
    question_lower = (question or "").strip().lower()
    if not question_lower:
        return False
    if "overall risk" in question_lower:
        return True
    if question_lower.startswith("why is") and "risk" in question_lower:
        return True
    return False


def _uses_deterministic_timeline_response(question: str, intent: str) -> bool:
    question_lower = (question or "").strip().lower()
    if not question_lower:
        return False

    if intent == "TIMELINE_SUMMARY":
        return True

    if intent in {"SESSION_LOOKUP", "COMMAND_LOOKUP", "RISK_ANALYSIS"}:
        timeline_signals = (
            "timeline",
            "chronological",
            "what happened during",
            "what happened in this session",
            "what happened first",
            "what happened last",
            "what happened around",
            "sequence of events",
            "before",
            "after",
            "around",
            " first",
            " last",
            "when did",
            "when was",
        )
        return any(signal in question_lower for signal in timeline_signals)

    return False


class ChatbotQueryService:
    def __init__(self, db: Session, llm_provider: LLMProvider | None = None):
        self._db = db
        self._session_query_service = SessionQueryService(db)
        self._llm_provider = llm_provider or build_llm_provider()
        self._uses_ollama_provider = isinstance(self._llm_provider, OllamaProvider)
        self._query_understanding_service = QueryUnderstandingService()
        self._evidence_retrieval_service = EvidenceRetrievalService(self._session_query_service)
        self._evidence_context_service = EvidenceContextService()
        self._phase1_query_service = Phase1QueryService(self._session_query_service)
        self._phase2_query_service = Phase2QueryService(self._session_query_service)
        self._phase3_query_service = Phase3QueryService(self._session_query_service)
        self._ssh_knowledge_service = SSHKnowledgeService()
        self._application_knowledge_service = ApplicationKnowledgeService()

    def _try_total_commands_count(self, question: str) -> str | None:
        question_lower = (question or "").lower()
        if _extract_session_id_from_question(question):
            return None
        if not any(
            phrase in question_lower
            for phrase in (
                "total commands",
                "how many commands",
                "commands have been",
                "commands were executed",
                "commands run",
                "how many total commands",
            )
        ):
            return None
        if any(term in question_lower for term in ("what all", "which commands", "list commands", "show commands")):
            return None

        total = self._session_query_service.sum_total_commands()
        session_count = self._session_query_service.count_unique_sessions()
        average = round(total / session_count, 1) if session_count else 0
        return (
            f"Total commands executed on this system: {total}\n"
            f"Across {session_count} sessions (average {average} commands per session)"
        )

    def _answer_session_listing(self, question: str) -> dict[str, Any] | None:
        if not _is_session_listing_question(question):
            return None

        question_lower = question.casefold()
        date_range = extract_date_range(question)
        username_match = re.search(
            r"\b(?:user|username|by|for)\s+([a-z0-9_.-]{1,128})\b",
            question_lower,
        )
        target_match = re.search(
            r"\b(?:target|host)\s+([a-z0-9_.-]{1,256})\b",
            question_lower,
        )
        page_match = re.search(r"\bpage\s+(\d{1,6})\b", question_lower)
        page = max(1, int(page_match.group(1))) if page_match else 1
        sessions, total = self._session_query_service.query_sessions(
            limit=100,
            offset=(page - 1) * 100,
            username=username_match.group(1) if username_match else None,
            target=target_match.group(1) if target_match else None,
            protocol="SSH" if re.search(r"\bssh\b", question_lower) else None,
            start_date=date_range[0] if date_range else None,
            end_date=date_range[1] if date_range else None,
            occurred_before=datetime.now(timezone.utc),
        )
        if not sessions:
            scope = f"from {date_range[0].isoformat()} through {date_range[1].isoformat()}" if date_range else "in the requested scope"
            return {
                "answer": f"No SSH sessions were recorded {scope}.",
                "intent": "SESSION_LIST",
                "retrieval_mode": "rule-based",
                "evidence_available": True,
                "evidence_summary": "The complete logical-session query returned no matching records.",
                "conversation_entities": {"sessions": []},
            }

        display_limit = len(sessions)
        displayed = sessions[:display_limit]
        date_label = (
            f" from {date_range[0].isoformat()} through {date_range[1].isoformat()}"
            if date_range else ""
        )
        lines = [f"Found {total} distinct SSH session(s){date_label}:"]
        for session in displayed:
            session_identifier = session.session_id or session.unique_id
            started = session.started_at or session.login_time
            lines.append(
                f"- `{session_identifier}` | user: {session.username or 'unknown'} | "
                f"target: {session.target or 'unknown'} | "
                f"started: {started.isoformat() if started else 'unknown'} | "
                f"remote: {session.remote_address or 'unknown'}"
            )
        if total > page * 100:
            lines.append(
                f"Showing page {page}; ask for page {page + 1} to continue."
            )

        return {
            "answer": "\n".join(lines),
            "intent": "SESSION_LIST",
            "retrieval_mode": "rule-based",
            "evidence_available": True,
            "evidence_summary": f"Retrieved {total} complete logical SSH session record(s); displayed {len(displayed)}.",
            "conversation_entities": {
                "sessions": [
                    {"session_id": session.session_id or session.unique_id, "protocol": "SSH"}
                    for session in displayed
                ]
            },
        }

    def _answer_event_search(self, question: str) -> dict[str, Any] | None:
        question_lower = (question or "").casefold()
        if (
            _extract_session_id_from_question(question)
            or not any(re.search(pattern, question_lower) for pattern in EVENT_SEARCH_PATTERNS)
        ):
            return None

        quoted = re.search(r"`([^`]+)`|\"([^\"]+)\"|'([^']+)'", question)
        if quoted:
            terms = [next(group for group in quoted.groups() if group).strip()]
        else:
            search_match = re.search(
                r"\b(?:for|about|containing|with)\s+(.+?)(?:\s+(?:on|between|today|yesterday|this week|last week|page\s+\d+)\b|[?.!]|$)",
                question,
                re.IGNORECASE,
            )
            terms = re.findall(r"[A-Za-z0-9_.:/-]+", search_match.group(1)) if search_match else []

        if not terms:
            return {
                "answer": "What event text, type, or date range should I search for?",
                "intent": "EVENT_SEARCH",
                "retrieval_mode": "rule-based",
                "evidence_available": False,
                "evidence_summary": "The event search did not include a search term.",
            }

        page_match = re.search(r"\bpage\s+(\d{1,7})\b", question, re.IGNORECASE)
        page_number = max(1, min(int(page_match.group(1)), 100_000)) if page_match else 1
        page_size = 20
        offset = (page_number - 1) * page_size
        date_range = extract_date_range(question)
        matches, total = self._session_query_service.search_event_matches(
            terms,
            limit=page_size,
            offset=offset,
            start_date=date_range[0] if date_range else None,
            end_date=date_range[1] if date_range else None,
        )
        if not matches:
            return {
                "answer": (
                    f"No recorded events matched {' '.join(terms)} on page {page_number}."
                    if offset
                    else f"No recorded events matched {' '.join(terms)}."
                ),
                "intent": "EVENT_SEARCH",
                "retrieval_mode": "rule-based",
                "evidence_available": True,
                "evidence_summary": f"The event search completed with no matches for {len(terms)} term(s).",
            }

        lines = [
            f"Found {total} recorded event(s); showing page {page_number} "
            f"({len(matches)} event(s)):"
        ]
        for match in matches:
            severity = f" [{match.severity}]" if match.severity else ""
            lines.append(
                f"- {match.timestamp.isoformat()} | {match.event_type}{severity} | "
                f"user: {match.username or 'unknown'} | session: {match.session_id} | "
                f"{match.message or 'No event message was recorded.'}"
            )
        if total > offset + len(matches):
            lines.append(f"More events are available; ask for page {page_number + 1}.")
        return {
            "answer": "\n".join(lines),
            "intent": "EVENT_SEARCH",
            "retrieval_mode": "rule-based",
            "evidence_available": True,
            "evidence_summary": f"Searched recorded events and found {total} matching event(s).",
            "conversation_entities": {
                "sessions": [
                    {"session_id": match.session_id, "protocol": match.protocol}
                    for match in matches
                ],
            },
        }

    def _try_command_ever_run(self, question: str) -> str | None:
        import json
        import re

        question_lower = (question or "").lower()
        if not any(
            phrase in question_lower
            for phrase in (
                "ever run",
                "ever executed",
                "ever used",
                "ever been run",
                "been ever run",
                "ever ran",
            )
        ):
            return None

        match = re.search(
            r"(?:was|were|has|have)\s+([\w\s/\-.]+?)\s+(?:ever|been)",
            question_lower,
        )
        if not match:
            return None

        command_term = match.group(1).strip()
        stop_words = {"it", "this", "that", "the", "a", "an", "any", "command", "your", "system", "on"}
        if command_term in stop_words or len(command_term) < 2:
            return None

        found: list[dict[str, Any]] = []
        for session in self._session_query_service.list_all_sessions():
            commands = session.commands or []
            if isinstance(commands, str):
                try:
                    commands = json.loads(commands)
                except (TypeError, ValueError):
                    commands = []
            if not isinstance(commands, list):
                continue

            matching_commands = [
                str(command)
                for command in commands
                if command_term in str(command).lower()
            ]
            if not matching_commands:
                continue

            login = (
                session.login_time.strftime("%Y-%m-%d %H:%M:%S")
                if session.login_time
                else str(session.date)
            )
            found.append(
                {
                    "session": str(session.session_id or "")[:8],
                    "username": session.username or "unknown",
                    "date": login,
                    "commands": matching_commands[:2],
                }
            )

        if not found:
            return f"No, `{command_term}` has never been run on this system."

        lines = [f"Yes, `{command_term}` was run {len(found)} time(s):"]
        for item in found[:5]:
            lines.append(
                f"- {item['username']} on {item['date']} "
                f"(session {item['session']}): {', '.join(item['commands'])}"
            )
        return "\n".join(lines)

    def _try_log_tampering(self, question: str) -> str | None:
        import json

        question_lower = (question or "").lower()
        if not any(
            phrase in question_lower
            for phrase in (
                "tamper with logs",
                "log tampering",
                "tamper logs",
                "clear logs",
                "delete logs",
                "erase logs",
                "tried to tamper",
                "tampered with",
                "clearing history",
                "clear history",
                "clear their history",
                "cleared history",
                "clearing logs",
                "cover their tracks",
                "cover tracks",
            )
        ):
            return None

        tampering_commands = (
            "history -c",
            "history -w",
            "history -r",
            "rm /var/log",
            "rm -rf /var/log",
            "> /var/log",
            "truncate",
            "shred",
            "unset histfile",
            "export histsize=0",
            "export histfilesize=0",
        )
        found: list[dict[str, str]] = []
        for session in self._session_query_service.list_all_sessions():
            commands = session.commands or []
            if isinstance(commands, str):
                try:
                    commands = json.loads(commands)
                except (TypeError, ValueError):
                    commands = []
            if not isinstance(commands, list):
                continue

            for command in commands:
                command_text = str(command)
                if not any(marker in command_text.lower() for marker in tampering_commands):
                    continue
                login = (
                    session.login_time.strftime("%Y-%m-%d %H:%M:%S")
                    if session.login_time
                    else str(session.date or "unknown")
                )
                found.append(
                    {
                        "command": command_text,
                        "username": session.username or "unknown",
                        "date": login,
                        "session": str(session.session_id or "")[:8],
                    }
                )

        if not found:
            return "No log tampering attempts detected in any recorded session."

        lines = [f"{len(found)} log tampering attempt(s) detected:"]
        for item in found[:5]:
            lines.append(
                f"- {item['username']} ran `{item['command']}` on {item['date']} "
                f"(session {item['session']})"
            )
        return "\n".join(lines)

    def _try_most_dangerous_command(self, question: str) -> str | None:
        import json

        question_lower = (question or "").lower()
        if not any(
            phrase in question_lower
            for phrase in (
                "most dangerous command",
                "most dangerous",
                "worst command",
                "highest risk command",
                "most risky command",
                "most harmful command",
                "dangerous command ever",
            )
        ):
            return None
        if "user" in question_lower or "session" in question_lower:
            return None

        risk_scores = (
            ("rm -rf", "CRITICAL", 10),
            ("dd if=", "CRITICAL", 10),
            ("mkfs", "CRITICAL", 10),
            ("> /dev/", "CRITICAL", 10),
            ("fork bomb", "CRITICAL", 10),
            ("chmod 777 /etc/passwd", "CRITICAL", 9),
            ("chmod 777 /etc/shadow", "CRITICAL", 9),
            ("cat /etc/shadow", "HIGH", 8),
            ("sudo useradd", "HIGH", 7),
            ("passwd root", "HIGH", 7),
            ("history -c", "HIGH", 6),
            ("chmod 777", "HIGH", 6),
            ("wget ", "MEDIUM", 4),
            ("curl ", "MEDIUM", 4),
            ("nmap", "MEDIUM", 3),
        )
        best: dict[str, str] | None = None
        best_score = -1
        for session in self._session_query_service.list_all_sessions():
            command_records = self._session_query_service.get_command_evidence(
                session.session_id or session.unique_id
            )
            commands = [record.command for record in command_records if record.command]
            if not commands:
                commands = session.commands or []
                if isinstance(commands, str):
                    try:
                        commands = json.loads(commands)
                    except (TypeError, ValueError):
                        commands = []
                if not isinstance(commands, list):
                    continue

            for command in commands:
                command_text = str(command)
                command_lower = command_text.lower()
                for pattern, severity, score in risk_scores:
                    if pattern in command_lower:
                        if score > best_score:
                            best_score = score
                            best = {
                                "command": command_text,
                                "severity": severity,
                                "username": session.username or "unknown",
                                "date": (
                                    session.login_time.strftime("%Y-%m-%d %H:%M:%S")
                                    if session.login_time
                                    else str(session.date or "unknown")
                                ),
                                "session": str(session.session_id or "")[:8],
                            }
                        break

        if best is None:
            return "No dangerous commands found in any recorded session."
        return (
            "Most dangerous command ever run:\n"
            f"- Command: `{best['command']}`\n"
            f"- Severity: {best['severity']}\n"
            f"- Run by: {best['username']}\n"
            f"- Date: {best['date']}\n"
            f"- Session: {best['session']}"
        )

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

    def _try_remaining_recorded_activity(self, question: str) -> dict[str, Any] | None:
        question_lower = (question or "").strip().lower()
        activity_signals = (
            "exact time",
            "first command",
            "last command",
            "sudo",
            "sensitive file",
            "most suspicious",
            "most risky",
            "riskiest",
            "typically",
            "after midnight",
            "peak",
            "login hour",
        )
        if not any(signal in question_lower for signal in activity_signals):
            return None

        username = self._extract_recorded_username(question_lower)
        requested_date_range = extract_date_range(question)
        handles_question = (
            ("exact time" in question_lower and username is not None and requested_date_range is not None)
            or ("first command" in question_lower and username is not None and "today" in question_lower)
            or ("last command" in question_lower and "logout" in question_lower)
            or ("sudo" in question_lower and "how many times" in question_lower and "this week" in question_lower)
            or "sensitive file" in question_lower
            or (username is not None and any(term in question_lower for term in ("most suspicious", "most risky", "riskiest")))
            or (username is not None and "typically" in question_lower)
            or (username is not None and "after midnight" in question_lower)
            or ("peak" in question_lower and "login" in question_lower and "hour" in question_lower)
            or ("login" in question_lower and "hour" in question_lower and "most" in question_lower)
        )
        if not handles_question:
            return None

        analytics = self._phase1_query_service._analytics
        sessions = self._session_query_service.list_sessions(limit=10000)

        if "exact time" in question_lower and username is not None and requested_date_range is not None:
            target_date = requested_date_range[0]
            user_sessions = analytics.list_user_sessions_between(username, target_date, target_date)
            if not user_sessions:
                return self._result(
                    f"No {username} login was recorded on {target_date.isoformat()}.",
                    intent="TEMPORAL_ACCESS",
                    evidence_available=False,
                    evidence_summary=f"No {username} sessions were recorded on {target_date.isoformat()}.",
                )
            lines = [f"{username.title()} login times on {target_date.isoformat()}:"]
            for session in user_sessions:
                started = session.started_at or session.login_time
                lines.append(f"- {started.isoformat() if started else 'unknown time'} (session {session.session_id or session.unique_id})")
            return self._result(
                "\n".join(lines),
                intent="TEMPORAL_ACCESS",
                evidence_available=True,
                evidence_summary=f"Retrieved {len(user_sessions)} {username} login(s) on {target_date.isoformat()}.",
            )

        if "first command" in question_lower and username is not None and "today" in question_lower:
            start_date, end_date = extract_date_range("today") or (date.today(), date.today())
            user_sessions = analytics.list_user_sessions_between(username, start_date, end_date)
            command_rows = []
            for session in user_sessions:
                item = analytics.first_command(session.session_id or session.unique_id)
                if item and item.command:
                    command_rows.append((session, item))
            if not command_rows:
                return self._result(
                    f"No {username} commands were recorded today ({start_date.isoformat()}).",
                    intent="COMMAND_LOOKUP",
                    evidence_available=False,
                    evidence_summary=f"No {username} commands were recorded on {start_date.isoformat()}.",
                )
            lines = [f"First {username} command(s) after login today ({start_date.isoformat()}):"]
            for session, item in command_rows:
                lines.append(f"- `{item.command}` in session {session.session_id or session.unique_id} at {item.executed_at.isoformat() if item.executed_at else 'unknown time'}")
            return self._result(
                "\n".join(lines),
                intent="COMMAND_LOOKUP",
                evidence_available=True,
                evidence_summary=f"Retrieved first command(s) for {len(command_rows)} {username} session(s) today.",
            )

        if "last command" in question_lower and "logout" in question_lower:
            completed = [session for session in sessions if session.ended_at or session.logout_time]
            completed.sort(
                key=lambda session: (
                    (session.ended_at or session.logout_time).replace(tzinfo=timezone.utc)
                    if (session.ended_at or session.logout_time).tzinfo is None
                    else (session.ended_at or session.logout_time)
                ),
                reverse=True,
            )
            for session in completed:
                item = analytics.last_command(session.session_id or session.unique_id)
                if item and item.command:
                    return self._result(
                        f"The last command before logout was `{item.command}` in session {session.session_id or session.unique_id} at {item.executed_at.isoformat() if item.executed_at else 'unknown time'}.",
                        intent="COMMAND_LOOKUP",
                        evidence_available=True,
                        evidence_summary="Retrieved the last command from the latest completed session.",
                    )
            return self._result(
                "No completed session with a recorded command was found.",
                intent="COMMAND_LOOKUP",
                evidence_available=False,
                evidence_summary="No completed session command was found.",
            )

        if "sudo" in question_lower and "how many times" in question_lower and "this week" in question_lower:
            date_range = extract_date_range("this week")
            start_date, end_date = date_range or (date.today(), date.today())
            usages = analytics.find_command_usages_between("sudo", start_date, end_date)
            return self._result(
                f"`sudo` was used {len(usages)} time(s) this week ({start_date.isoformat()} to {end_date.isoformat()}).",
                intent="COMMAND_LOOKUP",
                evidence_available=bool(usages),
                evidence_summary=f"Counted {len(usages)} sudo command occurrence(s) this week.",
            )

        if "sensitive file" in question_lower:
            matches = []
            seen_matches: set[tuple[str, str, str | None]] = set()
            for session in sessions:
                session_id = session.session_id or session.unique_id
                for item in self._session_query_service.get_command_evidence(session_id):
                    findings = [finding for finding in item.risk_findings if finding.category == "CREDENTIAL_FILE_ACCESS"]
                    if findings:
                        match_key = (session_id, item.command or "", item.executed_at.isoformat() if item.executed_at else None)
                        if match_key in seen_matches:
                            continue
                        seen_matches.add(match_key)
                        matches.append((session, item))
            if not matches:
                return self._result(
                    "No sensitive-file access was recorded in any session.",
                    intent="RISK_ANALYSIS",
                    evidence_available=False,
                    evidence_summary="No CREDENTIAL_FILE_ACCESS findings were found.",
                )
            lines = [f"Sensitive-file access was recorded {len(matches)} time(s):"]
            for session, item in matches[:10]:
                lines.append(f"- {session.username or 'unknown'} ran `{item.command}` in session {session.session_id or session.unique_id} at {item.executed_at.isoformat() if item.executed_at else 'unknown time'}")
            return self._result("\n".join(lines), intent="RISK_ANALYSIS", evidence_available=True, evidence_summary=f"Found {len(matches)} sensitive-file access occurrence(s).")

        if username is not None and any(term in question_lower for term in ("most suspicious", "most risky", "riskiest")):
            user_sessions = [session for session in sessions if (session.username or "").lower() == username.lower()]
            ranked = []
            for session in user_sessions:
                evidence = self._session_query_service.get_command_evidence(session.session_id or session.unique_id)
                findings = [finding for item in evidence for finding in item.risk_findings]
                summary = aggregate_session_risks(findings)
                if summary.finding_count:
                    ranked.append((summary.overall_severity, summary.finding_count, session, summary))
            if not ranked:
                return self._result(f"No suspicious {username} session was found.", intent="RISK_ANALYSIS", evidence_available=False, evidence_summary=f"No {username} risk findings were found.")
            severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
            _, _, session, summary = max(ranked, key=lambda row: (severity_order.get(row[0], 0), row[1]))
            return self._result(
                f"The most suspicious {username} session was `{session.session_id or session.unique_id}` with overall risk {summary.overall_severity} and {summary.finding_count} finding(s). Categories: {', '.join(summary.categories)}.",
                intent="RISK_ANALYSIS", evidence_available=True,
                evidence_summary=f"Ranked {username} sessions by recorded risk findings.",
            )

        if username is not None and "typically" in question_lower:
            counter = Counter()
            user_sessions = [session for session in sessions if (session.username or "").lower() == username.lower()]
            for session in user_sessions:
                for item in self._session_query_service.get_command_evidence(session.session_id or session.unique_id):
                    if item.command:
                        counter[item.command.strip()] += 1
            if not counter:
                return self._result(f"No recorded {username} commands are available to establish a typical pattern.", intent="CROSS_SESSION_ANALYSIS", evidence_available=False, evidence_summary=f"No {username} command history was found.")
            common = counter.most_common(5)
            answer = f"{username.title()} typically runs:\n" + "\n".join(f"- `{command}` ({count} time(s))" for command, count in common)
            return self._result(answer, intent="CROSS_SESSION_ANALYSIS", evidence_available=True, evidence_summary=f"Summarized {sum(counter.values())} {username} command occurrence(s).")

        if username is not None and "after midnight" in question_lower:
            matches = [session for session in sessions if (session.username or "").lower() == username.lower() and (session.started_at or session.login_time) and (session.started_at or session.login_time).hour < 6]
            if not matches:
                return self._result(f"No {username} logins after midnight were recorded.", intent="TEMPORAL_ACCESS", evidence_available=False, evidence_summary=f"No {username} sessions started between 00:00 and 05:59.")
            return self._result(f"Yes. {username.title()} logged in after midnight in:\n" + "\n".join(f"- {(session.started_at or session.login_time).isoformat()} (session {session.session_id or session.unique_id})" for session in matches[:10]), intent="TEMPORAL_ACCESS", evidence_available=True, evidence_summary=f"Found {len(matches)} {username} after-midnight login(s).")

        if "peak login hour" in question_lower or ("login hour" in question_lower and "most" in question_lower):
            counts = Counter()
            for session in sessions:
                started = session.started_at or session.login_time
                if started:
                    counts[started.hour] += 1
            if not counts:
                return self._result("No login timestamps are available to calculate a peak hour.", intent="CROSS_SESSION_ANALYSIS", evidence_available=False, evidence_summary="No login timestamps were found.")
            hour, count = counts.most_common(1)[0]
            return self._result(f"Peak login hour: {hour:02d}:00-{hour:02d}:59 UTC ({count} login(s)).", intent="CROSS_SESSION_ANALYSIS", evidence_available=True, evidence_summary=f"Peak login hour was {hour:02d}:00 UTC.")

        return None

    def _extract_recorded_username(self, question_lower: str) -> str | None:
        users = self._query_understanding_service._extract_users(question_lower)
        if users:
            return users[0]
        recorded_users = {
            (session.username or "").strip()
            for session in self._session_query_service.list_sessions(limit=10000)
            if (session.username or "").strip()
        }
        for recorded_user in sorted(recorded_users, key=len, reverse=True):
            if re.search(rf"(?<![\w.-]){re.escape(recorded_user)}(?![\w.-])", question_lower, re.IGNORECASE):
                return recorded_user
        return None

    def _try_incidents_query(self, question: str) -> dict[str, Any] | None:
        """Answer questions about incidents recorded by the agentic pipeline."""
        from datetime import date, timedelta

        question_lower = (question or "").strip().lower()
        if not any(
            phrase in question_lower
            for phrase in (
                "incident", "incidents", "threat detected", "threats detected",
                "detected recently", "dangerous command detected", "dangerous commands detected", "alert",
                "security alert", "how many threats",
            )
        ):
            return None

        severity = next(
            (value for value in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if value.lower() in question_lower),
            None,
        )
        today = date.today()
        where = []
        parameters: dict[str, Any] = {}
        if severity:
            where.append("severity = :severity")
            parameters["severity"] = severity
        if "today" in question_lower:
            where.append("DATE(detected_at) = :target_date")
            parameters["target_date"] = today
            period = "today"
        elif "yesterday" in question_lower:
            where.append("DATE(detected_at) = :target_date")
            parameters["target_date"] = today - timedelta(days=1)
            period = "yesterday"
        elif any(phrase in question_lower for phrase in ("this week", "last 7 days", "past week")):
            where.append("DATE(detected_at) >= :start_date")
            parameters["start_date"] = today - timedelta(days=7)
            period = "this week"
        else:
            period = "recently" if any(phrase in question_lower for phrase in ("recent", "latest", "last")) else ""

        where_sql = " AND ".join(where) or "TRUE"
        try:
            count_request = any(phrase in question_lower for phrase in ("how many", "count", "total"))
            if count_request:
                count = self._db.execute(
                    text(f"SELECT COUNT(*) FROM incidents WHERE {where_sql}"),
                    parameters,
                ).scalar() or 0
                label = f"{severity} " if severity else ""
                return self._result(
                    f"{count} {label}incident(s) detected {period or 'in total'}.",
                    intent="RISK_ANALYSIS",
                    evidence_available=bool(count),
                    evidence_summary=f"Counted {count} incident(s) {period or 'in total'}.",
                )

            limit = 5 if period == "recently" else 10
            rows = self._db.execute(
                text(
                    f"""
                    SELECT command, severity, username, session_id, detected_at,
                           anomaly_score, is_anomaly, action_taken
                    FROM incidents
                    WHERE {where_sql}
                    ORDER BY detected_at DESC
                    LIMIT :limit
                    """
                ),
                {**parameters, "limit": limit},
            ).mappings().all()
            if not rows:
                return self._result(
                    f"No incidents detected {period or 'in the recorded incident log'}.",
                    intent="RISK_ANALYSIS",
                    evidence_available=False,
                    evidence_summary=f"No incidents matched {period or 'the requested scope'}.",
                )

            lines = [f"{len(rows)} incident(s) found:"]
            for row in rows:
                detected_at = row["detected_at"]
                timestamp = detected_at.strftime("%Y-%m-%d %H:%M:%S") if detected_at else "unknown"
                lines.append(
                    f"- [{row['severity']}] `{row['command']}` by {row['username'] or 'unknown'} "
                    f"at {timestamp} (session {row['session_id'] or 'unknown'})"
                )
                if row["is_anomaly"] and row["anomaly_score"] is not None:
                    lines.append(f"  Anomaly detected (score: {float(row['anomaly_score']):.3f})")
            return self._result(
                "\n".join(lines),
                intent="RISK_ANALYSIS",
                evidence_available=True,
                evidence_summary=f"Retrieved {len(rows)} incident(s) {period or 'from the incident log'}.",
            )
        except Exception as exc:
            return self._result(
                f"Could not query incidents: {exc}",
                intent="RISK_ANALYSIS",
                evidence_available=False,
                evidence_summary="Incident table query failed.",
            )

    def answer_question(
        self,
        question: str,
        session_id: str | None = None,
        resolved_command: str | None = None,
        followup_type: str | None = None,
    ) -> dict[str, Any]:
        question_text = _sanitize_question_for_understanding((question or "").strip())

        if SCHEDULED_SESSION_QUERY.search(question_text):
            return {
                "answer": (
                    "I can't confirm scheduled or planned future sessions: the available "
                    "session sources contain recorded activity, not a scheduled-session register."
                ),
                "intent": "SESSION_LIST",
                "retrieval_mode": "rule-based",
                "session_id": session_id,
                "evidence_available": False,
                "evidence_summary": "No reliable scheduled-session data source is configured.",
                "conversation_entities": {"sessions": []},
            }

        live_information_intent = classify_live_information_intent(question_text)
        if live_information_intent is not None:
            live_information = LiveInformationService(llm_provider=self._llm_provider)
            return live_information.answer_question(question_text, live_information_intent)

        event_search_answer = self._answer_event_search(question_text)
        if event_search_answer is not None:
            return event_search_answer

        session_list_answer = self._answer_session_listing(question_text)
        if session_list_answer is not None:
            return session_list_answer

        if ApplicationKnowledgeService.is_application_question(question_text):
            application_plan = self._query_understanding_service.understand(
                question_text,
                session_id=session_id,
            )
            if application_plan.query_type in {"GENERAL_KNOWLEDGE", "COMMAND_EXPLANATION"}:
                application_context = self._application_knowledge_service.context_for(question_text)
                if application_context is None:
                    return {
                        "answer": "I couldn't retrieve the project documentation needed to answer that application-specific question.",
                        "intent": application_plan.query_type,
                        "retrieval_mode": "rule-based",
                        "session_id": session_id,
                        "evidence_available": False,
                        "evidence_summary": "Project documentation was unavailable.",
                    }
                answer = self._generate_llm_answer(
                    question_text,
                    application_plan.query_type,
                    application_context,
                )
                if answer is None:
                    return {
                        "answer": "I retrieved the relevant project documentation, but the configured model is unavailable to summarize it.",
                        "intent": application_plan.query_type,
                        "retrieval_mode": "rule-based",
                        "session_id": session_id,
                        "evidence_available": True,
                        "evidence_summary": "Retrieved bounded excerpts from project documentation.",
                    }
                return {
                    "answer": answer,
                    "intent": application_plan.query_type,
                    "retrieval_mode": "llm",
                    "session_id": session_id,
                    "evidence_available": True,
                    "evidence_summary": "Answered using bounded repository documentation excerpts.",
                }

        incidents_answer = self._try_incidents_query(question_text)
        if incidents_answer is not None:
            return incidents_answer

        total_commands_answer = self._try_total_commands_count(question_text)
        if total_commands_answer is not None:
            return {
                "answer": total_commands_answer,
                "intent": "SESSION_STATS",
                "retrieval_mode": "rule-based",
                "evidence_available": True,
                "evidence_summary": "Counted total commands across recorded sessions.",
            }

        command_ever_run_answer = self._try_command_ever_run(question_text)
        if command_ever_run_answer is not None:
            return {
                "answer": command_ever_run_answer,
                "intent": "COMMAND_LOOKUP",
                "retrieval_mode": "rule-based",
                "evidence_available": True,
                "evidence_summary": "Searched recorded session commands.",
            }

        log_tampering_answer = self._try_log_tampering(question_text)
        if log_tampering_answer is not None:
            return {
                "answer": log_tampering_answer,
                "intent": "RISK_ANALYSIS",
                "retrieval_mode": "rule-based",
                "evidence_available": True,
                "evidence_summary": "Searched recorded session commands for log tampering indicators.",
            }

        most_dangerous_command_answer = self._try_most_dangerous_command(question_text)
        if most_dangerous_command_answer is not None:
            return {
                "answer": most_dangerous_command_answer,
                "intent": "RISK_ANALYSIS",
                "retrieval_mode": "rule-based",
                "evidence_available": True,
                "evidence_summary": "Ranked recorded commands by configured risk severity.",
            }

        remaining_activity_answer = self._try_remaining_recorded_activity(question_text)
        if remaining_activity_answer is not None:
            return remaining_activity_answer

        system_status = self._answer_system_status(question_text)
        if system_status is not None:
            return system_status

        latest_session_risk = self._answer_latest_session_risk_findings(question_text, session_id)
        if latest_session_risk is not None:
            return latest_session_risk

        recent_session = self._try_last_session_details(question_text)
        if recent_session is not None:
            return recent_session

        analytical_grounded = self._try_analytical_grounded_fallback(question_text, session_id)
        if analytical_grounded is not None:
            return analytical_grounded

        # Accept common misspellings before command/general-knowledge routing.
        if any(term in question_text.lower() for term in ("privilage escalation", "priviledge escalation")):
            misspelled_risk_answer = self._phase1_query_service.try_answer(
                question_text,
                session_id=session_id,
            )
            if misspelled_risk_answer is not None:
                return misspelled_risk_answer

        embedded_session_id = _extract_session_id_from_question(question_text)
        if _is_session_command_list_query(question_text):
            session_commands = self._answer_session_command_list(
                question_text,
                embedded_session_id or session_id,
            )
            if session_commands is not None:
                return session_commands

        # Keep explicit admin/date listings ahead of generic evidence retrieval.
        if _is_admin_session_date_query(question_text):
            admin_date_answer = self._phase1_query_service.try_answer(question_text, session_id=session_id)
            if admin_date_answer is not None:
                return admin_date_answer

        analytics_priority = (
            "most commands" in question_text.lower()
            or "total commands" in question_text.lower()
            or "earliest login" in question_text.lower()
            or "latest login" in question_text.lower()
            or "all login times" in question_text.lower()
            or "all logout times" in question_text.lower()
        )
        if analytics_priority:
            analytics_answer = self._phase1_query_service.try_answer(question_text, session_id=session_id)
            if analytics_answer is not None:
                return analytics_answer

        followup_answer = self._answer_conversation_followup(
            question=question_text,
            session_id=session_id,
            resolved_command=resolved_command,
            followup_type=followup_type,
        )
        if followup_answer is not None:
            return followup_answer

        active_sessions_answer = self._answer_active_sessions(question_text)
        if active_sessions_answer is not None:
            return active_sessions_answer

        logout_time_answer = self._answer_logout_time(question_text)
        if logout_time_answer is not None:
            return logout_time_answer

        command_audit = self._answer_command_audit(question_text)
        if command_audit is not None:
            return command_audit

        command_explanation = self._answer_command_explanation(question_text)
        if command_explanation is not None:
            return command_explanation

        # Recent-actor listings ("who logged in recently and what did they run") are more
        # specific than generic phase1 command-frequency answers — run them first.
        recent_session_answer = self._answer_recent_session_command_list(question_text, session_id)
        if recent_session_answer is not None:
            return recent_session_answer

        phase1_answer = self._phase1_query_service.try_answer(question_text, session_id=session_id)
        if phase1_answer is not None:
            return phase1_answer

        phase2_answer = self._phase2_query_service.try_answer(question_text, session_id=session_id)
        if phase2_answer is not None:
            return phase2_answer

        phase3_answer = self._phase3_query_service.try_answer(question_text, session_id=session_id)
        if phase3_answer is not None:
            return phase3_answer

        if (
            _is_important_sessions_query(question_text)
            or _is_all_risk_overview_query(question_text)
            or _is_risk_follow_up_query(question_text)
        ):
            risk_overview = self._answer_all_risk_overview(question_text, session_id)
            if risk_overview is not None:
                return risk_overview

        embedded_session_id = _extract_session_id_from_question(question_text)
        if _is_session_context_query(question_text):
            session_context = self._answer_session_context_query(question_text, session_id)
            if session_context is not None:
                return session_context

        query_plan = self._query_understanding_service.understand(question_text, session_id=session_id)
        effective_session_id = query_plan.session_id or session_id
        date_range = query_plan.date_range
        intent = (
            "TEMPORAL_ACCESS"
            if query_plan.needs_only_temporal_access()
            else classify_chat_intent(question_text, effective_session_id)
        )
        if query_plan.requires_grounded_retrieval():
            intent = "GROUNDED_ANALYSIS"

        if (
            effective_session_id
            and "commands" in query_plan.needs
            and intent == "COMMAND_SEARCH"
        ):
            intent = "COMMAND_LOOKUP"

        if not hasattr(self._db, "scalars") or not hasattr(self._db, "get"):
            return {
                "answer": "I couldn't retrieve session evidence because database access is unavailable.",
                "intent": intent,
                "retrieval_mode": "rule-based",
                "session_id": session_id,
                "evidence_available": False,
                "evidence_summary": "Database access is unavailable.",
            }

        if self._is_grounded_session_fallback(question_text, query_plan):
            grounded_plan = replace(
                query_plan,
                query_type="SECURITY_SUMMARY",
                needs=set(query_plan.needs) | {"sessions", "commands", "events", "risk_findings"},
                risk_domain_query=True,
                analysis=query_plan.analysis or "security_summary",
            )
            grounded_result = self._answer_grounded(grounded_plan, effective_session_id)
            if grounded_result.get("retrieval_mode") == "llm":
                grounded_result["retrieval_mode"] = "grounded_llm"
            return grounded_result

        if not question_text:
            return {
                "answer": "Please provide a question about the session data.",
                "intent": "UNKNOWN",
                "retrieval_mode": "rule-based",
                "session_id": session_id,
                "evidence_available": False,
                "evidence_summary": "No question supplied.",
            }

        if query_plan.query_type in {"GENERAL_KNOWLEDGE", "COMMAND_EXPLANATION"}:
            answer = self._generate_llm_answer(
                question_text,
                query_plan.query_type,
                {"source": "ssh_linux_knowledge", "command": query_plan.command},
            )
            if answer is not None:
                return {
                    "answer": answer,
                    "intent": query_plan.query_type,
                    "retrieval_mode": "llm",
                    "session_id": session_id,
                    "evidence_available": False,
                    "evidence_summary": "Answered from SSH/Linux general knowledge.",
                }
            return {
                "answer": self._knowledge_fallback(query_plan.command),
                "intent": query_plan.query_type,
                "retrieval_mode": "rule-based",
                "session_id": session_id,
                "evidence_available": False,
                "evidence_summary": "Answered from built-in SSH/Linux knowledge because Ollama was unavailable.",
            }

        if query_plan.needs_only_temporal_access():
            return self._answer_temporal(question_text, date_range, session_id)

        if query_plan.requires_grounded_retrieval():
            return self._answer_grounded(query_plan, effective_session_id)

        session = None
        commands: list[Any] = []
        events: list[Any] = []
        matched_commands: list[Any] = []
        matched_sessions: list[Any] = []
        timeline_entries: list[Any] = []
        timeline_analysis: Any | None = None
        evidence_summary = "No session context was available."
        evidence_available = False
        search_terms: list[str] = []
        risk_categories: list[str] = []
        risk_severity: str | None = None
        risk_domain_query: bool = False
        session_count: int | None = None

        if effective_session_id:
            session = self._session_query_service.get_session(effective_session_id)
            if session is not None:
                commands = self._session_query_service.get_command_evidence(effective_session_id)
                events = self._session_query_service.get_events(effective_session_id)
                timeline_entries = self._session_query_service.get_session_timeline(effective_session_id)
                timeline_analysis = analyze_timeline(timeline_entries)
                evidence_available = True
                evidence_summary = (
                    f"Session {effective_session_id} with username {session.username or 'unknown'} "
                    f"and {len(commands)} command(s), {len(events)} event(s)."
                )

        if intent == "COMMAND_SEARCH":
            search_terms = extract_search_terms(question_text)
            matched_commands = self._session_query_service.search_command_matches(search_terms)
            evidence_available = bool(matched_commands)
            if search_terms:
                evidence_summary = (
                    f"Matched {len(matched_commands)} command row(s) across sessions for search terms {search_terms}."
                )
            else:
                evidence_summary = "No useful search terms were extracted from the question."

        if intent == "SESSION_COUNT":
            risk_categories = extract_risk_categories(question_text)
            risk_severity = extract_risk_severity(question_text)
            risk_domain_query = is_risk_domain_query(question_text)

            if risk_categories:
                matched_sessions = self._session_query_service.search_sessions_by_risk_categories(risk_categories)
                session_count = len(matched_sessions)
                evidence_summary = (
                    f"Counted {session_count} session(s) for risk categories {risk_categories}."
                )
            elif risk_severity:
                matched_sessions = self._session_query_service.search_sessions_by_risk_severity(risk_severity)
                session_count = len(matched_sessions)
                evidence_summary = (
                    f"Counted {session_count} session(s) for risk severity {risk_severity}."
                )
            elif risk_domain_query:
                matched_sessions = self._session_query_service.search_sessions_with_risk_findings()
                session_count = len(matched_sessions)
                evidence_summary = f"Counted {session_count} session(s) with risk findings."
            else:
                session_count = self._session_query_service.count_unique_sessions()
                evidence_summary = f"Counted {session_count} unique session(s) in total."

            evidence_available = True

        if intent == "SESSION_SEARCH":
            search_terms = extract_search_terms(question_text)
            risk_categories = extract_risk_categories(question_text)
            risk_severity = extract_risk_severity(question_text)
            risk_domain_query = is_risk_domain_query(question_text)
            if risk_categories:
                matched_sessions = self._session_query_service.search_sessions_by_risk_categories(risk_categories)
            elif risk_severity:
                matched_sessions = self._session_query_service.search_sessions_by_risk_severity(risk_severity)
            elif risk_domain_query:
                matched_sessions = self._session_query_service.search_sessions_with_risk_findings()
            else:
                matched_sessions = self._session_query_service.search_sessions_by_command_terms(search_terms)
            matched_commands = [
                command
                for matched_session in matched_sessions
                for command in matched_session.matching_commands
            ]
            evidence_available = bool(matched_sessions)
            if risk_categories:
                evidence_summary = (
                    f"Matched {len(matched_sessions)} session(s) across the session history for risk categories {risk_categories}."
                )
            elif risk_severity:
                evidence_summary = (
                    f"Matched {len(matched_sessions)} session(s) across the session history for risk severity {risk_severity}."
                )
            elif risk_domain_query:
                evidence_summary = (
                    f"Matched {len(matched_sessions)} session(s) across the session history with risk findings."
                )
            elif search_terms:
                evidence_summary = (
                    f"Matched {len(matched_sessions)} session(s) across the command history for search terms {search_terms}."
                )
            else:
                evidence_summary = "No useful search terms were extracted from the question."

        if not session and session_id:
            evidence_summary = f"Session {session_id} was not found in the database."

        if session_id and session is None:
            answer = f"I couldn't retrieve session evidence for {session_id}."
            return {
                "answer": answer,
                "intent": intent,
                "retrieval_mode": "rule-based",
                "session_id": session_id,
                "evidence_available": False,
                "evidence_summary": evidence_summary,
            }

        evidence = self._build_evidence(
            intent=intent,
            question=question_text,
            session_id=session_id,
            search_terms=search_terms,
            risk_categories=risk_categories,
            risk_severity=risk_severity,
            risk_domain_query=risk_domain_query,
            session_count=session_count,
            session=session,
            commands=commands,
            events=events,
            timeline_entries=timeline_entries,
            timeline_analysis=timeline_analysis,
            matched_commands=matched_commands,
            matched_sessions=matched_sessions,
            evidence_summary=evidence_summary,
        )

        answer, retrieval_mode = self._build_answer(
            question_text,
            intent,
            evidence_available,
            evidence,
        )
        return {
            "answer": answer,
            "intent": intent,
            "retrieval_mode": retrieval_mode,
            "session_id": session_id,
            "evidence_available": evidence_available,
            "evidence_summary": evidence_summary,
            "conversation_entities": _conversation_entities(evidence),
        }

    def _answer_system_status(self, question: str) -> dict[str, Any] | None:
        status_phrases = {
            "status",
            "health",
            "system status",
            "chatbot status",
            "health check",
            "system health",
            "check status",
            "are you running",
            "is everything ok",
        }
        normalized = (question or "").strip().lower().rstrip("?.")
        if normalized not in status_phrases and not any(
            phrase in normalized for phrase in status_phrases if len(phrase.split()) > 1
        ):
            return None

        try:
            self._db.execute(text("SELECT 1"))
            answer = "System Status: healthy. PostgreSQL connected. Chatbot is running."
            evidence_available = True
            evidence_summary = "System and PostgreSQL health check passed."
        except Exception:
            answer = "System Status: degraded. PostgreSQL is unavailable."
            evidence_available = False
            evidence_summary = "PostgreSQL health check failed."
        return {
            "answer": answer,
            "intent": "SYSTEM_STATUS",
            "retrieval_mode": "rule-based",
            "session_id": None,
            "evidence_available": evidence_available,
            "evidence_summary": evidence_summary,
        }

    def _try_last_session_details(self, question: str) -> dict[str, Any] | None:
        question_lower = (question or "").strip().lower()
        if any(term in question_lower for term in ("risk", "risky", "suspicious", "dangerous")):
            return None
        if not any(
            phrase in question_lower
            for phrase in (
                "most recent session",
                "most recent ssh session",
                "latest session",
                "latest ssh session",
                "last session",
                "last ssh session",
                "previous session",
                "newest session",
                "newest ssh session",
                "show me the most recent",
            )
        ):
            return None

        protocol = "SSH" if re.search(r"\bssh\b", question_lower) else None
        sessions, _ = self._session_query_service.query_sessions(
            limit=1,
            protocol=protocol,
        )
        if not sessions:
            return {
                "answer": "No sessions found.",
                "intent": "SESSION_LOOKUP",
                "retrieval_mode": "rule-based",
                "session_id": None,
                "evidence_available": False,
                "evidence_summary": "No sessions were found.",
            }

        latest = sessions[0]
        session_identifier = latest.session_id or latest.unique_id
        started = latest.started_at or latest.login_time
        ended = latest.ended_at or latest.logout_time
        command_evidence = self._session_query_service.get_command_evidence(session_identifier)
        command_names = [item.command for item in command_evidence if item.command]
        command_text = ", ".join(command_names[:8]) or None
        protocol_label = latest.protocol or latest.session_type or "unknown"
        risk = latest.risk or "unknown"
        answer = (
            "Most recent session:\n"
            f"- Protocol: {protocol_label}\n"
            f"- User: {latest.username or 'unknown'}\n"
            f"- Session: {session_identifier}\n"
            f"- Login: {started.isoformat() if started else 'unknown'}\n"
            f"- Logout: {ended.isoformat() if ended else 'still active'}\n"
            f"- Duration: {_format_session_duration(started, ended, latest.duration)}\n"
            f"- Risk: {risk}"
        )
        evidence_available = bool(command_names)
        if command_text:
            answer += f"\n- Commands executed ({len(command_names)}): {command_text}"
            answer += "\n\n" + "\n".join(_format_command_log(command_evidence))
        elif latest.recording_path or latest.recording_id:
            answer += (
                "\n- A recording is linked, but no command records were extracted; "
                "command activity could not be confirmed."
            )
        else:
            answer += (
                "\n- No recording or command log is linked; command activity could "
                "not be verified."
            )
        return {
            "answer": answer,
            "intent": "SESSION_LOOKUP",
            "retrieval_mode": "rule-based",
            "session_id": session_identifier,
            "evidence_available": evidence_available,
            "evidence_summary": (
                f"Retrieved the most recent {protocol_label} session and "
                f"{len(command_names)} command record(s)."
            ),
        }

    @staticmethod
    def _is_grounded_session_fallback(question: str, query_plan: Any) -> bool:
        question_lower = (question or "").strip().lower()
        if query_plan.query_type not in {"GENERAL_KNOWLEDGE", "COMMAND_EXPLANATION"}:
            return False
        if query_plan.command and any(
            phrase in question_lower
            for phrase in ("what does", "what is", "explain", "meaning of", "how to use")
        ):
            return False
        session_keywords = (
            "session", "login", "logout", "access", "who", "admin", "user", "command",
            "ran", "executed", "risk", "dangerous", "suspicious", "threat", "when", "time",
            "duration", "active", "today", "yesterday", "this week", "this month", "incident",
            "alert", "flagged", "critical", "high", "summarize", "summary", "report", "overview",
            "what happened", "secure", "security", "audit", "pattern", "behavior", "worried",
        )
        return any(keyword in question_lower for keyword in session_keywords)

    def _try_analytical_grounded_fallback(
        self,
        question: str,
        session_id: str | None,
    ) -> dict[str, Any] | None:
        question_lower = (question or "").strip().lower()
        if not any(
            term in question_lower
            for term in (
                "secure",
                "worried",
                "patterns",
                "pattern",
                "behavior",
                "audit analysis",
                "complete audit",
                "security analysis",
            )
        ):
            return None
        if any(phrase in question_lower for phrase in ("what does", "what is", "explain", "meaning of")) and "system" not in question_lower:
            return None

        query_plan = self._query_understanding_service.understand(question, session_id=session_id)
        grounded_plan = replace(
            query_plan,
            query_type="SECURITY_SUMMARY",
            needs=set(query_plan.needs) | {"sessions", "commands", "events", "risk_findings"},
            risk_domain_query=True,
            analysis=query_plan.analysis or "security_summary",
        )
        result = self._answer_grounded(grounded_plan, session_id or query_plan.session_id)
        if result.get("retrieval_mode") == "llm":
            result["retrieval_mode"] = "grounded_llm"
        return result

    def _classify_intent(self, question: str, session_id: str | None) -> str:
        return classify_chat_intent(question, session_id)

    def _answer_active_sessions(self, question: str) -> dict[str, Any] | None:
        question_lower = (question or "").strip().lower()
        if not _is_active_sessions_query(question_lower):
            return None

        sessions = self._session_query_service.list_active_sessions(limit=20)
        if not sessions:
            return {
                "answer": "No SSH sessions are currently active.",
                "intent": "USER_ACTIVITY",
                "retrieval_mode": "rule-based",
                "session_id": None,
                "evidence_available": True,
                "evidence_summary": "Matched 0 active session(s).",
            }

        lines = [f"Currently active SSH sessions ({len(sessions)}):"]
        entities_sessions: list[dict[str, Any]] = []

        for index, session in enumerate(sessions, start=1):
            session_identifier = session.session_id or session.unique_id
            username = session.username or "unknown"
            date_label, time_label = _format_session_datetime(session.started_at)
            command_evidence = self._session_query_service.get_command_evidence(
                session_identifier
            )
            location = _resolve_session_location(session, command_evidence)

            lines.append(
                f"{index}. **{username}** on host `{location}`, "
                f"connected since {date_label} at {time_label} "
                f"(session `{session_identifier}`)"
            )
            entities_sessions.append(
                {
                    "session_id": session_identifier,
                    "username": session.username,
                    "hostname": location,
                    "date": date_label,
                    "time": time_label,
                }
            )

        return {
            "answer": "\n".join(lines),
            "intent": "USER_ACTIVITY",
            "retrieval_mode": "rule-based",
            "session_id": None,
            "evidence_available": True,
            "evidence_summary": f"Retrieved {len(sessions)} active session(s).",
            "conversation_entities": {"sessions": entities_sessions},
        }

    def _answer_logout_time(self, question: str) -> dict[str, Any] | None:
        question_lower = (question or "").strip().lower()
        if not _is_logout_time_query(question_lower):
            return None

        users = self._query_understanding_service._extract_users(question_lower)
        username = users[0] if users else None
        if not username:
            return {
                "answer": "Please specify a username to look up a logout time.",
                "intent": "USER_ACTIVITY",
                "retrieval_mode": "rule-based",
                "session_id": None,
                "evidence_available": False,
                "evidence_summary": "No username was identified for logout lookup.",
            }

        session = self._session_query_service.get_latest_session_for_user(username)
        if session is None:
            return {
                "answer": f"No sessions found for {username}.",
                "intent": "USER_ACTIVITY",
                "retrieval_mode": "rule-based",
                "session_id": None,
                "evidence_available": False,
                "evidence_summary": f"Found no sessions for user {username}.",
            }

        session_identifier = session.session_id or session.unique_id
        if session.ended_at is None:
            answer = f"{username}'s session is still active (or has no recorded end time)."
            evidence_summary = f"Latest session for {username} has no recorded logout time."
        else:
            answer = f"{username} logged out at {session.ended_at.isoformat()} (session `{session_identifier}`)."
            evidence_summary = f"Retrieved the recorded logout time for {username}."

        return {
            "answer": answer,
            "intent": "USER_ACTIVITY",
            "retrieval_mode": "rule-based",
            "session_id": session_identifier,
            "evidence_available": True,
            "evidence_summary": evidence_summary,
            "conversation_entities": {
                "sessions": [{"session_id": session_identifier, "username": session.username}],
            },
        }

    def _answer_command_audit(self, question: str) -> dict[str, Any] | None:
        """Answer 'who executed the command X?' / 'which user ran X?' across all sessions."""
        question_lower = (question or "").strip().lower()
        if not _is_command_audit_query(question_lower):
            return None

        command_term = self._extract_audit_command(question)
        wants_hostname = _mentions_hostname(question_lower)

        # Vague / pronoun-only phrasing like "who executed these commands" — no specific
        # command name. Fall back to a listing of recent sessions with users (+ hosts if
        # asked).
        if not command_term or _is_placeholder_command_phrase(command_term):
            return self._answer_recent_actors_with_hosts(
                session_limit=5,
                include_hostname=wants_hostname,
                include_commands=True,
            )

        analytics = self._phase1_query_service._analytics  # reuse existing analytics
        usages = analytics.find_command_usages_recent(command_term)
        if not usages:
            # Compound phrases ("whoami and hostname", "ip addr or ss") — retry by
            # splitting on English connectives and merging the results.
            if any(
                connector in f" {command_term.lower()} "
                for connector in (" and ", " or ", " plus ", " with ", " ,", ", ")
            ):
                parts: list[str] = []
                import re as _re

                for chunk in _re.split(r"\s+(?:and|or|plus|with|,)\s+", command_term, flags=_re.IGNORECASE):
                    chunk = chunk.strip()
                    if chunk:
                        parts.append(chunk)
                combined: list[tuple[Any, Any]] = []
                for part in parts:
                    combined.extend(analytics.find_command_usages_recent(part))
                if combined:
                    return self._format_command_audit_listing(
                        command_term=" / ".join(parts),
                        usages=combined,
                        include_hostname=wants_hostname,
                    )
            # Nothing matched — fall back to the recent-actor listing if user also
            # asked about hosts (they likely just want a session overview).
            if wants_hostname:
                return self._answer_recent_actors_with_hosts(
                    session_limit=5,
                    include_hostname=True,
                    include_commands=True,
                )
            return {
                "answer": (
                    f"No user has executed a command matching `{command_term}` in any recorded SSH session."
                ),
                "intent": "COMMAND_LOOKUP",
                "retrieval_mode": "rule-based",
                "session_id": None,
                "evidence_available": False,
                "evidence_summary": f"Matched 0 sessions for command `{command_term}`.",
            }

        return self._format_command_audit_listing(
            command_term=command_term,
            usages=usages,
            include_hostname=wants_hostname,
        )

    def _format_command_audit_listing(
        self,
        *,
        command_term: str,
        usages: list[tuple[Any, Any]],
        include_hostname: bool,
    ) -> dict[str, Any]:
        by_user: dict[str, list[tuple[Any, Any]]] = {}
        for session, evidence in usages:
            username = session.username or "unknown"
            by_user.setdefault(username, []).append((session, evidence))

        lines = [
            f"Users who executed `{command_term}` ({len(usages)} occurrence(s) across {len(by_user)} user(s)):"
        ]
        for username in sorted(by_user.keys()):
            occurrences = by_user[username]
            latest = max(occurrences, key=lambda pair: pair[1].executed_at or datetime.min.replace(tzinfo=timezone.utc))
            latest_session, latest_evidence = latest
            latest_sid = latest_session.session_id or latest_session.unique_id
            executed_at = (
                latest_evidence.executed_at.strftime("%Y-%m-%d %H:%M UTC")
                if latest_evidence.executed_at
                else "unknown time"
            )
            actual_command = latest_evidence.command or command_term
            host_suffix = ""
            if include_hostname:
                host = _resolve_session_location(latest_session, [latest_evidence])
                host_suffix = f" on host `{host}`"
            lines.append(
                f"- **{username}**: {len(occurrences)} time(s), most recent `{actual_command}` "
                f"on {executed_at}{host_suffix} (session `{latest_sid}`)"
            )

        entities_sessions = []
        for username, occurrences in by_user.items():
            for session, _ in occurrences[:5]:
                sid = session.session_id or session.unique_id
                host = _resolve_session_location(session, [])
                entities_sessions.append(
                    {"session_id": sid, "username": username, "hostname": host}
                )

        return {
            "answer": "\n".join(lines),
            "intent": "COMMAND_LOOKUP",
            "retrieval_mode": "rule-based",
            "session_id": None,
            "evidence_available": True,
            "evidence_summary": (
                f"Matched {len(usages)} occurrence(s) of `{command_term}` across "
                f"{len(by_user)} user(s)."
            ),
            "conversation_entities": {
                "sessions": entities_sessions,
                "commands": [{"command": command_term}],
            },
        }

    def _answer_recent_actors_with_hosts(
        self,
        *,
        session_limit: int = 5,
        include_hostname: bool = True,
        include_commands: bool = True,
    ) -> dict[str, Any]:
        """Listing of recent sessions with user, host and (optionally) commands.

        Used as a fallback for vague audit questions like 'who executed these commands
        give me the hostname?' where no specific command term is provided.
        """
        sessions = self._session_query_service.list_sessions(limit=session_limit)
        if not sessions:
            return {
                "answer": "No SSH sessions were found in PostgreSQL.",
                "intent": "USER_ACTIVITY",
                "retrieval_mode": "rule-based",
                "session_id": None,
                "evidence_available": False,
                "evidence_summary": "Matched 0 recent session(s).",
            }

        lines = [f"Recent SSH sessions ({len(sessions)}):"]
        entities_sessions: list[dict[str, Any]] = []
        entities_commands: list[dict[str, Any]] = []
        total_commands = 0

        for index, session in enumerate(sessions, start=1):
            session_identifier = session.session_id or session.unique_id
            username = session.username or "unknown"
            date_label, time_label = _format_session_datetime(session.started_at)

            command_evidence = self._session_query_service.get_command_evidence(session_identifier)
            command_names = [item.command for item in command_evidence if item.command]
            location = _resolve_session_location(session, command_evidence)
            total_commands += len(command_names)

            header_parts = [f"{index}. **{username}**"]
            if include_hostname:
                header_parts.append(f"on host `{location}`")
            header_parts.append(f"on {date_label} at {time_label}")
            header_parts.append(f"(session `{session_identifier}`)")
            lines.append(" ".join(header_parts))

            if include_commands:
                if command_names:
                    joined = ", ".join(f"`{name}`" for name in command_names)
                    lines.append(f"   Commands ({len(command_names)}): {joined}")
                else:
                    lines.append("   No commands recorded.")

            entities_sessions.append(
                {
                    "session_id": session_identifier,
                    "username": session.username,
                    "hostname": location,
                    "date": date_label,
                    "time": time_label,
                }
            )
            for name in command_names[:10]:
                entities_commands.append(
                    {"command": name, "session_id": session_identifier, "hostname": location}
                )

        return {
            "answer": "\n".join(lines),
            "intent": "USER_ACTIVITY",
            "retrieval_mode": "rule-based",
            "session_id": None,
            "evidence_available": True,
            "evidence_summary": (
                f"Retrieved {len(sessions)} recent session(s) and {total_commands} command(s)."
            ),
            "conversation_entities": {
                "sessions": entities_sessions,
                "commands": entities_commands,
            },
        }

    def _extract_audit_command(self, question: str) -> str | None:
        """Pull the command name out of 'who executed the command X' style questions."""
        import re as _re

        text = (question or "").strip()
        backtick = _re.search(r"`([^`]+)`", text)
        if backtick:
            return backtick.group(1).strip()

        lowered = text.lower()
        # Prefer explicit anchor 'the command <X>' or 'command <X>'.
        for anchor in ("the command ", "command "):
            idx = lowered.find(anchor)
            if idx >= 0:
                tail = text[idx + len(anchor):]
                tail = tail.strip(" ?.!,'\"")
                if tail:
                    return tail.split("?")[0].strip()

        # Fallback: strip actor prefix and return remainder.
        for prefix in (
            "who executed", "who ran", "who used",
            "which user ran", "which user executed", "which user used",
            "what user ran", "what user executed",
            "who has executed", "who has run",
        ):
            idx = lowered.find(prefix)
            if idx >= 0:
                tail = text[idx + len(prefix):].strip(" ?.!,'\"")
                if tail:
                    tail = _re.split(
                        r"\s+(?:and\s+when|when|what\s+time|on\s+this\s+system|in\s+this\s+system|today|recently)\b.*$",
                        tail,
                        maxsplit=1,
                        flags=_re.IGNORECASE,
                    )[0]
                    return tail.strip(" ?.!,'\"") or None
        return None

    def _answer_command_explanation(self, question: str) -> dict[str, Any] | None:
        if not _is_command_explanation_query(question):
            return None

        answer = self._ssh_knowledge_service.answer_question(question)
        if answer is None:
            return None

        command = self._ssh_knowledge_service.extract_command_from_question(question) or "command"
        return {
            "answer": answer,
            "intent": "COMMAND_EXPLANATION",
            "retrieval_mode": "rule-based",
            "session_id": None,
            "evidence_available": True,
            "evidence_summary": f"SSH knowledge explanation for `{command}`.",
        }

    def _answer_conversation_followup(
        self,
        question: str,
        session_id: str | None,
        resolved_command: str | None,
        followup_type: str | None,
    ) -> dict[str, Any] | None:
        """Answer short pronoun/context follow-ups using conversation memory.

        Fires only when the previous turn already anchored a session and/or command,
        so questions like "when was it executed?" or "was that risky?" produce
        a concise, precise answer without needing the user to repeat context.
        """
        if not followup_type and not (resolved_command or session_id):
            return None
        if not resolved_command and not session_id:
            return None

        if followup_type == "risk":
            return self._followup_session_risk(session_id, resolved_command)
        if followup_type == "who":
            return self._followup_session_who(session_id, resolved_command)
        if followup_type == "where":
            return self._followup_session_where(session_id, resolved_command)
        if followup_type == "when":
            return self._followup_command_when(session_id, resolved_command)
        if followup_type == "before":
            return self._followup_adjacent_command(session_id, resolved_command, direction="before")
        if followup_type == "after":
            return self._followup_adjacent_command(session_id, resolved_command, direction="after")
        if followup_type == "output":
            return self._followup_command_output(session_id, resolved_command)
        return None

    def _followup_session_risk(
        self,
        session_id: str | None,
        resolved_command: str | None,
    ) -> dict[str, Any] | None:
        if not session_id:
            return None
        session = self._session_query_service.get_session(session_id)
        if session is None:
            return None
        command_evidence = self._session_query_service.get_command_evidence(session_id)
        findings = [
            finding
            for item in command_evidence
            for finding in item.risk_findings
        ]
        risk_summary = aggregate_session_risks(findings)
        severity = risk_summary.overall_severity or "NONE"

        if severity == "NONE" or risk_summary.finding_count == 0:
            answer = f"Session `{session_id}` has no risk findings."
        else:
            categories = risk_summary.categories or []
            top_categories = ", ".join(categories[:3]) if categories else "unspecified categories"
            answer = (
                f"Session `{session_id}` is {severity} risk "
                f"({risk_summary.finding_count} finding(s): {top_categories})."
            )
        return {
            "answer": answer,
            "intent": "RISK_ANALYSIS",
            "retrieval_mode": "rule-based",
            "session_id": session_id,
            "evidence_available": True,
            "evidence_summary": (
                f"Session {session_id} risk severity: {severity} "
                f"with {risk_summary.finding_count} finding(s)."
            ),
            "conversation_entities": {
                "sessions": [
                    {
                        "session_id": session_id,
                        "username": session.username,
                        "risk": severity,
                    }
                ],
                "commands": [{"command": resolved_command}] if resolved_command else [],
            },
        }

    def _followup_session_who(
        self,
        session_id: str | None,
        resolved_command: str | None,
    ) -> dict[str, Any] | None:
        if not session_id:
            return None
        session = self._session_query_service.get_session(session_id)
        if session is None:
            return None
        username = session.username or "unknown user"
        if resolved_command:
            answer = f"`{resolved_command}` in session `{session_id}` was executed by {username}."
        else:
            answer = f"Session `{session_id}` was used by {username}."
        return {
            "answer": answer,
            "intent": "SESSION_LOOKUP",
            "retrieval_mode": "rule-based",
            "session_id": session_id,
            "evidence_available": True,
            "evidence_summary": f"Resolved session {session_id} username to {username}.",
            "conversation_entities": {
                "sessions": [{"session_id": session_id, "username": session.username}],
                "commands": [{"command": resolved_command}] if resolved_command else [],
            },
        }

    def _followup_session_where(
        self,
        session_id: str | None,
        resolved_command: str | None,
    ) -> dict[str, Any] | None:
        if not session_id:
            return None
        session = self._session_query_service.get_session(session_id)
        if session is None:
            return None
        commands = self._session_query_service.get_command_evidence(session_id)
        location = _resolve_session_location(session, commands)
        return {
            "answer": f"Session `{session_id}` ran on host: {location}.",
            "intent": "SESSION_LOOKUP",
            "retrieval_mode": "rule-based",
            "session_id": session_id,
            "evidence_available": location != "unknown",
            "evidence_summary": f"Resolved session {session_id} host to {location}.",
            "conversation_entities": {
                "sessions": [
                    {
                        "session_id": session_id,
                        "username": session.username,
                        "host": location,
                    }
                ],
                "commands": [{"command": resolved_command}] if resolved_command else [],
            },
        }

    def _followup_command_when(
        self,
        session_id: str | None,
        resolved_command: str | None,
    ) -> dict[str, Any] | None:
        if not session_id or not resolved_command:
            return None
        command_evidence = self._session_query_service.get_command_evidence(session_id)
        matched = self._match_command_in_evidence(command_evidence, resolved_command)
        if matched is None:
            return None
        if matched.executed_at is None:
            return None
        date_label, time_label = _format_session_datetime(matched.executed_at)
        return {
            "answer": (
                f"`{resolved_command}` was executed in session `{session_id}` "
                f"on {date_label} at {time_label}."
            ),
            "intent": "COMMAND_LOOKUP",
            "retrieval_mode": "rule-based",
            "session_id": session_id,
            "evidence_available": True,
            "evidence_summary": (
                f"Resolved execution time for `{resolved_command}` in session {session_id}."
            ),
            "conversation_entities": {
                "sessions": [{"session_id": session_id}],
                "commands": [
                    {
                        "command": resolved_command,
                        "session_id": session_id,
                        "executed_at": matched.executed_at.isoformat(),
                    }
                ],
            },
        }

    def _followup_adjacent_command(
        self,
        session_id: str | None,
        resolved_command: str | None,
        *,
        direction: str,
    ) -> dict[str, Any] | None:
        if not session_id or not resolved_command:
            return None
        command_evidence = self._session_query_service.get_command_evidence(session_id)
        if not command_evidence:
            return None

        index = self._find_command_index(command_evidence, resolved_command)
        if index is None:
            return None

        adjacent_index = index - 1 if direction == "before" else index + 1
        if adjacent_index < 0 or adjacent_index >= len(command_evidence):
            edge_label = "first" if direction == "before" else "last"
            return {
                "answer": (
                    f"`{resolved_command}` was the {edge_label} command in session `{session_id}`; "
                    f"there was no command {direction} it."
                ),
                "intent": "COMMAND_LOOKUP",
                "retrieval_mode": "rule-based",
                "session_id": session_id,
                "evidence_available": True,
                "evidence_summary": (
                    f"No command {direction} `{resolved_command}` in session {session_id}."
                ),
                "conversation_entities": {
                    "sessions": [{"session_id": session_id}],
                    "commands": [{"command": resolved_command, "session_id": session_id}],
                },
            }

        neighbor = command_evidence[adjacent_index]
        preposition = "before" if direction == "before" else "after"
        return {
            "answer": (
                f"The command {preposition} `{resolved_command}` in session `{session_id}` was "
                f"`{neighbor.command}`."
            ),
            "intent": "COMMAND_LOOKUP",
            "retrieval_mode": "rule-based",
            "session_id": session_id,
            "evidence_available": True,
            "evidence_summary": (
                f"Resolved adjacent command {preposition} `{resolved_command}` "
                f"in session {session_id}."
            ),
            "conversation_entities": {
                "sessions": [{"session_id": session_id}],
                "commands": [
                    {"command": resolved_command, "session_id": session_id},
                    {"command": neighbor.command, "session_id": session_id},
                ],
            },
        }

    def _followup_command_output(
        self,
        session_id: str | None,
        resolved_command: str | None,
    ) -> dict[str, Any] | None:
        if not session_id or not resolved_command:
            return None
        command_evidence = self._session_query_service.get_command_evidence(session_id)
        matched = self._match_command_in_evidence(command_evidence, resolved_command)
        if matched is None:
            return None
        output = (matched.output or "").strip()
        if not output:
            answer = (
                f"`{resolved_command}` in session `{session_id}` did not record any output."
            )
        else:
            snippet = output if len(output) <= 400 else output[:400].rstrip() + "..."
            answer = (
                f"Output of `{resolved_command}` in session `{session_id}`:\n```\n{snippet}\n```"
            )
        return {
            "answer": answer,
            "intent": "COMMAND_LOOKUP",
            "retrieval_mode": "rule-based",
            "session_id": session_id,
            "evidence_available": bool(output),
            "evidence_summary": (
                f"Resolved output for `{resolved_command}` in session {session_id}."
            ),
            "conversation_entities": {
                "sessions": [{"session_id": session_id}],
                "commands": [
                    {
                        "command": resolved_command,
                        "session_id": session_id,
                        "output": output or None,
                    }
                ],
            },
        }

    def _match_command_in_evidence(self, command_evidence, resolved_command: str):
        target = (resolved_command or "").strip().lower()
        if not target:
            return None
        for item in command_evidence:
            if (item.command or "").strip().lower() == target:
                return item
        for item in command_evidence:
            if target in (item.command or "").strip().lower():
                return item
        return None

    def _find_command_index(self, command_evidence, resolved_command: str) -> int | None:
        target = (resolved_command or "").strip().lower()
        if not target:
            return None
        for index, item in enumerate(command_evidence):
            if (item.command or "").strip().lower() == target:
                return index
        for index, item in enumerate(command_evidence):
            if target in (item.command or "").strip().lower():
                return index
        return None

    def _answer_recent_session_command_list(
        self,
        question: str,
        session_id: str | None,
    ) -> dict[str, Any] | None:
        wants_actor_listing = _wants_recent_actor_listing(question)
        matches_recent_command = _is_recent_session_command_list_query(question)
        if not wants_actor_listing and not matches_recent_command:
            return None

        # Plural / multi-session phrasing wants a listing, not just the single latest.
        multi_session = wants_actor_listing and any(
            term in question.lower()
            for term in (
                "who", "users", "logins", "everyone", "anyone",
                "they", "them", "recent activity", "recent logins",
            )
        )

        limit = 5 if multi_session else 1
        sessions, _ = self._session_query_service.query_sessions(
            limit=limit,
            protocol="SSH",
        )
        total_sessions = self._session_query_service.count_unique_sessions()
        if not sessions:
            return {
                "answer": (
                    f"No SSH sessions were found in PostgreSQL (checked {total_sessions} session record(s))."
                ),
                "intent": "GROUNDED_ANALYSIS",
                "retrieval_mode": "rule-based",
                "session_id": session_id,
                "evidence_available": False,
                "evidence_summary": f"Retrieved 0 session(s), 0 command(s), and 0 risk finding(s) for latest_session.",
            }

        if multi_session:
            return self._format_recent_actor_listing(question, sessions, session_id)

        session = sessions[0]
        session_identifier = session.session_id or session.unique_id
        command_evidence = self._session_query_service.get_command_evidence(session_identifier)
        command_names = [item.command for item in command_evidence if item.command]
        started_label = session.started_at.date().isoformat() if session.started_at else "unknown date"
        findings = [
            finding
            for item in command_evidence
            for finding in item.risk_findings
        ]
        risk_summary = aggregate_session_risks(findings)

        answer_parts = [
            f"The most recent SSH session was by {session.username or 'unknown'} "
            f"on {started_label} (session {session_identifier}).",
        ]
        if command_names:
            answer_parts.append(
                f"Commands executed ({len(command_names)}): {', '.join(command_names)}."
            )
            evidence_available = True
        elif getattr(session, "recording_path", None) or getattr(session, "recording_id", None):
            answer_parts.append(
                "A recording is linked to this session, but no command records were "
                "extracted from it; I can't confirm whether commands were executed."
            )
            evidence_available = False
        else:
            answer_parts.append(
                "No recording or command log is linked to this session, so I can't "
                "verify which commands were executed."
            )
            evidence_available = False
        if risk_summary.overall_severity and risk_summary.overall_severity != "NONE":
            answer_parts.append(f"Session risk level: {risk_summary.overall_severity}.")

        return {
            "answer": " ".join(answer_parts),
            "intent": "GROUNDED_ANALYSIS",
            "retrieval_mode": "rule-based",
            "session_id": session_id or session_identifier,
            "evidence_available": evidence_available,
            "evidence_summary": (
                f"Retrieved 1 session(s) and {len(command_names)} command(s) for latest_session; "
                + (
                    f"{risk_summary.finding_count} risk finding(s) were found."
                    if evidence_available
                    else "the command log is unavailable or contains no extracted command records."
                )
            ),
            "conversation_entities": {
                "sessions": [{"session_id": session_identifier, "username": session.username}],
                "commands": [{"command": name} for name in command_names[:20]],
            },
        }

    def _format_recent_actor_listing(
        self,
        question: str,
        sessions: list[Any],
        session_id: str | None,
    ) -> dict[str, Any]:
        wants_commands = any(
            term in question.lower()
            for term in ("command", "commands", "executed", "execute", "run", "ran", "list", "activity", "do", "did")
        )

        lines = [f"Recent SSH sessions ({len(sessions)}):"]
        entities_sessions: list[dict[str, Any]] = []
        entities_commands: list[dict[str, Any]] = []
        total_commands = 0
        total_findings = 0

        for index, session in enumerate(sessions, start=1):
            session_identifier = session.session_id or session.unique_id
            started_at = session.started_at
            date_label, time_label = _format_session_datetime(started_at)
            username = session.username or "unknown"

            command_evidence = self._session_query_service.get_command_evidence(session_identifier)
            command_names = [item.command for item in command_evidence if item.command]
            findings = [
                finding
                for item in command_evidence
                for finding in item.risk_findings
            ]
            risk_summary = aggregate_session_risks(findings)
            severity = risk_summary.overall_severity or "NONE"
            total_commands += len(command_names)
            total_findings += risk_summary.finding_count

            header = (
                f"{index}. {username} on {date_label} at {time_label} "
                f"(session `{session_identifier}` | risk: {severity})"
            )
            lines.append(header)
            if wants_commands:
                if command_names:
                    joined = ", ".join(f"`{name}`" for name in command_names)
                    lines.append(f"   Commands ({len(command_names)}): {joined}")
                elif getattr(session, "recording_path", None) or getattr(session, "recording_id", None):
                    lines.append(
                        "   A recording is linked, but no command records were extracted; "
                        "command activity could not be confirmed."
                    )
                else:
                    lines.append(
                        "   No recording or command log is linked; command activity could not be verified."
                    )

            entities_sessions.append(
                {
                    "session_id": session_identifier,
                    "username": session.username,
                    "date": date_label,
                    "time": time_label,
                    "risk": severity,
                }
            )
            for name in command_names[:10]:
                entities_commands.append({"command": name, "session_id": session_identifier})

        answer = "\n".join(lines)
        return {
            "answer": answer,
            "intent": "USER_ACTIVITY",
            "retrieval_mode": "rule-based",
            "session_id": session_id,
            "evidence_available": True,
            "evidence_summary": (
                f"Retrieved {len(sessions)} recent session(s), {total_commands} command(s), "
                f"and {total_findings} risk finding(s)."
            ),
            "conversation_entities": {
                "sessions": entities_sessions,
                "commands": entities_commands,
            },
        }

    def _answer_latest_session_risk_findings(
        self,
        question: str,
        session_id: str | None,
    ) -> dict[str, Any] | None:
        if not _is_latest_session_risk_query(question):
            return None

        sessions, _ = self._session_query_service.query_sessions(
            limit=1,
            protocol="SSH",
        )
        if not sessions:
            return {
                "answer": "No SSH sessions were found in PostgreSQL.",
                "intent": "RISK_ANALYSIS",
                "retrieval_mode": "rule-based",
                "session_id": session_id,
                "evidence_available": False,
                "evidence_summary": "Retrieved 0 session(s) for latest_session risk lookup.",
            }

        session = sessions[0]
        session_identifier = session.session_id or session.unique_id
        command_evidence = self._session_query_service.get_command_evidence(session_identifier)
        finding_entries: list[tuple[str, datetime | None, Any]] = []
        for item in command_evidence:
            for finding in item.risk_findings:
                finding_entries.append((item.command or "", item.executed_at, finding))

        if not finding_entries:
            if command_evidence:
                lines = [
                    f"No recorded command matched the configured risk rules in the latest SSH session "
                    f"({session_identifier}). {len(command_evidence)} command(s) were checked.",
                    "This rule-based check evaluates command text; it does not establish that command output "
                    "was harmless.",
                    "",
                    *_format_command_log(command_evidence),
                ]
                answer = "\n".join(lines)
                evidence_available = True
            else:
                answer = (
                    f"No command records are available for the latest SSH session ({session_identifier}), "
                    "so I can't determine whether risky commands were executed."
                )
                evidence_available = False
            return {
                "answer": answer,
                "intent": "RISK_ANALYSIS",
                "retrieval_mode": "rule-based",
                "session_id": session_id or session_identifier,
                "evidence_available": evidence_available,
                "evidence_summary": (
                    f"Checked {len(command_evidence)} latest-session command(s); "
                    f"{len(finding_entries)} matched configured risk rules."
                ),
            }

        started_label = session.started_at.date().isoformat() if session.started_at else "unknown date"
        lines = [
            f"The latest SSH session ({session_identifier}, {started_label}) "
            f"has {len(finding_entries)} configured command-risk finding(s):"
        ]
        for index, (command_text, executed_at, finding) in enumerate(finding_entries, start=1):
            lines.append(
                f"{index}. `{command_text}` — {finding.category} ({finding.severity}); "
                f"{_format_command_execution_time(executed_at)}"
            )
        if command_evidence:
            lines.extend(("", *_format_command_log(command_evidence)))
        answer = "\n".join(lines)

        return {
            "answer": answer,
            "intent": "RISK_ANALYSIS",
            "retrieval_mode": "rule-based",
            "session_id": session_id or session_identifier,
            "evidence_available": True,
            "evidence_summary": (
                f"Retrieved {len(finding_entries)} risk finding(s) for latest_session."
            ),
        }

    def _answer_session_context_query(
        self,
        question: str,
        session_id: str | None,
    ) -> dict[str, Any] | None:
        question_lower = (question or "").strip().lower()
        plan = self._query_understanding_service.understand(question, session_id=session_id)
        if plan.scope == "latest_session" or session_id is None:
            protocol = "SSH" if re.search(r"\bssh\b", question_lower) else None
            sessions, _ = self._session_query_service.query_sessions(
                limit=1,
                protocol=protocol,
            )
        else:
            session = self._session_query_service.get_session(session_id)
            sessions = [session] if session is not None else []

        if not sessions:
            return {
                "answer": "No SSH session evidence is available to answer that question.",
                "intent": "COMMAND_LOOKUP",
                "retrieval_mode": "rule-based",
                "session_id": session_id,
                "evidence_available": False,
                "evidence_summary": "Retrieved 0 session(s) for latest_session.",
            }

        session = sessions[0]
        session_identifier = session.session_id or session.unique_id
        commands = self._session_query_service.get_command_evidence(session_identifier)
        username = session.username or "unknown"

        def _command_output(name: str) -> str | None:
            for item in commands:
                if (item.command or "").strip().lower() == name:
                    output = (item.output or "").strip()
                    if output:
                        return output
            for item in commands:
                if name in (item.command or "").lower():
                    output = (item.output or "").strip()
                    if output:
                        return output
            return None

        asks_who = any(term in question_lower for term in ("who", "user", "username"))
        asks_hostname = "hostname" in question_lower
        asks_date = "date" in question_lower and "update" not in question_lower
        asks_whoami = "whoami" in question_lower
        asks_pwd = "pwd" in question_lower

        parts: list[str] = []
        if asks_who and asks_hostname:
            hostname_value = _command_output("hostname")
            if hostname_value:
                parts.append(f"User `{username}` executed commands on host `{hostname_value}`.")
            else:
                parts.append(
                    f"User `{username}` executed commands in session `{session_identifier}`, "
                    f"but no hostname output was recorded."
                )
        elif asks_hostname:
            hostname_value = _command_output("hostname")
            if hostname_value:
                parts.append(f"The hostname is `{hostname_value}`.")
            else:
                parts.append("No hostname output was recorded in the latest session evidence.")
        elif asks_who:
            parts.append(f"User `{username}` executed commands in the latest session.")
        elif asks_date:
            date_value = _command_output("date")
            parts.append(
                f"The recorded date output is `{date_value}`." if date_value
                else "No date command output was recorded in the latest session evidence."
            )
        elif asks_whoami:
            whoami_value = _command_output("whoami")
            parts.append(
                f"The effective user is `{whoami_value}`." if whoami_value
                else f"Session user is `{username}`."
            )
        elif asks_pwd:
            pwd_value = _command_output("pwd")
            parts.append(
                f"The working directory is `{pwd_value}`." if pwd_value
                else "No pwd output was recorded in the latest session evidence."
            )
        else:
            return None

        return {
            "answer": parts[0],
            "intent": "COMMAND_LOOKUP",
            "retrieval_mode": "rule-based",
            "session_id": session_id or session_identifier,
            "evidence_available": True,
            "evidence_summary": (
                f"Retrieved 1 session(s) for latest_session with user {username}."
            ),
            "conversation_entities": {
                "sessions": [{"session_id": session_identifier, "username": username}],
                "commands": [{"command": plan.command}] if plan.command else [],
            },
        }

    def _answer_session_command_list(
        self,
        question: str,
        session_id: str | None,
    ) -> dict[str, Any] | None:
        if not session_id:
            return None

        session = self._session_query_service.get_session(session_id)
        if session is None:
            return {
                "answer": f"Session `{session_id}` was not found in PostgreSQL.",
                "intent": "COMMAND_LOOKUP",
                "retrieval_mode": "rule-based",
                "session_id": session_id,
                "evidence_available": False,
                "evidence_summary": f"Session {session_id} was not found in the database.",
            }

        canonical_session_id = session.unique_id
        command_evidence = self._session_query_service.get_command_evidence(canonical_session_id)
        if not command_evidence and session.commands:
            command_values = session.commands
            if isinstance(command_values, str):
                try:
                    command_values = json.loads(command_values)
                except (TypeError, ValueError):
                    command_values = []
            if isinstance(command_values, list):
                command_evidence = [
                    type("StoredCommandEvidence", (), {
                        "command": str(command),
                        "executed_at": None,
                        "risk_findings": (),
                    })()
                    for command in command_values
                ]
        command_names = [item.command for item in command_evidence if item.command]
        findings = [
            finding
            for item in command_evidence
            for finding in item.risk_findings
        ]
        risk_summary = aggregate_session_risks(findings)
        started = session.started_at or session.login_time
        ended = session.ended_at or session.logout_time
        started_label = started.isoformat() if started else "unknown"
        ended_label = ended.isoformat() if ended else "still active / no logout recorded"
        question_lower = (question or "").strip().lower()
        detailed = any(
            phrase in question_lower
            for phrase in ("description", "details", "detail", "what happened", "information", "activity")
        )

        lines = [
            f"Session `{session.session_id or session.unique_id}` by {session.username or 'unknown'}:",
            f"Login: {started_label}",
            f"Logout: {ended_label}",
        ]
        if command_names:
            if detailed or "list" in question_lower:
                lines.append(f"Commands executed ({len(command_names)}):")
                for index, item in enumerate(command_evidence, start=1):
                    if not item.command:
                        continue
                    executed_label = item.executed_at.isoformat() if item.executed_at else "unknown time"
                    categories = sorted({finding.category for finding in item.risk_findings if finding.category})
                    kind = ", ".join(categories) if categories else "NORMAL / no risk finding"
                    base_command = item.command.strip().split(maxsplit=1)[0].strip("`'\";|").lower()
                    description = COMMAND_KNOWLEDGE.get(base_command, "Recorded shell command")
                    lines.append(
                        f"{index}. `{item.command}` | executed: {executed_label} | "
                        f"type: {kind} | description: {description}"
                    )
            else:
                lines.append(f"Commands used ({len(command_names)}): {', '.join(command_names)}.")
        else:
            lines.append("No commands were recorded for this session.")

        risky = [
            item for item in command_evidence
            if item.risk_findings and item.command
        ]
        if risky:
            lines.append("Risky commands:")
            for item in risky:
                for finding in item.risk_findings:
                    lines.append(f"- `{item.command}`: {finding.category} ({finding.severity})")
        elif risk_summary.overall_severity and risk_summary.overall_severity != "NONE":
            lines.append(f"Session risk level: {risk_summary.overall_severity}.")

        return {
            "answer": "\n".join(lines),
            "intent": "COMMAND_LOOKUP",
            "retrieval_mode": "rule-based",
            "session_id": session.session_id or session.unique_id,
            "evidence_available": bool(command_names),
            "evidence_summary": (
                f"Session {session.session_id or session.unique_id} with {len(command_names)} command(s) "
                f"and {risk_summary.finding_count} risk finding(s)."
            ),
            "conversation_entities": {
                "sessions": [{"session_id": session.session_id or session.unique_id, "username": session.username}],
                "commands": [{"command": name, "session_id": session.session_id or session.unique_id} for name in command_names[:20]],
            },
        }

    def _answer_all_risk_overview(
        self,
        question: str,
        session_id: str | None,
    ) -> dict[str, Any] | None:
        risk_severity = extract_risk_severity(question)
        if risk_severity:
            matches = self._session_query_service.search_sessions_by_risk_severity(risk_severity, limit=100)
        else:
            matches = self._session_query_service.search_sessions_with_risk_findings(limit=100)

        date_range = extract_date_range(question)
        if date_range is not None:
            start_date, end_date = date_range
            matches = [
                match
                for match in matches
                if match.started_at is not None
                and start_date <= match.started_at.date() <= end_date
            ]

        scope_label = ""
        if date_range is not None:
            start_date, end_date = date_range
            scope_label = (
                start_date.isoformat()
                if start_date == end_date
                else f"{start_date.isoformat()} to {end_date.isoformat()}"
            )
        if not matches:
            total = self._session_query_service.count_unique_sessions()
            scope_suffix = f" for {scope_label}" if scope_label else ""
            risk_label = f"{risk_severity}-risk sessions" if risk_severity else "sessions with risk findings"
            return {
                "answer": (
                    f"No {risk_label} were found{scope_suffix} in PostgreSQL "
                    f"({total} total session(s) checked)."
                ),
                "intent": "RISK_ANALYSIS",
                "retrieval_mode": "rule-based",
                "session_id": session_id,
                "evidence_available": False,
                "evidence_summary": "Retrieved 0 session(s), 0 command(s), and 0 risk finding(s) for all.",
            }

        scope_suffix = f" for {scope_label}" if scope_label else ""
        heading = (
            f"Found {len(matches)} {risk_severity}-risk session(s){scope_suffix}:"
            if risk_severity
            else f"Found {len(matches)} session(s) with risk findings{scope_suffix}:"
        )
        lines = [heading, ""]
        total_commands = 0
        total_findings = 0
        entities_sessions = []
        entities_commands = []
        include_timing = _wants_session_timing_details(question)

        for index, match in enumerate(matches, start=1):
            risky_commands = [
                command
                for command in match.matching_commands
                if command.risk_findings and command.command
            ]
            total_commands += len(risky_commands)
            severity = "NONE"
            if match.risk_summary is not None:
                severity = match.risk_summary.overall_severity

            lines.append(
                f"{index}. Session ID: {match.session_id} | user: {match.username or 'unknown'} | risk: {severity}"
            )
            session_entity = {
                "session_id": match.session_id,
                "username": match.username,
                "risk": severity,
            }
            if include_timing:
                session = self._session_query_service.get_session(match.session_id)
                started_at = match.started_at
                if session is not None and started_at is None:
                    started_at = session.started_at or session.login_time
                date_label, time_label = _format_session_datetime(started_at)
                location = _resolve_session_location(session, match.matching_commands)
                lines.append(
                    f"   Conducted on {date_label} at {time_label} | host: {location}"
                )
                session_entity["date"] = date_label
                session_entity["time"] = time_label
                session_entity["host"] = location
            entities_sessions.append(session_entity)

            if not risky_commands:
                lines.append("   - No risky commands recorded")
            else:
                lines.append("   Risky commands:")
                for command in risky_commands:
                    entities_commands.append({"command": command.command, "session_id": match.session_id})
                    for finding in command.risk_findings:
                        total_findings += 1
                        lines.append(
                            f"   - `{command.command}`: {finding.category} ({finding.severity})"
                        )
            lines.append("")

        answer = "\n".join(lines).strip()
        return {
            "answer": answer,
            "intent": "RISK_ANALYSIS",
            "retrieval_mode": "rule-based",
            "session_id": session_id,
            "evidence_available": True,
            "evidence_summary": (
                f"Retrieved {len(matches)} session(s), {total_commands} command(s), "
                f"and {total_findings} risk finding(s) for all."
            ),
            "conversation_entities": {
                "sessions": entities_sessions,
                "commands": entities_commands,
            },
        }

    def _knowledge_fallback(self, command: str | None) -> str:
        known = self._ssh_knowledge_service.explain(command)
        if known is not None:
            return known
        normalized = (command or "").strip().lower()
        if not normalized:
            return "I can explain SSH and Linux commands. Please tell me which command you would like me to describe."

        if normalized in COMMAND_KNOWLEDGE:
            return COMMAND_KNOWLEDGE[normalized]

        # Try base command only (e.g., 'foo -x arg' -> 'foo')
        base = normalized.split()[0]
        base_text = self._ssh_knowledge_service.lookup(base)
        if base_text is not None:
            args = " ".join(normalized.split()[1:])
            return (
                f"`{command}` invokes `{base}` with arguments `{args}`.\n\n"
                f"{base_text}"
            )

        return (
            f"`{command}` is not in my offline SSH/Linux knowledge base, and Ollama is currently "
            f"unavailable to look it up. Please check `man {base}` on a Linux system for full documentation."
        )

    def _answer_grounded(self, query_plan: Any, session_id: str | None) -> dict[str, Any]:
        retrieved = self._evidence_retrieval_service.retrieve(query_plan)
        evidence = self._evidence_context_service.build_context(retrieved)
        evidence_available = bool(
            evidence.get("sessions") or evidence.get("findings") or evidence.get("summary", {}).get("session_count")
        )
        evidence_summary = self._format_grounded_evidence_summary(evidence)

        deterministic_answer = self._format_command_follow_up(query_plan, evidence)
        if deterministic_answer is not None:
            return {
                "answer": deterministic_answer,
                "intent": "GROUNDED_ANALYSIS",
                "retrieval_mode": "rule-based",
                "session_id": session_id or query_plan.session_id,
                "evidence_available": evidence_available,
                "evidence_summary": evidence_summary,
                "conversation_entities": _conversation_entities(evidence),
            }

        answer = None
        retrieval_mode = "rule-based"
        if evidence_available:
            answer = self._generate_llm_answer(query_plan.question, "GROUNDED_ANALYSIS", evidence)
            if answer is not None:
                retrieval_mode = "llm"

        if answer is None:
            answer = self._format_grounded_deterministic_answer(query_plan, evidence)
        if answer is None:
            answer = self._format_grounded_fallback(query_plan, evidence, evidence_available)

        if query_plan.risk_domain_query and evidence.get("sessions"):
            matched_count = len(evidence["sessions"])
            total_count = self._session_query_service.count_unique_sessions()
            if matched_count < total_count:
                answer = (
                    f"Risk analysis scope: {matched_count} risk-relevant session(s) "
                    f"out of {total_count} total recorded session(s). "
                    "The remaining sessions were not risk-matched in this response.\n\n"
                    f"{answer}"
                )

        return {
            "answer": answer,
            "intent": "GROUNDED_ANALYSIS",
            "retrieval_mode": retrieval_mode,
            "session_id": session_id or query_plan.session_id,
            "evidence_available": evidence_available,
            "evidence_summary": evidence_summary,
            "conversation_entities": _conversation_entities(evidence),
        }

    def _format_command_follow_up(self, query_plan: Any, evidence: dict[str, Any]) -> str | None:
        if "Conversation context:" not in query_plan.question:
            return None
        command_name = query_plan.command
        if not command_name:
            return None

        commands = [
            command
            for session in evidence.get("sessions", [])
            for command in session.get("commands", [])
            if command.get("command", "").strip().lower() == command_name.strip().lower()
        ]
        if not commands:
            return None

        question_lower = query_plan.question.lower()
        if "when" in question_lower or "what time" in question_lower:
            occurrences = [
                command for command in commands if command.get("executed_at") is not None
            ]
            if not occurrences:
                return f"`{command_name}` has no recorded execution timestamp in the retrieved evidence."
            return "; ".join(
                f"`{command_name}` was executed at {command['executed_at']}"
                for command in occurrences
            ) + "."

        if "output" in question_lower:
            return "; ".join(
                f"The output of `{command_name}` was: {command.get('output') or '[no output recorded]'}"
                for command in commands
            ) + "."

        if "before" in question_lower or "after" in question_lower:
            direction = "before" if "before" in question_lower else "after"
            related: list[dict[str, Any]] = []
            for session in evidence.get("sessions", []):
                session_commands = session.get("commands", [])
                for index, command in enumerate(session_commands):
                    if command.get("command", "").strip().lower() != command_name.strip().lower():
                        continue
                    neighbor_index = index - 1 if direction == "before" else index + 1
                    if 0 <= neighbor_index < len(session_commands):
                        related.append(session_commands[neighbor_index])
            if not related:
                return f"No command was recorded {direction} `{command_name}`."
            return "; ".join(
                f"Immediately {direction} `{command_name}`, the user executed `{item.get('command')}`"
                for item in related
            ) + "."

        return None

    def _format_grounded_evidence_summary(self, evidence: dict[str, Any]) -> str:
        summary = evidence.get("summary", {})
        scope = evidence.get("query_scope", {})
        date_from = scope.get("date_from")
        date_to = scope.get("date_to")
        if date_from and date_to:
            date_label = date_from if date_from == date_to else f"{date_from} to {date_to}"
        else:
            date_label = scope.get("scope") or "the retrieved scope"
        matched_sessions = summary.get("session_count", 0)
        if evidence.get("query_scope", {}).get("risk_domain"):
            total_sessions = self._session_query_service.count_unique_sessions()
            scope_text = (
                f"Retrieved {matched_sessions} risk-relevant session(s) out of "
                f"{total_sessions} total recorded session(s), "
            )
        else:
            scope_text = f"Retrieved {matched_sessions} session(s), "
        return (
            scope_text +
            f"{summary.get('command_count', 0)} command(s), and "
            f"{summary.get('risk_finding_count', 0)} risk finding(s) for {date_label}."
        )

    def _format_no_evidence_message(self, query_plan: Any) -> str:
        total_sessions = self._session_query_service.count_unique_sessions()
        if query_plan.command and query_plan.command.lower() in COMMAND_STOP_WORDS:
            return (
                f"No SSH session evidence matched command `{query_plan.command}` "
                f"(that word was parsed from your sentence, not a real command). "
                f"PostgreSQL contains {total_sessions} session(s). "
                f"Try: 'What happened in the latest SSH session?'"
            )
        if query_plan.risk_severity:
            return (
                f"No {query_plan.risk_severity.lower()}-risk sessions were found in PostgreSQL "
                f"({total_sessions} total session(s) available)."
            )
        if query_plan.date_range is not None:
            start_date, end_date = query_plan.date_range
            date_label = (
                start_date.isoformat()
                if start_date == end_date
                else f"{start_date.isoformat()} to {end_date.isoformat()}"
            )
            latest_sessions, _ = self._session_query_service.query_sessions(
                limit=1,
                protocol="SSH",
            )
            if latest_sessions:
                latest = latest_sessions[0]
                started = latest.started_at.date().isoformat() if latest.started_at else "unknown date"
                return (
                    f"No SSH sessions were recorded on {date_label}. "
                    f"The most recent session in PostgreSQL was on {started} "
                    f"by {latest.username or 'unknown'} (session {latest.session_id or latest.unique_id}). "
                    f"Try asking about that date instead."
                )
            return f"No SSH sessions were recorded on {date_label}."
        return (
            f"No matching SSH session evidence was found for that question. "
            f"PostgreSQL contains {total_sessions} session(s)."
        )

    def _format_grounded_deterministic_answer(
        self,
        query_plan: Any,
        evidence: dict[str, Any],
    ) -> str | None:
        sessions = evidence.get("sessions", [])
        if not sessions:
            return None

        question_lower = query_plan.question.lower()

        if query_plan.command:
            matching = [
                command
                for session in sessions
                for command in session.get("commands", [])
                if query_plan.command.lower() in (command.get("command") or "").lower()
            ]
            if matching:
                if any(term in question_lower for term in ("output", "result", "show", "what was")):
                    return "; ".join(
                        f"`{item.get('command')}` output: {item.get('output') or '[no output recorded]'}"
                        for item in matching
                    ) + "."
                if any(term in question_lower for term in ("when", "what time", "at what time")):
                    timed = [item for item in matching if item.get("executed_at") is not None]
                    if timed:
                        return "; ".join(
                            f"`{item.get('command')}` was executed at {item['executed_at']}"
                            for item in timed
                        ) + "."
                return "; ".join(
                    f"`{item.get('command')}` was executed"
                    + (f" at {item['executed_at']}" if item.get("executed_at") else "")
                    + (f" with output: {item.get('output')}" if item.get("output") else "")
                    for item in matching
                ) + "."

        if query_plan.scope == "latest_session" and "commands" in query_plan.needs:
            session = sessions[0]
            commands = [command.get("command") for command in session.get("commands", []) if command.get("command")]
            started = session.get("started_at")
            started_label = started.date().isoformat() if started else "unknown date"
            lines = [
                f"The most recent SSH session was by {session.get('username') or 'unknown'} "
                f"on {started_label} (session {session.get('session_id')}).",
            ]
            if commands:
                lines.append(f"Commands executed ({len(commands)}): {', '.join(commands)}.")
            else:
                lines.append("No commands were recorded for that session.")
            risk = session.get("risk") or session.get("risk_summary", {}).get("overall_severity")
            if risk and str(risk).upper() not in {"NONE", ""}:
                lines.append(f"Session risk level: {risk}.")
            return " ".join(lines)

        if query_plan.date_range is not None and "commands" in query_plan.needs:
            start_date, end_date = query_plan.date_range
            date_label = (
                start_date.isoformat()
                if start_date == end_date
                else f"{start_date.isoformat()} to {end_date.isoformat()}"
            )
            users = sorted({session.get("username") or "unknown" for session in sessions})
            all_commands = [
                command.get("command")
                for session in sessions
                for command in session.get("commands", [])
                if command.get("command")
            ]
            return (
                f"On {date_label}, {len(users)} user(s) logged in: {', '.join(users)} "
                f"across {len(sessions)} session(s). "
                f"Commands executed: {', '.join(all_commands) if all_commands else 'none recorded'}."
            )

        if query_plan.risk_severity:
            severity = query_plan.risk_severity
            lines = [f"Found {len(sessions)} {severity.lower()}-risk session(s):"]
            for index, session in enumerate(sessions[:10], start=1):
                commands = [
                    command.get("command")
                    for command in session.get("commands", [])
                    if command.get("command")
                ]
                lines.append(
                    f"{index}. {session.get('session_id')} by {session.get('username') or 'unknown'}"
                    + (f" — commands: {', '.join(commands[:5])}" if commands else "")
                )
            return " ".join(lines)

        return None

    def _format_grounded_fallback(
        self,
        query_plan: Any,
        evidence: dict[str, Any],
        evidence_available: bool,
    ) -> str:
        if not evidence_available:
            return self._format_no_evidence_message(query_plan)

        summary = evidence.get("summary", {})
        sessions = evidence.get("sessions", [])
        users = sorted({session.get("username") or "unknown" for session in sessions})
        risk_findings = evidence.get("findings", [])
        commands = [
            command.get("command")
            for session in sessions
            for command in session.get("commands", [])
            if command.get("command")
        ]

        parts = [
            f"Retrieved {summary.get('session_count', 0)} session(s) involving {', '.join(users)}.",
            f"The retrieved evidence contains {summary.get('command_count', 0)} command(s).",
        ]
        if commands:
            parts.append(f"Commands included: {', '.join(commands[:10])}.")
        if risk_findings:
            finding_text = "; ".join(
                f"{finding['command']}: {finding['category']} ({finding['severity']})"
                for finding in risk_findings[:10]
            )
            parts.append(f"Risk findings: {finding_text}.")
        else:
            parts.append("No risk findings were present in the retrieved evidence.")
        return " ".join(parts)

    def _answer_temporal(
        self,
        question: str,
        date_range: tuple[date, date],
        session_id: str | None,
    ) -> dict[str, Any]:
        start_date, end_date = date_range
        sessions = self._session_query_service.list_sessions_started_between(start_date, end_date)
        date_label = start_date.isoformat() if start_date == end_date else f"{start_date.isoformat()} to {end_date.isoformat()}"
        date_phrase = f"on {date_label}" if start_date == end_date else f"from {date_label}"

        if not sessions:
            return {
            "answer": f"No SSH sessions were recorded {date_phrase}.",
                "intent": "TEMPORAL_ACCESS",
                "retrieval_mode": "rule-based",
                "session_id": session_id,
                "evidence_available": False,
                "evidence_summary": f"Matched 0 unique session(s) from {date_label}.",
            }

        users = sorted({session.username or "unknown" for session in sessions})
        return {
            "answer": (
                f"{date_phrase.capitalize()}, {len(users)} user(s) accessed SSH: "
                f"{', '.join(users)} across {len(sessions)} unique session(s)."
            ),
            "intent": "TEMPORAL_ACCESS",
            "retrieval_mode": "rule-based",
            "session_id": session_id,
            "evidence_available": True,
            "evidence_summary": f"Matched {len(sessions)} unique session(s) from {date_label}.",
        }

    def _build_evidence(
        self,
        *,
        intent: str,
        question: str,
        session_id: str | None,
        search_terms: list[str],
        risk_categories: list[str],
        risk_severity: str | None,
        risk_domain_query: bool,
        session_count: int | None,
        session: Any | None,
        commands: list[Any],
        events: list[Any],
        timeline_entries: list[Any],
        timeline_analysis: Any | None,
        matched_commands: list[Any],
        matched_sessions: list[Any],
        evidence_summary: str,
    ) -> dict[str, Any]:
        evidence: dict[str, Any] = {
            "intent": intent,
            "question": question,
            "session_id": session_id,
            "search_terms": search_terms,
            "risk_categories": risk_categories,
            "risk_severity": risk_severity,
            "risk_domain_query": risk_domain_query,
            "session_count": session_count,
            "evidence_summary": evidence_summary,
        }

        if session is not None:
            evidence["session"] = {
                "session_id": session.session_id or session.unique_id,
                "username": session.username,
                "protocol": session.protocol,
                "remote_address": session.remote_address,
                "started_at": session.started_at,
                "ended_at": session.ended_at,
                "total_commands": session.total_commands,
            }

        if commands:
            evidence["risk_summary"] = _serialize_session_risk_summary(commands)

        if commands:
            evidence["commands"] = [
                {
                    "sequence_number": command.sequence_number,
                    "command": command.command,
                    "output": command.output,
                    "executed_at": command.executed_at,
                    "exit_code": command.exit_code,
                    "risk_findings": _serialize_risk_findings(getattr(command, "risk_findings", [])),
                }
                for command in commands
            ]

        if events:
            evidence["events"] = [
                {
                    "event_type": event.event_type,
                    "timestamp": event.timestamp,
                    "severity": event.severity,
                    "message": event.message,
                }
                for event in events
            ]

        if timeline_entries or timeline_analysis is not None:
            evidence["timeline"] = _serialize_timeline_entries(timeline_entries)
            if timeline_analysis is not None:
                evidence["timeline_analysis"] = _serialize_timeline_analysis(timeline_analysis)

        if matched_commands:
            evidence["matched_commands"] = [
                {
                    "session_id": command.session_id,
                    "username": command.username,
                    "protocol": command.protocol,
                    "sequence_number": command.sequence_number,
                    "command": command.command,
                    "output": command.output,
                    "executed_at": command.executed_at,
                    "matched_terms": command.matched_terms,
                }
                for command in matched_commands
            ]

        if matched_sessions:
            evidence["matched_sessions"] = [
                {
                    "session_id": matched_session.session_id,
                    "username": matched_session.username,
                    "protocol": matched_session.protocol,
                    "started_at": matched_session.started_at,
                    "ended_at": matched_session.ended_at,
                    "matched_terms": matched_session.matched_terms,
                    "matching_commands": [
                        {
                            "sequence_number": command.sequence_number,
                            "command": command.command,
                            "output": command.output,
                            "executed_at": command.executed_at,
                            "matched_terms": command.matched_terms,
                            "risk_findings": _serialize_risk_findings(getattr(command, "risk_findings", [])),
                        }
                        for command in matched_session.matching_commands
                    ],
                    "risk_summary": _serialize_session_risk_summary(matched_session.matching_commands),
                }
                for matched_session in matched_sessions
            ]

        return evidence

    def _build_answer(
        self,
        question: str,
        intent: str,
        evidence_available: bool,
        evidence: dict[str, Any],
    ) -> tuple[str, str]:
        if intent == "SESSION_COUNT":
            session_count = evidence.get("session_count", 0)
            risk_categories = evidence.get("risk_categories", [])
            risk_severity = evidence.get("risk_severity")
            risk_domain_query = evidence.get("risk_domain_query", False)

            if risk_categories:
                category_label = ", ".join(risk_categories)
                return (f"{session_count} session(s) had {category_label}.", "rule-based")
            if risk_severity:
                return (f"{session_count} session(s) were {risk_severity} risk.", "rule-based")
            if risk_domain_query:
                return (f"{session_count} session(s) contained risk findings.", "rule-based")
            return (f"There are {session_count} unique session(s).", "rule-based")

        if intent == "RISK_ANALYSIS" and _uses_deterministic_risk_response(question):
            commands = evidence.get("commands", [])
            risk_findings = [
                finding
                for command in commands
                for finding in command.get("risk_findings", [])
            ]
            return (
                format_risk_summary(
                    evidence.get("risk_summary", {}),
                    risk_findings,
                    commands,
                ),
                "rule-based",
            )

        matched_sessions = evidence.get("matched_sessions", [])
        risk_categories = evidence.get("risk_categories", [])
        risk_severity = evidence.get("risk_severity")
        risk_domain_query = evidence.get("risk_domain_query", False)

        if intent == "SESSION_SEARCH" and (risk_categories or risk_severity or risk_domain_query):
            if not matched_sessions:
                if risk_categories:
                    return (
                        format_cross_session_risk_search([], risk_categories),
                        "rule-based",
                    )
                if risk_severity:
                    return (
                        f"No {risk_severity} risk sessions were found.",
                        "rule-based",
                    )
                return (
                    "No sessions with risk findings were found.",
                    "rule-based",
                )
            if risk_categories:
                return (
                    format_cross_session_risk_search(matched_sessions, risk_categories),
                    "rule-based",
                )
            return (
                format_cross_session_risk_search(matched_sessions, []),
                "rule-based",
            )

        if _uses_deterministic_timeline_response(question, intent):
            timeline = evidence.get("timeline", [])
            timeline_analysis = evidence.get("timeline_analysis", {})
            timeline_risk_categories = extract_risk_categories(question)
            question_lower = (question or "").strip().lower()

            if _is_first_risky_query(question_lower):
                return (format_first_risky_timeline_entry(timeline), "rule-based")

            if _is_last_command_query(question_lower):
                return (format_last_command_entry(timeline), "rule-based")

            if timeline_risk_categories and "before" in question_lower:
                return (
                    format_timeline_relative_to_risk(
                        timeline,
                        timeline_analysis,
                        timeline_risk_categories[0],
                        "before",
                    ),
                    "rule-based",
                )

            if timeline_risk_categories and "after" in question_lower:
                return (
                    format_timeline_relative_to_risk(
                        timeline,
                        timeline_analysis,
                        timeline_risk_categories[0],
                        "after",
                    ),
                    "rule-based",
                )

            if _is_when_risk_query(question_lower):
                when_category = (
                    timeline_risk_categories[0]
                    if timeline_risk_categories
                    else _extract_when_risk_category_label(question)
                )
                if when_category:
                    return (format_when_risk_occurred(timeline, when_category), "rule-based")

            command_anchor = _extract_command_anchor(question)
            if command_anchor is not None:
                anchor_direction, anchor_command = command_anchor
                return (
                    format_timeline_relative_to_command(timeline, anchor_command, anchor_direction),
                    "rule-based",
                )

            return (
                format_timeline_summary(timeline, timeline_analysis),
                "rule-based",
            )

        if evidence_available and (
            _is_analyst_query(question.lower()) or not self._uses_ollama_provider
        ):
            llm_answer = self._generate_llm_answer(question, intent, evidence)
            if llm_answer is not None:
                return (llm_answer, "llm")

        session = evidence.get("session")
        commands = evidence.get("commands", [])
        events = evidence.get("events", [])
        matched_commands = evidence.get("matched_commands", [])

        if intent == "COMMAND_SEARCH":
            if not matched_commands:
                return ("I couldn't retrieve command evidence for that search.", "rule-based")
            command_hits = [
                f"{command['session_id']}: {command['command']}"
                for command in matched_commands[:5]
                if command.get("command")
            ]
            return (f"The matching commands were: {', '.join(command_hits)}.", "rule-based")

        if intent == "SESSION_SEARCH":
            if not matched_sessions:
                return ("I couldn't retrieve session evidence for that search.", "rule-based")
            session_hits = [
                f"{matched_session['session_id']}"
                for matched_session in matched_sessions[:5]
            ]
            return (f"The matching sessions were: {', '.join(session_hits)}.", "rule-based")

        if not session:
            return (
                "I couldn't retrieve session evidence to answer that question.",
                "rule-based",
            )

        if intent == "RISK_ANALYSIS":
            risk_commands = [
                command
                for command in commands
                if command.get("risk_findings")
            ]
            if not risk_commands:
                return (
                    "No risk findings were identified in the retrieved session evidence.",
                    "rule-based",
                )

            findings_summary = []
            for command in risk_commands[:5]:
                finding_labels = [
                    f"{finding['category']} ({finding['severity']})"
                    for finding in command.get("risk_findings", [])
                ]
                findings_summary.append(f"{command['command']}: {', '.join(finding_labels)}")

            return (
                f"The retrieved session evidence includes the following risk findings: {'; '.join(findings_summary)}.",
                "rule-based",
            )

        if intent == "COMMAND_LOOKUP":
            command_names = [command["command"] for command in commands if command.get("command")]
            if not command_names:
                return ("No commands were recorded for this session.", "rule-based")
            return (
                f"The recorded commands were: {', '.join(command_names)}.",
                "rule-based",
            )

        if intent == "TIMELINE_SUMMARY":
            event_types = [event["event_type"] for event in events[:5] if event.get("event_type")]
            if not event_types:
                return ("No events were recorded for this session.", "rule-based")
            return (
                f"The session timeline includes: {', '.join(event_types)}.",
                "rule-based",
            )

        if intent == "SESSION_LOOKUP":
            return (
                f"Session {session['session_id']} started at {session['started_at']} and ended at {session['ended_at']}.",
                "rule-based",
            )

        summary = (
            f"Session {session['session_id']} started with protocol "
            f"{session['protocol'] or 'unknown'} and recorded {len(commands)} command(s). "
            f"Evidence summary: {evidence.get('evidence_summary', 'No evidence summary was available.')}"
        )
        return (summary, "rule-based")

    def _generate_llm_answer(self, question: str, intent: str, evidence: dict[str, Any]) -> str | None:
        if self._llm_provider is None:
            return None
        try:
            return self._llm_provider.generate(question=question, intent=intent, evidence=evidence)
        except Exception:
            logger.exception("Chatbot LLM generation failed")
            return None
