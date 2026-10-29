from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


REFERENCE_PATTERNS = (
    r"\bthat command\b",
    r"\bthat session\b",
    r"\bthat user\b",
    r"\bthat one\b",
    r"\bthe first one\b",
    r"\bthe second one\b",
    r"\bthe third one\b",
    r"\bthe last one\b",
    r"\bthe next one\b",
    r"\bthe previous one\b",
    r"\bwhich one\b",
    r"\bthe user\b",
    r"\bthe session\b",
    r"\bthe command\b",
    r"\bwhat about it\b",
    r"\bbefore it\b",
    r"\bafter it\b",
    r"\babout it\b",
    r"\bdid they\b",
    r"\bwas it\b",
    r"\bwas that\b",
    r"\bwas that session\b",
    r"\bis that\b",
    r"\bis it\b",
    r"\bwhen was it\b",
    r"\bwhen did it\b",
    r"\bwhen did that\b",
    r"\bhow risky (?:is|was) (?:it|that)\b",
    r"\bhow dangerous (?:is|was) (?:it|that)\b",
    r"\bwho (?:executed|ran|used) (?:it|that|them)\b",
    r"\bwho did (?:it|that)\b",
    r"\bwhere (?:was|did) (?:it|that)\b",
    r"\bshow (?:its|their) output\b",
    r"\boutput of (?:it|that)\b",
    r"\bhas it\b",
    r"\bthem\b",
    r"\bthose commands\b",
    r"\bthose sessions\b",
    r"\bthose users\b",
    r"^\s*it\b",
    r"^\s*and (?:it|that|them)\b",
)


FOLLOWUP_CATEGORY_PATTERNS = {
    "when": (
        re.compile(r"\bwhen\s+(?:was|did)\b", re.IGNORECASE),
        re.compile(r"\bwhat\s+time\b", re.IGNORECASE),
        re.compile(r"\bat\s+what\s+time\b", re.IGNORECASE),
    ),
    "who": (
        re.compile(r"\bwho\s+(?:ran|executed|used|did|is|was)\b", re.IGNORECASE),
    ),
    "before": (
        re.compile(r"\bbefore\s+(?:it|that|it\?)\b", re.IGNORECASE),
        re.compile(r"\bwhat\s+happened\s+before\b", re.IGNORECASE),
        re.compile(r"\bwhat\s+came\s+before\b", re.IGNORECASE),
    ),
    "after": (
        re.compile(r"\bafter\s+(?:it|that|it\?)\b", re.IGNORECASE),
        re.compile(r"\bwhat\s+happened\s+after\b", re.IGNORECASE),
        re.compile(r"\bwhat\s+came\s+after\b", re.IGNORECASE),
    ),
    "risk": (
        re.compile(
            r"\b(?:was|is|are)\s+(?:it|that|those|them|"
            r"that\s+session|that\s+command|"
            r"the\s+(?:first|second|third|last|previous|next|one)(?:\s+one)?)\s+"
            r"(?:a\s+)?(?:risky|dangerous|high[- ]?risk|"
            r"malicious|suspicious|anomalous)\b",
            re.IGNORECASE,
        ),
        re.compile(r"\brisk\s+(?:level|severity)\b", re.IGNORECASE),
        re.compile(r"\bhow\s+risky\b", re.IGNORECASE),
        re.compile(r"\bhow\s+dangerous\b", re.IGNORECASE),
    ),
    "output": (
        re.compile(r"\bwhat\s+was\s+the\s+output\b", re.IGNORECASE),
        re.compile(r"\boutput\s+of\s+(?:it|that)\b", re.IGNORECASE),
        re.compile(r"\bshow\s+(?:its|the)\s+output\b", re.IGNORECASE),
    ),
    "where": (
        re.compile(r"\bwhere\s+(?:was|did)\b", re.IGNORECASE),
        re.compile(r"\bon\s+which\s+(?:host|server)\b", re.IGNORECASE),
    ),
}


@dataclass(frozen=True)
class ResolvedConversationContext:
    question: str
    session_id: str | None = None
    command: str | None = None
    username: str | None = None
    followup_type: str | None = None
    has_pronoun: bool = False


class ConversationContextService:
    def resolve(self, question: str, history: list[Any]) -> ResolvedConversationContext:
        question_text = (question or "").strip()
        question_lower = question_text.lower()

        has_pronoun = self._has_follow_up_reference(question_lower)
        if not has_pronoun or not history:
            return ResolvedConversationContext(question=question_text, has_pronoun=has_pronoun)

        previous_user = self._latest(history, "user")
        previous_assistant = self._latest(history, "assistant")

        entities = self._entities_from_history(history)
        commands = self._commands_from_messages(previous_user, previous_assistant, entities)
        command = self._select_command(question_lower, commands, entities)
        session_id = self._resolve_session_id(history, entities, command, question_lower)
        username = self._resolve_username(history, entities, previous_user)
        followup_type = self._classify_followup(question_lower)

        anchors: list[str] = []
        if command:
            anchors.append(f"The referenced command is `{command}`.")
        if session_id and (
            "session" in question_lower
            or followup_type in {"risk", "when", "before", "after", "who", "where"}
        ):
            anchors.append(f"The referenced session ID is `{session_id}`.")
        if username and "user" in question_lower:
            anchors.append(f"The referenced username is `{username}`.")

        rewritten = question_text
        if anchors:
            rewritten = f"{question_text}\n\nConversation context: {' '.join(anchors)}"

        return ResolvedConversationContext(
            question=rewritten,
            session_id=session_id,
            command=command,
            username=username,
            followup_type=followup_type,
            has_pronoun=True,
        )

    def _has_follow_up_reference(self, question_lower: str) -> bool:
        return any(re.search(pattern, question_lower) for pattern in REFERENCE_PATTERNS)

    def _classify_followup(self, question_lower: str) -> str | None:
        for kind, patterns in FOLLOWUP_CATEGORY_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(question_lower):
                    return kind
        return None

    def _latest(self, history: list[Any], role: str) -> Any | None:
        for message in reversed(history):
            if getattr(message, "role", None) == role:
                return message
        return None

    def _resolve_session_id(
        self,
        history: list[Any],
        entities: list[dict[str, Any]],
        command: str | None,
        question_lower: str,
    ) -> str | None:
        if command:
            for entity in entities:
                if entity.get("command") == command and entity.get("session_id"):
                    return entity["session_id"]
        session_ids = [
            entity["session_id"]
            for entity in entities
            if entity.get("protocol") == "WEB" and entity.get("session_id")
        ]
        for phrase, index in (("first one", 0), ("second one", 1), ("third one", 2)):
            if phrase in question_lower and len(session_ids) > index:
                return session_ids[index]
        if "last one" in question_lower and session_ids:
            return session_ids[-1]
        for message in reversed(history):
            metadata = getattr(message, "metadata_json", {}) or {}
            if metadata.get("session_id"):
                return metadata["session_id"]
        for entity in entities:
            if entity.get("session_id"):
                return entity["session_id"]
        return None

    def _entities_from_history(self, history: list[Any]) -> list[dict[str, Any]]:
        for message in reversed(history):
            metadata = getattr(message, "metadata_json", {}) or {}
            entities = metadata.get("entities", {}) or {}
            commands = entities.get("commands", [])
            sessions = entities.get("sessions", [])
            structured = [
                entity
                for entity in [*commands, *sessions]
                if isinstance(entity, dict)
            ]
            if structured:
                return structured
        return []

    def _commands_from_messages(
        self,
        user_message: Any | None,
        assistant_message: Any | None,
        entities: list[dict[str, Any]],
    ) -> list[str]:
        commands: list[str] = []
        for entity in entities:
            command = entity.get("command") if isinstance(entity, dict) else None
            if command and command not in commands:
                commands.append(command)
        for message in (assistant_message, user_message):
            if message is None:
                continue
            content = getattr(message, "content", "") or ""
            for command in re.findall(r"`([^`]+)`", content):
                normalized = command.strip()
                if not normalized or self._looks_like_metadata(normalized):
                    continue
                if normalized not in commands:
                    commands.append(normalized)
        return commands

    def _select_command(
        self,
        question_lower: str,
        commands: list[str],
        entities: list[dict[str, Any]],
    ) -> str | None:
        if not commands:
            return None

        for entity in entities:
            categories = " ".join(entity.get("risk_categories", [])).lower()
            if "privilege escalation" in question_lower and "privilege_escalation" in categories:
                return entity.get("command")
            if "permission modification" in question_lower and "permission_modification" in categories:
                return entity.get("command")
            if "anti-forensics" in question_lower and "anti_forensics" in categories:
                return entity.get("command")

        if "second one" in question_lower and len(commands) > 1:
            return commands[1]
        if "third one" in question_lower and len(commands) > 2:
            return commands[2]
        if "last one" in question_lower:
            return commands[-1]
        if "previous one" in question_lower and len(commands) > 1:
            return commands[-2]
        return commands[0]

    def _resolve_username(
        self,
        history: list[Any],
        entities: list[dict[str, Any]],
        user_message: Any | None,
    ) -> str | None:
        for message in reversed(history):
            metadata = getattr(message, "metadata_json", {}) or {}
            entities_meta = metadata.get("entities", {}) or {}
            sessions = entities_meta.get("sessions", []) or []
            for session in sessions:
                if isinstance(session, dict) and session.get("username"):
                    return session["username"]
        if user_message is None:
            return None
        content = getattr(user_message, "content", "") or ""
        match = re.search(r"\b(?:did|for|by|user)\s+([\w.-]+)", content, re.IGNORECASE)
        return match.group(1) if match else None

    def _looks_like_metadata(self, value: str) -> bool:
        lowered = value.lower()
        return lowered in {
            "high", "medium", "low", "none",
            "high-risk", "low-risk", "medium-risk",
            "risk", "severity", "unknown",
        }
