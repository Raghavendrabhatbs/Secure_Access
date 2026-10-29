from typing import Literal

from pydantic import BaseModel, Field, model_validator


class ChatSource(BaseModel):
    title: str
    url: str
    published_at: str | None = None


ChatIntent = Literal[
    "GENERAL_KNOWLEDGE",
    "COMMAND_EXPLANATION",
    "SYSTEM_STATUS",
    "MIXED_QUERY",
    "SESSION_SUMMARY",
    "TIMELINE_QUERY",
    "USER_ACTIVITY",
    "SECURITY_SUMMARY",
    "CROSS_SESSION_ANALYSIS",
    "COMMAND_LOOKUP",
    "SESSION_LOOKUP",
    "TIMELINE_SUMMARY",
    "RISK_ANALYSIS",
    "COMMAND_SEARCH",
    "SESSION_SEARCH",
    "SESSION_COUNT",
    "SESSION_LIST",
    "SESSION_STATS",
    "SESSION_STATUS",
    "SESSION_TIMING",
    "TEMPORAL_ACCESS",
    "AUDIT_EXPORT",
    "GROUNDED_ANALYSIS",
    "GENERAL_QUESTION",
    "EVENT_SEARCH",
    "RECORDING_SEARCH",
    "SECURITY_ANALYSIS",
    "CURRENT_EVENTS",
    "UPCOMING_EVENTS",
    "CURRENT_WEATHER_OR_TIME",
    "UNKNOWN",
]


class ChatQueryRequest(BaseModel):
    question: str | None = Field(default=None, min_length=1, max_length=4000)
    message: str | None = Field(default=None, min_length=1, max_length=4000)
    session_id: str | None = Field(default=None, max_length=255)
    conversation_id: str | None = Field(default=None, max_length=36)

    @model_validator(mode="after")
    def require_question_or_message(self):
        if not any(value and value.strip() for value in (self.question, self.message)):
            raise ValueError("Either question or message must be provided.")
        return self

    @property
    def prompt_text(self) -> str:
        question = self.question or ""
        return question if question.strip() else (self.message or "")


class ChatQueryResponse(BaseModel):
    answer: str
    intent: ChatIntent
    retrieval_mode: Literal["llm", "rule-based"]
    mode: Literal["llm", "rule-based"] | None = None
    session_id: str | None = None
    evidence_available: bool
    evidence_summary: str
    conversation_id: str | None = None
    sources: list[ChatSource] = Field(default_factory=list)


class ConversationMessageRead(BaseModel):
    id: str
    role: Literal["user", "assistant"]
    content: str
    metadata_json: dict

    model_config = {"from_attributes": True}
