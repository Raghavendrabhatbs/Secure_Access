from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from shared.models.conversation import Conversation, ConversationMessage


class ConversationService:
    def __init__(self, db: Session):
        self._db = db

    def get_or_create(self, conversation_id: str | None, owner_username: str) -> Conversation:
        if conversation_id:
            conversation = self._db.get(Conversation, conversation_id)
            if conversation is None:
                conversation = Conversation(id=conversation_id)
                self._db.add(conversation)
            elif not self.is_owned_by(conversation_id, owner_username):
                raise PermissionError("Conversation access denied.")
        else:
            conversation = Conversation()
            self._db.add(conversation)
        self._db.flush()
        return conversation

    def is_owned_by(self, conversation_id: str, owner_username: str) -> bool:
        first_message = self._db.scalars(
            select(ConversationMessage)
            .where(
                ConversationMessage.conversation_id == conversation_id,
                ConversationMessage.role == "user",
            )
            .order_by(ConversationMessage.created_at.asc(), ConversationMessage.id.asc())
            .limit(1)
        ).first()
        if first_message is None or not isinstance(first_message.metadata_json, dict):
            return False
        return first_message.metadata_json.get("owner_username") == owner_username

    def history(self, conversation_id: str, limit: int = 12) -> list[ConversationMessage]:
        statement = (
            select(ConversationMessage)
            .where(ConversationMessage.conversation_id == conversation_id)
            .order_by(ConversationMessage.created_at.desc(), ConversationMessage.id.desc())
            .limit(limit)
        )
        return list(reversed(self._db.scalars(statement).all()))

    def add_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> ConversationMessage:
        message = ConversationMessage(
            conversation_id=conversation_id,
            role=role,
            content=content,
            metadata_json=metadata or {},
        )
        self._db.add(message)
        self._db.flush()
        return message
