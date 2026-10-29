from collections.abc import Callable

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as SqlAlchemySession

from app.domain.command import ParsedCommand
from shared.models.command import Command as CommandModel


class CommandRepository:
    def __init__(self, session_factory: Callable[[], SqlAlchemySession]):
        self._session_factory = session_factory

    def upsert_commands(
        self,
        session_id: str,
        commands: list[ParsedCommand],
    ) -> int:
        db_session = self._session_factory()

        try:
            upserted = 0

            for command in commands:
                existing = db_session.execute(
                    select(CommandModel).where(
                        CommandModel.session_id == session_id,
                        CommandModel.sequence_number == command.sequence_number,
                    )
                ).scalar_one_or_none()

                if existing is None:
                    existing = CommandModel(
                        id=f"{session_id}:{command.sequence_number}",
                        session_id=session_id,
                        sequence_number=command.sequence_number,
                        command=command.command,
                        output=command.output,
                        executed_at=command.executed_at,
                        exit_code=command.exit_code,
                    )
                    db_session.add(existing)
                else:
                    existing.command = command.command
                    existing.output = command.output
                    existing.executed_at = command.executed_at
                    existing.exit_code = command.exit_code

                upserted += 1

            sequence_numbers = {command.sequence_number for command in commands}
            db_session.execute(
                delete(CommandModel).where(
                    CommandModel.session_id == session_id,
                    CommandModel.sequence_number.not_in(sequence_numbers),
                )
            )

            db_session.commit()
            return upserted
        except Exception:
            db_session.rollback()
            raise
