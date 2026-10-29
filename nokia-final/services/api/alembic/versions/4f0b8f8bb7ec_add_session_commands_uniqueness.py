"""add session_commands uniqueness

Revision ID: 4f0b8f8bb7ec
Revises: 3a3a9ae7da5b
Create Date: 2026-08-08 20:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "4f0b8f8bb7ec"
down_revision: Union[str, Sequence[str], None] = "3a3a9ae7da5b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_session_commands_session_id_sequence_number",
        "session_commands",
        ["session_id", "sequence_number"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_session_commands_session_id_sequence_number",
        "session_commands",
        type_="unique",
    )
