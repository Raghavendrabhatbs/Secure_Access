"""add blocked users table

Revision ID: 9d2a7f4c1e30
Revises: 7c1d4b2e8a10
"""

from alembic import op
import sqlalchemy as sa


revision = "9d2a7f4c1e30"
down_revision = "7c1d4b2e8a10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "blocked_users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=255), nullable=False, unique=True),
        sa.Column("blocked_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("blocked_reason", sa.Text()),
        sa.Column("trigger_command", sa.Text()),
        sa.Column("severity", sa.String(length=20)),
        sa.Column("session_id", sa.String(length=255)),
        sa.Column("unblocked_at", sa.DateTime()),
        sa.Column("unblocked_by", sa.String(length=255)),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
    )
    op.create_index("idx_blocked_users_username", "blocked_users", ["username"])
    op.create_index("idx_blocked_users_active", "blocked_users", ["is_active"])


def downgrade() -> None:
    op.drop_index("idx_blocked_users_active", table_name="blocked_users")
    op.drop_index("idx_blocked_users_username", table_name="blocked_users")
    op.drop_table("blocked_users")
