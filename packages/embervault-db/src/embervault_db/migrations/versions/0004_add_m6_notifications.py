"""0004_add_m6_notifications

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-21 10:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add notifications_enabled column to jobs table
    op.add_column(
        "jobs",
        sa.Column(
            "notifications_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
    )

    # 2. Add notification_sent_at column to job_runs table
    op.add_column(
        "job_runs",
        sa.Column(
            "notification_sent_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # 3. Create notification_channels table
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("channel_type", sa.String(20), nullable=False, server_default="custom"),
        sa.Column("url_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("telegram_format", sa.String(20), nullable=False, server_default="html"),
        sa.Column("rate_limit_interval_s", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("config_metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "channel_type IN ('email', 'telegram', 'custom')",
            name="ck_notification_channels_channel_type",
        ),
        sa.CheckConstraint(
            "telegram_format IN ('text', 'html', 'markdown')",
            name="ck_notification_channels_telegram_format",
        ),
    )


def downgrade() -> None:
    op.drop_table("notification_channels")
    op.drop_column("job_runs", "notification_sent_at")
    op.drop_column("jobs", "notifications_enabled")
