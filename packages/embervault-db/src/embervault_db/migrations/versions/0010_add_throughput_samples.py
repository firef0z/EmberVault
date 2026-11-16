"""0010_add_throughput_samples

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-24 16:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "throughput_samples",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("bytes_per_sec", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("active_runs", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index(
        "ix_throughput_samples_recorded_at",
        "throughput_samples",
        ["recorded_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_throughput_samples_recorded_at", table_name="throughput_samples")
    op.drop_table("throughput_samples")
