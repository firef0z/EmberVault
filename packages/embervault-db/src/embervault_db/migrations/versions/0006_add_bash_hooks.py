"""0006_add_bash_hooks

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-21 17:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add pre_run_hook and post_run_hook columns to jobs table
    op.add_column("jobs", sa.Column("pre_run_hook", sa.Text(), nullable=True))
    op.add_column("jobs", sa.Column("post_run_hook", sa.Text(), nullable=True))

    # 2. Create job_run_hooks table
    op.create_table(
        "job_run_hooks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("hook_type", sa.String(length=20), nullable=False),
        sa.Column("script_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Float(), nullable=False),
        sa.Column("output", sa.Text(), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "hook_type IN ('pre_run', 'post_run')",
            name=op.f("ck_job_run_hooks_hook_type"),
        ),
        sa.CheckConstraint(
            "status IN ('succeeded', 'failed', 'timeout', 'skipped')",
            name=op.f("ck_job_run_hooks_status"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["job_runs.id"],
            name=op.f("fk_job_run_hooks_run_id_job_runs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_job_run_hooks")),
    )
    op.create_index(
        "ix_job_run_hooks_run_id",
        "job_run_hooks",
        ["run_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_job_run_hooks_run_id", table_name="job_run_hooks")
    op.drop_table("job_run_hooks")
    op.drop_column("jobs", "post_run_hook")
    op.drop_column("jobs", "pre_run_hook")
