"""0009_add_job_notification_policy

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-24 16:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "jobs",
        sa.Column(
            "notification_policy",
            sa.String(length=20),
            nullable=True,
        ),
    )

    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("jobs") as batch_op:
            batch_op.create_check_constraint(
                "ck_jobs_notification_policy",
                "notification_policy IS NULL OR notification_policy IN ('always', 'only_errors')",
            )
    else:
        op.create_check_constraint(
            "ck_jobs_notification_policy",
            "jobs",
            "notification_policy IS NULL OR notification_policy IN ('always', 'only_errors')",
        )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("jobs") as batch_op:
            batch_op.drop_constraint("ck_jobs_notification_policy", type_="check")
            batch_op.drop_column("notification_policy")
    else:
        op.drop_constraint("ck_jobs_notification_policy", "jobs", type_="check")
        op.drop_column("jobs", "notification_policy")
