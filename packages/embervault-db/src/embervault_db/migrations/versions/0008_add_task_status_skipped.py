"""0008_add_task_status_skipped

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-22 17:00:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Update tasks ck_tasks_status constraint to include 'skipped'
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("tasks") as batch_op:
            batch_op.drop_constraint("ck_tasks_status", type_="check")
            batch_op.create_check_constraint(
                "ck_tasks_status",
                "status IN ('pending', 'ready', 'assigned', 'running', 'retry_wait', 'succeeded', 'failed', 'cancelled', 'skipped')",
            )
    else:
        op.drop_constraint("ck_tasks_status", "tasks", type_="check")
        op.create_check_constraint(
            "ck_tasks_status",
            "tasks",
            "status IN ('pending', 'ready', 'assigned', 'running', 'retry_wait', 'succeeded', 'failed', 'cancelled', 'skipped')",
        )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("tasks") as batch_op:
            batch_op.drop_constraint("ck_tasks_status", type_="check")
            batch_op.create_check_constraint(
                "ck_tasks_status",
                "status IN ('pending', 'ready', 'assigned', 'running', 'retry_wait', 'succeeded', 'failed', 'cancelled')",
            )
    else:
        op.drop_constraint("ck_tasks_status", "tasks", type_="check")
        op.create_check_constraint(
            "ck_tasks_status",
            "tasks",
            "status IN ('pending', 'ready', 'assigned', 'running', 'retry_wait', 'succeeded', 'failed', 'cancelled')",
        )
