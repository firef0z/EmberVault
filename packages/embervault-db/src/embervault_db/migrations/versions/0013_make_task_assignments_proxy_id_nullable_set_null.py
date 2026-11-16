"""0013_make_task_assignments_proxy_id_nullable_set_null

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-27 15:15:00.000000

"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("task_assignments") as batch_op:
            batch_op.alter_column(
                "proxy_id",
                existing_type=sa.Uuid(),
                nullable=True,
            )
            batch_op.drop_constraint("fk_task_assignments_proxy_id_proxies", type_="foreignkey")
            batch_op.create_foreign_key(
                "fk_task_assignments_proxy_id_proxies",
                "proxies",
                ["proxy_id"],
                ["id"],
                ondelete="SET NULL",
            )
    else:
        op.alter_column(
            "task_assignments",
            "proxy_id",
            existing_type=sa.Uuid(),
            nullable=True,
        )
        op.drop_constraint(
            "fk_task_assignments_proxy_id_proxies",
            "task_assignments",
            type_="foreignkey",
        )
        op.create_foreign_key(
            "fk_task_assignments_proxy_id_proxies",
            "task_assignments",
            "proxies",
            ["proxy_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("task_assignments") as batch_op:
            batch_op.drop_constraint("fk_task_assignments_proxy_id_proxies", type_="foreignkey")
            batch_op.create_foreign_key(
                "fk_task_assignments_proxy_id_proxies",
                "proxies",
                ["proxy_id"],
                ["id"],
            )
            batch_op.alter_column(
                "proxy_id",
                existing_type=sa.Uuid(),
                nullable=False,
            )
    else:
        op.drop_constraint(
            "fk_task_assignments_proxy_id_proxies",
            "task_assignments",
            type_="foreignkey",
        )
        op.create_foreign_key(
            "fk_task_assignments_proxy_id_proxies",
            "task_assignments",
            "proxies",
            ["proxy_id"],
            ["id"],
        )
        op.alter_column(
            "task_assignments",
            "proxy_id",
            existing_type=sa.Uuid(),
            nullable=False,
        )
