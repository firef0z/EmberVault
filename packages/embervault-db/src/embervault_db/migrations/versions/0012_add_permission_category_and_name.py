"""0012_add_permission_category_and_name

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-25 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("permissions") as batch_op:
            batch_op.add_column(sa.Column("name", sa.String(length=100), nullable=True))
            batch_op.add_column(
                sa.Column(
                    "category",
                    sa.String(length=50),
                    nullable=False,
                    server_default="Generale",
                )
            )
    else:
        op.add_column(
            "permissions",
            sa.Column("name", sa.String(length=100), nullable=True),
        )
        op.add_column(
            "permissions",
            sa.Column(
                "category",
                sa.String(length=50),
                nullable=False,
                server_default="Generale",
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("permissions") as batch_op:
            batch_op.drop_column("category")
            batch_op.drop_column("name")
    else:
        op.drop_column("permissions", "category")
        op.drop_column("permissions", "name")
