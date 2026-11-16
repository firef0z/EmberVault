"""0007_add_user_theme

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-22 16:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "theme",
            sa.String(length=50),
            nullable=False,
            server_default="embervault",
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "theme")
