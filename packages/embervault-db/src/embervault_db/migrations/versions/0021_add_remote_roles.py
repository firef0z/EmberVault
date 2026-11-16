"""0021_add_remote_roles

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-14 18:00:00.000000

"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "remote_roles",
        sa.Column(
            "remote_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("rclone_remotes.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "role_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("roles.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )
    # Populate existing remotes with all existing roles so existing remotes remain visible
    op.execute(
        "INSERT INTO remote_roles (remote_id, role_id) "
        "SELECT rclone_remotes.id, roles.id FROM rclone_remotes CROSS JOIN roles"
    )


def downgrade() -> None:
    op.drop_table("remote_roles")
