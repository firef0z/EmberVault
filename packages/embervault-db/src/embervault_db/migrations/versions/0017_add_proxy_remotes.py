"""0017_add_proxy_remotes

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-06 15:30:00.000000

"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "proxy_remotes",
        sa.Column(
            "proxy_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("proxies.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "remote_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("rclone_remotes.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )
    # Populate existing proxies and remotes (default: all proxies can reach all remotes)
    op.execute(
        "INSERT INTO proxy_remotes (proxy_id, remote_id) "
        "SELECT proxies.id, rclone_remotes.id FROM proxies CROSS JOIN rclone_remotes"
    )


def downgrade() -> None:
    op.drop_table("proxy_remotes")
