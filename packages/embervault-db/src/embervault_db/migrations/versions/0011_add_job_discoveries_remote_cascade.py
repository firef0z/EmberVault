"""0011_add_job_discoveries_remote_cascade

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-25 02:30:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("job_discoveries") as batch_op:
            batch_op.drop_constraint(
                "fk_job_discoveries_source_remote_id_rclone_remotes", type_="foreignkey"
            )
            batch_op.create_foreign_key(
                "fk_job_discoveries_source_remote_id_rclone_remotes",
                "rclone_remotes",
                ["source_remote_id"],
                ["id"],
                ondelete="CASCADE",
            )
    else:
        op.drop_constraint(
            "fk_job_discoveries_source_remote_id_rclone_remotes",
            "job_discoveries",
            type_="foreignkey",
        )
        op.create_foreign_key(
            "fk_job_discoveries_source_remote_id_rclone_remotes",
            "job_discoveries",
            "rclone_remotes",
            ["source_remote_id"],
            ["id"],
            ondelete="CASCADE",
        )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "sqlite":
        with op.batch_alter_table("job_discoveries") as batch_op:
            batch_op.drop_constraint(
                "fk_job_discoveries_source_remote_id_rclone_remotes", type_="foreignkey"
            )
            batch_op.create_foreign_key(
                "fk_job_discoveries_source_remote_id_rclone_remotes",
                "rclone_remotes",
                ["source_remote_id"],
                ["id"],
            )
    else:
        op.drop_constraint(
            "fk_job_discoveries_source_remote_id_rclone_remotes",
            "job_discoveries",
            type_="foreignkey",
        )
        op.create_foreign_key(
            "fk_job_discoveries_source_remote_id_rclone_remotes",
            "job_discoveries",
            "rclone_remotes",
            ["source_remote_id"],
            ["id"],
        )
