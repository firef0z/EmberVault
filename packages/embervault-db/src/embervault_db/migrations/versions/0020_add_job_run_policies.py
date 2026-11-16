"""0020_add_job_run_policies

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-14 15:45:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ACTIVE_RUN_WHERE = sa.text(
    "status IN ('queued', 'planning', 'awaiting_confirmation', 'running')"
)


def _find_check_constraints(table_name: str, column_hint: str) -> list[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    names: list[str] = []
    for ck in inspector.get_check_constraints(table_name):
        cname = ck.get("name")
        sqltext = ck.get("sqltext") or ""
        if cname and (column_hint in cname or column_hint in sqltext):
            names.append(cname)
    return names


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    missed_ck_names = _find_check_constraints("jobs", "missed_run_policy")
    overlap_ck_names = _find_check_constraints("jobs", "overlap_policy")

    if dialect == "sqlite":
        with op.batch_alter_table("jobs") as batch_op:
            for cname in missed_ck_names:
                batch_op.drop_constraint(op.f(cname), type_="check")
            for cname in overlap_ck_names:
                batch_op.drop_constraint(op.f(cname), type_="check")
            batch_op.add_column(
                sa.Column(
                    "pending_policy",
                    sa.String(length=20),
                    nullable=False,
                    server_default="fail",
                )
            )
            batch_op.add_column(sa.Column("max_runtime_minutes", sa.Integer(), nullable=True))
            batch_op.add_column(
                sa.Column(
                    "missed_run_notify",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.text("false"),
                )
            )
            batch_op.add_column(
                sa.Column(
                    "overlap_notify",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.text("false"),
                )
            )
            batch_op.add_column(
                sa.Column(
                    "pending_notify",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.text("false"),
                )
            )
            batch_op.add_column(
                sa.Column(
                    "max_runtime_notify",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.text("false"),
                )
            )
            batch_op.create_check_constraint(
                op.f("ck_jobs_ck_jobs_missed_run_policy"),
                "missed_run_policy IN ('skip', 'run_once', 'fail')",
            )
            batch_op.create_check_constraint(
                op.f("ck_jobs_ck_jobs_overlap_policy"),
                "overlap_policy IN ('skip', 'allow', 'cancel_previous', 'queue', 'fail')",
            )
            batch_op.create_check_constraint(
                op.f("ck_jobs_ck_jobs_pending_policy"),
                "pending_policy IN ('fail', 'retry')",
            )
    else:
        for cname in missed_ck_names:
            op.drop_constraint(op.f(cname), "jobs", type_="check")
        for cname in overlap_ck_names:
            op.drop_constraint(op.f(cname), "jobs", type_="check")
        op.add_column(
            "jobs",
            sa.Column(
                "pending_policy",
                sa.String(length=20),
                nullable=False,
                server_default="fail",
            ),
        )
        op.add_column("jobs", sa.Column("max_runtime_minutes", sa.Integer(), nullable=True))
        op.add_column(
            "jobs",
            sa.Column(
                "missed_run_notify",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
        )
        op.add_column(
            "jobs",
            sa.Column(
                "overlap_notify",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
        )
        op.add_column(
            "jobs",
            sa.Column(
                "pending_notify",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
        )
        op.add_column(
            "jobs",
            sa.Column(
                "max_runtime_notify",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
        )
        op.create_check_constraint(
            op.f("ck_jobs_ck_jobs_missed_run_policy"),
            "jobs",
            "missed_run_policy IN ('skip', 'run_once', 'fail')",
        )
        op.create_check_constraint(
            op.f("ck_jobs_ck_jobs_overlap_policy"),
            "jobs",
            "overlap_policy IN ('skip', 'allow', 'cancel_previous', 'queue', 'fail')",
        )
        op.create_check_constraint(
            op.f("ck_jobs_ck_jobs_pending_policy"),
            "jobs",
            "pending_policy IN ('fail', 'retry')",
        )

    op.drop_index("ix_job_runs_one_active_per_job", table_name="job_runs")
    op.create_index(
        "ix_job_runs_one_active_per_job",
        "job_runs",
        ["job_id"],
        unique=False,
        postgresql_where=_ACTIVE_RUN_WHERE,
        sqlite_where=_ACTIVE_RUN_WHERE,
    )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    op.drop_index("ix_job_runs_one_active_per_job", table_name="job_runs")
    op.create_index(
        "ix_job_runs_one_active_per_job",
        "job_runs",
        ["job_id"],
        unique=True,
        postgresql_where=_ACTIVE_RUN_WHERE,
        sqlite_where=_ACTIVE_RUN_WHERE,
    )

    missed_ck_names = _find_check_constraints("jobs", "missed_run_policy")
    overlap_ck_names = _find_check_constraints("jobs", "overlap_policy")
    pending_ck_names = _find_check_constraints("jobs", "pending_policy")

    if dialect == "sqlite":
        with op.batch_alter_table("jobs") as batch_op:
            for cname in missed_ck_names:
                batch_op.drop_constraint(op.f(cname), type_="check")
            for cname in overlap_ck_names:
                batch_op.drop_constraint(op.f(cname), type_="check")
            for cname in pending_ck_names:
                batch_op.drop_constraint(op.f(cname), type_="check")
            batch_op.drop_column("max_runtime_notify")
            batch_op.drop_column("pending_notify")
            batch_op.drop_column("overlap_notify")
            batch_op.drop_column("missed_run_notify")
            batch_op.drop_column("max_runtime_minutes")
            batch_op.drop_column("pending_policy")
            batch_op.create_check_constraint(
                op.f("ck_jobs_ck_jobs_missed_run_policy"),
                "missed_run_policy IN ('skip', 'run_once')",
            )
            batch_op.create_check_constraint(
                op.f("ck_jobs_ck_jobs_overlap_policy"),
                "overlap_policy IN ('skip', 'queue', 'fail')",
            )
    else:
        for cname in missed_ck_names:
            op.drop_constraint(op.f(cname), "jobs", type_="check")
        for cname in overlap_ck_names:
            op.drop_constraint(op.f(cname), "jobs", type_="check")
        for cname in pending_ck_names:
            op.drop_constraint(op.f(cname), "jobs", type_="check")
        op.drop_column("jobs", "max_runtime_notify")
        op.drop_column("jobs", "pending_notify")
        op.drop_column("jobs", "overlap_notify")
        op.drop_column("jobs", "missed_run_notify")
        op.drop_column("jobs", "max_runtime_minutes")
        op.drop_column("jobs", "pending_policy")
        op.create_check_constraint(
            op.f("ck_jobs_ck_jobs_missed_run_policy"),
            "jobs",
            "missed_run_policy IN ('skip', 'run_once')",
        )
        op.create_check_constraint(
            op.f("ck_jobs_ck_jobs_overlap_policy"),
            "jobs",
            "overlap_policy IN ('skip', 'queue', 'fail')",
        )
