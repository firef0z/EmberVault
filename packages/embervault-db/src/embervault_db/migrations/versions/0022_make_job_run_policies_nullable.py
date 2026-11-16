"""0022_make_job_run_policies_nullable

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-14 18:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


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
    pending_ck_names = _find_check_constraints("jobs", "pending_policy")

    if dialect == "sqlite":
        with op.batch_alter_table("jobs") as batch_op:
            for cname in missed_ck_names:
                batch_op.drop_constraint(op.f(cname), type_="check")
            for cname in overlap_ck_names:
                batch_op.drop_constraint(op.f(cname), type_="check")
            for cname in pending_ck_names:
                batch_op.drop_constraint(op.f(cname), type_="check")

            batch_op.alter_column(
                "missed_run_policy",
                existing_type=sa.String(length=20),
                nullable=True,
            )
            batch_op.alter_column(
                "overlap_policy",
                existing_type=sa.String(length=20),
                nullable=True,
            )
            batch_op.alter_column(
                "pending_policy",
                existing_type=sa.String(length=20),
                nullable=True,
                server_default=None,
            )
            batch_op.create_check_constraint(
                op.f("ck_jobs_ck_jobs_missed_run_policy"),
                "missed_run_policy IS NULL OR missed_run_policy IN ('skip', 'run_once', 'fail')",
            )
            batch_op.create_check_constraint(
                op.f("ck_jobs_ck_jobs_overlap_policy"),
                "overlap_policy IS NULL OR overlap_policy IN ('skip', 'allow', 'cancel_previous', 'queue', 'fail')",
            )
            batch_op.create_check_constraint(
                op.f("ck_jobs_ck_jobs_pending_policy"),
                "pending_policy IS NULL OR pending_policy IN ('fail', 'retry')",
            )
    else:
        for cname in missed_ck_names:
            op.drop_constraint(op.f(cname), "jobs", type_="check")
        for cname in overlap_ck_names:
            op.drop_constraint(op.f(cname), "jobs", type_="check")
        for cname in pending_ck_names:
            op.drop_constraint(op.f(cname), "jobs", type_="check")

        op.alter_column(
            "jobs",
            "missed_run_policy",
            existing_type=sa.String(length=20),
            nullable=True,
        )
        op.alter_column(
            "jobs",
            "overlap_policy",
            existing_type=sa.String(length=20),
            nullable=True,
        )
        op.alter_column(
            "jobs",
            "pending_policy",
            existing_type=sa.String(length=20),
            nullable=True,
            server_default=None,
        )
        op.create_check_constraint(
            op.f("ck_jobs_ck_jobs_missed_run_policy"),
            "jobs",
            "missed_run_policy IS NULL OR missed_run_policy IN ('skip', 'run_once', 'fail')",
        )
        op.create_check_constraint(
            op.f("ck_jobs_ck_jobs_overlap_policy"),
            "jobs",
            "overlap_policy IS NULL OR overlap_policy IN ('skip', 'allow', 'cancel_previous', 'queue', 'fail')",
        )
        op.create_check_constraint(
            op.f("ck_jobs_ck_jobs_pending_policy"),
            "jobs",
            "pending_policy IS NULL OR pending_policy IN ('fail', 'retry')",
        )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    op.execute("UPDATE jobs SET missed_run_policy = 'run_once' WHERE missed_run_policy IS NULL")
    op.execute("UPDATE jobs SET overlap_policy = 'skip' WHERE overlap_policy IS NULL")
    op.execute("UPDATE jobs SET pending_policy = 'fail' WHERE pending_policy IS NULL")

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

            batch_op.alter_column(
                "missed_run_policy",
                existing_type=sa.String(length=20),
                nullable=False,
                server_default="run_once",
            )
            batch_op.alter_column(
                "overlap_policy",
                existing_type=sa.String(length=20),
                nullable=False,
                server_default="skip",
            )
            batch_op.alter_column(
                "pending_policy",
                existing_type=sa.String(length=20),
                nullable=False,
                server_default="fail",
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
        for cname in pending_ck_names:
            op.drop_constraint(op.f(cname), "jobs", type_="check")

        op.alter_column(
            "jobs",
            "missed_run_policy",
            existing_type=sa.String(length=20),
            nullable=False,
            server_default="run_once",
        )
        op.alter_column(
            "jobs",
            "overlap_policy",
            existing_type=sa.String(length=20),
            nullable=False,
            server_default="skip",
        )
        op.alter_column(
            "jobs",
            "pending_policy",
            existing_type=sa.String(length=20),
            nullable=False,
            server_default="fail",
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
