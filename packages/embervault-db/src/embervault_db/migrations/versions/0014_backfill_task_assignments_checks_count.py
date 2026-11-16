"""0014_backfill_task_assignments_checks_count

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-29 22:45:00.000000

"""

from collections.abc import Sequence
import re

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    try:
        rows = bind.execute(
            sa.text(
                "SELECT tl.assignment_id, tl.message "
                "FROM task_logs tl "
                "JOIN task_assignments ta ON tl.assignment_id = ta.id "
                "WHERE ta.checks_count = 0 AND tl.message LIKE '%Checks:%' "
                "ORDER BY tl.assignment_id, tl.seq ASC"
            )
        ).fetchall()

        checks_re = re.compile(r"Checks:\s*(\d+)\s*/")
        asgn_max_checks: dict[str, int] = {}
        for asgn_id, msg in rows:
            m = checks_re.search(str(msg))
            if m:
                c_val = int(m.group(1))
                str_id = str(asgn_id)
                if c_val > asgn_max_checks.get(str_id, 0):
                    asgn_max_checks[str_id] = c_val

        for asgn_id, count in asgn_max_checks.items():
            bind.execute(
                sa.text("UPDATE task_assignments SET checks_count = :count WHERE id = :id"),
                {"count": count, "id": asgn_id},
            )
    except Exception:
        pass


def downgrade() -> None:
    pass
