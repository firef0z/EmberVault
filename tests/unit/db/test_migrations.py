"""Tests for Alembic schema migrations upgrade and downgrade."""

import contextlib
import importlib
import io
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect

from embervault_db.cli import run_downgrade, run_migrations
from embervault_db.models import metadata
from embervault_db.session import create_engine_from_url

EXPECTED_TABLES = frozenset(
    {
        "roles",
        "permissions",
        "role_permissions",
        "users",
        "user_sessions",
        "user_mfa_factors",
        "user_recovery_codes",
        "audit_log",
        "settings",
        "rclone_remotes",
        "jobs",
        "job_sources",
        "job_discoveries",
        "proxies",
        "proxy_status",
        "proxy_state_events",
        "job_runs",
        "tasks",
        "task_assignments",
        "task_logs",
        "error_events",
    }
)


def test_migration_upgrade_and_downgrade_cycle() -> None:
    """Test that upgrade head creates all tables and downgrade base drops them cleanly."""
    with tempfile.NamedTemporaryFile("w", suffix=".db", delete=False) as f:
        db_path = f.name

    db_url = f"sqlite:///{Path(db_path).as_posix()}"

    try:
        # 1. Upgrade to head
        run_migrations(db_url=db_url, revision="head")

        engine = create_engine_from_url(db_url)
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())

        assert EXPECTED_TABLES.issubset(tables), (
            f"Missing tables after upgrade head: {EXPECTED_TABLES - tables}"
        )

        # 2. Downgrade to base
        run_downgrade(db_url=db_url, revision="base")

        inspector_after_down = inspect(engine)
        remaining_tables = set(inspector_after_down.get_table_names()) - {"alembic_version"}
        assert not remaining_tables, f"Tables remained after downgrade base: {remaining_tables}"

        # 3. Upgrade back to head (idempotent re-run)
        run_migrations(db_url=db_url, revision="head")
        inspector_reup = inspect(engine)
        reup_tables = set(inspector_reup.get_table_names())
        assert EXPECTED_TABLES.issubset(reup_tables)

        engine.dispose()
    finally:
        if "engine" in locals():
            engine.dispose()
        with contextlib.suppress(OSError):
            Path(db_path).unlink(missing_ok=True)


def test_migration_0020_postgresql_ddl_avoids_double_constraint_prefix() -> None:
    """Verify 0020 upgrade/downgrade emits exact constraint names on PostgreSQL."""
    mod = importlib.import_module("embervault_db.migrations.versions.0020_add_job_run_policies")

    for is_downgrade in (False, True):
        buf = io.StringIO()
        mock_engine = sa.create_mock_engine("postgresql+psycopg://", lambda *_a, **_kw: None)
        ctx = MigrationContext.configure(
            connection=mock_engine,
            opts={"target_metadata": metadata, "as_sql": True, "output_buffer": buf},
        )
        fake_inspector = MagicMock()
        fake_inspector.get_check_constraints.return_value = [
            {
                "name": "ck_jobs_ck_jobs_missed_run_policy",
                "sqltext": "missed_run_policy IN ('skip', 'run_once')",
            },
            {
                "name": "ck_jobs_ck_jobs_overlap_policy",
                "sqltext": "overlap_policy IN ('skip', 'queue', 'fail')",
            },
            {
                "name": "ck_jobs_ck_jobs_pending_policy",
                "sqltext": "pending_policy IN ('fail', 'retry')",
            },
        ]

        with Operations.context(ctx), patch.object(sa, "inspect", return_value=fake_inspector):
            if is_downgrade:
                mod.downgrade()
            else:
                mod.upgrade()

        joined_sql = buf.getvalue()
        assert "ck_jobs_ck_jobs_ck_jobs_" not in joined_sql
        assert "DROP CONSTRAINT ck_jobs_ck_jobs_missed_run_policy" in joined_sql
        assert "DROP CONSTRAINT ck_jobs_ck_jobs_overlap_policy" in joined_sql
        assert "ADD CONSTRAINT ck_jobs_ck_jobs_missed_run_policy CHECK" in joined_sql
        assert "ADD CONSTRAINT ck_jobs_ck_jobs_overlap_policy CHECK" in joined_sql
        if is_downgrade:
            assert "DROP CONSTRAINT ck_jobs_ck_jobs_pending_policy" in joined_sql
        else:
            assert "ADD CONSTRAINT ck_jobs_ck_jobs_pending_policy CHECK" in joined_sql


def test_migration_0019_to_0020_upgrade_and_downgrade_cycle() -> None:
    """Test incremental 0019 -> 0020 -> 0019 -> 0020 migration preserves constraint names."""
    with tempfile.NamedTemporaryFile("w", suffix=".db", delete=False) as f:
        db_path = f.name

    db_url = f"sqlite:///{Path(db_path).as_posix()}"

    try:
        run_migrations(db_url=db_url, revision="0019")
        run_migrations(db_url=db_url, revision="head")

        engine = create_engine_from_url(db_url)
        inspector = inspect(engine)
        ck_names = {ck["name"] for ck in inspector.get_check_constraints("jobs")}
        assert "ck_jobs_ck_jobs_missed_run_policy" in ck_names
        assert "ck_jobs_ck_jobs_overlap_policy" in ck_names
        assert "ck_jobs_ck_jobs_pending_policy" in ck_names
        assert not any(name and name.startswith("ck_jobs_ck_jobs_ck_jobs_") for name in ck_names)

        run_downgrade(db_url=db_url, revision="0019")
        inspector_down = inspect(sa.create_engine(db_url))
        ck_names_down = {ck["name"] for ck in inspector_down.get_check_constraints("jobs")}
        assert "ck_jobs_ck_jobs_missed_run_policy" in ck_names_down
        assert "ck_jobs_ck_jobs_overlap_policy" in ck_names_down
        assert "ck_jobs_ck_jobs_pending_policy" not in ck_names_down
        inspector_down.bind.dispose()

        run_migrations(db_url=db_url, revision="head")
    finally:
        if "engine" in locals():
            engine.dispose()
        with contextlib.suppress(OSError):
            Path(db_path).unlink(missing_ok=True)
