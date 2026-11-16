"""Database migration and seed CLI commands for EmberVault."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from alembic import command
from alembic.config import Config

from embervault_common.config import DatabaseSettings
from embervault_db.seed import seed_initial_data
from embervault_db.session import create_engine_from_url, create_session_factory, get_session


def get_alembic_config(db_url: str | None = None) -> Config:
    """Create Alembic Config pointing to embervault_db migrations directory."""
    pkg_dir = Path(__file__).resolve().parent
    ini_path = pkg_dir.parent.parent / "alembic.ini"
    migrations_dir = pkg_dir / "migrations"

    alembic_cfg = Config(str(ini_path))
    alembic_cfg.set_main_option("script_location", str(migrations_dir))
    alembic_cfg.set_main_option("version_locations", str(migrations_dir / "versions"))

    if db_url is None:
        try:
            db_url = DatabaseSettings.load().resolved_database_url
        except Exception:
            db_url = "postgresql+psycopg://embervault:secret@postgres:5432/embervault"

    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    return alembic_cfg


def run_migrations(db_url: str | None = None, revision: str = "head") -> None:
    """Run Alembic database upgrade to the specified revision."""
    cfg = get_alembic_config(db_url)
    command.upgrade(cfg, revision)


def run_downgrade(db_url: str | None = None, revision: str = "base") -> None:
    """Run Alembic database downgrade to the specified revision."""
    cfg = get_alembic_config(db_url)
    command.downgrade(cfg, revision)


def run_seed(db_url: str | None = None) -> None:
    """Run idempotent initial data seeding and abort stale running runs."""
    if db_url is None:
        db_url = DatabaseSettings.load().resolved_database_url
    engine = create_engine_from_url(db_url)
    factory = create_session_factory(engine)
    with get_session(factory) as session:
        seed_initial_data(session)
        from embervault_db.repositories.execution_repository import ExecutionRepository

        aborted = ExecutionRepository.abort_stale_running_runs_on_startup(session)
        if aborted:
            session.commit()


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for database migrations and seeding."""
    parser = argparse.ArgumentParser(description="EmberVault Database Migration Utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # upgrade
    upgrade_parser = subparsers.add_parser("upgrade", help="Run database migrations")
    upgrade_parser.add_argument(
        "--revision", default="head", help="Target revision (default: head)"
    )
    upgrade_parser.add_argument("--url", default=None, help="Database connection URL")

    # downgrade
    downgrade_parser = subparsers.add_parser("downgrade", help="Downgrade database")
    downgrade_parser.add_argument(
        "--revision", default="base", help="Target revision (default: base)"
    )
    downgrade_parser.add_argument("--url", default=None, help="Database connection URL")

    # seed
    seed_parser = subparsers.add_parser("seed", help="Seed default roles and permissions")
    seed_parser.add_argument("--url", default=None, help="Database connection URL")

    # all (upgrade head + seed)
    all_parser = subparsers.add_parser(
        "all", help="Run migrations to head followed by idempotent seed"
    )
    all_parser.add_argument("--url", default=None, help="Database connection URL")

    args = parser.parse_args(argv)

    try:
        if args.command == "upgrade":
            run_migrations(db_url=args.url, revision=args.revision)
        elif args.command == "downgrade":
            run_downgrade(db_url=args.url, revision=args.revision)
        elif args.command == "seed":
            run_seed(db_url=args.url)
        elif args.command == "all":
            run_migrations(db_url=args.url, revision="head")
            run_seed(db_url=args.url)
        return 0
    except Exception as e:
        sys.stderr.write(f"Migration error: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
