"""Tests for SQLAlchemy models, constraints, and relationships."""

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from embervault_db.models import (
    Base,
    Job,
    JobRun,
    JobSource,
    RcloneRemote,
    Role,
    User,
)
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.session import create_engine_from_url, create_session_factory, get_session


@pytest.fixture
def db_session_factory() -> sessionmaker[Session]:
    """Create in-memory SQLite engine with tables."""
    engine = create_engine_from_url("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return create_session_factory(engine)


def test_user_creation_and_role_relationship(
    db_session_factory: sessionmaker[Session],
) -> None:
    """Test user creation with foreign key and role relationship."""
    with get_session(db_session_factory) as session:
        role = Role(name="operator", is_system=True)
        session.add(role)
        session.flush()

        user = User(
            username="operator1",
            role_id=role.id,
            auth_source="local",
        )
        session.add(user)
        session.flush()

        assert user.role.name == "operator"
        assert role.users[0].username == "operator1"


def test_job_and_rclone_remotes(db_session_factory: sessionmaker[Session]) -> None:
    """Test creating RcloneRemote and associated Job."""
    with get_session(db_session_factory) as session:
        src = RcloneRemote(
            name="local_src",
            backend_type="local",
            config_encrypted=b"encrypted_src_blob",
        )
        dst = RcloneRemote(
            name="s3_dst",
            backend_type="s3",
            config_encrypted=b"encrypted_dst_blob",
        )
        session.add_all([src, dst])
        session.flush()

        job = Job(
            name="daily_backup",
            source_remote_id=src.id,
            source_path="/data/important",
            destination_remote_id=dst.id,
            destination_path="backups/daily",
            source_kind="folder",
            operation="copy",
            parallelization="none",
        )
        session.add(job)
        session.flush()

        assert job.source_remote.name == "local_src"
        assert job.destination_remote.name == "s3_dst"


def test_job_cascade_delete(db_session_factory: sessionmaker[Session]) -> None:
    """Test that deleting a Job cascades to JobSource and JobRun."""
    with get_session(db_session_factory) as session:
        src = RcloneRemote(name="src2", backend_type="local", config_encrypted=b"blob")
        dst = RcloneRemote(name="dst2", backend_type="local", config_encrypted=b"blob")
        session.add_all([src, dst])
        session.flush()

        job = Job(
            name="temp_job",
            source_remote_id=src.id,
            source_path="/src",
            destination_remote_id=dst.id,
            destination_path="/dst",
        )
        session.add(job)
        session.flush()

        source = JobSource(job_id=job.id, kind="dir", path="/src")
        run = JobRun(job_id=job.id, trigger="manual", status="succeeded")
        session.add_all([source, run])
        session.flush()

        # Delete job
        session.delete(job)
        session.flush()

        # Verify sources and runs are deleted
        assert session.get(JobSource, source.id) is None
        assert session.get(JobRun, run.id) is None


def test_partial_unique_index_active_job_run(
    db_session_factory: sessionmaker[Session],
) -> None:
    """Test active job run concurrency: overlap_policy='skip' blocks while 'allow' permits multiple active runs."""
    with get_session(db_session_factory) as session:
        src = RcloneRemote(name="src3", backend_type="local", config_encrypted=b"blob")
        dst = RcloneRemote(name="dst3", backend_type="local", config_encrypted=b"blob")
        session.add_all([src, dst])
        session.flush()

        job = Job(
            name="concurrency_job",
            source_remote_id=src.id,
            source_path="/src",
            destination_remote_id=dst.id,
            destination_path="/dst",
            overlap_policy="skip",
        )
        session.add(job)
        session.flush()

        # First active run succeeds
        run1 = ExecutionRepository.create_job_run(session, job.id, trigger="manual")
        assert run1.id is not None

        # Second active run while overlap_policy='skip' raises ValueError
        with pytest.raises(ValueError, match="overlap policy 'skip'"):
            ExecutionRepository.create_job_run(session, job.id, trigger="manual")

        # Switching to overlap_policy='allow' permits concurrent active runs in DB
        job.overlap_policy = "allow"
        session.flush()
        run2 = ExecutionRepository.create_job_run(session, job.id, trigger="manual")
        assert run2.id is not None
        assert run2.id != run1.id
        assert len(ExecutionRepository.get_active_runs_for_job(session, job.id)) == 2

        # Terminal run (succeeded) alongside active runs is permitted
        run3 = JobRun(job_id=job.id, trigger="manual", status="succeeded")
        session.add(run3)
        session.flush()
        assert run3.id is not None
