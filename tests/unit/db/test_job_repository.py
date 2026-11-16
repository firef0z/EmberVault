"""Unit tests for JobRepository (Milestone M1.3)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.base import Base
from embervault_db.models.execution import JobRun
from embervault_db.repositories.job_repository import JobRepository
from embervault_db.repositories.remote_repository import RemoteRepository


@pytest.fixture
def db_session() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "test_encryption_key_32_characters_"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_create_and_get_job(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-local", "local", {"path": "/data/src"})
        r2 = RemoteRepository.create_remote(session, "dst-local", "local", {"path": "/data/dst"})
        session.commit()
        r1_id, r2_id = r1.id, r2.id

    with db_session() as session:
        job = JobRepository.create_job(
            session=session,
            name="daily-sync",
            source_remote_id=r1_id,
            source_path="/photos",
            destination_remote_id=r2_id,
            destination_path="/photos-backup",
            operation="sync",
            parallelization="by_subfolder",
            schedule_cron="0 2 * * *",
            max_parallel_tasks=4,
        )
        session.commit()
        job_id = job.id

    with db_session() as session:
        loaded = JobRepository.get_job_by_id(session, job_id)
        assert loaded is not None
        assert loaded.name == "daily-sync"
        assert loaded.operation == "sync"
        assert loaded.parallelization == "by_subfolder"
        assert loaded.source_remote_id == r1_id
        assert loaded.destination_remote_id == r2_id
        assert loaded.max_parallel_tasks == 4
        assert loaded.schedule_cron == "0 2 * * *"
        assert loaded.next_run_at is not None
        assert loaded.next_run_at.hour == 2
        assert loaded.enabled is True

        by_name = JobRepository.get_job_by_name(session, "daily-sync")
        assert by_name is not None
        assert by_name.id == job_id


def test_job_validation_errors(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-local", "local", {"path": "/data/src"})
        session.commit()
        r1_id = r1.id

    # Same source and destination path on same remote
    with db_session() as session, pytest.raises(ValueError, match="coincidere"):
        JobRepository.create_job(
            session=session,
            name="invalid-job",
            source_remote_id=r1_id,
            source_path="/data",
            destination_remote_id=r1_id,
            destination_path="/data",
        )

    # Invalid operation
    with db_session() as session, pytest.raises(ValueError, match="Operazione non supportata"):
        JobRepository.create_job(
            session=session,
            name="invalid-job-op",
            source_remote_id=r1_id,
            source_path="/data1",
            destination_remote_id=r1_id,
            destination_path="/data2",
            operation="delete_all",
        )


def test_update_and_delete_job(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "local-a", "local", {"path": "/a"})
        r2 = RemoteRepository.create_remote(session, "local-b", "local", {"path": "/b"})
        session.commit()
        r1_id, r2_id = r1.id, r2.id

    with db_session() as session:
        job = JobRepository.create_job(
            session=session,
            name="job-to-edit",
            source_remote_id=r1_id,
            source_path="/a",
            destination_remote_id=r2_id,
            destination_path="/b",
        )
        session.commit()
        job_id = job.id

    # Update job
    with db_session() as session:
        updated = JobRepository.update_job(
            session=session,
            job_id=job_id,
            name="job-edited",
            operation="sync",
            is_enabled=False,
        )
        session.commit()
        assert updated.name == "job-edited"
        assert updated.operation == "sync"
        assert updated.enabled is False

    # Block deletion if run in progress
    with db_session() as session:
        run = JobRun(
            id=uuid.uuid4(),
            job_id=job_id,
            trigger="manual",
            status="running",
        )
        session.add(run)
        session.commit()

        ok, err = JobRepository.delete_job(session, job_id)
        assert ok is False
        assert "esecuzione" in (err or "").lower()

        # Mark run finished
        run.status = "succeeded"
        session.commit()

        ok, err = JobRepository.delete_job(session, job_id)
        assert ok is True
        assert err is None

        deleted = JobRepository.get_job_by_id(session, job_id)
        assert deleted is None


def test_discovery_recording(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "local-disc", "local", {"path": "/disc"})
        session.commit()
        r1_id = r1.id

    with db_session() as session:
        disc = JobRepository.record_discovery(
            session=session,
            source_remote_id=r1_id,
            source_path="/root",
            subfolders=["a", "b", "c"],
            root_file_count=5,
            trigger="job_form",
        )
        session.commit()
        disc_id = disc.id

    with db_session() as session:
        loaded = JobRepository.get_discovery_by_id(session, disc_id)
        assert loaded is not None
        assert loaded.folder_count == 3
        assert loaded.root_file_count == 5
        assert loaded.task_count_estimate == 4
        assert loaded.level == "ok"
        assert loaded.entries == {"subfolders": ["a", "b", "c"], "root_file_count": 5}


def test_job_assigned_proxies_db(db_session: sessionmaker[Session]) -> None:
    from embervault_db.models.proxy import Proxy
    from embervault_db.repositories.proxy_repository import ProxyRepository

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-repo", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-repo", "local", {"path": "/dst"})
        p1 = Proxy(
            id=uuid.uuid4(),
            name="p-net-1",
            host="192.168.1.10",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("x" * 32, uuid.uuid4()),
            cert_fingerprint_sha256="11" * 32,
            is_enabled=True,
            reachable_remotes=[r1, r2],
        )
        p2 = Proxy(
            id=uuid.uuid4(),
            name="p-net-2",
            host="192.168.2.10",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("y" * 32, uuid.uuid4()),
            cert_fingerprint_sha256="22" * 32,
            is_enabled=True,
            reachable_remotes=[r1, r2],
        )
        session.add_all([p1, p2])
        session.commit()
        r1_id, r2_id, p1_id, p2_id = r1.id, r2.id, p1.id, p2.id

    # 1. Create with assigned proxies
    with db_session() as session:
        job = JobRepository.create_job(
            session=session,
            name="segregated-job",
            source_remote_id=r1_id,
            source_path="/net",
            destination_remote_id=r2_id,
            destination_path="/net-backup",
            assigned_proxy_ids=[p1_id],
        )
        session.commit()
        job_id = job.id

    with db_session() as session:
        loaded = JobRepository.get_job_by_id(session, job_id)
        assert loaded is not None
        assert len(loaded.assigned_proxies) == 1
        assert loaded.assigned_proxies[0].id == p1_id

    # 2. Update to assign p1 and p2
    with db_session() as session:
        JobRepository.update_job(
            session=session,
            job_id=job_id,
            assigned_proxy_ids=[p1_id, p2_id],
        )
        session.commit()

    with db_session() as session:
        loaded = JobRepository.get_job_by_id(session, job_id)
        assert loaded is not None
        assert {p.id for p in loaded.assigned_proxies} == {p1_id, p2_id}

    # 3. Clear assigned proxies
    with db_session() as session:
        JobRepository.update_job(
            session=session,
            job_id=job_id,
            assigned_proxy_ids=[],
        )
        session.commit()

    with db_session() as session:
        loaded = JobRepository.get_job_by_id(session, job_id)
        assert loaded is not None
        assert len(loaded.assigned_proxies) == 0

    # 4. Error on non-existent proxy ID
    with db_session() as session, pytest.raises(ValueError, match="Proxy con ID"):
        JobRepository.create_job(
            session=session,
            name="invalid-proxy-job",
            source_remote_id=r1_id,
            source_path="/a",
            destination_remote_id=r2_id,
            destination_path="/b",
            assigned_proxy_ids=[uuid.uuid4()],
        )


def test_job_timezone_and_follow_dst_persistence(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "tz-src", "local", {"path": "/tz/src"})
        r2 = RemoteRepository.create_remote(session, "tz-dst", "local", {"path": "/tz/dst"})
        session.commit()
        r1_id, r2_id = r1.id, r2.id

    with db_session() as session:
        job = JobRepository.create_job(
            session=session,
            name="tz-job",
            source_remote_id=r1_id,
            source_path="/src",
            destination_remote_id=r2_id,
            destination_path="/dst",
            schedule_cron="0 1 * * *",
            timezone="Europe/Rome",
            follow_dst=True,
        )
        session.commit()
        job_id = job.id
        assert job.timezone == "Europe/Rome"
        assert job.follow_dst is True
        assert job.next_run_at is not None

    with db_session() as session:
        updated = JobRepository.update_job(
            session=session,
            job_id=job_id,
            timezone="America/New_York",
            follow_dst=False,
        )
        session.commit()
        assert updated.timezone == "America/New_York"
        assert updated.follow_dst is False

    with db_session() as session, pytest.raises(ValueError, match="Timezone non valida"):
        JobRepository.create_job(
            session=session,
            name="bad-tz-job",
            source_remote_id=r1_id,
            source_path="/src",
            destination_remote_id=r2_id,
            destination_path="/dst",
            timezone="Mars/Olympus_Mons",
        )
