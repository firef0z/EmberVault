"""Unit tests for RemoteRepository with envelope encryption."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.base import Base
from embervault_db.models.remotes import Job
from embervault_db.repositories.remote_repository import RemoteRepository


@pytest.fixture
def db_session() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "test_encryption_key_32_characters_"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_create_and_decrypt_remote(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        remote = RemoteRepository.create_remote(
            session=session,
            name="aws-backup-s3",
            backend_type="s3",
            raw_config={
                "provider": "AWS",
                "region": "eu-central-1",
                "access_key_id": "AKIA1234567890",
                "secret_access_key": "SECRET_KEY_ABCDEF12345",
            },
        )
        session.commit()
        remote_id = remote.id

    with db_session() as session:
        loaded = RemoteRepository.get_remote_by_id(session, remote_id)
        assert loaded is not None
        assert loaded.name == "aws-backup-s3"
        assert loaded.backend_type == "s3"
        assert loaded.version == 1
        assert "access_key_id" in loaded.secret_field_names
        assert "secret_access_key" in loaded.secret_field_names

        # Decrypted full config has secrets intact
        full = RemoteRepository.get_decrypted_config(loaded)
        assert full["access_key_id"] == "AKIA1234567890"
        assert full["secret_access_key"] == "SECRET_KEY_ABCDEF12345"
        assert full["region"] == "eu-central-1"

        # Masked config hides secrets
        masked = RemoteRepository.get_masked_config(loaded)
        assert masked["access_key_id"] == "***"
        assert masked["secret_access_key"] == "***"
        assert masked["region"] == "eu-central-1"


def test_unique_name_constraint(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        RemoteRepository.create_remote(
            session=session,
            name="sftp-primary",
            backend_type="sftp",
            raw_config={"host": "1.1.1.1", "user": "root", "pass": "secret"},
        )
        session.commit()

        with pytest.raises(ValueError, match="esiste già"):
            RemoteRepository.create_remote(
                session=session,
                name="sftp-primary",
                backend_type="sftp",
                raw_config={"host": "2.2.2.2", "user": "admin", "pass": "other"},
            )


def test_update_remote_preserving_masked_secrets(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        remote = RemoteRepository.create_remote(
            session=session,
            name="b2-archive",
            backend_type="b2",
            raw_config={
                "account": "ACCOUNT_SECRET_123",
                "key": "KEY_SECRET_456",
                "hard_delete": False,
            },
        )
        session.commit()
        remote_id = remote.id

    # Update without re-entering secrets (submitting '***')
    with db_session() as session:
        updated = RemoteRepository.update_remote(
            session=session,
            remote_id=remote_id,
            name="b2-archive-renamed",
            raw_config={
                "account": "***",
                "key": "***",
                "hard_delete": True,
            },
        )
        session.commit()
        assert updated.version == 2
        assert updated.name == "b2-archive-renamed"

        # Secrets preserved from previous config!
        decrypted = RemoteRepository.get_decrypted_config(updated)
        assert decrypted["account"] == "ACCOUNT_SECRET_123"
        assert decrypted["key"] == "KEY_SECRET_456"
        assert decrypted["hard_delete"] is True


def test_delete_remote_with_referencing_job_blocked(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        src = RemoteRepository.create_remote(
            session=session,
            name="src-local",
            backend_type="local",
            raw_config={},
        )
        dst = RemoteRepository.create_remote(
            session=session,
            name="dst-s3",
            backend_type="s3",
            raw_config={
                "provider": "AWS",
                "access_key_id": "K1",
                "secret_access_key": "K2",
            },
        )
        job = Job(
            id=uuid.uuid4(),
            name="daily-sync",
            source_remote_id=src.id,
            source_path="/data",
            destination_remote_id=dst.id,
            destination_path="/backup",
        )
        session.add(job)
        session.commit()
        src_id = src.id

    with db_session() as session:
        ok, err = RemoteRepository.delete_remote(session, src_id)
        assert ok is False
        assert err is not None
        assert "è attualmente utilizzato dal job 'daily-sync'" in err

    # Remove referencing job, add a JobDiscovery referencing src_id, and delete succeeds
    with db_session() as session:
        from embervault_db.models.remotes import JobDiscovery

        session.query(Job).delete()
        discovery = JobDiscovery(
            id=uuid.uuid4(),
            job_id=None,
            source_remote_id=src_id,
            source_remote_version=1,
            source_path="/data",
            trigger="manual",
            status="succeeded",
        )
        session.add(discovery)
        session.commit()

        ok, err = RemoteRepository.delete_remote(session, src_id)
        assert ok is True
        assert err is None
        # Verify discovery was also cleaned up
        remaining_disc = session.get(JobDiscovery, discovery.id)
        assert remaining_disc is None


def test_remote_roles_and_visibility(db_session: sessionmaker[Session]) -> None:
    from embervault_db.models.auth import Role, User

    with db_session() as session:
        admin_role = Role(id=uuid.uuid4(), name="Administrator", is_system=True)
        operator_role = Role(id=uuid.uuid4(), name="Operator", is_system=True)
        viewer_role = Role(id=uuid.uuid4(), name="Viewer", is_system=True)
        session.add_all([admin_role, operator_role, viewer_role])
        session.commit()

        admin_user = User(
            id=uuid.uuid4(), username="admin", email="admin@local", role_id=admin_role.id
        )
        operator_user = User(
            id=uuid.uuid4(), username="op", email="op@local", role_id=operator_role.id
        )
        viewer_user = User(
            id=uuid.uuid4(), username="view", email="view@local", role_id=viewer_role.id
        )
        session.add_all([admin_user, operator_user, viewer_user])
        session.commit()

        # Remote 1: visible to all roles by default
        r1 = RemoteRepository.create_remote(
            session=session,
            name="shared-remote",
            backend_type="local",
            raw_config={},
        )

        # Remote 2: visible only to Operator (and Administrator)
        r2 = RemoteRepository.create_remote(
            session=session,
            name="operator-only-remote",
            backend_type="local",
            raw_config={},
            allowed_role_ids=[operator_role.id],
        )
        session.commit()

        r1_id = r1.id
        r2_id = r2.id

    with db_session() as session:
        r1_loaded = RemoteRepository.get_remote_by_id(session, r1_id)
        r2_loaded = RemoteRepository.get_remote_by_id(session, r2_id)
        u_admin = session.get(User, admin_user.id)
        u_op = session.get(User, operator_user.id)
        u_view = session.get(User, viewer_user.id)

        # Admin can view both
        assert RemoteRepository.can_user_view_remote(r1_loaded, u_admin, is_admin=True) is True
        assert RemoteRepository.can_user_view_remote(r2_loaded, u_admin, is_admin=True) is True

        # Operator can view both
        assert RemoteRepository.can_user_view_remote(r1_loaded, u_op, is_admin=False) is True
        assert RemoteRepository.can_user_view_remote(r2_loaded, u_op, is_admin=False) is True

        # Viewer can only view r1, not r2
        assert RemoteRepository.can_user_view_remote(r1_loaded, u_view, is_admin=False) is True
        assert RemoteRepository.can_user_view_remote(r2_loaded, u_view, is_admin=False) is False

        # list_remotes_for_user
        viewer_list = RemoteRepository.list_remotes_for_user(session, u_view, is_admin=False)
        assert len(viewer_list) == 1
        assert viewer_list[0].id == r1_id

        op_list = RemoteRepository.list_remotes_for_user(session, u_op, is_admin=False)
        assert len(op_list) == 2

        admin_list = RemoteRepository.list_remotes_for_user(session, u_admin, is_admin=True)
        assert len(admin_list) == 2

        # Update allowed_role_ids: remove Operator, add Viewer
        RemoteRepository.update_remote(
            session=session,
            remote_id=r2_id,
            allowed_role_ids=[viewer_role.id],
        )
        session.commit()

    with db_session() as session:
        r2_updated = RemoteRepository.get_remote_by_id(session, r2_id)
        u_op = session.get(User, operator_user.id)
        u_view = session.get(User, viewer_user.id)

        assert RemoteRepository.can_user_view_remote(r2_updated, u_op, is_admin=False) is False
        assert RemoteRepository.can_user_view_remote(r2_updated, u_view, is_admin=False) is True
