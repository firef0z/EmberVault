"""Unit tests for PostgreSQL Advisory Lock simulation and leader election."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_orchestrator.advisory_lock import PostgresAdvisoryLock


@pytest.fixture
def session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")
    return sessionmaker(bind=engine)


class TestAdvisoryLock:
    """Tests for advisory lock acquisition, mutual exclusion, and release."""

    def test_single_instance_acquisition_and_release(
        self, session_factory: sessionmaker[Session]
    ) -> None:
        lock = PostgresAdvisoryLock(session_factory, lock_id=1001)
        assert lock.is_leader == False  # noqa: E712

        first_acquire = lock.acquire()
        assert first_acquire is True
        assert lock.is_leader == True  # noqa: E712

        # Re-acquiring by same instance returns True
        second_acquire = lock.acquire()
        assert second_acquire is True

        released = lock.release()
        assert released is True
        assert lock.is_leader == False  # noqa: E712

    def test_mutual_exclusion(self, session_factory: sessionmaker[Session]) -> None:
        lock1 = PostgresAdvisoryLock(session_factory, lock_id=1002)
        lock2 = PostgresAdvisoryLock(session_factory, lock_id=1002)

        assert lock1.acquire() is True
        assert lock1.is_leader == True  # noqa: E712

        # Second instance must be denied leadership
        assert lock2.acquire() is False
        assert lock2.is_leader == False  # noqa: E712

        # Once lock1 releases, lock2 can acquire
        assert lock1.release() is True
        assert lock2.acquire() is True
        assert lock2.is_leader == True  # noqa: E712
        assert lock2.release() is True

    def test_context_manager(self, session_factory: sessionmaker[Session]) -> None:
        lock = PostgresAdvisoryLock(session_factory, lock_id=1003)

        with lock as is_acquired:
            assert is_acquired is True
            assert lock.is_leader == True  # noqa: E712

        assert lock.is_leader == False  # noqa: E712
