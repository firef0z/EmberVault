"""Distributed leader election and single-instance coordination via PostgreSQL Advisory Locks."""

from __future__ import annotations

import threading
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.observability import get_logger

logger = get_logger("embervault_orchestrator.advisory_lock")

# Default 64-bit advisory lock key for EmberVault Orchestrator leader election:
# ASCII bytes for "EMBER_OR" = 0x454D4245525F4F52 (4993806282037743442)
DEFAULT_ORCHESTRATOR_LOCK_ID: int = 4993806282037743442

# In-memory lock simulation for non-Postgres engines (e.g. SQLite during unit tests)
_SIMULATED_LOCKS: dict[int, threading.Lock] = {}
_SIMULATED_ACQUIRED: dict[int, bool] = {}
_SIMULATION_MUTEX = threading.Lock()


class PostgresAdvisoryLock:
    """Manages PostgreSQL session-level advisory locks for single-instance leader election."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        lock_id: int = DEFAULT_ORCHESTRATOR_LOCK_ID,
    ) -> None:
        self.session_factory = session_factory
        self.lock_id = lock_id
        self._session: Session | None = None
        self._is_leader: bool = False

    @property
    def is_leader(self) -> bool:
        """Return True if this instance currently holds the leadership lock."""
        return self._is_leader

    def acquire(self) -> bool:
        """Attempt to acquire the advisory lock.

        Returns:
            True if acquired and this instance is the leader, False otherwise.
        """
        if self._is_leader:
            return True

        session = self.session_factory()
        bind = session.get_bind()
        dialect_name = bind.dialect.name if bind else "unknown"

        if dialect_name == "postgresql":
            try:
                result = session.execute(
                    text("SELECT pg_try_advisory_lock(:lock_id) AS acquired"),
                    {"lock_id": self.lock_id},
                ).scalar_one()

                if bool(result):
                    self._is_leader = True
                    self._session = session
                    logger.info("advisory_lock_acquired", lock_id=self.lock_id, role="leader")
                    return True
                else:
                    logger.warning("advisory_lock_busy", lock_id=self.lock_id, role="standby")
                    session.close()
                    return False
            except Exception as exc:
                logger.error("advisory_lock_acquire_failed", error=str(exc))
                session.close()
                return False

        # SQLite / Non-PostgreSQL simulation for tests
        with _SIMULATION_MUTEX:
            if self.lock_id not in _SIMULATED_LOCKS:
                _SIMULATED_LOCKS[self.lock_id] = threading.Lock()
                _SIMULATED_ACQUIRED[self.lock_id] = False

            if not _SIMULATED_ACQUIRED[self.lock_id]:
                _SIMULATED_ACQUIRED[self.lock_id] = True
                self._is_leader = True
                self._session = session
                logger.info("simulated_advisory_lock_acquired", lock_id=self.lock_id, role="leader")
                return True
            else:
                logger.warning("simulated_advisory_lock_busy", lock_id=self.lock_id, role="standby")
                session.close()
                return False

    def release(self) -> bool:
        """Release the advisory lock if held."""
        if not self._is_leader or self._session is None:
            return False

        bind = self._session.get_bind()
        dialect_name = bind.dialect.name if bind else "unknown"

        try:
            if dialect_name == "postgresql":
                result = self._session.execute(
                    text("SELECT pg_advisory_unlock(:lock_id) AS released"),
                    {"lock_id": self.lock_id},
                ).scalar_one()
                logger.info("advisory_lock_released", lock_id=self.lock_id, success=bool(result))
            else:
                with _SIMULATION_MUTEX:
                    _SIMULATED_ACQUIRED[self.lock_id] = False
                logger.info("simulated_advisory_lock_released", lock_id=self.lock_id)
            return True
        except Exception as exc:
            logger.error("advisory_lock_release_failed", error=str(exc))
            return False
        finally:
            self._is_leader = False
            self._session.close()
            self._session = None

    def __enter__(self) -> bool:
        return self.acquire()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()
