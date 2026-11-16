"""Unit tests for throughput history recording, retrieval, downsampling, and retention cleanup."""

from datetime import UTC, datetime, timedelta
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base
from embervault_db.models.execution import ThroughputSample
from embervault_db.repositories.execution_repository import ExecutionRepository


@pytest.fixture
def db_session_factory() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "test_settings_master_key_16_chars"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_record_throughput_sample(db_session_factory: sessionmaker[Session]) -> None:
    with db_session_factory() as session:
        # 1. Record first sample
        s1 = ExecutionRepository.record_throughput_sample(
            session, bytes_per_sec=1048576.0, active_runs=1
        )
        session.commit()
        assert s1 is not None
        assert s1.bytes_per_sec == 1048576.0
        assert s1.active_runs == 1

        # 2. Immediate record within throttle window (min_interval_s=3.0) returns existing sample
        s2 = ExecutionRepository.record_throughput_sample(
            session, bytes_per_sec=2097152.0, min_interval_s=3.0
        )
        assert s2.id == s1.id


def test_get_throughput_history_and_downsample(db_session_factory: sessionmaker[Session]) -> None:
    now = datetime.now(UTC)
    with db_session_factory() as session:
        # Create 10 samples spaced by 1 minute
        for i in range(10):
            sample = ThroughputSample(
                recorded_at=now - timedelta(minutes=10 - i),
                bytes_per_sec=float(i * 100000),
                active_runs=1,
            )
            session.add(sample)
        session.commit()

        # Query full window
        start_time = now - timedelta(minutes=15)
        end_time = now
        history = ExecutionRepository.get_throughput_history(
            session, start_time, end_time, max_points=120
        )
        assert len(history) == 10
        assert history[0]["bytes_per_sec"] == 0.0
        assert history[-1]["bytes_per_sec"] == 900000.0

        # Query with downsampling max_points=3
        downsampled = ExecutionRepository.get_throughput_history(
            session, start_time, end_time, max_points=3
        )
        assert len(downsampled) <= 3
        assert all("speed_display" in item for item in downsampled)


def test_cleanup_expired_throughput_samples(db_session_factory: sessionmaker[Session]) -> None:
    now = datetime.now(UTC)
    with db_session_factory() as session:
        # 2 old samples (10 days old)
        s_old1 = ThroughputSample(
            recorded_at=now - timedelta(days=10),
            bytes_per_sec=5000.0,
            active_runs=0,
        )
        s_old2 = ThroughputSample(
            recorded_at=now - timedelta(days=8),
            bytes_per_sec=6000.0,
            active_runs=0,
        )
        # 1 recent sample (2 days old)
        s_recent = ThroughputSample(
            recorded_at=now - timedelta(days=2),
            bytes_per_sec=12000.0,
            active_runs=1,
        )
        session.add_all([s_old1, s_old2, s_recent])
        session.commit()

        # Cleanup with retention of 7 days
        deleted = ExecutionRepository.cleanup_expired_throughput_samples(session, retention_days=7)
        session.commit()
        assert deleted == 2

        # Check remaining
        remaining = session.query(ThroughputSample).all()
        assert len(remaining) == 1
        assert remaining[0].id == s_recent.id
