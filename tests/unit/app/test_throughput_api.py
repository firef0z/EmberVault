"""Unit tests for Throughput History API and Dashboard Range Controls."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base
from embervault_db.models.execution import ThroughputSample
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.seed import seed_initial_data


@pytest.fixture
def app_and_db() -> tuple[FlaskClient, sessionmaker[Session]]:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as session:
        seed_initial_data(session)

    settings = AppSettings(app_port=8080, dev_noauth=True)
    app = create_app(
        settings=settings,
        session_factory=session_factory,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    return app.test_client(), session_factory


def test_throughput_metrics_api_ranges(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db
    now = datetime.now(UTC)

    with session_factory() as session:
        # Seed samples across last 24h
        for hours_ago in [20, 15, 5, 2, 0.5]:
            session.add(
                ThroughputSample(
                    recorded_at=now - timedelta(hours=hours_ago),
                    bytes_per_sec=float(hours_ago * 1024 * 1024),
                    active_runs=1,
                )
            )
        session.commit()

    # 1. Test 24h range (default)
    res_24h = client.get("/api/ui/metrics/throughput?range=24h")
    assert res_24h.status_code == 200
    data_24h = res_24h.get_json()
    assert data_24h["range"] == "24h"
    assert len(data_24h["samples"]) == 5
    assert "current_speed_bytes" in data_24h
    assert "current_speed_display" in data_24h

    # 2. Test 6h range
    res_6h = client.get("/api/ui/metrics/throughput?range=6h")
    assert res_6h.status_code == 200
    data_6h = res_6h.get_json()
    assert data_6h["range"] == "6h"
    assert len(data_6h["samples"]) == 3

    # 3. Test 1h range
    res_1h = client.get("/api/ui/metrics/throughput?range=1h")
    assert res_1h.status_code == 200
    data_1h = res_1h.get_json()
    assert data_1h["range"] == "1h"
    assert len(data_1h["samples"]) == 1

    # 4. Test 5m range (fallback sample when none in last 5m)
    res_5m = client.get("/api/ui/metrics/throughput?range=5m")
    assert res_5m.status_code == 200
    data_5m = res_5m.get_json()
    assert data_5m["range"] == "5m"
    assert len(data_5m["samples"]) >= 1

    # 5. Test custom range
    import urllib.parse

    start_iso = urllib.parse.quote((now - timedelta(hours=18)).isoformat())
    end_iso = urllib.parse.quote((now - timedelta(hours=10)).isoformat())
    res_custom = client.get(
        f"/api/ui/metrics/throughput?range=custom&start={start_iso}&end={end_iso}"
    )
    assert res_custom.status_code == 200
    data_custom = res_custom.get_json()
    assert data_custom["range"] == "custom"
    assert len(data_custom["samples"]) == 1  # only the sample at 15h ago


def test_throughput_retention_setting(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db

    # Test settings update with throughput_retention_days
    res = client.put(
        "/api/ui/settings/general",
        json={"throughput_retention_days": 14},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
