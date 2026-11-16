from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_db.models.base import Base


def test_app_endpoints() -> None:
    """Test healthz, readyz, and metrics endpoints for App."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    settings = AppSettings(app_port=8080, log_level="INFO")
    app = create_app(settings, session_factory=session_factory)
    client = app.test_client()

    # /healthz
    res = client.get("/healthz")
    assert res.status_code == 200
    assert res.json == {"status": "ok", "service": "app"}

    # /readyz
    res = client.get("/readyz")
    assert res.status_code == 200
    assert res.json == {"status": "ready", "service": "app"}

    # /metrics
    res = client.get("/metrics")
    assert res.status_code == 200
    assert (
        b'embervault_service_info{milestone="M9",service="app",version="1.0.0"}' in res.data
        or b'embervault_service_info{service="app",version="1.0.0",milestone="M9"}' in res.data
    )
