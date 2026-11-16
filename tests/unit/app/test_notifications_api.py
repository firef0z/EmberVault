"""Unit tests for Notification Channels API, General Policies, and Job Notifications Toggle."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_app.orchestrator_client import OrchestratorClient
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.seed import seed_initial_data


class DummyOrchestrator(OrchestratorClient):
    """Stub Orchestrator client."""

    pass


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
        orchestrator_client=DummyOrchestrator(),
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    return app.test_client(), session_factory


def test_settings_ui_view_contains_notifications(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, _ = app_and_db
    res = client.get("/settings")
    assert res.status_code == 200
    assert b"Canali di Notifica Apprise" in res.data or b"Apprise Notification Channels" in res.data
    assert (
        b"Politiche di Notifica Generali" in res.data
        or b"General Notification Policies" in res.data
    )
    assert b"only_errors" in res.data
    assert b"always" in res.data


def test_notification_channels_crud(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db

    # 1. Initially empty
    res = client.get("/api/ui/notification-channels")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert len(data["channels"]) == 0

    # 2. Create Telegram channel via helper fields
    tg_payload = {
        "name": "DevOps Telegram",
        "channel_type": "telegram",
        "telegram_bot_token": "123456789:AAHq_Abc123def456ghi789jkl",
        "telegram_chat_id": "-100123456789",
        "telegram_format": "markdown",
        "rate_limit_interval_s": 30,
        "enabled": True,
    }
    create_res = client.post("/api/ui/notification-channels", json=tg_payload)
    assert create_res.status_code == 201
    tg_data = create_res.get_json()
    assert tg_data["status"] == "created"
    assert tg_data["channel"]["name"] == "DevOps Telegram"
    assert tg_data["channel"]["channel_type"] == "telegram"
    assert tg_data["channel"]["telegram_format"] == "markdown"
    assert "AAHq_Abc123def456ghi789jkl" not in tg_data["channel"]["url"]
    assert "••••••••" in tg_data["channel"]["url"]
    tg_channel_id = tg_data["channel"]["id"]

    # 3. Create Email channel via helper fields
    email_payload = {
        "name": "Ops Alerts Email",
        "channel_type": "email",
        "smtp_host": "smtp.company.com",
        "smtp_port": 587,
        "smtp_user": "backup-alerts",
        "smtp_password": "SuperSecretPassword123!",
        "smtp_from": "backup-alerts@company.com",
        "smtp_to": "admin@company.com",
        "smtp_secure": False,
        "rate_limit_interval_s": 60,
    }
    create_res2 = client.post("/api/ui/notification-channels", json=email_payload)
    assert create_res2.status_code == 201
    email_data = create_res2.get_json()
    assert email_data["channel"]["name"] == "Ops Alerts Email"
    assert "SuperSecretPassword123!" not in email_data["channel"]["url"]
    assert "••••••••" in email_data["channel"]["url"]
    email_channel_id = email_data["channel"]["id"]

    # 4. List channels
    list_res = client.get("/api/ui/notification-channels")
    assert list_res.status_code == 200
    channels = list_res.get_json()["channels"]
    assert len(channels) == 2

    # 5. Get channel details
    detail_res = client.get(f"/api/ui/notification-channels/{tg_channel_id}")
    assert detail_res.status_code == 200
    assert detail_res.get_json()["channel"]["name"] == "DevOps Telegram"

    # 6. Update channel (updating name, enabled, and keeping bot token)
    update_res = client.put(
        f"/api/ui/notification-channels/{tg_channel_id}",
        json={
            "name": "DevOps Telegram Primary",
            "channel_type": "telegram",
            "telegram_chat_id": "-100123456789",
            "telegram_format": "html",
            "telegram_bot_token": "••••••••",  # Keep existing token
            "enabled": False,
        },
    )
    assert update_res.status_code == 200
    updated_data = update_res.get_json()["channel"]
    assert updated_data["name"] == "DevOps Telegram Primary"
    assert updated_data["telegram_format"] == "html"
    assert updated_data["enabled"] is False

    # 7. Delete channel
    del_res = client.delete(f"/api/ui/notification-channels/{email_channel_id}")
    assert del_res.status_code == 200

    # Verify deleted
    get_del = client.get(f"/api/ui/notification-channels/{email_channel_id}")
    assert get_del.status_code == 404


def test_notification_channels_validation_errors(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, _ = app_and_db

    # Empty name
    res = client.post(
        "/api/ui/notification-channels",
        json={"name": "", "url": "mailto://user@example.com"},
    )
    assert res.status_code == 400
    assert "vuoto" in res.get_json()["message"]

    # Invalid URL scheme
    res = client.post(
        "/api/ui/notification-channels",
        json={"name": "Bad Channel", "url": "ftp://files.example.com"},
    )
    assert res.status_code == 400
    assert "non valido" in res.get_json()["message"]


@patch("embervault_common.notifications.apprise_notifier.AppriseNotifier.send")
def test_test_notification_endpoints(
    mock_send: MagicMock,
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    mock_send.return_value = True
    client, _ = app_and_db

    # 1. Test live unsaved config
    test_live_res = client.post(
        "/api/ui/notification-channels/test",
        json={
            "channel_type": "telegram",
            "telegram_bot_token": "123456789:AAHq_Abc123def456ghi789jkl",
            "telegram_chat_id": "-100123456789",
            "telegram_format": "html",
            "channel_name": "Live Test Channel",
        },
    )
    assert test_live_res.status_code == 200
    assert test_live_res.get_json()["status"] == "ok"
    assert mock_send.call_count == 1

    mock_send.reset_mock()

    # 2. Create saved channel and test saved channel endpoint
    create_res = client.post(
        "/api/ui/notification-channels",
        json={
            "name": "Saved Test Channel",
            "channel_type": "email",
            "smtp_host": "smtp.test.com",
            "smtp_port": 587,
            "smtp_from": "test@test.com",
            "smtp_to": "admin@test.com",
        },
    )
    assert create_res.status_code == 201
    channel_id = create_res.get_json()["channel"]["id"]

    test_saved_res = client.post(f"/api/ui/notification-channels/{channel_id}/test")
    assert test_saved_res.status_code == 200
    assert test_saved_res.get_json()["status"] == "ok"
    assert mock_send.call_count == 1


def test_notification_general_settings_api(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, _ = app_and_db

    # 1. Get initial notification settings
    get_res = client.get("/api/ui/notifications/settings")
    assert get_res.status_code == 200
    settings = get_res.get_json()
    assert "notifications_enabled" in settings
    assert "notification_job_policy" in settings
    assert "notification_proxy_offline_enabled" in settings
    assert settings["notification_job_policy"] == "only_errors"

    # 2. Update notification policy to 'always'
    put_res = client.put(
        "/api/ui/notifications/settings",
        json={
            "notification_job_policy": "always",
            "notifications_enabled": True,
            "notification_proxy_offline_enabled": False,
        },
    )
    assert put_res.status_code == 200
    assert put_res.get_json()["status"] == "ok"

    # Verify updated
    get_res_2 = client.get("/api/ui/notifications/settings")
    settings_2 = get_res_2.get_json()
    assert settings_2["notification_job_policy"] == "always"
    assert settings_2["notification_proxy_offline_enabled"] is False

    # 3. Invalid policy value should be rejected
    bad_put = client.put(
        "/api/ui/notifications/settings",
        json={"notification_job_policy": "never"},
    )
    assert bad_put.status_code == 400


def test_job_create_and_update_with_notifications_toggle(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db

    with session_factory() as session:
        r1 = RemoteRepository.create_remote(session, "src-job", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-job", "local", {"path": "/dst"})
        session.commit()
        r1_id, r2_id = str(r1.id), str(r2.id)

    # 1. Create job with notifications_enabled=False
    job_payload = {
        "name": "Silent Nightly Job",
        "source_remote_id": r1_id,
        "source_path": "/data",
        "destination_remote_id": r2_id,
        "destination_path": "/backup",
        "operation": "copy",
        "parallelization": "none",
        "notifications_enabled": False,
    }
    create_res = client.post("/api/ui/jobs", json=job_payload)
    assert create_res.status_code == 201
    job_id = create_res.get_json()["job_id"]

    # 2. Get job details
    get_res = client.get(f"/api/ui/jobs/{job_id}")
    assert get_res.status_code == 200
    assert get_res.get_json()["job"]["notifications_enabled"] is False

    # 3. Update job to turn notifications_enabled=True
    update_res = client.put(
        f"/api/ui/jobs/{job_id}",
        json={
            "notifications_enabled": True,
        },
    )
    assert update_res.status_code == 200

    # 4. Verify updated value
    get_res_2 = client.get(f"/api/ui/jobs/{job_id}")
    assert get_res_2.status_code == 200
    assert get_res_2.get_json()["job"]["notifications_enabled"] is True


def test_notifications_settings_and_channels_alias_routes(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    """Verify that both /notifications/settings and /settings/notifications/general resolve without 404."""
    client, _ = app_and_db

    # 1. Test GET /settings/notifications/general
    res = client.get("/api/ui/settings/notifications/general")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert "notifications_enabled" in data

    # 2. Test PUT /settings/notifications/general
    put_res = client.put(
        "/api/ui/settings/notifications/general",
        json={
            "notifications_enabled": True,
            "notification_job_policy": "always",
            "notification_proxy_offline_enabled": True,
        },
    )
    assert put_res.status_code == 200
    put_data = put_res.get_json()
    assert put_data["status"] == "ok"
    assert put_data["notification_job_policy"] == "always"

    # 3. Test GET /settings/notifications/channels
    ch_res = client.get("/api/ui/settings/notifications/channels")
    assert ch_res.status_code == 200
    assert "channels" in ch_res.get_json()
