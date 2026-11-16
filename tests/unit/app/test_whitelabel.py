"""Unit tests for Whitelabel & Branding functionality."""

from __future__ import annotations

import base64
import io
import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_app.whitelabel import get_whitelabel_config
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base
from embervault_db.seed import seed_initial_data
from embervault_db.settings_store import SettingsStore


@pytest.fixture
def app_and_client() -> tuple[FlaskClient, SettingsStore]:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as session:
        seed_initial_data(session)

    store = SettingsStore(session_factory)
    settings = AppSettings(app_port=8080, dev_noauth=True)
    app = create_app(
        settings=settings,
        session_factory=session_factory,
        settings_store=store,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    return app.test_client(), store


def test_whitelabel_default_config(app_and_client: tuple[FlaskClient, SettingsStore]) -> None:
    client, store = app_and_client
    res = client.get("/api/ui/settings/whitelabel")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["app_name"] == "EmberVault"
    assert data["custom_app_name"] == ""
    assert data["has_custom_logo"] is False
    assert data["logo_url"] == "/app-logo"


def test_serve_default_logo(app_and_client: tuple[FlaskClient, SettingsStore]) -> None:
    client, store = app_and_client
    res = client.get("/app-logo")
    assert res.status_code == 200
    assert "svg" in res.headers.get("Content-Type", "").lower()
    assert b"<svg" in res.data


def test_update_and_reset_app_name(app_and_client: tuple[FlaskClient, SettingsStore]) -> None:
    client, store = app_and_client

    # Update app name
    res = client.put(
        "/api/ui/settings/whitelabel/app-name", json={"custom_app_name": "MyCompany Vault"}
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["app_name"] == "MyCompany Vault"

    # Verify via GET
    res_get = client.get("/api/ui/settings/whitelabel")
    assert res_get.get_json()["app_name"] == "MyCompany Vault"
    assert res_get.get_json()["custom_app_name"] == "MyCompany Vault"

    # Check that template renders custom app name (e.g. /about or /settings)
    res_about = client.get("/about")
    assert res_about.status_code == 200
    assert "MyCompany Vault" in res_about.text
    assert (
        "<title>Informazioni | MyCompany Vault</title>" in res_about.text
        or "MyCompany Vault" in res_about.text
    )

    # Test name too long error (>64 chars)
    res_long = client.put(
        "/api/ui/settings/whitelabel/app-name", json={"custom_app_name": "A" * 65}
    )
    assert res_long.status_code == 400

    # Reset app name with reset: True
    res_reset = client.put("/api/ui/settings/whitelabel/app-name", json={"reset": True})
    assert res_reset.status_code == 200
    assert res_reset.get_json()["app_name"] == "EmberVault"
    assert res_reset.get_json()["custom_app_name"] == ""

    # Verify reset via GET
    res_get2 = client.get("/api/ui/settings/whitelabel")
    assert res_get2.get_json()["app_name"] == "EmberVault"


def test_upload_and_delete_custom_logo_file(
    app_and_client: tuple[FlaskClient, SettingsStore],
) -> None:
    client, store = app_and_client

    # Create dummy PNG bytes
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    file_data = {"logo": (io.BytesIO(png_bytes), "test_logo.png", "image/png")}

    res = client.post(
        "/api/ui/settings/whitelabel/logo", data=file_data, content_type="multipart/form-data"
    )
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"
    assert res.get_json()["has_custom_logo"] is True

    # Verify custom logo served at /app-logo
    res_logo = client.get("/app-logo")
    assert res_logo.status_code == 200
    assert "image/png" in res_logo.headers.get("Content-Type", "")
    assert res_logo.data == png_bytes

    # Delete custom logo
    res_del = client.delete("/api/ui/settings/whitelabel/logo")
    assert res_del.status_code == 200
    assert res_del.get_json()["status"] == "ok"
    assert res_del.get_json()["has_custom_logo"] is False

    # Check fallback to default logo
    res_logo_def = client.get("/app-logo")
    assert res_logo_def.status_code == 200
    assert b"<svg" in res_logo_def.data


def test_upload_custom_logo_json(app_and_client: tuple[FlaskClient, SettingsStore]) -> None:
    client, store = app_and_client

    svg_data = '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10" fill="red"/></svg>'
    b64_svg = base64.b64encode(svg_data.encode("utf-8")).decode("ascii")
    data_uri = f"data:image/svg+xml;base64,{b64_svg}"

    res = client.post("/api/ui/settings/whitelabel/logo", json={"logo": data_uri})
    assert res.status_code == 200
    assert res.get_json()["has_custom_logo"] is True

    res_logo = client.get("/app-logo")
    assert res_logo.status_code == 200
    assert "svg" in res_logo.headers.get("Content-Type", "")
    assert res_logo.data.decode("utf-8") == svg_data


def test_logo_validation_errors(app_and_client: tuple[FlaskClient, SettingsStore]) -> None:
    client, store = app_and_client

    # Empty payload
    res_empty = client.post("/api/ui/settings/whitelabel/logo", json={})
    assert res_empty.status_code == 400

    # Unsupported format
    file_bad = {"logo": (io.BytesIO(b"fake exe"), "app.exe", "application/octet-stream")}
    res_bad = client.post(
        "/api/ui/settings/whitelabel/logo", data=file_bad, content_type="multipart/form-data"
    )
    assert res_bad.status_code == 400

    # Oversized file (>5MB)
    huge_bytes = b"0" * (5 * 1024 * 1024 + 10)
    file_huge = {"logo": (io.BytesIO(huge_bytes), "huge.png", "image/png")}
    res_huge = client.post(
        "/api/ui/settings/whitelabel/logo", data=file_huge, content_type="multipart/form-data"
    )
    assert res_huge.status_code == 400


def test_portal_whitelabel_default_config(
    app_and_client: tuple[FlaskClient, SettingsStore],
) -> None:
    client, store = app_and_client
    res = client.get("/api/ui/settings/whitelabel/portal")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["app_name"] == "EmberVault public portal"
    assert data["custom_app_name"] == ""
    assert data["has_custom_logo"] is False
    assert data["logo_url"] == "/portal-logo"


def test_serve_default_portal_logo(app_and_client: tuple[FlaskClient, SettingsStore]) -> None:
    client, store = app_and_client
    res = client.get("/portal-logo")
    assert res.status_code == 200
    assert "svg" in res.headers.get("Content-Type", "").lower()
    assert b"<svg" in res.data


def test_update_and_reset_portal_app_name(
    app_and_client: tuple[FlaskClient, SettingsStore],
) -> None:
    client, store = app_and_client

    # Update portal app name
    res = client.put(
        "/api/ui/settings/whitelabel/portal/app-name",
        json={"custom_app_name": "MyPortal Client Area"},
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["app_name"] == "MyPortal Client Area"

    # Verify via GET
    res_get = client.get("/api/ui/settings/whitelabel/portal")
    assert res_get.get_json()["app_name"] == "MyPortal Client Area"
    assert res_get.get_json()["custom_app_name"] == "MyPortal Client Area"

    # Reset portal app name
    res_reset = client.put("/api/ui/settings/whitelabel/portal/app-name", json={"reset": True})
    assert res_reset.status_code == 200
    assert res_reset.get_json()["app_name"] == "EmberVault public portal"
    assert res_reset.get_json()["custom_app_name"] == ""


def test_upload_and_delete_portal_logo(app_and_client: tuple[FlaskClient, SettingsStore]) -> None:
    client, store = app_and_client

    svg_data = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"><circle cx="10" cy="10" r="10" fill="blue"/></svg>'
    b64_svg = base64.b64encode(svg_data.encode("utf-8")).decode("ascii")
    data_uri = f"data:image/svg+xml;base64,{b64_svg}"

    res = client.post("/api/ui/settings/whitelabel/portal/logo", json={"logo": data_uri})
    assert res.status_code == 200
    assert res.get_json()["has_custom_logo"] is True

    # Serve custom portal logo
    res_logo = client.get("/portal-logo")
    assert res_logo.status_code == 200
    assert "svg" in res_logo.headers.get("Content-Type", "")
    assert res_logo.data.decode("utf-8") == svg_data

    # Delete portal logo
    res_del = client.delete("/api/ui/settings/whitelabel/portal/logo")
    assert res_del.status_code == 200
    assert res_del.get_json()["has_custom_logo"] is False

    # Check fallback to default
    res_logo_def = client.get("/portal-logo")
    assert res_logo_def.status_code == 200
    assert b"<svg" in res_logo_def.data


def test_portal_global_status_toggle_and_blocking(
    app_and_client: tuple[FlaskClient, SettingsStore],
) -> None:
    client, store = app_and_client

    # Default status: enabled
    res = client.get("/api/ui/settings/portal/status")
    assert res.status_code == 200
    assert res.get_json()["enabled"] is True

    # Disable portal
    res_dis = client.put("/api/ui/settings/portal/status", json={"enabled": False})
    assert res_dis.status_code == 200
    assert res_dis.get_json()["enabled"] is False

    # Check /public-shares UI view returns 403 when disabled
    res_view = client.get("/public-shares")
    assert res_view.status_code == 403

    # Check creating a share returns 403 when disabled
    from uuid import uuid4

    res_create = client.post(
        "/api/ui/public-shares",
        json={"remote_id": str(uuid4()), "base_path": "folder", "expires_in_hours": 24},
    )
    assert res_create.status_code == 403
    assert (
        "disabled" in res_create.get_json()["message"].lower()
        or "disattivato" in res_create.get_json()["message"].lower()
    )

    # Re-enable portal
    res_en = client.put("/api/ui/settings/portal/status", json={"enabled": True})
    assert res_en.status_code == 200
    assert res_en.get_json()["enabled"] is True

    # /public-shares UI view is accessible again
    res_view_ok = client.get("/public-shares")
    assert res_view_ok.status_code == 200


def test_portal_language_settings(app_and_client: tuple[FlaskClient, SettingsStore]) -> None:
    client, store = app_and_client

    # 1. Default language is 'en'
    res = client.get("/api/ui/settings/portal/language")
    assert res.status_code == 200
    assert res.get_json() == {"status": "ok", "language": "en"}

    # 2. Invalid language returns 400
    res_inv = client.put("/api/ui/settings/portal/language", json={"language": "invalid_lang"})
    assert res_inv.status_code == 400
    assert res_inv.get_json()["status"] == "error"

    # 3. Update to 'it'
    res_it = client.put("/api/ui/settings/portal/language", json={"language": "it"})
    assert res_it.status_code == 200
    assert res_it.get_json()["status"] == "ok"
    assert res_it.get_json()["language"] == "it"

    # 4. Verify via GET
    res_get = client.get("/api/ui/settings/portal/language")
    assert res_get.status_code == 200
    assert res_get.get_json()["language"] == "it"

    # 5. Update to 'de'
    res_de = client.put("/api/ui/settings/portal/language", json={"language": "de"})
    assert res_de.status_code == 200
    assert res_de.get_json()["language"] == "de"


def test_logo_caching_and_smooth_rendering(
    app_and_client: tuple[FlaskClient, SettingsStore],
) -> None:
    client, store = app_and_client

    # 1. Verify strong caching headers on default logo
    res_logo = client.get("/app-logo")
    assert res_logo.status_code == 200
    cache_control = res_logo.headers.get("Cache-Control", "")
    assert "public" in cache_control
    assert "max-age=31536000" in cache_control
    assert "immutable" in cache_control
    etag = res_logo.headers.get("ETag")
    assert etag is not None

    # 2. Verify conditional request returns 304 Not Modified
    res_304 = client.get("/app-logo", headers={"If-None-Match": etag})
    assert res_304.status_code == 304

    # 3. Verify base template renders inlined data URI and decoding="sync" for instant zero-latency paint
    res_page = client.get("/")
    assert res_page.status_code == 200
    html = res_page.text
    assert "data:image/svg+xml;base64," in html
    assert 'decoding="sync"' in html
    assert 'class="brand-logo"' in html
