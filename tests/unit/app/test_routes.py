"""Unit tests for EmberVault Web UI routes and views."""

from __future__ import annotations

import uuid

import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import embervault_db.models  # noqa: F401
from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.base import Base
from embervault_db.models.proxy import Proxy, ProxyStatus
from embervault_db.repositories.proxy_repository import ProxyRepository


@pytest.fixture
def app_client() -> FlaskClient:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    # Seed test proxy
    with session_factory() as session:
        p_id = uuid.uuid4()
        proxy = Proxy(
            id=p_id,
            name="test-proxy-alpha",
            host="127.0.0.1",
            port=8443,
            token_encrypted=ProxyRepository.encrypt_token("a" * 32, p_id),
            cert_fingerprint_sha256="a" * 64,
            is_enabled=True,
            max_concurrent_tasks=2,
        )
        session.add(proxy)
        status = ProxyStatus(
            proxy_id=p_id,
            state="online",
            latency_ms=12,
            running_tasks=0,
            capacity=2,
        )
        session.add(status)
        session.commit()

    settings = AppSettings(app_port=8080, dev_noauth=True)
    app = create_app(settings=settings, session_factory=session_factory)
    app.config["TESTING"] = True
    return app.test_client()


def test_dashboard_route(app_client: FlaskClient) -> None:
    """Test dashboard route displays proxy metrics and live table."""
    res = app_client.get("/")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "test-proxy-alpha" in html
    assert "EmberVault" in html
    assert "Dashboard" in html


def test_proxies_route(app_client: FlaskClient) -> None:
    """Test proxies route lists proxies and renders TOFU modal."""
    res = app_client.get("/proxies")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "test-proxy-alpha" in html
    assert "modal-register-proxy" in html


def test_remotes_route(app_client: FlaskClient) -> None:
    """Test remotes route displays curated empty state."""
    res = app_client.get("/remotes")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert (
        "Nessun Remote RClone Configurato" in html
        or "No Rclone Remotes Configured" in html
        or "No RClone Remotes Configured" in html
    )


def test_jobs_route(app_client: FlaskClient) -> None:
    """Test jobs route displays curated empty state."""
    res = app_client.get("/jobs")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Nessun Job di Backup Configurato" in html or "No Backup Jobs Configured" in html


def test_runs_route(app_client: FlaskClient) -> None:
    """Test runs history route."""
    res = app_client.get("/runs")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Esecuzioni" in html or "Runs" in html or "Executions" in html


def test_run_detail_route_not_found(app_client: FlaskClient) -> None:
    """Test run detail with unknown ID displays clean empty state."""
    fake_id = uuid.uuid4()
    res = app_client.get(f"/runs/{fake_id}")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert (
        "Esecuzione non trovata" in html
        or "Run non trovata" in html
        or "Run Not Found" in html
        or "run not found" in html.lower()
        or "Execution not found" in html
    )


def test_logs_route(app_client: FlaskClient) -> None:
    """Test audit logs route."""
    res = app_client.get("/logs")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Registro Audit" in html or "Audit Log" in html or "Audit Logs" in html
    assert "btn-export-xlsx" in html
    assert "modal-audit-details" in html


def test_logs_filtering_and_export(app_client: FlaskClient) -> None:
    """Test audit logs filtering parameters and XLSX export endpoint."""
    # 1. Test filtering params
    res = app_client.get("/logs?limit=50&start_date=2026-01-01T00:00&end_date=2026-12-31T23:59")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Registro Audit" in html or "Audit Log" in html or "Audit Logs" in html

    # 2. Test export endpoint
    export_res = app_client.get("/logs/export?limit=100")
    assert export_res.status_code == 200
    assert (
        export_res.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    assert "attachment; filename=" in export_res.headers.get("Content-Disposition", "")
    assert len(export_res.data) > 500  # Valid zip/xlsx package content


def test_settings_route(app_client: FlaskClient) -> None:
    """Test settings route displays CONFIG_REGISTRY table in read-only mode."""
    res = app_client.get("/settings")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "CONFIG_REGISTRY" in html
    assert "heartbeat_interval_s" in html
    assert (
        "Le impostazioni di sistema mostrano la gerarchia" in html
        or "System settings display the resolved hierarchy" in html
    )


def test_about_route(app_client: FlaskClient) -> None:
    """Test about page displays architecture and version."""
    res = app_client.get("/about")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "1.0.0" in html
    assert "embervault-orchestrator" in html
    assert "embervault-hook-runner" in html
    assert "embervault-portal" in html
    assert "Rete privata Docker" in html or "Docker private network" in html
    assert ("Raggiungibile" in html and "esterno" in html) or ("Reachable from outside" in html)


def test_offline_route(app_client: FlaskClient) -> None:
    """Test offline shell fallback."""
    res = app_client.get("/offline")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Dispositivo Offline" in html or "Device Offline" in html


def test_static_assets(app_client: FlaskClient) -> None:
    """Test that static PWA assets, manifest, and icons are served correctly."""
    # Manifest
    res = app_client.get("/static/manifest.webmanifest")
    assert res.status_code == 200
    assert b"EmberVault" in res.data

    # Service Worker
    res = app_client.get("/static/service-worker.js")
    assert res.status_code == 200
    assert b"CACHE_NAME" in res.data

    # CSS
    res = app_client.get("/static/css/app.css")
    assert res.status_code == 200
    assert b"--ember-primary" in res.data

    # JS
    res = app_client.get("/static/js/app.js")
    assert res.status_code == 200

    # Logo
    res = app_client.get("/static/img/logo.svg")
    assert res.status_code == 200


def test_i18n_language_toggle(app_client: FlaskClient) -> None:
    """Test language switching between Italian and English."""
    # Italian default
    res = app_client.get("/?lang=it")
    assert res.status_code == 200
    assert "Proxy Online" in res.data.decode("utf-8")

    # English switch
    res = app_client.get("/?lang=en")
    assert res.status_code == 200
    assert "Proxies Online" in res.data.decode("utf-8")


def test_proxies_route_registration_modal(app_client: FlaskClient) -> None:
    """Verify that /proxies renders registration button with data-open-modal and no blocked onclicks."""
    res = app_client.get("/proxies")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert 'data-open-modal="modal-register-proxy"' in html
    assert "modal-register-proxy" in html
    assert "onclick=" not in html


def test_remotes_new_route_catalog(app_client: FlaskClient) -> None:
    """Verify that /remotes/new renders provider catalog and script with CSP nonce."""
    res = app_client.get("/remotes/new")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Amazon S3" in html
    assert "provider-card" in html
    assert "dynamic-fields-container" in html
    assert '<script nonce="' in html
    assert "onclick=" not in html


def test_rclone_settings_api_and_ui(app_client: FlaskClient) -> None:
    """Verify that /api/ui/settings/rclone accepts list of filter rules and /settings renders them."""
    import re

    # 0. Get CSRF token
    init_res = app_client.get("/settings")
    assert init_res.status_code == 200
    csrf_match = re.search(
        r'<meta name="csrf-token" content="([^"]+)">', init_res.data.decode("utf-8")
    )
    assert csrf_match is not None
    csrf_token = csrf_match.group(1)

    # 1. Update RClone settings passing list for filters
    payload = {
        "task_retries": 3,
        "rclone_checkers": 16,
        "rclone_transfers": 8,
        "rclone_check_first": True,
        "rclone_recurse": True,
        "rclone_order_by": "size,ascending",
        "rclone_first_level_filters": ["+ *.pdf", "- *.tmp"],
        "rclone_second_level_filters": ["- *.log", "+ *.txt"],
    }
    put_res = app_client.put(
        "/api/ui/settings/rclone",
        json=payload,
        headers={"X-CSRFToken": csrf_token},
    )
    assert put_res.status_code == 200, put_res.get_json()
    assert put_res.get_json()["status"] == "ok"

    # 2. Get RClone settings and ensure lists are returned
    get_res = app_client.get("/api/ui/settings/rclone")
    assert get_res.status_code == 200
    data = get_res.get_json()
    assert data["task_retries"] == 3
    assert data["rclone_checkers"] == 16
    assert data["rclone_transfers"] == 8
    assert data["rclone_check_first"] is True
    assert data["rclone_recurse"] is True
    assert data["rclone_order_by"] == "size,ascending"
    assert data["rclone_first_level_filters"] == ["+ *.pdf", "- *.tmp"]
    assert data["rclone_second_level_filters"] == ["- *.log", "+ *.txt"]

    # 3. Check /settings page renders correctly
    page_res = app_client.get("/settings")
    assert page_res.status_code == 200
    html = page_res.data.decode("utf-8")
    assert "+ *.pdf" in html
    assert "- *.tmp" in html
    assert "- *.log" in html
    assert "+ *.txt" in html


def _extract_csrf_token(app_client: FlaskClient) -> str:
    import re

    init_res = app_client.get("/settings")
    assert init_res.status_code == 200
    csrf_match = re.search(
        r'<meta name="csrf-token" content="([^"]+)">', init_res.data.decode("utf-8")
    )
    assert csrf_match is not None
    return csrf_match.group(1)


def test_settings_canonical_registry_filters_out_gui_overridables(app_client: FlaskClient) -> None:
    """Verify that CONFIG_REGISTRY table at the bottom ONLY contains bootstrap/env settings."""
    from embervault_common.config.registry import CONFIG_REGISTRY

    res = app_client.get("/settings")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # Non-overridable settings MUST appear in the bootstrap registry table
    assert "<strong>database_url</strong>" in html
    assert "<strong>master_key</strong>" in html
    assert "<strong>orch_port</strong>" in html
    assert "<strong>proxy_rclone_bin</strong>" in html

    # Overridable settings MUST NOT appear inside the table rows
    for key_def in CONFIG_REGISTRY:
        if key_def.overridable_from_gui:
            assert f"<strong>{key_def.name}</strong>" not in html, (
                f"{key_def.name} should not be in the bootstrap table"
            )


def test_general_settings_api(app_client: FlaskClient) -> None:
    """Test GET and PUT /api/ui/settings/general."""
    csrf_token = _extract_csrf_token(app_client)

    # 1. GET general settings
    get_res = app_client.get("/api/ui/settings/general")
    assert get_res.status_code == 200
    data = get_res.get_json()
    assert data["status"] == "ok"
    assert "settings" in data
    assert "log_level" in data["settings"]
    assert "scheduler_tick_s" in data["settings"]
    assert "global_concurrency" in data["settings"]

    # 2. PUT general settings (valid overridable settings)
    payload = {
        "log_level": "WARNING",
        "log_format": "json",
        "default_locale": "en",
        "scheduler_tick_s": 15,
        "global_concurrency": 25,
        "session_cookie_secure": True,
    }
    put_res = app_client.put(
        "/api/ui/settings/general",
        json=payload,
        headers={"X-CSRFToken": csrf_token},
    )
    assert put_res.status_code == 200, put_res.get_json()
    assert put_res.get_json()["status"] == "ok"
    assert put_res.get_json()["settings"]["log_level"] == "WARNING"
    assert put_res.get_json()["settings"]["scheduler_tick_s"] == 15

    # Verify updated values via GET
    get_res2 = app_client.get("/api/ui/settings/general")
    assert get_res2.status_code == 200
    data2 = get_res2.get_json()["settings"]
    assert data2["log_level"] == "WARNING"
    assert data2["log_format"] == "json"
    assert data2["default_locale"] == "en"
    assert data2["scheduler_tick_s"] == 15
    assert data2["global_concurrency"] == 25
    assert data2["session_cookie_secure"] is True


def test_general_settings_security_blocking(app_client: FlaskClient) -> None:
    """Ensure sensitive/bootstrap settings cannot be modified via GUI endpoint."""
    csrf_token = _extract_csrf_token(app_client)

    # Attempting to change database_url via GUI MUST return 403 Forbidden
    bad_payload = {"database_url": "postgresql://hacked:evil@remote/db"}
    put_res = app_client.put(
        "/api/ui/settings/general",
        json=bad_payload,
        headers={"X-CSRFToken": csrf_token},
    )
    assert put_res.status_code == 403
    err_msg = put_res.get_json()["message"]
    assert "database_url" in err_msg
    assert (
        "non può essere modificata da interfaccia web" in err_msg
        or "cannot be modified via the web interface" in err_msg
    )

    # Attempting to change master_key MUST return 403 Forbidden
    put_res2 = app_client.put(
        "/api/ui/settings/general",
        json={"master_key": "mysecretkey"},
        headers={"X-CSRFToken": csrf_token},
    )
    assert put_res2.status_code == 403

    # Attempting to change orch_port MUST return 403 Forbidden
    put_res3 = app_client.put(
        "/api/ui/settings/general",
        json={"orch_port": 9999},
        headers={"X-CSRFToken": csrf_token},
    )
    assert put_res3.status_code == 403


def test_job_edit_proxy_affinity_tab(app_client: FlaskClient) -> None:
    """Ensure Assigned Execution Proxies lives inside the new Proxy Affinity tab (i18n-enabled)."""
    res_it = app_client.get("/jobs/new?lang=it")
    assert res_it.status_code == 200
    html_it = res_it.data.decode("utf-8")

    assert 'id="btn-tab-proxy-affinity"' in html_it
    assert 'data-tab="tab-proxy-affinity"' in html_it
    assert "Affinità Proxy" in html_it

    schedule_pane_start = html_it.index('id="tab-mode-schedule"')
    affinity_pane_start = html_it.index('id="tab-proxy-affinity"')
    rclone_pane_start = html_it.index('id="tab-rclone-params"')
    assert schedule_pane_start < affinity_pane_start < rclone_pane_start

    schedule_pane_html = html_it[schedule_pane_start:affinity_pane_start]
    affinity_pane_html = html_it[affinity_pane_start:rclone_pane_start]
    assert 'id="assigned-proxies-container"' not in schedule_pane_html
    assert 'id="assigned-proxies-container"' in affinity_pane_html
    assert "Proxy di Esecuzione Assegnati" in affinity_pane_html

    res_en = app_client.get("/jobs/new?lang=en")
    assert res_en.status_code == 200
    html_en = res_en.data.decode("utf-8")
    assert "Proxy Affinity" in html_en
    assert "Assigned Execution Proxies" in html_en


def test_job_edit_run_policies_tab(app_client: FlaskClient) -> None:
    """Ensure Run Policies tab renders all 4 policies and independent notify toggles (i18n)."""
    res_it = app_client.get("/jobs/new?lang=it")
    assert res_it.status_code == 200
    html_it = res_it.data.decode("utf-8")

    assert 'id="btn-tab-run-policies"' in html_it
    assert 'data-tab="tab-run-policies"' in html_it
    assert "Policy di esecuzione" in html_it

    affinity_pane_start = html_it.index('id="tab-proxy-affinity"')
    policies_pane_start = html_it.index('id="tab-run-policies"')
    rclone_pane_start = html_it.index('id="tab-rclone-params"')
    assert affinity_pane_start < policies_pane_start < rclone_pane_start

    policies_pane_html = html_it[policies_pane_start:rclone_pane_start]
    for elem_id in (
        'id="job-missed-run-policy"',
        'id="job-overlap-policy"',
        'id="job-pending-policy"',
        'id="job-max-runtime-enabled"',
        'id="job-max-runtime-hours"',
        'id="job-max-runtime-minutes"',
        'id="job-missed-run-notify"',
        'id="job-overlap-notify"',
        'id="job-pending-notify"',
        'id="job-max-runtime-notify"',
    ):
        assert elem_id in policies_pane_html

    res_en = app_client.get("/jobs/new?lang=en")
    assert res_en.status_code == 200
    html_en = res_en.data.decode("utf-8")
    assert "Run Policies" in html_en
    assert "Missed Run Policy" in html_en
    assert "Overlap Policy" in html_en
    assert "Pending Policy" in html_en
    assert "Max Runtime Policy" in html_en
    assert "Notify" in html_en
