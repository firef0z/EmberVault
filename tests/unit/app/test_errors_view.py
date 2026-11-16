"""Unit tests for Recent Errors view (/errors) and AI diagnostics."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.blueprints.api import _build_dashboard_snapshot
from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import AuditLog, Base, Job, JobRun, RcloneRemote, Task, TaskAssignment
from embervault_db.seed import seed_initial_data
from embervault_db.settings_store import SettingsStore


@pytest.fixture
def test_app_ctx() -> tuple[FlaskClient, sessionmaker[Session], SettingsStore]:
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

    return app.test_client(), session_factory, store


def test_dashboard_card_links_to_errors(
    test_app_ctx: tuple[FlaskClient, sessionmaker[Session], SettingsStore],
) -> None:
    client, _, _ = test_app_ctx
    res = client.get("/")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert '<a href="/errors" class="stat-card"' in html
    assert "stat-recent-errors" in html


def test_errors_view_empty_state(
    test_app_ctx: tuple[FlaskClient, sessionmaker[Session], SettingsStore],
) -> None:
    client, _, _ = test_app_ctx
    res = client.get("/errors")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Errori Recenti" in html or "Recent Errors" in html
    assert "Nessun errore riscontrato" in html or "No errors found" in html


def test_errors_view_with_ai_and_standard_errors(
    test_app_ctx: tuple[FlaskClient, sessionmaker[Session], SettingsStore],
) -> None:
    client, session_factory, _ = test_app_ctx

    with session_factory() as session:
        remote = RcloneRemote(name="remote_err", backend_type="local", config_encrypted=b"{}")
        session.add(remote)
        session.flush()

        job = Job(
            name="Daily Database Backup",
            source_remote_id=remote.id,
            source_path="/data/db",
            destination_remote_id=remote.id,
            destination_path="/backup/db",
            operation="copy",
        )
        session.add(job)
        session.flush()

        run = JobRun(
            job_id=job.id,
            trigger="manual",
            status="partially_failed",
            job_snapshot={"name": job.name, "operation": job.operation},
        )
        session.add(run)
        session.flush()

        task = Task(
            run_id=run.id,
            kind="transfer",
            scope="files",
            status="failed",
            spec={"subpath": "dump.sql"},
        )
        session.add(task)
        session.flush()

        # 1. Error with AI evaluation
        ai_audit = AuditLog(
            action="ai.error_decision",
            entity_type="task",
            entity_id=str(task.id),
            details={
                "run_id": str(run.id),
                "decision": "retry",
                "confidence": 0.95,
                "reason": "Connection timeout to endpoint occurred. Temporary network glitch.",
                "interpretation": "L'IA ha classificato l'errore come TEMPORANEO (retry consigliato). Confidenza: 95%.",
                "action_taken": "Pianificato nuovo tentativo di esecuzione del task (backoff: 45s).",
                "raw_response": '{"decision": "retry", "confidence": 0.95}',
                "suggested_backoff_seconds": 45,
            },
        )

        # 2. Standard system error without AI evaluation
        standard_audit = AuditLog(
            action="system.storage_error",
            entity_type="proxy",
            entity_id=str(uuid4()),
            details={
                "error": "Disk I/O latency spike detected",
            },
        )

        session.add_all([ai_audit, standard_audit])
        session.commit()

        run_id_str = str(run.id)

    res = client.get("/errors")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # Verify AI error content
    assert "Daily Database Backup" in html
    assert f"/runs/{run_id_str}" in html
    assert "Riprova (Temporaneo)" in html or "Retry (Temporary)" in html
    assert "95%" in html
    assert "Connection timeout to endpoint" in html
    assert "Pianificato nuovo tentativo di esecuzione" in html
    assert "Backoff: 45s" in html

    # Verify standard error without AI
    assert "Disk I/O latency spike detected" in html
    assert "Non interpellata" in html or "Not consulted" in html


def test_errors_view_english_localization(
    test_app_ctx: tuple[FlaskClient, sessionmaker[Session], SettingsStore],
) -> None:
    client, _, _ = test_app_ctx
    res = client.get("/errors", headers={"Accept-Language": "en-US,en;q=0.9"})
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Recent Errors" in html
    assert "No errors found" in html
    assert "Back to Dashboard" in html


def test_errors_view_ai_ignore_badge(
    test_app_ctx: tuple[FlaskClient, sessionmaker[Session], SettingsStore],
) -> None:
    client, session_factory, _ = test_app_ctx

    with session_factory() as session:
        remote = RcloneRemote(
            name="remote_ignore_test", backend_type="local", config_encrypted=b"{}"
        )
        session.add(remote)
        session.flush()

        job = Job(
            name="Job Ignore Test",
            source_remote_id=remote.id,
            source_path="/data",
            destination_remote_id=remote.id,
            destination_path="/backup",
            operation="sync",
        )
        session.add(job)
        session.flush()

        run = JobRun(
            job_id=job.id,
            trigger="manual",
            status="partially_failed",
            job_snapshot={"name": job.name, "operation": job.operation},
        )
        session.add(run)
        session.flush()

        task = Task(
            run_id=run.id,
            kind="transfer",
            scope="subfolder",
            status="failed",
            spec={"subpath": "corrupt_folder"},
        )
        session.add(task)
        session.flush()

        ai_audit = AuditLog(
            action="ai.error_decision",
            entity_type="task",
            entity_id=str(task.id),
            details={
                "run_id": str(run.id),
                "decision": "ignore",
                "confidence": 0.92,
                "reason": "File broken.zip is permanently corrupt. Ignore file to resume sync.",
                "interpretation": "L'IA ha classificato l'errore come FILE PROBLEMATICO.",
                "action_taken": "Pianificata riesecuzione della sincronizzazione ignorando il file problematico.",
                "suggested_backoff_seconds": 15,
            },
        )
        session.add(ai_audit)
        session.commit()

    res = client.get("/errors")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    assert "Ignora (Salta file)" in html or "Ignore (Skip file)" in html
    assert "92%" in html
    assert "Pianificata riesecuzione" in html


def test_dashboard_recent_errors_24h_filter(
    test_app_ctx: tuple[FlaskClient, sessionmaker[Session], SettingsStore],
) -> None:
    client, session_factory, _ = test_app_ctx
    now = datetime.now(UTC)

    with session_factory() as session:
        # Error older than 24 hours (e.g. 36 hours ago)
        old_error = AuditLog(
            action="job.error",
            entity_type="job",
            entity_id="old-job-1",
            ts=now - timedelta(hours=36),
            details={"error": "Old database error occurred 36h ago"},
        )
        # Error within last 24 hours (e.g. 2 hours ago)
        recent_error_1 = AuditLog(
            action="proxy.error",
            entity_type="proxy",
            entity_id="proxy-1",
            ts=now - timedelta(hours=2),
            details={"error": "Connection glitch 2h ago"},
        )
        # Another error within last 24 hours (e.g. 30 minutes ago)
        recent_error_2 = AuditLog(
            action="system.error",
            entity_type="system",
            entity_id="sys-1",
            ts=now - timedelta(minutes=30),
            details={"error": "Transient disk issue 30m ago"},
        )
        session.add_all([old_error, recent_error_1, recent_error_2])
        session.commit()

        # Check API snapshot calculates exactly 2 errors (excluding the one older than 24h)
        snapshot = _build_dashboard_snapshot(session)
        assert snapshot["recent_errors"] == 2

    # Check Dashboard UI renders 2 in recent_errors card
    res = client.get("/")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert '<span class="stat-value" id="stat-recent-errors">2</span>' in html


def test_errors_view_pagination_more_than_100_errors(
    test_app_ctx: tuple[FlaskClient, sessionmaker[Session], SettingsStore],
) -> None:
    client, session_factory, _ = test_app_ctx
    now = datetime.now(UTC)

    # Insert 150 errors into AuditLog
    with session_factory() as session:
        logs = [
            AuditLog(
                action="system.error",
                entity_type="system",
                entity_id=f"node-{i}",
                ts=now - timedelta(minutes=i),
                details={"error": f"Error batch sample number {i}"},
            )
            for i in range(1, 151)
        ]
        session.add_all(logs)
        session.commit()

    # 1. Page 1 (default)
    res_page1 = client.get("/errors")
    assert res_page1.status_code == 200
    html_page1 = res_page1.data.decode("utf-8")

    # Header badge shows total 150
    assert ">150<" in html_page1
    # Exactly 100 table rows
    assert html_page1.count('id="error-row-audit-') == 100
    # Pagination info displays 1-100 of 150
    assert "1-100" in html_page1 and "150" in html_page1
    # Next page button links to ?page=2
    assert 'href="?page=2"' in html_page1
    # Prev button is disabled
    assert 'id="btn-pagination-prev" disabled' in html_page1

    # 2. Page 2
    res_page2 = client.get("/errors?page=2")
    assert res_page2.status_code == 200
    html_page2 = res_page2.data.decode("utf-8")

    # Remaining 50 table rows
    assert html_page2.count('id="error-row-audit-') == 50
    # Pagination info displays 101-150 of 150
    assert "101-150" in html_page2 and "150" in html_page2
    # Prev page button links to ?page=1
    assert 'href="?page=1"' in html_page2
    # Next button is disabled
    assert 'id="btn-pagination-next" disabled' in html_page2

    # 3. Clamping: page beyond total_pages (e.g. page 999) clamps to page 2
    res_clamped = client.get("/errors?page=999")
    assert res_clamped.status_code == 200
    html_clamped = res_clamped.data.decode("utf-8")
    assert html_clamped.count('id="error-row-audit-') == 50

    # 4. Fallback: page < 1 (e.g. page 0 or invalid) falls back to page 1
    res_invalid = client.get("/errors?page=-5")
    assert res_invalid.status_code == 200
    html_invalid = res_invalid.data.decode("utf-8")
    assert html_invalid.count('id="error-row-audit-') == 100

