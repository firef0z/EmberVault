"""Unit tests for AIReporter and AI report analysis in notifications."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.ai.client import AIResponse
from embervault_common.notifications.apprise_notifier import AppriseNotifier
from embervault_common.notifications.formatter import NotificationFormatter
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.auth import AuditLog
from embervault_db.models.base import Base, utc_now
from embervault_db.models.execution import JobRun, Task, TaskAssignment
from embervault_db.models.proxy import Proxy
from embervault_db.repositories.job_repository import JobRepository
from embervault_db.repositories.notification_repository import NotificationRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.settings_store import SettingsStore
from embervault_orchestrator.ai_reporter import AIReporter
from embervault_orchestrator.notifier import NotificationService


@pytest.fixture
def db_session() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "test_encryption_key_32_characters_"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_ai_reporter_is_enabled(db_session: sessionmaker[Session]) -> None:
    store = SettingsStore(session_factory=db_session)
    reporter = AIReporter(settings_store=store)

    # Defaults: ai_enabled=False, ai_reporting_analysis_enabled=False
    assert reporter.is_enabled() is False

    # Enable master AI switch only
    store.set_setting("ai_enabled", True)
    assert reporter.is_enabled() is False

    # Enable reporting switch too
    store.set_setting("ai_reporting_analysis_enabled", True)
    assert reporter.is_enabled() is True

    # Empty endpoint or model makes it False
    store.set_setting("ai_endpoint_url", "")
    assert reporter.is_enabled() is False


def test_ai_reporter_generate_report_analysis_success(db_session: sessionmaker[Session]) -> None:
    store = SettingsStore(session_factory=db_session)
    store.set_setting("ai_enabled", True)
    store.set_setting("ai_reporting_analysis_enabled", True)
    store.set_setting("ai_endpoint_url", "http://localhost:11434")
    store.set_setting("ai_model", "llama3.2")

    reporter = AIReporter(settings_store=store)

    ai_response_text = (
        "• Riassunto: Backup terminato con 1 fallimento.\n"
        "• Problemi Rilevati: Timeout di rete verso il server remoto.\n"
        "• Soluzioni Proposte: Aumentare il timeout rclone e verificare connettività."
    )
    mock_ai_resp = AIResponse(raw_content=ai_response_text, model="llama3.2", latency_ms=120.0)

    with patch("embervault_common.ai.client.AIClient.chat_completion", return_value=mock_ai_resp):
        with db_session() as session:
            analysis = reporter.generate_report_analysis(
                session=session,
                event_type="job_run_completion",
                context={
                    "job_name": "backup-daily",
                    "status": "failed",
                    "error_message": "Network timeout occurred",
                    "files_transferred": 50,
                },
                entity_id="run-123",
            )

            assert analysis == ai_response_text

            # Verify 4-point audit log recorded
            audit_logs = session.scalars(
                select(AuditLog).where(AuditLog.action == "ai.report_analysis")
            ).all()
            assert len(audit_logs) == 1
            log = audit_logs[0]
            assert log.details["status"] == "success"
            assert "system_prompt" in log.details["point_1_prompt"]
            assert "user_prompt" in log.details["point_1_prompt"]
            assert log.details["point_2_raw_response"] == ai_response_text
            assert "successo" in log.details["point_3_interpretation"]
            assert "incorporate" in log.details["point_4_action_taken"]


def test_ai_reporter_graceful_failure(db_session: sessionmaker[Session]) -> None:
    store = SettingsStore(session_factory=db_session)
    store.set_setting("ai_enabled", True)
    store.set_setting("ai_reporting_analysis_enabled", True)

    reporter = AIReporter(settings_store=store)

    with patch(
        "embervault_common.ai.client.AIClient.chat_completion",
        side_effect=RuntimeError("Connection refused"),
    ):
        with db_session() as session:
            analysis = reporter.generate_report_analysis(
                session=session,
                event_type="job_run_completion",
                context={"job_name": "test"},
                entity_id="run-456",
            )
            # Must return None without raising exception
            assert analysis is None

            # Verify audit log recorded the failure
            audit_logs = session.scalars(
                select(AuditLog).where(AuditLog.action == "ai.report_analysis")
            ).all()
            assert len(audit_logs) == 1
            assert audit_logs[0].details["status"] == "error"
            assert "Connection refused" in audit_logs[0].details["point_2_raw_response"]


def test_notification_service_integration_with_ai_report(
    db_session: sessionmaker[Session],
) -> None:
    store = SettingsStore(session_factory=db_session)
    store.set_setting("ai_enabled", True)
    store.set_setting("ai_reporting_analysis_enabled", True)
    store.set_setting("notification_job_policy", "always")

    mock_notifier = MagicMock(spec=AppriseNotifier)
    mock_notifier.send.return_value = True

    service = NotificationService(settings_store=store, notifier=mock_notifier)

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="daily-report-test",
            source_remote_id=r1.id,
            source_path="/data",
            destination_remote_id=r2.id,
            destination_path="/backup",
            operation="sync",
            parallelization="none",
            notifications_enabled=True,
        )
        NotificationRepository.create_channel(
            session=session,
            name="Telegram Channel",
            url="tgram://123456789:ABCdef/-100123456789/?format=html",
            channel_type="telegram",
            telegram_format="html",
            enabled=True,
        )
        session.commit()
        job_id = job.id

    ai_summary = "• Riassunto: 100 file sincronizzati.\n• Problemi Rilevati: Nessuno.\n• Soluzioni Proposte: Nessuna azione necessaria."

    with patch.object(
        service.ai_reporter, "generate_report_analysis", return_value=ai_summary
    ) as mock_report:
        with db_session() as session:
            run = JobRun(
                job_id=job_id,
                trigger="manual",
                status="succeeded",
                files_transferred=100,
                bytes_transferred=5242880,
                started_at=utc_now(),
                finished_at=utc_now(),
            )
            session.add(run)
            session.commit()

            sent = service.notify_job_run_completion(session, run)
            assert sent == 1
            assert mock_report.called is True

            # Verify send was called with body containing the AI section
            assert mock_notifier.send.call_count == 1
            call_kwargs = mock_notifier.send.call_args.kwargs
            body = call_kwargs["body"]
            assert (
                "Analisi &amp; Raccomandazioni IA:" in body
                or "Analisi & Raccomandazioni IA:" in body
            )
            assert "100 file sincronizzati" in body


def test_formatter_ai_analysis_rendering() -> None:
    context = {
        "job_name": "JobTest",
        "job_id": "job-123",
        "status": "failed",
        "trigger": "manual",
        "error_message": "Disk full",
        "ai_analysis": "• Riassunto: Spazio disco insufficiente.\n• Soluzioni Proposte: Liberare spazio.",
    }

    # HTML
    _, html_body, _ = NotificationFormatter.format(
        "job_run_completed", context, telegram_format="html"
    )
    assert "Analisi & Raccomandazioni IA:" in html_body
    assert "Spazio disco insufficiente" in html_body

    # Markdown
    _, md_body, _ = NotificationFormatter.format(
        "job_run_completed", context, telegram_format="markdown"
    )
    assert "Analisi & Raccomandazioni IA:" in md_body
    assert "Spazio disco insufficiente" in md_body

    # Text
    _, txt_body, _ = NotificationFormatter.format(
        "job_run_completed", context, telegram_format="text"
    )
    assert "[Analisi & Raccomandazioni IA]" in txt_body
    assert "Spazio disco insufficiente" in txt_body


def test_ai_reporter_formats_task_details_and_timing_in_prompt(
    db_session: sessionmaker[Session],
) -> None:
    store = SettingsStore(session_factory=db_session)
    store.set_setting("ai_enabled", True)
    store.set_setting("ai_reporting_analysis_enabled", True)
    store.set_setting("ai_language", "it")

    reporter = AIReporter(settings_store=store)

    tasks_detail = [
        {
            "seq": 0,
            "kind": "transfer",
            "scope": "subfolder",
            "subpath": "documents",
            "status": "succeeded",
            "attempt_count": 1,
            "max_attempts": 3,
            "duration_ms": 3500,
            "duration_s": 3.5,
            "files_transferred": 42,
            "bytes_transferred": 1048576,  # 1 MB
            "proxy": "node-alpha",
            "last_error_code": None,
            "last_error_class": None,
        },
        {
            "seq": 1,
            "kind": "transfer",
            "scope": "subfolder",
            "subpath": "videos",
            "status": "failed",
            "attempt_count": 2,
            "max_attempts": 3,
            "duration_ms": 125400,
            "duration_s": 125.4,
            "files_transferred": 120,
            "bytes_transferred": 5368709120,  # 5 GB
            "proxy": "node-beta",
            "last_error_code": "NETWORK_TIMEOUT",
            "last_error_class": "temporary",
        },
    ]

    mock_resp = AIResponse(
        raw_content="• Riassunto: 1 riuscito, 1 fallito.\n• Analisi Tempistiche & Prestazioni Task: Il task videos ha richiesto 125.4s ed è fallito.\n• Soluzioni & Ottimizzazioni Proposte: Aumentare il timeout e verificare node-beta.",
        model="llama3.2",
        latency_ms=150.0,
    )

    with patch(
        "embervault_common.ai.client.AIClient.chat_completion", return_value=mock_resp
    ) as mock_chat:
        with db_session() as session:
            reporter.generate_report_analysis(
                session=session,
                event_type="job_run_completed",
                context={
                    "job_name": "backup-multitask",
                    "status": "partially_failed",
                    "operation": "sync",
                    "parallelization": "by_subfolder",
                    "max_parallel_tasks": 4,
                    "tasks_detail": tasks_detail,
                },
                entity_id="run-xyz",
            )

            assert mock_chat.called is True
            call_kwargs = mock_chat.call_args.kwargs
            system_prompt = call_kwargs["system_prompt"]
            user_prompt = call_kwargs["user_prompt"]

            # Verify system prompt instructs AI on timing, task breakdown and optimization
            assert "performance optimization" in system_prompt
            assert "Task Timing & Performance Analysis" in system_prompt
            assert "Proposed Solutions & Optimizations" in system_prompt
            assert "Italian" in system_prompt

            # Verify user prompt includes task details with timing, files, volume, proxy, attempts
            assert "Dettaglio Esecuzione Singoli Task:" in user_prompt
            assert "Task #0 (transfer, scope=subfolder, percorso='documents')" in user_prompt
            assert "durata=3.5s (3500ms)" in user_prompt
            assert "file sincronizzati=42" in user_prompt
            assert "1.00 MB" in user_prompt
            assert "proxy=node-alpha" in user_prompt

            assert "Task #1 (transfer, scope=subfolder, percorso='videos')" in user_prompt
            assert "durata=125.4s (125400ms)" in user_prompt
            assert "file sincronizzati=120" in user_prompt
            assert "5.00 GB" in user_prompt
            assert "proxy=node-beta" in user_prompt
            assert "errore=NETWORK_TIMEOUT" in user_prompt


def test_notification_service_extracts_rich_task_metrics_for_ai(
    db_session: sessionmaker[Session],
) -> None:
    store = SettingsStore(session_factory=db_session)
    store.set_setting("ai_enabled", True)
    store.set_setting("ai_reporting_analysis_enabled", True)
    store.set_setting("notification_job_policy", "always")

    mock_notifier = MagicMock(spec=AppriseNotifier)
    mock_notifier.send.return_value = True

    service = NotificationService(settings_store=store, notifier=mock_notifier)

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-remote", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-remote", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-with-tasks",
            source_remote_id=r1.id,
            source_path="/data",
            destination_remote_id=r2.id,
            destination_path="/backup",
            operation="sync",
            parallelization="by_subfolder",
            max_parallel_tasks=2,
            notifications_enabled=True,
        )
        proxy = Proxy(
            name="fast-worker-01",
            host="192.168.1.10",
            port=8080,
            token_encrypted=b"dummy_token",
            cert_fingerprint_sha256="0" * 64,
        )
        session.add(proxy)
        session.flush()

        run = JobRun(
            job_id=job.id,
            trigger="manual",
            status="succeeded",
            files_transferred=25,
            bytes_transferred=1048576,
            tasks_succeeded=1,
            tasks_failed=0,
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        session.add(run)
        session.flush()

        task = Task(
            run_id=run.id,
            kind="transfer",
            scope="subfolder",
            seq=0,
            spec={"source_subpath": "documents"},
            status="succeeded",
            attempt_count=1,
        )
        session.add(task)
        session.flush()

        assignment = TaskAssignment(
            task_id=task.id,
            attempt_no=1,
            proxy_id=proxy.id,
            status="succeeded",
            duration_ms=4200,
            files_transferred=25,
            bytes_transferred=1048576,
        )
        session.add(assignment)

        NotificationRepository.create_channel(
            session=session,
            name="Alerts",
            url="tgram://123456789:ABCdef/-100123456789/?format=html",
            channel_type="telegram",
            telegram_format="html",
            enabled=True,
        )
        session.commit()

        captured_context: dict[str, Any] = {}

        def mock_generate_report(session, event_type, context, entity_id, actor_user_id):
            nonlocal captured_context
            captured_context = context
            return "• Riassunto: Esecuzione completata con successo.\n• Analisi Tempistiche & Prestazioni Task: Durata task documents 4.2s.\n• Soluzioni & Ottimizzazioni Proposte: Nessuna correzione necessaria."

        with patch.object(
            service.ai_reporter, "generate_report_analysis", side_effect=mock_generate_report
        ):
            service.notify_job_run_completion(session, run)

            assert captured_context.get("job_name") == "job-with-tasks"
            assert captured_context.get("operation") == "sync"
            assert captured_context.get("parallelization") == "by_subfolder"
            assert captured_context.get("max_parallel_tasks") == 2

            tasks_detail = captured_context.get("tasks_detail")
            assert tasks_detail is not None
            assert len(tasks_detail) == 1
            t0 = tasks_detail[0]
            assert t0["seq"] == 0
            assert t0["subpath"] == "documents"
            assert t0["duration_ms"] == 4200
            assert t0["duration_s"] == 4.2
            assert t0["files_transferred"] == 25
            assert t0["bytes_transferred"] == 1048576
            assert t0["proxy"] == "fast-worker-01"
            assert t0["status"] == "succeeded"


def test_ai_reporter_proxy_offline_prompt_and_truncation(
    db_session: sessionmaker[Session],
) -> None:
    store = SettingsStore(session_factory=db_session)
    store.set_setting("ai_enabled", True)
    store.set_setting("ai_reporting_analysis_enabled", True)
    store.set_setting("ai_language", "it")

    reporter = AIReporter(settings_store=store)

    # Simulated long response with preamble
    fluffy_long_response = (
        "Certamente. Di seguito un'analisi strutturata e approfondita basata sul report fornito.\n\n"
        "• Causa: Il proxy Proxy01 non risponde dopo 3 tentativi consecutivi di connessione (porta 8443).\n"
        "• Impatto: Tutti i job assegnati esclusivamente a questo nodo rimarranno in coda in attesa di un proxy disponibile.\n"
        "• Azioni: Verificare che il servizio demone sul server remoto sia attivo; controllare le regole firewall sulla porta 8443; verificare la validità del certificato TLS.\n"
        + (
            "Ulteriori raccomandazioni superflue e prolisse che non dovrebbero occupare spazio nel messaggio di notifica. "
            * 10
        )
    )

    mock_resp = AIResponse(
        raw_content=fluffy_long_response,
        model="llama3.2",
        latency_ms=90.0,
    )

    with patch(
        "embervault_common.ai.client.AIClient.chat_completion", return_value=mock_resp
    ) as mock_chat:
        with db_session() as session:
            result = reporter.generate_report_analysis(
                session=session,
                event_type="proxy_offline",
                context={
                    "proxy_name": "Proxy01",
                    "host": "embervault-proxy-3",
                    "port": 8443,
                    "consecutive_failures": 3,
                    "reason": "Offline after 3 consecutive connection failures",
                },
                entity_id="proxy-123",
            )

            assert result is not None
            # 1. Preamble stripped
            assert not result.startswith("Certamente")
            # 2. Strict character limit enforced (<= 500)
            assert len(result) <= 500

            # 3. System prompt verified
            call_kwargs = mock_chat.call_args.kwargs
            sys_prompt = call_kwargs["system_prompt"]
            assert "Do NOT assume or mention synchronized files" in sys_prompt
            assert "connectivity" in sys_prompt
            assert "Italian" in sys_prompt
