"""Unit tests for AIErrorEvaluator in embervault_orchestrator.ai_evaluator."""

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.ai.client import AIResponse
from embervault_db.models.auth import AuditLog
from embervault_db.models.base import Base
from embervault_db.models.execution import JobRun, Task, TaskAssignment, TaskLog
from embervault_db.models.remotes import Job, RcloneRemote
from embervault_db.settings_store import SettingsStore
from embervault_orchestrator.ai_evaluator import AIErrorEvaluator


@pytest.fixture
def db_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def test_setup(db_session: Session) -> tuple[Job, JobRun, Task, TaskAssignment]:
    remote1 = RcloneRemote(
        name="test_remote1",
        backend_type="local",
        config_encrypted=b"{}",
    )
    remote2 = RcloneRemote(
        name="test_remote2",
        backend_type="s3",
        config_encrypted=b"{}",
    )
    db_session.add_all([remote1, remote2])
    db_session.flush()

    job = Job(
        name="Backup Finance Server",
        source_remote_id=remote1.id,
        source_path="/var/data/finance",
        destination_remote_id=remote2.id,
        destination_path="s3://backup-vault/finance",
        operation="sync",
    )
    db_session.add(job)
    db_session.flush()

    run = JobRun(
        job_id=job.id,
        trigger="manual",
        status="running",
        job_snapshot={"name": job.name, "operation": job.operation},
    )
    db_session.add(run)
    db_session.flush()

    task = Task(
        run_id=run.id,
        kind="transfer",
        scope="subfolder",
        status="running",
        spec={"source_subpath": "2026/invoices"},
        attempt_count=1,
        max_attempts=3,
    )
    db_session.add(task)
    db_session.flush()

    assignment = TaskAssignment(
        task_id=task.id,
        attempt_no=1,
        proxy_id=uuid4(),
        status="running",
    )
    db_session.add(assignment)
    db_session.flush()

    return job, run, task, assignment


def test_ai_evaluator_is_enabled_flag(db_session: Session) -> None:
    session_factory = sessionmaker(bind=db_session.get_bind())
    settings_store = SettingsStore(session_factory)
    evaluator = AIErrorEvaluator(settings_store)

    assert not evaluator.is_enabled()

    with patch.object(settings_store, "get_setting") as mock_get:
        mock_get.side_effect = lambda k: {
            "ai_enabled": True,
            "ai_error_handling_enabled": True,
            "ai_endpoint_url": "http://localhost:11434",
            "ai_model": "llama3.2",
        }.get(k)
        assert evaluator.is_enabled() is True


def test_ai_evaluator_censored_evaluation_and_logging(
    db_session: Session, test_setup: tuple[Job, JobRun, Task, TaskAssignment]
) -> None:
    job, run, task, assignment = test_setup
    session_factory = sessionmaker(bind=db_session.get_bind())
    settings_store = SettingsStore(session_factory)
    evaluator = AIErrorEvaluator(settings_store)

    # Mock settings: enabled, censored (uncensored=False)
    with patch.object(settings_store, "get_setting") as mock_get:
        mock_get.side_effect = lambda k: {
            "ai_enabled": True,
            "ai_error_handling_enabled": True,
            "ai_endpoint_url": "http://localhost:11434",
            "ai_model": "llama3.2",
            "ai_error_handling_uncensored": False,
            "ai_timeout_seconds": 15,
        }.get(k)

        mock_ai_resp = AIResponse(
            raw_content='{"decision": "retry", "reason": "Errore di timeout di rete temporaneo", "confidence": 0.95, "suggested_backoff_seconds": 45}',
            model="llama3.2",
            latency_ms=250.0,
        )

        with patch.object(evaluator, "_get_ai_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.chat_completion.return_value = mock_ai_resp
            mock_get_client.return_value = mock_client

            error_logs = [
                "Connection to 192.168.1.100 timed out after 30s",
                "Failed to sync /var/data/finance/2026/invoices/inv_01.pdf",
            ]

            decision = evaluator.evaluate_task_failure(
                session=db_session,
                task=task,
                assignment=assignment,
                exit_code=1,
                error_class="temporary",
                error_code="TIMEOUT",
                recent_log_lines=error_logs,
            )

            assert decision is not None
            assert decision.decision == "retry"
            assert decision.suggested_backoff_seconds == 45
            assert "timeout" in decision.reason.lower()

            # Verify that censorship took place in user_prompt
            assert "192.168.1.100" not in decision.user_prompt
            assert "[IP_1]" in decision.user_prompt
            assert "inv_01.pdf" not in decision.user_prompt

            # Verify MANDATORY logging in TaskLog (all 4 aspects)
            task_logs = db_session.scalars(
                select(TaskLog).where(TaskLog.task_id == task.id).order_by(TaskLog.seq)
            ).all()

            log_messages = [l.message for l in task_logs]
            assert any("[AI-DECISION-MAKING]" in m for m in log_messages)
            assert any("[AI-SYSTEM-PROMPT]" in m for m in log_messages)
            assert any("[AI-USER-PROMPT]" in m for m in log_messages)
            assert any("[AI-RAW-RESPONSE]" in m for m in log_messages)
            assert any("[AI-INTERPRETATION]" in m for m in log_messages)
            assert any("[AI-ACTION]" in m for m in log_messages)

            # Verify MANDATORY logging in AuditLog
            audit_entry = db_session.scalar(
                select(AuditLog).where(AuditLog.action == "ai.error_decision")
            )
            assert audit_entry is not None
            assert audit_entry.entity_id == str(task.id)
            assert audit_entry.details["decision"] == "retry"
            assert "system_prompt" in audit_entry.details
            assert "user_prompt" in audit_entry.details
            assert "raw_response" in audit_entry.details
            assert "interpretation" in audit_entry.details
            assert "action_taken" in audit_entry.details


def test_ai_evaluator_uncensored_evaluation(
    db_session: Session, test_setup: tuple[Job, JobRun, Task, TaskAssignment]
) -> None:
    job, run, task, assignment = test_setup
    session_factory = sessionmaker(bind=db_session.get_bind())
    settings_store = SettingsStore(session_factory)
    evaluator = AIErrorEvaluator(settings_store)

    with patch.object(settings_store, "get_setting") as mock_get:
        mock_get.side_effect = lambda k: {
            "ai_enabled": True,
            "ai_error_handling_enabled": True,
            "ai_endpoint_url": "http://localhost:11434",
            "ai_model": "llama3.2",
            "ai_error_handling_uncensored": True,
            "ai_timeout_seconds": 15,
        }.get(k)

        mock_ai_resp = AIResponse(
            raw_content='{"decision": "fail", "reason": "File corrotto irrecuperabile", "confidence": 0.99}',
            model="llama3.2",
            latency_ms=210.0,
        )

        with patch.object(evaluator, "_get_ai_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.chat_completion.return_value = mock_ai_resp
            mock_get_client.return_value = mock_client

            error_logs = ["Corrupt data encountered in /var/data/finance/invoices/corrupted.zip"]

            decision = evaluator.evaluate_task_failure(
                session=db_session,
                task=task,
                assignment=assignment,
                exit_code=2,
                error_class="io",
                error_code="DATA_CORRUPT",
                recent_log_lines=error_logs,
            )

            assert decision is not None
            assert decision.decision == "fail"
            # Since uncensored=True, the exact path should remain in the prompt
            assert "corrupted.zip" in decision.user_prompt
            assert "[FILE_" not in decision.user_prompt


def test_ai_evaluator_ignore_decision(
    db_session: Session, test_setup: tuple[Job, JobRun, Task, TaskAssignment]
) -> None:
    job, run, task, assignment = test_setup
    session_factory = sessionmaker(bind=db_session.get_bind())
    settings_store = SettingsStore(session_factory)
    evaluator = AIErrorEvaluator(settings_store)

    with patch.object(settings_store, "get_setting") as mock_get:
        mock_get.side_effect = lambda k: {
            "ai_enabled": True,
            "ai_error_handling_enabled": True,
            "ai_endpoint_url": "http://localhost:11434",
            "ai_model": "llama3.2",
            "ai_language": "it",
        }.get(k)

        mock_ai_resp = AIResponse(
            raw_content="""{
                "decision": "ignore",
                "reason": "File broken_archive.tar risulta corrotto e illeggibile. Ripetere sincronizzazione escludendo questo file.",
                "confidence": 0.95,
                "suggested_backoff_seconds": 10
            }""",
            model="llama3.2",
            latency_ms=180.0,
        )

        with patch.object(evaluator, "_get_ai_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.chat_completion.return_value = mock_ai_resp
            mock_get_client.return_value = mock_client

            error_logs = ["corrupted file encountered: broken_archive.tar checksum mismatch"]

            decision = evaluator.evaluate_task_failure(
                session=db_session,
                task=task,
                assignment=assignment,
                exit_code=1,
                error_class="io",
                error_code="CORRUPTED_FILE",
                recent_log_lines=error_logs,
            )

            assert decision is not None
            assert decision.decision == "ignore"
            assert decision.suggested_backoff_seconds == 10
            assert "FILE PROBLEMATICO" in decision.interpretation
            assert "Pianificata riesecuzione" in decision.action_taken

            # Verify prompt contains the 3 actions schema
            assert '"decision": "retry" | "fail" | "ignore"' in decision.system_prompt
            assert (
                "'ignore': Repeat the synchronization while ignoring/skipping a specific problematic file"
                in decision.system_prompt
            )
