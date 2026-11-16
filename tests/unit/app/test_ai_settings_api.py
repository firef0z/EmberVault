"""Unit tests for AI Integration Settings API and UI views."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_common.ai.client import AIResponse
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base, Job, JobRun, RcloneRemote, Task, TaskAssignment
from embervault_db.seed import seed_initial_data
from embervault_db.settings_store import SettingsStore
from embervault_orchestrator.ai_evaluator import AIErrorEvaluator
from embervault_orchestrator.ai_reporter import AIReporter


@pytest.fixture
def app_client() -> tuple[FlaskClient, SettingsStore]:
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


def test_get_ai_settings_default(app_client: tuple[FlaskClient, SettingsStore]) -> None:
    client, store = app_client
    res = client.get("/api/ui/settings/ai")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["ai_enabled"] is False
    assert data["ai_provider_type"] == "openai_compatible"
    assert data["ai_endpoint_url"] == "http://localhost:11434"
    assert data["ai_model"] == "llama3.2"
    assert data["ai_timeout_seconds"] == 15
    assert data["ai_language"] == "en"
    # Preloaded default prompts for easy customization:
    assert len(data["ai_system_prompt"]) > 50
    assert "expert distributed systems reliability engineer" in data["ai_system_prompt"]
    assert len(data["ai_reporting_system_prompt"]) > 50
    assert "EmberVault expert assistant" in data["ai_reporting_system_prompt"]
    assert data["ai_custom_system_prompt"] == ""
    assert data["ai_custom_reporting_system_prompt"] == ""
    assert data["ai_error_handling_enabled"] is False
    assert data["ai_error_handling_uncensored"] is False
    assert data["ai_reporting_analysis_enabled"] is False


def test_update_ai_settings(app_client: tuple[FlaskClient, SettingsStore]) -> None:
    client, store = app_client
    payload = {
        "ai_enabled": True,
        "ai_provider_type": "ollama",
        "ai_endpoint_url": "http://ollama-vm:11434",
        "ai_model": "mistral-nemo",
        "ai_timeout_seconds": 25,
        "ai_api_key": "custom-secret-key",
        "ai_language": "it",
        "ai_system_prompt": "Custom error prompt in Italian",
        "ai_reporting_system_prompt": "Custom reporting prompt in Italian",
        "ai_error_handling_enabled": True,
        "ai_error_handling_uncensored": True,
        "ai_reporting_analysis_enabled": True,
    }
    res = client.put("/api/ui/settings/ai", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"

    # Verify settings updated in store
    assert store.get_setting("ai_enabled") is True
    assert store.get_setting("ai_provider_type") == "ollama"
    assert store.get_setting("ai_endpoint_url") == "http://ollama-vm:11434"
    assert store.get_setting("ai_model") == "mistral-nemo"
    assert store.get_setting("ai_timeout_seconds") == 25
    assert store.get_setting("ai_language") == "it"
    assert store.get_setting("ai_system_prompt") == "Custom error prompt in Italian"
    assert store.get_setting("ai_reporting_system_prompt") == "Custom reporting prompt in Italian"
    assert store.get_setting("ai_error_handling_enabled") is True
    assert store.get_setting("ai_error_handling_uncensored") is True
    assert store.get_setting("ai_reporting_analysis_enabled") is True

    # Verify GET reflects changes
    get_res = client.get("/api/ui/settings/ai")
    get_data = get_res.get_json()
    assert get_data["ai_enabled"] is True
    assert get_data["ai_provider_type"] == "ollama"
    assert get_data["ai_endpoint_url"] == "http://ollama-vm:11434"
    assert get_data["ai_model"] == "mistral-nemo"
    assert get_data["ai_has_api_key"] is True
    assert get_data["ai_language"] == "it"
    assert get_data["ai_system_prompt"] == "Custom error prompt in Italian"
    assert get_data["ai_reporting_system_prompt"] == "Custom reporting prompt in Italian"
    assert get_data["ai_reporting_analysis_enabled"] is True


def test_test_ai_connection_endpoint(app_client: tuple[FlaskClient, SettingsStore]) -> None:
    client, _ = app_client

    with patch("embervault_common.ai.client.AIClient.test_connection") as mock_test:
        mock_test.return_value = (True, "Connessione riuscita. Risposta: 'OK'")
        res = client.post(
            "/api/ui/settings/ai/test",
            json={
                "ai_endpoint_url": "http://localhost:11434",
                "ai_model": "llama3.2",
                "ai_provider_type": "ollama",
            },
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "ok"
        assert data["success"] is True
        assert "Connessione riuscita" in data["message"]

    with patch("embervault_common.ai.client.AIClient.test_connection") as mock_test:
        mock_test.return_value = (False, "Test fallito: Connection refused")
        res = client.post(
            "/api/ui/settings/ai/test",
            json={
                "ai_endpoint_url": "http://unreachable-host:11434",
                "ai_model": "llama3.2",
            },
        )
        assert res.status_code == 400
        data = res.get_json()
        assert data["status"] == "error"
        assert data["success"] is False
        assert "Test fallito" in data["message"]


def test_settings_html_renders_ai_card(app_client: tuple[FlaskClient, SettingsStore]) -> None:
    client, _ = app_client
    res = client.get("/settings")
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    assert "Integrazione IA" in html or "AI Integration" in html
    assert "ai_enabled_input" in html
    assert "ai_provider_type_input" in html
    assert "ai_endpoint_url_input" in html
    assert "ai_model_input" in html
    assert "ai_language_input" in html
    assert "ai_system_prompt_input" in html
    assert "ai_reporting_system_prompt_input" in html
    assert "btn-test-ai-connection" in html
    assert "btn-reset-ai-system-prompt" in html
    assert "Decision-making AI-Driven" in html or "AI-Driven decision-making" in html
    assert "Non censurare dati sensibili" in html or "Do not censor sensitive data" in html
    assert "Analisi e riassunto AI-Driven" in html or "AI-Driven analysis and summary" in html
    assert "ai_reporting_analysis_enabled_input" in html
    # Verify preloaded default system prompt content is loaded inside the textarea
    assert "expert distributed systems reliability engineer" in html
    assert "EmberVault expert assistant" in html


def test_ai_evaluator_respects_ai_language_default_english(
    app_client: tuple[FlaskClient, SettingsStore],
) -> None:
    _, store = app_client
    store.set_setting("ai_enabled", True)
    store.set_setting("ai_error_handling_enabled", True)
    # ai_language not set -> defaults to "en"

    evaluator = AIErrorEvaluator(settings_store=store)
    lang_code, lang_name = evaluator.get_ai_language()
    assert lang_code == "en"
    assert lang_name == "English"

    session_factory = store.session_factory
    with session_factory() as session:
        remote = RcloneRemote(name="r_en", backend_type="local", config_encrypted=b"{}")
        session.add(remote)
        session.flush()

        job = Job(
            name="Job EN",
            source_remote_id=remote.id,
            source_path="/a",
            destination_remote_id=remote.id,
            destination_path="/b",
            operation="sync",
        )
        session.add(job)
        session.flush()

        run = JobRun(
            job_id=job.id, trigger="manual", status="running", job_snapshot={"name": "Job EN"}
        )
        session.add(run)
        session.flush()

        task = Task(run_id=run.id, kind="transfer", scope="files", status="running")
        session.add(task)
        session.flush()

        assignment = TaskAssignment(task_id=task.id, attempt_no=1, status="running")
        session.add(assignment)
        session.flush()

        mock_resp = AIResponse(
            raw_content='{"decision": "retry", "reason": "Network hiccup, retry suggested", "confidence": 0.9}',
            model="llama3.2",
            latency_ms=100.0,
        )

        with patch.object(evaluator, "_get_ai_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.chat_completion.return_value = mock_resp
            mock_get_client.return_value = mock_client

            dec = evaluator.evaluate_task_failure(session=session, task=task, assignment=assignment)
            assert dec is not None

            # Verify query sent to AI is in English
            call_kwargs = mock_client.chat_completion.call_args.kwargs
            assert "Job Details:" in call_kwargs["user_prompt"]
            assert "Task Details:" in call_kwargs["user_prompt"]
            assert "Error Details:" in call_kwargs["user_prompt"]
            assert "English" in call_kwargs["system_prompt"]

            # Verify decision interpretation and action are in English
            assert "The AI classified the error as TEMPORARY" in dec.interpretation
            assert "Scheduled new execution attempt" in dec.action_taken


def test_ai_evaluator_respects_custom_system_prompt_and_italian_language(
    app_client: tuple[FlaskClient, SettingsStore],
) -> None:
    _, store = app_client
    store.set_setting("ai_enabled", True)
    store.set_setting("ai_error_handling_enabled", True)
    store.set_setting("ai_language", "it")
    store.set_setting("ai_system_prompt", "Sei un analista senior di sistemi EmberVault.")

    evaluator = AIErrorEvaluator(settings_store=store)
    lang_code, lang_name = evaluator.get_ai_language()
    assert lang_code == "it"
    assert lang_name == "Italian"

    session_factory = store.session_factory
    with session_factory() as session:
        remote = RcloneRemote(name="r_it", backend_type="local", config_encrypted=b"{}")
        session.add(remote)
        session.flush()

        job = Job(
            name="Job IT",
            source_remote_id=remote.id,
            source_path="/a",
            destination_remote_id=remote.id,
            destination_path="/b",
            operation="sync",
        )
        session.add(job)
        session.flush()

        run = JobRun(
            job_id=job.id, trigger="manual", status="running", job_snapshot={"name": "Job IT"}
        )
        session.add(run)
        session.flush()

        task = Task(run_id=run.id, kind="transfer", scope="files", status="running")
        session.add(task)
        session.flush()

        assignment = TaskAssignment(task_id=task.id, attempt_no=1, status="running")
        session.add(assignment)
        session.flush()

        mock_resp = AIResponse(
            raw_content='{"decision": "retry", "reason": "Errore temporaneo di rete", "confidence": 0.95}',
            model="llama3.2",
            latency_ms=100.0,
        )

        with patch.object(evaluator, "_get_ai_client") as mock_get_client:
            mock_client = MagicMock()
            mock_client.chat_completion.return_value = mock_resp
            mock_get_client.return_value = mock_client

            dec = evaluator.evaluate_task_failure(session=session, task=task, assignment=assignment)
            assert dec is not None

            # Verify custom prompt was passed along with Italian instruction
            call_kwargs = mock_client.chat_completion.call_args.kwargs
            assert "Sei un analista senior di sistemi EmberVault." in call_kwargs["system_prompt"]
            assert "Italian" in call_kwargs["system_prompt"]
            assert "Dettagli Job:" in call_kwargs["user_prompt"]

            # Verify interpretation is in Italian
            assert "L'IA ha classificato l'errore come TEMPORANEO" in dec.interpretation
            assert "Pianificato nuovo tentativo di esecuzione" in dec.action_taken
