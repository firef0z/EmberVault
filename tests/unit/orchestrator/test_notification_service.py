"""Unit tests for Orchestrator NotificationService."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.notifications.apprise_notifier import AppriseNotifier
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.base import Base, utc_now
from embervault_db.models.execution import JobRun
from embervault_db.models.proxy import Proxy
from embervault_db.repositories.job_repository import JobRepository
from embervault_db.repositories.notification_repository import NotificationRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.settings_store import SettingsStore
from embervault_orchestrator.notifier import NotificationService


@pytest.fixture
def db_session() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "test_encryption_key_32_characters_"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def mock_notifier() -> MagicMock:
    notifier = MagicMock(spec=AppriseNotifier)
    notifier.send.return_value = True
    return notifier


def test_notify_job_run_policy_only_errors_vs_always(
    db_session: sessionmaker[Session],
    mock_notifier: MagicMock,
) -> None:
    store = SettingsStore(session_factory=db_session)
    service = NotificationService(settings_store=store, notifier=mock_notifier)

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="backup-policy-test",
            source_remote_id=r1.id,
            source_path="/photos",
            destination_remote_id=r2.id,
            destination_path="/photos-dst",
            operation="copy",
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

    # 1. Policy = only_errors, run = succeeded -> NO notification
    store.set_setting("notification_job_policy", "only_errors")
    with db_session() as session:
        run_succeeded = JobRun(
            job_id=job_id,
            trigger="schedule",
            status="succeeded",
            files_transferred=10,
            bytes_transferred=1024,
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        session.add(run_succeeded)
        session.commit()

        sent = service.notify_job_run_completion(session, run_succeeded)
        assert sent == 0
        assert mock_notifier.send.call_count == 0
        assert run_succeeded.notification_sent_at is not None

    # 2. Policy = only_errors, run = failed -> Notification SENT
    with db_session() as session:
        run_failed = JobRun(
            job_id=job_id,
            trigger="manual",
            status="failed",
            error_message="Connection reset by peer",
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        session.add(run_failed)
        session.commit()

        sent = service.notify_job_run_completion(session, run_failed)
        assert sent == 1
        assert mock_notifier.send.call_count == 1
        assert run_failed.notification_sent_at is not None
        call_kwargs = mock_notifier.send.call_args[1]
        assert "Job 'backup-policy-test' Fallito" in call_kwargs["title"]

    mock_notifier.reset_mock()

    # 3. Policy = always, run = succeeded -> Notification SENT
    store.set_setting("notification_job_policy", "always")
    with db_session() as session:
        run_succeeded_2 = JobRun(
            job_id=job_id,
            trigger="schedule",
            status="succeeded",
            files_transferred=5,
            bytes_transferred=512,
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        session.add(run_succeeded_2)
        session.commit()

        sent = service.notify_job_run_completion(session, run_succeeded_2)
        assert sent == 1
        assert mock_notifier.send.call_count == 1
        call_kwargs = mock_notifier.send.call_args[1]
        assert "Job 'backup-policy-test' Completato" in call_kwargs["title"]


def test_notify_job_run_per_job_toggle(
    db_session: sessionmaker[Session],
    mock_notifier: MagicMock,
) -> None:
    store = SettingsStore(session_factory=db_session)
    store.set_setting("notification_job_policy", "always")
    service = NotificationService(settings_store=store, notifier=mock_notifier)

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-2", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-2", "local", {"path": "/dst"})
        job_disabled = JobRepository.create_job(
            session=session,
            name="job-notifications-off",
            source_remote_id=r1.id,
            source_path="/data",
            destination_remote_id=r2.id,
            destination_path="/data-dst",
            operation="copy",
            parallelization="none",
            notifications_enabled=False,  # Specific per-job toggle OFF
        )
        NotificationRepository.create_channel(
            session=session,
            name="Email Channel",
            url="mailto://user:pass@smtp.example.com",
            channel_type="email",
            enabled=True,
        )
        session.commit()
        job_disabled_id = job_disabled.id

    with db_session() as session:
        run_failed = JobRun(
            job_id=job_disabled_id,
            trigger="manual",
            status="failed",
            error_message="Fatal rclone error",
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        session.add(run_failed)
        session.commit()

        sent = service.notify_job_run_completion(session, run_failed)
        # Even though failed and policy is 'always', per-job toggle is OFF -> 0 sent
        assert sent == 0
        assert mock_notifier.send.call_count == 0
        assert run_failed.notification_sent_at is not None


def test_notify_rate_limiting(
    db_session: sessionmaker[Session],
    mock_notifier: MagicMock,
) -> None:
    store = SettingsStore(session_factory=db_session)
    store.set_setting("notification_job_policy", "always")
    service = NotificationService(settings_store=store, notifier=mock_notifier)

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-3", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-3", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-rate-limited",
            source_remote_id=r1.id,
            source_path="/data",
            destination_remote_id=r2.id,
            destination_path="/data-dst",
            operation="copy",
            parallelization="none",
            notifications_enabled=True,
        )
        NotificationRepository.create_channel(
            session=session,
            name="Rate Limited Channel",
            url="tgram://123456789:ABCdef/-100123456789/?format=html",
            channel_type="telegram",
            rate_limit_interval_s=60,  # 60s cooldown
            enabled=True,
        )
        session.commit()
        job_id = job.id

    # First run sends
    with db_session() as session:
        run1 = JobRun(
            job_id=job_id,
            trigger="manual",
            status="succeeded",
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        session.add(run1)
        session.commit()
        sent1 = service.notify_job_run_completion(session, run1)
        assert sent1 == 1
        assert mock_notifier.send.call_count == 1

    # Immediate second run is suppressed by rate limiter
    with db_session() as session:
        run2 = JobRun(
            job_id=job_id,
            trigger="manual",
            status="succeeded",
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        session.add(run2)
        session.commit()
        sent2 = service.notify_job_run_completion(session, run2)
        assert sent2 == 0
        assert mock_notifier.send.call_count == 1  # No additional send call


def test_notify_proxy_offline(
    db_session: sessionmaker[Session],
    mock_notifier: MagicMock,
) -> None:
    store = SettingsStore(session_factory=db_session)
    service = NotificationService(settings_store=store, notifier=mock_notifier)

    with db_session() as session:
        NotificationRepository.create_channel(
            session=session,
            name="Alerts Channel",
            url="tgram://123456789:ABCdef/-100123456789/?format=html",
            channel_type="telegram",
            enabled=True,
        )
        proxy = Proxy(
            name="edge-node-milan",
            host="192.168.1.50",
            port=50051,
            token_encrypted=b"encrypted_token",
            cert_fingerprint_sha256="a" * 64,
        )
        session.add(proxy)
        session.commit()
        proxy_id = proxy.id

    with db_session() as session:
        proxy_obj = session.get(Proxy, proxy_id)
        assert proxy_obj is not None

        # 1. Enabled -> sends alert
        store.set_setting("notification_proxy_offline_enabled", True)
        sent = service.notify_proxy_offline(
            session=session,
            proxy=proxy_obj,
            reason="Probe timeout after 3 attempts",
            consecutive_failures=3,
        )
        assert sent == 1
        assert mock_notifier.send.call_count == 1
        call_kwargs = mock_notifier.send.call_args[1]
        assert "Proxy 'edge-node-milan' Offline" in call_kwargs["title"]

    mock_notifier.reset_mock()

    with db_session() as session:
        proxy_obj = session.get(Proxy, proxy_id)
        assert proxy_obj is not None

        # 2. Disabled -> suppressed
        store.set_setting("notification_proxy_offline_enabled", False)
        sent = service.notify_proxy_offline(
            session=session,
            proxy=proxy_obj,
            reason="Probe timeout after 3 attempts",
            consecutive_failures=3,
        )
        assert sent == 0
        assert mock_notifier.send.call_count == 0


def test_notify_hook_failure(
    db_session: sessionmaker[Session],
    mock_notifier: MagicMock,
) -> None:
    store = SettingsStore(session_factory=db_session)
    service = NotificationService(settings_store=store, notifier=mock_notifier)

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-hook", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-hook", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="job-hook-test",
            source_remote_id=r1.id,
            source_path="/data",
            destination_remote_id=r2.id,
            destination_path="/backup",
            notifications_enabled=True,
        )
        NotificationRepository.create_channel(
            session=session,
            name="Telegram Ops",
            url="tgram://123456789:ABCdef/-100123456789/?format=html",
            channel_type="telegram",
            telegram_format="html",
            enabled=True,
        )
        session.commit()
        job_id = job.id

    # 1. Global notifications enabled -> sends notification on pre_run hook failure
    store.set_setting("notifications_enabled", True)
    with db_session() as session:
        run = JobRun(
            job_id=job_id,
            trigger="manual",
            status="queued",
            started_at=utc_now(),
        )
        session.add(run)
        session.commit()

        sent = service.notify_hook_failure(
            session=session,
            run=run,
            hook_type="pre_run",
            status="failed",
            exit_code=127,
            duration_ms=45.2,
            output="bash: /usr/local/bin/custom_script.sh: No such file or directory",
        )
        assert sent == 1
        assert mock_notifier.send.call_count == 1
        title = mock_notifier.send.call_args[1]["title"]
        body = mock_notifier.send.call_args[1]["body"]
        assert "Script Pre-Run" in title
        assert "job-hook-test" in title
        assert "custom_script.sh" in body

    mock_notifier.reset_mock()

    # 2. Global notifications disabled -> no notification
    store.set_setting("notifications_enabled", False)
    with db_session() as session:
        run = session.query(JobRun).filter_by(job_id=job_id).first()
        assert run is not None
        sent = service.notify_hook_failure(
            session=session,
            run=run,
            hook_type="post_run",
            status="failed",
            exit_code=1,
            output="Error in post-run",
        )
        assert sent == 0
        assert mock_notifier.send.call_count == 0


def test_notify_job_run_per_job_policy_override(
    db_session: sessionmaker[Session],
    mock_notifier: MagicMock,
) -> None:
    """Verify that per-job notification_policy ('always' / 'only_errors') overrides global policy."""
    store = SettingsStore(session_factory=db_session)
    service = NotificationService(settings_store=store, notifier=mock_notifier)

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-override", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-override", "local", {"path": "/dst"})
        job_always = JobRepository.create_job(
            session=session,
            name="job-policy-always",
            source_remote_id=r1.id,
            source_path="/data",
            destination_remote_id=r2.id,
            destination_path="/backup-always",
            operation="copy",
            parallelization="none",
            notifications_enabled=True,
            notification_policy="always",
        )
        job_only_errors = JobRepository.create_job(
            session=session,
            name="job-policy-only-errors",
            source_remote_id=r1.id,
            source_path="/data",
            destination_remote_id=r2.id,
            destination_path="/backup-errors",
            operation="copy",
            parallelization="none",
            notifications_enabled=True,
            notification_policy="only_errors",
        )
        NotificationRepository.create_channel(
            session=session,
            name="Alerts Channel",
            url="tgram://123456789:ABCdef/-100123456789/?format=html",
            channel_type="telegram",
            telegram_format="html",
            enabled=True,
        )
        session.commit()
        always_id = job_always.id
        only_errors_id = job_only_errors.id

    # CASE 1: Global policy is 'only_errors', but Job has 'always' -> SUCCESS triggers notification!
    store.set_setting("notification_job_policy", "only_errors")
    with db_session() as session:
        run_ok = JobRun(
            job_id=always_id,
            trigger="manual",
            status="succeeded",
            files_transferred=5,
            bytes_transferred=5000,
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        session.add(run_ok)
        session.commit()

        sent = service.notify_job_run_completion(session, run_ok)
        assert sent == 1
        assert mock_notifier.send.call_count == 1
        assert "job-policy-always" in mock_notifier.send.call_args[1]["title"]

    mock_notifier.reset_mock()

    # CASE 2: Global policy is 'always', but Job has 'only_errors' -> SUCCESS does NOT trigger notification!
    store.set_setting("notification_job_policy", "always")
    with db_session() as session:
        run_ok2 = JobRun(
            job_id=only_errors_id,
            trigger="manual",
            status="succeeded",
            files_transferred=10,
            bytes_transferred=10000,
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        session.add(run_ok2)
        session.commit()

        sent = service.notify_job_run_completion(session, run_ok2)
        assert sent == 0
        assert mock_notifier.send.call_count == 0

        # But a failed run DOES trigger notification
        run_fail = JobRun(
            job_id=only_errors_id,
            trigger="manual",
            status="failed",
            error_message="Disk full",
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        session.add(run_fail)
        session.commit()

        sent_fail = service.notify_job_run_completion(session, run_fail)
        assert sent_fail == 1
        assert mock_notifier.send.call_count == 1


def test_notify_proxy_untrusted(
    db_session: sessionmaker[Session],
    mock_notifier: MagicMock,
) -> None:
    import uuid

    store = SettingsStore(session_factory=db_session)
    service = NotificationService(settings_store=store, notifier=mock_notifier)

    with db_session() as session:
        NotificationRepository.create_channel(
            session=session,
            name="channel-untrusted",
            channel_type="webhook",
            url="json://localhost/untrusted",
            enabled=True,
        )
        proxy = Proxy(
            id=uuid.uuid4(),
            name="Proxy-Alpha",
            host="10.0.0.1",
            port=8443,
            token_encrypted=b"tok_bytes_dummy",
            cert_fingerprint_sha256="aa" * 32,
            is_enabled=True,
        )
        session.add(proxy)
        session.commit()

        sent = service.notify_proxy_untrusted(
            session=session,
            proxy=proxy,
            reason="TLS certificate fingerprint changed: expected aaaa..., received bbbb...",
        )
        assert sent == 1
        assert mock_notifier.send.call_count == 1
        call_kwargs = mock_notifier.send.call_args[1]
        assert "Proxy-Alpha" in call_kwargs["title"]
        assert "Proxy-Alpha" in call_kwargs["body"]


def test_notify_proxy_cert_expiring(
    db_session: sessionmaker[Session],
    mock_notifier: MagicMock,
) -> None:
    import datetime
    import uuid

    store = SettingsStore(session_factory=db_session)
    service = NotificationService(settings_store=store, notifier=mock_notifier)

    with db_session() as session:
        NotificationRepository.create_channel(
            session=session,
            name="channel-expiring",
            channel_type="webhook",
            url="json://localhost/expiring",
            enabled=True,
        )
        proxy = Proxy(
            id=uuid.uuid4(),
            name="Proxy-Beta",
            host="10.0.0.2",
            port=8443,
            token_encrypted=b"tok_bytes_dummy",
            cert_fingerprint_sha256="aa" * 32,
            is_enabled=True,
        )
        session.add(proxy)
        session.commit()

        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
        sent = service.notify_proxy_cert_expiring(
            session=session,
            proxy=proxy,
            days_remaining=10,
            cert_expires_at=expires_at,
        )
        assert sent == 1
        assert mock_notifier.send.call_count == 1
        call_kwargs = mock_notifier.send.call_args[1]
        assert "Proxy-Beta" in call_kwargs["title"]
        assert "10" in call_kwargs["body"]
