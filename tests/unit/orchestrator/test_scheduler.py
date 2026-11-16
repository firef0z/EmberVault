"""Unit tests for JobScheduler and cron evaluation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
import uuid
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.base import Base
from embervault_db.models.execution import JobRun
from embervault_db.models.remotes import Job
from embervault_db.repositories.job_repository import JobRepository, compute_next_run_at
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.settings_store import SettingsStore
from embervault_orchestrator.reconciler import ExecutionReconciler
from embervault_orchestrator.scheduler import JobScheduler


@pytest.fixture
def db_session() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "test_encryption_key_32_characters_"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_compute_next_run_at() -> None:
    # 1. Empty / None
    assert compute_next_run_at(None) is None
    assert compute_next_run_at("") is None
    assert compute_next_run_at("   ") is None

    # 2. Invalid cron
    assert compute_next_run_at("invalid cron syntax") is None

    # 3. Valid hourly cron
    base = datetime(2026, 10, 25, 3, 30, 0, tzinfo=UTC)
    next_run = compute_next_run_at("0 * * * *", tz_name="UTC", base_time=base)
    assert next_run is not None
    assert next_run == datetime(2026, 10, 25, 4, 0, 0, tzinfo=UTC)

    # 4. Advance with previous_fire_time
    t_0400 = datetime(2026, 10, 25, 4, 0, 0, tzinfo=UTC)
    next_after_fire = compute_next_run_at(
        "0 * * * *",
        tz_name="UTC",
        base_time=t_0400,
        previous_fire_time=t_0400,
    )
    assert next_after_fire == datetime(2026, 10, 25, 5, 0, 0, tzinfo=UTC)

    # 5. Non-UTC Timezone (e.g. Europe/Rome in winter +01:00)
    # Cron at 02:00 Rome time -> 01:00 UTC
    rome_base = datetime(2026, 10, 25, 10, 0, 0, tzinfo=UTC)
    next_rome = compute_next_run_at("0 2 * * *", tz_name="Europe/Rome", base_time=rome_base)
    assert next_rome is not None
    assert next_rome == datetime(2026, 10, 26, 1, 0, 0, tzinfo=UTC)

    # 6. Summer DST follow_dst=True vs follow_dst=False for 01:00 Europe/Rome
    summer_base = datetime(2026, 7, 15, 12, 0, 0, tzinfo=UTC)
    assert compute_next_run_at(
        "0 1 * * *", tz_name="Europe/Rome", base_time=summer_base, follow_dst=True
    ) == datetime(2026, 7, 15, 23, 0, 0, tzinfo=UTC)
    assert compute_next_run_at(
        "0 1 * * *", tz_name="Europe/Rome", base_time=summer_base, follow_dst=False
    ) == datetime(2026, 7, 16, 0, 0, 0, tzinfo=UTC)


def as_utc(dt: datetime | None) -> datetime:
    if dt is None:
        raise ValueError("Datetime is None")
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def test_job_scheduler_initializes_missing_next_run_at(
    db_session: sessionmaker[Session],
) -> None:
    store = SettingsStore(session_factory=db_session)
    scheduler = JobScheduler(session_factory=db_session, settings_store=store)

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst", "local", {"path": "/dst"})
        job = JobRepository.create_job(
            session=session,
            name="hourly-backup",
            source_remote_id=r1.id,
            source_path="/src",
            destination_remote_id=r2.id,
            destination_path="/dst",
            schedule_cron="0 * * * *",
        )
        # Force next_run_at to None to simulate pre-existing job in DB
        job.next_run_at = None
        session.commit()
        job_id = job.id

    # Running scheduler initializes next_run_at
    triggered = scheduler.check_and_trigger_due_jobs()
    assert len(triggered) == 0

    with db_session() as session:
        job = JobRepository.get_job_by_id(session, job_id)
        assert job is not None
        assert job.next_run_at is not None
        assert as_utc(job.next_run_at) > datetime.now(UTC)


def test_job_scheduler_triggers_due_job(
    db_session: sessionmaker[Session],
) -> None:
    store = SettingsStore(session_factory=db_session)
    scheduler = JobScheduler(session_factory=db_session, settings_store=store)

    past_time = datetime.now(UTC) - timedelta(minutes=5)

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src2", "local", {"path": "/src2"})
        r2 = RemoteRepository.create_remote(session, "dst2", "local", {"path": "/dst2"})
        job = JobRepository.create_job(
            session=session,
            name="due-job",
            source_remote_id=r1.id,
            source_path="/src2",
            destination_remote_id=r2.id,
            destination_path="/dst2",
            schedule_cron="0 * * * *",
        )
        job.next_run_at = past_time
        session.commit()
        job_id = job.id

    mock_execute_res = {
        "status": "dispatched",
        "run_id": str(uuid.uuid4()),
        "job_id": str(job_id),
        "job_name": "due-job",
        "planned_task_count": 1,
        "dispatched_count": 1,
    }

    with patch(
        "embervault_orchestrator.scheduler.execute_job_run", return_value=mock_execute_res
    ) as mock_exec:
        triggered = scheduler.check_and_trigger_due_jobs()
        assert len(triggered) == 1
        assert triggered[0]["job_id"] == str(job_id)
        assert mock_exec.called is True
        call_kwargs = mock_exec.call_args.kwargs
        assert call_kwargs["trigger"] == "schedule"
        assert call_kwargs["job_id"] == job_id

    # Verify next_run_at was advanced to a future time
    with db_session() as session:
        job = JobRepository.get_job_by_id(session, job_id)
        assert job is not None
        assert job.next_run_at is not None
        assert as_utc(job.next_run_at) > datetime.now(UTC)


def test_job_scheduler_overlap_policy_skip(
    db_session: sessionmaker[Session],
) -> None:
    store = SettingsStore(session_factory=db_session)
    scheduler = JobScheduler(session_factory=db_session, settings_store=store)

    past_time = datetime.now(UTC) - timedelta(minutes=2)

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src3", "local", {"path": "/src3"})
        r2 = RemoteRepository.create_remote(session, "dst3", "local", {"path": "/dst3"})
        job = JobRepository.create_job(
            session=session,
            name="overlap-skip-job",
            source_remote_id=r1.id,
            source_path="/src3",
            destination_remote_id=r2.id,
            destination_path="/dst3",
            schedule_cron="0 * * * *",
            overlap_policy="skip",
        )
        job.next_run_at = past_time
        # Create an active running run
        run = JobRun(
            job_id=job.id,
            trigger="schedule",
            status="running",
        )
        session.add(run)
        session.commit()
        job_id = job.id

    with patch("embervault_orchestrator.scheduler.execute_job_run") as mock_exec:
        triggered = scheduler.check_and_trigger_due_jobs()
        assert len(triggered) == 0
        assert mock_exec.called is False

    with db_session() as session:
        job = JobRepository.get_job_by_id(session, job_id)
        assert job is not None
        assert job.next_run_at is not None
        assert as_utc(job.next_run_at) > datetime.now(UTC)


def test_job_scheduler_overlap_policy_fail(
    db_session: sessionmaker[Session],
) -> None:
    store = SettingsStore(session_factory=db_session)
    scheduler = JobScheduler(session_factory=db_session, settings_store=store)

    past_time = datetime.now(UTC) - timedelta(minutes=2)

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src4", "local", {"path": "/src4"})
        r2 = RemoteRepository.create_remote(session, "dst4", "local", {"path": "/dst4"})
        job = JobRepository.create_job(
            session=session,
            name="overlap-fail-job",
            source_remote_id=r1.id,
            source_path="/src4",
            destination_remote_id=r2.id,
            destination_path="/dst4",
            schedule_cron="0 * * * *",
            overlap_policy="fail",
        )
        job.next_run_at = past_time
        # Create an active running run
        run = JobRun(
            job_id=job.id,
            trigger="schedule",
            status="running",
        )
        session.add(run)
        session.commit()
        job_id = job.id

    with patch("embervault_orchestrator.scheduler.execute_job_run") as mock_exec:
        triggered = scheduler.check_and_trigger_due_jobs()
        assert len(triggered) == 0
        assert mock_exec.called is False

    # Verify a failed run was created
    with db_session() as session:
        runs = session.scalars(select(JobRun).where(JobRun.job_id == job_id)).all()
        assert len(runs) == 2
        failed_run = next(r for r in runs if r.status == "failed")
        assert "sovrapposizione" in (failed_run.error_message or "").lower()


def test_reconciler_invokes_scheduler(
    db_session: sessionmaker[Session],
) -> None:
    reconciler = ExecutionReconciler(session_factory=db_session)

    with patch.object(
        reconciler.job_scheduler, "check_and_trigger_due_jobs", return_value=[]
    ) as mock_sched:
        stats = reconciler.reconcile_once()
        assert mock_sched.called is True
        assert "scheduled_jobs_triggered" in stats


def test_job_scheduler_respects_follow_dst_flag(
    db_session: sessionmaker[Session],
) -> None:
    store = SettingsStore(session_factory=db_session)
    scheduler = JobScheduler(session_factory=db_session, settings_store=store)

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src_dst", "local", {"path": "/src_dst"})
        r2 = RemoteRepository.create_remote(session, "dst_dst", "local", {"path": "/dst_dst"})
        job = JobRepository.create_job(
            session=session,
            name="rome-no-dst-job",
            source_remote_id=r1.id,
            source_path="/src_dst",
            destination_remote_id=r2.id,
            destination_path="/dst_dst",
            schedule_cron="0 1 * * *",
            timezone="Europe/Rome",
            follow_dst=False,
        )
        job.next_run_at = None
        session.commit()
        job_id = job.id

    with patch("embervault_orchestrator.scheduler.compute_next_run_at") as mock_compute:
        mock_compute.return_value = datetime(2026, 7, 16, 0, 0, 0, tzinfo=UTC)
        scheduler.check_and_trigger_due_jobs()
        assert mock_compute.called is True
        assert mock_compute.call_args.kwargs["tz_name"] == "Europe/Rome"
        assert mock_compute.call_args.kwargs["follow_dst"] is False

    with db_session() as session:
        loaded = JobRepository.get_job_by_id(session, job_id)
        assert loaded is not None
        assert loaded.follow_dst is False
        assert loaded.next_run_at is not None


def test_job_scheduler_missed_run_policy_fail_and_notify(
    db_session: sessionmaker[Session],
) -> None:
    store = SettingsStore(session_factory=db_session)
    notifier = MagicMock()
    scheduler = JobScheduler(
        session_factory=db_session,
        settings_store=store,
        notification_service=notifier,
    )

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src_mf", "local", {"path": "/src_mf"})
        r2 = RemoteRepository.create_remote(session, "dst_mf", "local", {"path": "/dst_mf"})
        job = JobRepository.create_job(
            session=session,
            name="missed-fail-job",
            source_remote_id=r1.id,
            source_path="/src_mf",
            destination_remote_id=r2.id,
            destination_path="/dst_mf",
            schedule_cron="0 1 * * *",
            missed_run_policy="fail",
            missed_run_notify=True,
        )
        # Missed by 2 hours (> 360s grace window)
        job.next_run_at = datetime.now(UTC) - timedelta(hours=2)
        session.commit()
        job_id = job.id

    with patch("embervault_orchestrator.scheduler.execute_job_run") as mock_exec:
        res = scheduler.check_and_trigger_due_jobs()
        assert res == []
        assert mock_exec.called is False

    assert notifier.notify_job_policy_executed.call_count == 1
    call_kwargs = notifier.notify_job_policy_executed.call_args.kwargs
    assert call_kwargs["policy_type"] == "missed_run"
    assert call_kwargs["policy_value"] == "fail"

    with db_session() as session:
        runs = list(session.scalars(select(JobRun).where(JobRun.job_id == job_id)).all())
        assert len(runs) == 1
        assert runs[0].status == "failed"
        assert runs[0].error_code == "MISSED_RUN_FAILED"
        assert "non era in esecuzione all'orario indicato" in (runs[0].error_message or "")
        reloaded = JobRepository.get_job_by_id(session, job_id)
        assert reloaded is not None and as_utc(reloaded.next_run_at) > datetime.now(UTC) - timedelta(seconds=5)


def test_job_scheduler_missed_run_once_and_independent_notify_flags(
    db_session: sessionmaker[Session],
) -> None:
    store = SettingsStore(session_factory=db_session)
    notifier = MagicMock()
    scheduler = JobScheduler(
        session_factory=db_session,
        settings_store=store,
        notification_service=notifier,
    )

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src_mo", "local", {"path": "/src_mo"})
        r2 = RemoteRepository.create_remote(session, "dst_mo", "local", {"path": "/dst_mo"})
        j_notify = JobRepository.create_job(
            session=session,
            name="missed-once-notify",
            source_remote_id=r1.id,
            source_path="/a",
            destination_remote_id=r2.id,
            destination_path="/b",
            schedule_cron="0 2 * * *",
            missed_run_policy="run_once",
            missed_run_notify=True,
        )
        j_silent = JobRepository.create_job(
            session=session,
            name="missed-once-silent",
            source_remote_id=r1.id,
            source_path="/c",
            destination_remote_id=r2.id,
            destination_path="/d",
            schedule_cron="0 3 * * *",
            missed_run_policy="run_once",
            missed_run_notify=False,
        )
        j_notify.next_run_at = datetime.now(UTC) - timedelta(hours=1)
        j_silent.next_run_at = datetime.now(UTC) - timedelta(hours=1)
        session.commit()

    with patch("embervault_orchestrator.scheduler.execute_job_run") as mock_exec:
        mock_exec.return_value = {"run_id": str(uuid.uuid4()), "planned_task_count": 1}
        triggered = scheduler.check_and_trigger_due_jobs()
        assert len(triggered) == 2
        assert mock_exec.call_count == 2

    # Only the job with missed_run_notify=True sent a policy notification
    assert notifier.notify_job_policy_executed.call_count == 1
    assert notifier.notify_job_policy_executed.call_args.args[1].name == "missed-once-notify"


def test_job_scheduler_overlap_cancel_previous_and_allow(
    db_session: sessionmaker[Session],
) -> None:
    store = SettingsStore(session_factory=db_session)
    notifier = MagicMock()
    scheduler = JobScheduler(
        session_factory=db_session,
        settings_store=store,
        notification_service=notifier,
    )

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src_ov", "local", {"path": "/src_ov"})
        r2 = RemoteRepository.create_remote(session, "dst_ov", "local", {"path": "/dst_ov"})
        j_cancel = JobRepository.create_job(
            session=session,
            name="overlap-cancel-job",
            source_remote_id=r1.id,
            source_path="/1",
            destination_remote_id=r2.id,
            destination_path="/2",
            schedule_cron="*/5 * * * *",
            overlap_policy="cancel_previous",
            overlap_notify=True,
            pending_notify=False,
        )
        j_allow = JobRepository.create_job(
            session=session,
            name="overlap-allow-job",
            source_remote_id=r1.id,
            source_path="/3",
            destination_remote_id=r2.id,
            destination_path="/4",
            schedule_cron="*/5 * * * *",
            overlap_policy="allow",
            overlap_notify=False,
        )
        run_prev = JobRun(
            id=uuid.uuid4(),
            job_id=j_cancel.id,
            trigger="schedule",
            status="running",
            started_at=datetime.now(UTC) - timedelta(minutes=10),
        )
        run_keep = JobRun(
            id=uuid.uuid4(),
            job_id=j_allow.id,
            trigger="schedule",
            status="running",
            started_at=datetime.now(UTC) - timedelta(minutes=8),
        )
        session.add_all([run_prev, run_keep])
        j_cancel.next_run_at = datetime.now(UTC) - timedelta(seconds=20)
        j_allow.next_run_at = datetime.now(UTC) - timedelta(seconds=20)
        session.commit()
        run_prev_id = run_prev.id
        run_keep_id = run_keep.id

    with (
        patch("embervault_orchestrator.scheduler.cancel_assignments_on_proxies") as mock_cancel_px,
        patch("embervault_orchestrator.scheduler.execute_job_run") as mock_exec,
    ):
        mock_exec.return_value = {"run_id": str(uuid.uuid4()), "planned_task_count": 1}
        triggered = scheduler.check_and_trigger_due_jobs()
        assert len(triggered) == 2
        assert mock_exec.call_count == 2
        assert mock_cancel_px.called is True

    # Only overlap-cancel-job has overlap_notify=True
    assert notifier.notify_job_policy_executed.call_count == 1
    assert notifier.notify_job_policy_executed.call_args.kwargs["policy_type"] == "overlap"
    assert notifier.notify_job_policy_executed.call_args.kwargs["policy_value"] == "cancel_previous"

    with db_session() as session:
        prev_loaded = session.get(JobRun, run_prev_id)
        keep_loaded = session.get(JobRun, run_keep_id)
        assert prev_loaded is not None and prev_loaded.status == "cancelled"
        assert prev_loaded.error_code == "OVERLAP_CANCELLED_PREVIOUS"
        assert keep_loaded is not None and keep_loaded.status == "running"


def test_reconciler_enforces_max_runtime_policy(
    db_session: sessionmaker[Session],
) -> None:
    notifier = MagicMock()
    reconciler = ExecutionReconciler(
        session_factory=db_session,
        notification_service=notifier,
    )

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src_rt", "local", {"path": "/src_rt"})
        r2 = RemoteRepository.create_remote(session, "dst_rt", "local", {"path": "/dst_rt"})
        job = JobRepository.create_job(
            session=session,
            name="max-rt-job",
            source_remote_id=r1.id,
            source_path="/src_rt",
            destination_remote_id=r2.id,
            destination_path="/dst_rt",
            max_runtime_minutes=30,
            max_runtime_notify=True,
        )
        run = JobRun(
            id=uuid.uuid4(),
            job_id=job.id,
            trigger="manual",
            status="running",
            started_at=datetime.now(UTC) - timedelta(minutes=45),
        )
        session.add(run)
        session.commit()
        run_id = run.id

    # Mark startup recovered so run isn't treated as prior-process pending run
    reconciler._startup_recovered = True
    reconciler.reconcile_once()

    with db_session() as session:
        loaded = session.get(JobRun, run_id)
        assert loaded is not None
        assert loaded.status == "failed"
        assert loaded.error_code == "MAX_RUNTIME_EXCEEDED"
        assert "Max Runtime Policy" in (loaded.error_message or "")

    assert notifier.notify_job_policy_executed.call_count == 1
    assert notifier.notify_job_policy_executed.call_args.kwargs["policy_type"] == "max_runtime"
    assert notifier.notify_job_policy_executed.call_args.kwargs["policy_value"] == "30m"


def test_scheduler_resolves_general_settings_defaults(
    db_session: sessionmaker[Session],
) -> None:
    """Verify that when a job has no policy set (None), the general settings default is applied."""
    store = SettingsStore(db_session)
    store.set_setting("default_missed_run_policy", "fail")
    store.set_setting("default_overlap_policy", "cancel_previous")
    store.set_setting("default_pending_policy", "retry")

    notifier = MagicMock()
    scheduler = JobScheduler(
        session_factory=db_session,
        settings_store=store,
        notification_service=notifier,
    )

    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src_def", "local", {"path": "/src_def"})
        r2 = RemoteRepository.create_remote(session, "dst_def", "local", {"path": "/dst_def"})
        # Create job with default policies (missed_run_policy=None, overlap_policy=None)
        job = JobRepository.create_job(
            session=session,
            name="job-default-policies",
            source_remote_id=r1.id,
            source_path="/src_def",
            destination_remote_id=r2.id,
            destination_path="/dst_def",
            schedule_cron="0 1 * * *",
            missed_run_policy=None,
            overlap_policy=None,
            pending_policy=None,
            missed_run_notify=True,
            overlap_notify=True,
        )
        assert job.missed_run_policy is None
        assert job.overlap_policy is None
        assert job.pending_policy is None

        # Simulate scheduled run overdue by 1 hour (3600s > 360s grace)
        past_time = datetime.now(UTC) - timedelta(hours=1)
        job.next_run_at = past_time
        session.commit()
        job_id = job.id

    # Missed run policy should resolve to general setting 'fail'
    scheduler.check_and_trigger_due_jobs()

    with db_session() as session:
        runs = list(session.scalars(select(JobRun).where(JobRun.job_id == job_id)).all())
        assert len(runs) == 1
        assert runs[0].status == "failed"
        assert runs[0].error_code == "MISSED_RUN_FAILED"

    assert notifier.notify_job_policy_executed.call_count == 1
    call_kwargs = notifier.notify_job_policy_executed.call_args.kwargs
    assert call_kwargs["policy_type"] == "missed_run"
    assert call_kwargs["policy_value"] == "fail"

