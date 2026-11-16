"""Periodic scheduler for evaluating and triggering cron-scheduled backup jobs."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
import uuid as _uuid
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.observability import get_logger
from embervault_db.models.execution import JobRun
from embervault_db.models.remotes import Job
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.repositories.job_repository import compute_next_run_at
from embervault_db.settings_store import SettingsStore
from embervault_orchestrator.internal_api import cancel_assignments_on_proxies, execute_job_run
from embervault_orchestrator.notifier import NotificationService
from embervault_orchestrator.proxy_client import ProxyClient

logger = get_logger("embervault_orchestrator.scheduler")

_MISSED_RUN_GRACE_SECONDS = 360.0


class JobScheduler:
    """Evaluates cron schedules on enabled jobs and triggers runs when due."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        settings_store: SettingsStore | None = None,
        proxy_client: ProxyClient | None = None,
        notification_service: NotificationService | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.settings_store = settings_store or SettingsStore(session_factory)
        self.proxy_client = proxy_client or ProxyClient()
        self.notification_service = notification_service or NotificationService(self.settings_store)

    @staticmethod
    def _format_time_in_job_tz(dt: datetime | None, tz_name: str | None) -> str:
        """Format a timestamp in the job's configured timezone for human-readable policy messages."""
        if dt is None:
            return "N/D"
        utc_dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
        try:
            tz = ZoneInfo(tz_name or "UTC")
        except Exception:
            tz = ZoneInfo("UTC")
        local_dt = utc_dt.astimezone(tz)
        return local_dt.strftime("%H:%M (%Y-%m-%d %Z)")

    def check_and_trigger_due_jobs(self) -> list[dict[str, Any]]:
        """Check all enabled jobs with schedule_cron and trigger runs if due.

        Returns:
            List of execution summary dictionaries for jobs that were triggered.
        """
        now = datetime.now(UTC)
        triggered_runs: list[dict[str, Any]] = []

        with self.session_factory() as session:
            stmt = select(Job).where(Job.enabled.is_(True), Job.schedule_cron.is_not(None))
            jobs = list(session.scalars(stmt).all())

            for job in jobs:
                if not job.schedule_cron or not job.schedule_cron.strip():
                    continue

                follow_dst = bool(getattr(job, "follow_dst", True))

                # 1. Initialize next_run_at if missing
                if job.next_run_at is None:
                    job.next_run_at = compute_next_run_at(
                        cron_expr=job.schedule_cron,
                        tz_name=job.timezone or "UTC",
                        base_time=now,
                        follow_dst=follow_dst,
                    )
                    session.commit()
                    logger.info(
                        "job_schedule_initialized",
                        job_id=str(job.id),
                        job_name=job.name,
                        cron=job.schedule_cron,
                        timezone=job.timezone,
                        follow_dst=follow_dst,
                        next_run_at=job.next_run_at.isoformat() if job.next_run_at else None,
                    )
                    continue

                scheduled_time = job.next_run_at
                if getattr(scheduled_time, "tzinfo", None) is None:
                    scheduled_time = scheduled_time.replace(tzinfo=UTC)

                # 2. Check if due
                if scheduled_time > now:
                    continue

                delay_s = (now - scheduled_time).total_seconds()
                scheduled_str = self._format_time_in_job_tz(scheduled_time, job.timezone)

                effective_missed_policy = (
                    job.missed_run_policy
                    if job.missed_run_policy in ("skip", "run_once", "fail")
                    else (
                        self.settings_store.get_setting("default_missed_run_policy")
                        if self.settings_store
                        else None
                    )
                    or "run_once"
                )
                effective_overlap_policy = (
                    job.overlap_policy
                    if job.overlap_policy in ("skip", "allow", "cancel_previous", "queue", "fail")
                    else (
                        self.settings_store.get_setting("default_overlap_policy")
                        if self.settings_store
                        else None
                    )
                    or "skip"
                )

                logger.info(
                    "scheduled_job_due",
                    job_id=str(job.id),
                    job_name=job.name,
                    scheduled_time=scheduled_time.isoformat(),
                    delay_seconds=delay_s,
                    missed_run_policy=effective_missed_policy,
                    overlap_policy=effective_overlap_policy,
                )

                # 3. Check missed run policy (when scheduled fire window was missed while down)
                missed_run_msg: str | None = None
                if delay_s >= _MISSED_RUN_GRACE_SECONDS:
                    if effective_missed_policy == "fail":
                        msg = (
                            f"L'esecuzione del job '{job.name}' prevista per le {scheduled_str} "
                            "non è stata avviata ed è stata segnata come fallita perché EmberVault "
                            "non era in esecuzione all'orario indicato nel Job."
                        )
                        logger.warning(
                            "scheduled_job_missed_run_failed",
                            job_id=str(job.id),
                            job_name=job.name,
                            delay_seconds=delay_s,
                            policy="fail",
                        )
                        failed_run = ExecutionRepository.create_failed_missed_run(
                            session, job, scheduled_time, msg
                        )
                        if getattr(job, "missed_run_notify", False):
                            self.notification_service.notify_job_policy_executed(
                                session,
                                job,
                                policy_type="missed_run",
                                policy_value="fail",
                                message=msg,
                                run_id=failed_run.id,
                            )
                        job.next_run_at = compute_next_run_at(
                            cron_expr=job.schedule_cron,
                            tz_name=job.timezone or "UTC",
                            base_time=now,
                            previous_fire_time=scheduled_time,
                            follow_dst=follow_dst,
                        )
                        session.commit()
                        continue
                    elif effective_missed_policy == "skip":
                        msg = (
                            f"L'esecuzione del job '{job.name}' prevista per le {scheduled_str} "
                            "non è stata avviata perché EmberVault non era in esecuzione e la "
                            "Missed Run Policy è impostata a SKIP."
                        )
                        logger.warning(
                            "scheduled_job_missed_run_skipped",
                            job_id=str(job.id),
                            job_name=job.name,
                            delay_seconds=delay_s,
                            policy="skip",
                        )
                        if getattr(job, "missed_run_notify", False):
                            self.notification_service.notify_job_policy_executed(
                                session,
                                job,
                                policy_type="missed_run",
                                policy_value="skip",
                                message=msg,
                            )
                        job.next_run_at = compute_next_run_at(
                            cron_expr=job.schedule_cron,
                            tz_name=job.timezone or "UTC",
                            base_time=now,
                            previous_fire_time=scheduled_time,
                            follow_dst=follow_dst,
                        )
                        session.commit()
                        continue
                    elif effective_missed_policy == "run_once":
                        missed_run_msg = (
                            f"Il job '{job.name}' aveva un'esecuzione prevista per le {scheduled_str} "
                            "mentre EmberVault non era in esecuzione. L'esecuzione mancata è stata "
                            "avviata ora perché la Missed Run Policy è impostata per avviarla."
                        )

                # 4. Check overlap policy
                active_runs = ExecutionRepository.get_active_runs_for_job(session, job.id)
                overlap_msg: str | None = None
                overlap_val: str | None = None

                if active_runs:
                    active_run = active_runs[0]
                    active_start_str = self._format_time_in_job_tz(
                        active_run.started_at or active_run.created_at, job.timezone
                    )
                    if effective_overlap_policy == "skip":
                        msg = (
                            f"Il job '{job.name}' era ancora in corso nell'esecuzione delle "
                            f"{active_start_str}. Non è stata istanziata una nuova esecuzione "
                            "perché la Overlap Policy è impostata a SKIP. L'esecuzione prevista "
                            f"per le {scheduled_str} è quindi stata saltata."
                        )
                        logger.info(
                            "scheduled_job_overlap_skipped",
                            job_id=str(job.id),
                            job_name=job.name,
                            active_run_id=str(active_run.id),
                        )
                        if getattr(job, "overlap_notify", False):
                            self.notification_service.notify_job_policy_executed(
                                session,
                                job,
                                policy_type="overlap",
                                policy_value="skip",
                                message=msg,
                                run_id=active_run.id,
                            )
                        job.next_run_at = compute_next_run_at(
                            cron_expr=job.schedule_cron,
                            tz_name=job.timezone or "UTC",
                            base_time=now,
                            previous_fire_time=scheduled_time,
                            follow_dst=follow_dst,
                        )
                        session.commit()
                        continue
                    elif effective_overlap_policy == "fail":
                        msg = (
                            f"Esecuzione pianificata fallita per sovrapposizione con run attiva {active_run.id} "
                            "(overlap_policy=fail)."
                        )
                        logger.warning(
                            "scheduled_job_overlap_failed",
                            job_id=str(job.id),
                            job_name=job.name,
                            active_run_id=str(active_run.id),
                        )
                        failed_run = JobRun(
                            id=_uuid.uuid4(),
                            job_id=job.id,
                            trigger="schedule",
                            status="failed",
                            error_message=msg,
                            started_at=now,
                            finished_at=now,
                            notification_sent_at=now,
                            job_snapshot={
                                "name": job.name,
                                "source_path": job.source_path,
                                "destination_path": job.destination_path,
                            },
                        )
                        session.add(failed_run)
                        if getattr(job, "overlap_notify", False):
                            self.notification_service.notify_job_policy_executed(
                                session,
                                job,
                                policy_type="overlap",
                                policy_value="fail",
                                message=msg,
                                run_id=failed_run.id,
                            )
                        job.next_run_at = compute_next_run_at(
                            cron_expr=job.schedule_cron,
                            tz_name=job.timezone or "UTC",
                            base_time=now,
                            previous_fire_time=scheduled_time,
                            follow_dst=follow_dst,
                        )
                        session.commit()
                        continue
                    elif effective_overlap_policy == "cancel_previous":
                        logger.info(
                            "scheduled_job_overlap_cancel_previous",
                            job_id=str(job.id),
                            job_name=job.name,
                            active_run_ids=[str(ar.id) for ar in active_runs],
                        )
                        for ar in active_runs:
                            _, active_assigns = ExecutionRepository.cancel_run(session, ar.id)
                            ar.error_code = "OVERLAP_CANCELLED_PREVIOUS"
                            ar.error_message = (
                                f"Esecuzione interrotta perché è stata avviata la nuova esecuzione "
                                f"pianificata delle {scheduled_str} (Overlap Policy: STOP_PREVIOUS)."
                            )
                            ar.notification_sent_at = now
                            cancel_assignments_on_proxies(
                                session, active_assigns, self.proxy_client
                            )
                        session.flush()
                        overlap_val = "cancel_previous"
                        overlap_msg = (
                            f"Il job '{job.name}' era ancora in corso nell'esecuzione delle "
                            f"{active_start_str}. La run precedente è stata interrotta ed è stata "
                            f"avviata la nuova esecuzione prevista per le {scheduled_str} "
                            "perché la Overlap Policy è impostata su STOP_PREVIOUS."
                        )
                    elif effective_overlap_policy == "allow":
                        logger.info(
                            "scheduled_job_overlap_allow",
                            job_id=str(job.id),
                            job_name=job.name,
                            active_run_id=str(active_run.id),
                        )
                        overlap_val = "allow"
                        overlap_msg = (
                            f"Il job '{job.name}' era ancora in corso nell'esecuzione delle "
                            f"{active_start_str}. È stata avviata comunque la nuova esecuzione "
                            f"prevista per le {scheduled_str} perché la Overlap Policy è impostata a ALLOW."
                        )

                # 5. Trigger the job run
                try:
                    res = execute_job_run(
                        session=session,
                        job_id=job.id,
                        trigger="schedule",
                        settings_store=self.settings_store,
                        proxy_client=self.proxy_client,
                    )
                    triggered_runs.append(res)
                    run_id_str = res.get("run_id")
                    logger.info(
                        "scheduled_job_run_dispatched",
                        job_id=str(job.id),
                        job_name=job.name,
                        run_id=run_id_str,
                        planned_task_count=res.get("planned_task_count"),
                    )
                    if missed_run_msg and getattr(job, "missed_run_notify", False):
                        self.notification_service.notify_job_policy_executed(
                            session,
                            job,
                            policy_type="missed_run",
                            policy_value="run_once",
                            message=missed_run_msg,
                            run_id=run_id_str,
                        )
                    if overlap_msg and overlap_val and getattr(job, "overlap_notify", False):
                        self.notification_service.notify_job_policy_executed(
                            session,
                            job,
                            policy_type="overlap",
                            policy_value=overlap_val,
                            message=overlap_msg,
                            run_id=run_id_str,
                        )
                except Exception as exc:
                    logger.error(
                        "scheduled_job_trigger_error",
                        job_id=str(job.id),
                        job_name=job.name,
                        error=str(exc),
                    )

                # 6. Advance next_run_at to the next future fire time
                job.next_run_at = compute_next_run_at(
                    cron_expr=job.schedule_cron,
                    tz_name=job.timezone or "UTC",
                    base_time=now,
                    previous_fire_time=scheduled_time,
                    follow_dst=follow_dst,
                )
                session.commit()

        return triggered_runs
