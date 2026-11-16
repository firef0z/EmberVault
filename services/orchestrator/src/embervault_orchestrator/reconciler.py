"""Background reconciliation loop for active JobRuns, running tasks, and stale leases."""

from __future__ import annotations

import os
import threading
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from embervault_common.contracts.enums import TaskState
from embervault_common.observability import get_logger
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.settings_store import SettingsStore
from embervault_orchestrator.ai_evaluator import AIErrorEvaluator
from embervault_orchestrator.internal_api import cancel_assignments_on_proxies
from embervault_orchestrator.notifier import NotificationService
from embervault_orchestrator.proxy_client import ProxyClient
from embervault_orchestrator.scheduler import JobScheduler

logger = get_logger("embervault_orchestrator.reconciler")


def utc_now() -> datetime:
    return datetime.now(UTC)


class ExecutionReconciler:
    """Monitors running tasks across proxies, synchronizes progress, reaps expired leases, and dispatches ready tasks."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        proxy_client: ProxyClient | None = None,
        poll_interval_s: float = 3.0,
        settings_store: SettingsStore | None = None,
        notification_service: NotificationService | None = None,
        settings: Any | None = None,
        recover_stale_on_startup: bool = False,
    ) -> None:
        self.session_factory = session_factory
        self.proxy_client = proxy_client or ProxyClient()
        self.poll_interval_s = poll_interval_s
        self.settings = settings
        self.settings_store = settings_store or SettingsStore(session_factory)
        self.notification_service = notification_service or NotificationService(self.settings_store)
        self.ai_evaluator = AIErrorEvaluator(self.settings_store)
        self.job_scheduler = JobScheduler(
            session_factory=self.session_factory,
            settings_store=self.settings_store,
            proxy_client=self.proxy_client,
            notification_service=self.notification_service,
        )
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_cleanup_ts: float = 0.0
        self._last_auto_backup_check_ts: float = 0.0
        self._last_rclone_update_check_ts: float = 0.0
        self._last_cert_expiration_check_ts: float = 0.0
        self._startup_recovered: bool = not recover_stale_on_startup

    def start(self) -> None:
        """Start background reconciliation thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="exec-reconciler")
        self._thread.start()
        logger.info("execution_reconciler_started")

    def stop(self) -> None:
        """Signal background thread to stop."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        logger.info("execution_reconciler_stopped")

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.reconcile_once()
            except Exception as exc:
                logger.error("reconciliation_cycle_failed", error=str(exc))
            self._stop_event.wait(self.poll_interval_s)

    def reconcile_once(self) -> dict[str, int]:
        """Perform a single reconciliation pass."""
        stats = {
            "active_runs": 0,
            "tasks_updated": 0,
            "tasks_dispatched": 0,
            "leases_reaped": 0,
            "scheduled_jobs_triggered": 0,
        }

        # Ensure stale active runs left over from prior system restart/crash are processed on initial pass
        if not self._startup_recovered:
            try:
                with self.session_factory() as session:
                    policy_events: list[dict[str, Any]] = []
                    aborted = ExecutionRepository.abort_stale_running_runs_on_startup(
                        session, policy_events_out=policy_events
                    )
                    for ev in policy_events:
                        ev_job = ev.get("job")
                        if ev_job and getattr(ev_job, "pending_notify", False):
                            self.notification_service.notify_job_policy_executed(
                                session,
                                ev_job,
                                policy_type="pending",
                                policy_value=ev["policy_value"],
                                message=ev["message"],
                                run_id=ev["run"].id,
                            )
                    if aborted:
                        session.commit()
                        logger.warning("stale_running_runs_aborted_on_startup", count=aborted)
                    self._startup_recovered = True
            except Exception as rec_err:
                logger.error("stale_runs_cleanup_on_reconciler_pass_failed", error=str(rec_err))

        # 0. Check and trigger due scheduled jobs
        try:
            scheduled_runs = self.job_scheduler.check_and_trigger_due_jobs()
            stats["scheduled_jobs_triggered"] = len(scheduled_runs)
        except Exception as sched_err:
            logger.error("scheduled_jobs_check_failed", error=str(sched_err))

        with self.session_factory() as session:
            try:
                released = ExecutionRepository.release_orphaned_work(session)
                if released:
                    logger.warning("orphaned_work_released", count=released)
                    session.commit()
            except Exception as orphan_err:
                session.rollback()
                logger.error("orphaned_work_release_failed", error=str(orphan_err))

            # 1. Fetch active runs
            active_runs = ExecutionRepository.list_runs(session, limit=20)
            running_runs = [r for r in active_runs if r.status in ("planning", "running", "queued")]
            stats["active_runs"] = len(running_runs)

            now_utc = utc_now()
            timed_out_run_ids: set[Any] = set()
            for run in running_runs:
                # Enforce Max Runtime Policy before polling tasks
                snap = run.job_snapshot or {}
                raw_max_rt = (
                    getattr(run.job, "max_runtime_minutes", None)
                    if run.job is not None
                    else snap.get("max_runtime_minutes")
                )
                if raw_max_rt is not None and int(raw_max_rt) > 0:
                    max_rt_min = int(raw_max_rt)
                    ref_start = run.started_at or run.created_at
                    if ref_start is not None:
                        if ref_start.tzinfo is None:
                            ref_start = ref_start.replace(tzinfo=UTC)
                        elapsed_s = (now_utc - ref_start).total_seconds()
                        if elapsed_s > max_rt_min * 60:
                            hours_part = max_rt_min // 60
                            mins_part = max_rt_min % 60
                            if hours_part > 0 and mins_part > 0:
                                dur_label = f"{hours_part}h {mins_part}m"
                            elif hours_part > 0:
                                dur_label = f"{hours_part}h"
                            else:
                                dur_label = f"{mins_part}m"
                            job_name = (
                                run.job.name
                                if run.job is not None
                                else snap.get("name", str(run.job_id))
                            )
                            rt_msg = (
                                f"L'esecuzione del job '{job_name}' è stata interrotta e segnata "
                                f"come fallita perché ha superato il tempo massimo indicato nella "
                                f"Max Runtime Policy ({dur_label})."
                            )
                            active_assigns = ExecutionRepository.fail_run_for_max_runtime(
                                session, run.id, max_rt_min, rt_msg
                            )
                            cancel_assignments_on_proxies(
                                session, active_assigns, self.proxy_client
                            )
                            if run.job is not None and getattr(
                                run.job, "max_runtime_notify", False
                            ):
                                self.notification_service.notify_job_policy_executed(
                                    session,
                                    run.job,
                                    policy_type="max_runtime",
                                    policy_value=dur_label,
                                    message=rt_msg,
                                    run_id=run.id,
                                )
                            session.commit()
                            timed_out_run_ids.add(run.id)
                            stats["tasks_updated"] += 1
                            continue

                # 2. Check and sync running tasks
                for task in run.tasks:
                    if task.status in (TaskState.ASSIGNED.value, TaskState.RUNNING.value):
                        for assignment in task.assignments:
                            if assignment.status in ("assigned", "running"):
                                self._sync_assignment(session, assignment, task, run, stats)

            running_runs = [r for r in running_runs if r.id not in timed_out_run_ids]
            stats["active_runs"] = len(running_runs)

            # Record periodic throughput sample
            total_active_speed = 0.0
            for r in running_runs:
                tasks_stats = ExecutionRepository.get_run_tasks_progress_stats(session, r)
                total_active_speed += sum(
                    s.get("speed_bytes_per_sec", 0.0) for s in tasks_stats.values()
                )
            ExecutionRepository.record_throughput_sample(
                session,
                bytes_per_sec=total_active_speed,
                active_runs=len(running_runs),
                min_interval_s=3.0,
            )

            # 3. Dispatch pending / ready tasks for running runs respecting concurrency limits
            ready_tasks = ExecutionRepository.get_ready_tasks(session, limit=20)
            if ready_tasks:
                proxies = ProxyRepository.get_all_enabled_proxies(session)
                online_proxies = [p for p in proxies if p.status and p.status.state == "online"]
                if online_proxies:
                    # Map proxy_id -> current active tasks
                    proxy_active_counts = (
                        ExecutionRepository.get_active_assignment_counts_by_proxies(session)
                    )
                    job_active_cache: dict[Any, int] = {}

                    for task in ready_tasks:
                        run = task.run
                        job = run.job if run else None
                        if not job:
                            continue

                        job_id = job.id
                        if job_id not in job_active_cache:
                            job_active_cache[job_id] = (
                                ExecutionRepository.get_active_task_count_by_job(session, job_id)
                            )

                        max_job_tasks = job.max_parallel_tasks or 4
                        if job_active_cache[job_id] >= max_job_tasks:
                            logger.info(
                                "dispatch_skipped_job_parallelism_limit",
                                job_id=str(job_id),
                                active=job_active_cache[job_id],
                                limit=max_job_tasks,
                            )
                            continue

                        # Filter by job's assigned proxies if any
                        import uuid as _uuid

                        assigned_proxy_ids = (
                            {p.id for p in job.assigned_proxies}
                            if getattr(job, "assigned_proxies", None)
                            else set()
                        )
                        if not assigned_proxy_ids and run and run.job_snapshot:
                            raw_snap_ids = run.job_snapshot.get("assigned_proxy_ids") or []
                            assigned_proxy_ids = {
                                _uuid.UUID(str(pid)) for pid in raw_snap_ids if pid
                            }

                        # Find eligible proxies with available capacity
                        eligible = [
                            p
                            for p in online_proxies
                            if (not assigned_proxy_ids or p.id in assigned_proxy_ids)
                            and (job.source_remote_id in {r.id for r in p.reachable_remotes})
                            and (job.destination_remote_id in {r.id for r in p.reachable_remotes})
                            and proxy_active_counts.get(p.id, 0) < p.max_concurrent_tasks
                        ]
                        if not eligible:
                            logger.info(
                                "dispatch_skipped_no_proxy_capacity",
                                task_id=str(task.id),
                                proxy_active_counts={
                                    str(k): v for k, v in proxy_active_counts.items()
                                },
                            )
                            continue

                        # Select candidate with lowest active task count (load balancing)
                        eligible.sort(key=lambda p: proxy_active_counts.get(p.id, 0))
                        target_proxy = eligible[0]

                        dispatched = self._dispatch_task_to_proxy(session, task, target_proxy)
                        if dispatched:
                            stats["tasks_dispatched"] += 1
                            proxy_active_counts[target_proxy.id] = (
                                proxy_active_counts.get(target_proxy.id, 0) + 1
                            )
                            job_active_cache[job_id] += 1

            # 4. Check for completed runs that require post-run hook execution and notification dispatch
            for run in active_runs:
                if (
                    run.status in ("succeeded", "failed", "partially_failed", "cancelled")
                    and run.notification_sent_at is None
                ):
                    # Check if post-run hook needs to be executed
                    job = run.job
                    post_hook = (
                        job.post_run_hook
                        if (job and job.post_run_hook)
                        else run.job_snapshot.get("post_run_hook")
                    )
                    has_post_hook_record = any(h.hook_type == "post_run" for h in (run.hooks or []))
                    if post_hook and post_hook.strip() and not has_post_hook_record:
                        from embervault_common.hooks.executor import (
                            HookExecutionResult,
                            HookExecutor,
                        )
                        from embervault_db.models.auth import AuditLog

                        hooks_enabled = bool(self.settings_store.get_setting("hooks_enabled"))
                        timeout_s = int(self.settings_store.get_setting("hooks_timeout_s") or 60)
                        hook_runner_url = str(
                            self.settings_store.get_setting("hook_runner_url")
                            or os.environ.get("EMBERVAULT_HOOK_RUNNER_URL")
                            or ""
                        )

                        if not hooks_enabled:
                            hook_record = ExecutionRepository.record_run_hook(
                                session=session,
                                run_id=run.id,
                                hook_type="post_run",
                                script_hash=HookExecutor.calculate_script_hash(post_hook),
                                status="skipped",
                                exit_code=0,
                                duration_ms=0.0,
                                output="Esecuzione hook disabilitata globalmente nelle impostazioni (hooks_enabled=false).",
                            )
                            session.add(
                                AuditLog(
                                    action="hook.post_run.skipped",
                                    actor_user_id=run.requested_by,
                                    entity_type="job_run",
                                    entity_id=str(run.id),
                                    details={
                                        "job_id": str(run.job_id),
                                        "reason": "hooks_disabled",
                                        "script_hash": hook_record.script_hash,
                                    },
                                )
                            )
                        else:
                            internal_token = os.environ.get("EMBERVAULT_INTERNAL_API_TOKEN", "")
                            executor = HookExecutor(
                                default_timeout_s=timeout_s,
                                runner_url=hook_runner_url,
                                auth_token=internal_token,
                            )
                            try:
                                hook_res = executor.execute(
                                    script_content=post_hook,
                                    context={
                                        "EMBERVAULT_JOB_ID": str(run.job_id),
                                        "EMBERVAULT_JOB_NAME": job.name
                                        if job
                                        else run.job_snapshot.get("name", ""),
                                        "EMBERVAULT_RUN_ID": str(run.id),
                                        "EMBERVAULT_TRIGGER": run.trigger,
                                        "EMBERVAULT_HOOK_TYPE": "post_run",
                                        "EMBERVAULT_RUN_STATUS": run.status,
                                        "EMBERVAULT_BYTES_TRANSFERRED": str(run.bytes_transferred),
                                        "EMBERVAULT_FILES_TRANSFERRED": str(run.files_transferred),
                                        "EMBERVAULT_TASKS_SUCCEEDED": str(run.tasks_succeeded),
                                        "EMBERVAULT_TASKS_FAILED": str(run.tasks_failed),
                                    },
                                    timeout_s=timeout_s,
                                )
                            except Exception as exc:
                                logger.error(
                                    "post_run_hook_execution_error",
                                    run_id=str(run.id),
                                    error=str(exc),
                                )
                                hook_res = HookExecutionResult(
                                    status="failed",
                                    exit_code=-1,
                                    duration_ms=0.0,
                                    script_hash=HookExecutor.calculate_script_hash(post_hook),
                                    output=f"[ERROR] Errore inaspettato durante l'esecuzione dell'hook post-run: {exc}",
                                )

                            ExecutionRepository.record_run_hook(
                                session=session,
                                run_id=run.id,
                                hook_type="post_run",
                                script_hash=hook_res.script_hash,
                                status=hook_res.status,
                                exit_code=hook_res.exit_code,
                                duration_ms=hook_res.duration_ms,
                                output=hook_res.output,
                            )
                            session.add(
                                AuditLog(
                                    action=f"hook.post_run.{hook_res.status}",
                                    actor_user_id=run.requested_by,
                                    entity_type="job_run",
                                    entity_id=str(run.id),
                                    details={
                                        "job_id": str(run.job_id),
                                        "status": hook_res.status,
                                        "exit_code": hook_res.exit_code,
                                        "script_hash": hook_res.script_hash,
                                        "duration_ms": hook_res.duration_ms,
                                    },
                                )
                            )

                            if hook_res.status != "succeeded":
                                try:
                                    self.notification_service.notify_hook_failure(
                                        session=session,
                                        run=run,
                                        hook_type="post_run",
                                        status=hook_res.status,
                                        exit_code=hook_res.exit_code,
                                        duration_ms=hook_res.duration_ms,
                                        output=hook_res.output,
                                        job_name=job.name if job else None,
                                    )
                                except Exception as notif_err:
                                    logger.error(
                                        "post_run_hook_notification_failed",
                                        run_id=str(run.id),
                                        error=str(notif_err),
                                    )

                    try:
                        self.notification_service.notify_job_run_completion(session, run)
                    except Exception as exc:
                        logger.error(
                            "notify_run_completion_error", run_id=str(run.id), error=str(exc)
                        )

            # 5. Periodic task log retention cleanup (run at most once per hour)
            import time

            now_ts = time.time()
            if now_ts - self._last_cleanup_ts > 3600:
                self._last_cleanup_ts = now_ts
                try:
                    retention_days = int(
                        self.settings_store.get_setting("log_retention_days") or 30
                    )
                    deleted_logs = ExecutionRepository.cleanup_expired_task_logs(
                        session, retention_days
                    )
                    if deleted_logs > 0:
                        logger.info(
                            "task_logs_retention_cleanup",
                            deleted_count=deleted_logs,
                            retention_days=retention_days,
                        )
                    tp_retention_days = int(
                        self.settings_store.get_setting("throughput_retention_days") or 7
                    )
                    deleted_samples = ExecutionRepository.cleanup_expired_throughput_samples(
                        session, tp_retention_days
                    )
                    if deleted_samples > 0:
                        logger.info(
                            "throughput_samples_retention_cleanup",
                            deleted_count=deleted_samples,
                            retention_days=tp_retention_days,
                        )
                except Exception as exc:
                    logger.warning("task_logs_retention_cleanup_failed", error=str(exc))

            session.commit()

        # 6. Automated configuration backup check (runs in its own session after reconciler commit)
        if now_ts - self._last_auto_backup_check_ts > 30:
            self._last_auto_backup_check_ts = now_ts
            try:
                from embervault_db.backup import run_automated_backup_if_due

                created_backup = run_automated_backup_if_due(self.session_factory)
                if created_backup:
                    logger.info("reconciler_auto_backup_created", path=created_backup)
            except Exception as exc:
                logger.warning("reconciler_auto_backup_failed", error=str(exc))

        # 7. Check for RClone updates on proxies periodically
        if now_ts - self._last_rclone_update_check_ts > 60:
            self._check_proxy_rclone_updates_if_due(now_ts)

        # 8. Check for proxy TLS certificate expiration (every 24 hours)
        if now_ts - self._last_cert_expiration_check_ts > 60:
            self._check_proxy_cert_expirations_if_due(now_ts)

        return stats

    def _check_proxy_rclone_updates_if_due(self, now_ts: float) -> None:
        """Evaluate whether to check proxies for available RClone updates and notify if found."""
        check_enabled = self.settings_store.get_setting("rclone_auto_update_check_enabled")
        if check_enabled is False:
            return

        interval_hours = int(
            self.settings_store.get_setting("rclone_auto_update_check_interval_hours") or 24
        )
        interval_s = max(1, interval_hours) * 3600

        if (
            self._last_rclone_update_check_ts > 0
            and (now_ts - self._last_rclone_update_check_ts) < interval_s
        ):
            return

        self._last_rclone_update_check_ts = now_ts

        try:
            from embervault_common.rclone_version import (
                get_latest_rclone_version,
                is_rclone_update_available,
            )
            from embervault_db.models.proxy import Proxy
            from sqlalchemy import select

            latest_ver = get_latest_rclone_version()
            if not latest_ver:
                return

            proxies_needing_update: list[str] = []

            with self.session_factory() as session:
                proxies = list(
                    session.scalars(select(Proxy).where(Proxy.is_enabled.is_(True))).all()
                )
                for p in proxies:
                    current_ver = p.rclone_version
                    needs_update, _ = is_rclone_update_available(current_ver, latest_ver)
                    if needs_update:
                        proxies_needing_update.append(p.name)

                if proxies_needing_update:
                    logger.info(
                        "rclone_updates_available_detected",
                        proxies=proxies_needing_update,
                        latest_version=latest_ver,
                    )
                    self.notification_service.notify_rclone_updates_available(
                        session=session,
                        proxy_names=proxies_needing_update,
                        latest_version=latest_ver,
                    )
        except Exception as exc:
            logger.error("rclone_update_check_failed", error=str(exc))

    def _check_proxy_cert_expirations_if_due(self, now_ts: float) -> None:
        """Check all enabled proxies for TLS certificate expiration every 24 hours and notify if < 15 days remain."""
        interval_s = 24 * 3600
        if (
            self._last_cert_expiration_check_ts > 0
            and (now_ts - self._last_cert_expiration_check_ts) < interval_s
        ):
            return

        self._last_cert_expiration_check_ts = now_ts

        try:
            with self.session_factory() as session:
                proxies = ProxyRepository.get_all_enabled_proxies(session)
                now_dt = utc_now()
                for proxy in proxies:
                    if not proxy.cert_expires_at:
                        continue
                    cert_exp = proxy.cert_expires_at
                    if cert_exp.tzinfo is None:
                        cert_exp = cert_exp.replace(tzinfo=UTC)
                    remaining = cert_exp - now_dt
                    days_remaining = int(remaining.total_seconds() // 86400)
                    if days_remaining < 15:
                        logger.warning(
                            "proxy_cert_expiring_soon",
                            proxy_id=str(proxy.id),
                            proxy_name=proxy.name,
                            days_remaining=days_remaining,
                            cert_expires_at=cert_exp.isoformat(),
                        )
                        self.notification_service.notify_proxy_cert_expiring(
                            session=session,
                            proxy=proxy,
                            days_remaining=days_remaining,
                            cert_expires_at=cert_exp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                        )
        except Exception as exc:
            logger.error("check_proxy_cert_expirations_failed", error=str(exc))

    def _sync_assignment(
        self,
        session: Session,
        assignment: Any,
        task: Any,
        run: Any,
        stats: dict[str, int],
    ) -> None:
        proxy_entity = ProxyRepository.get_proxy_by_id(session, assignment.proxy_id)
        if not proxy_entity:
            return

        now = utc_now()
        lease_s = getattr(self.settings, "assignment_timeout_s", 600)

        try:
            token = ProxyRepository.decrypt_token(proxy_entity.token_encrypted, proxy_entity.id)
            p_status = self.proxy_client.get_task_status(
                host=proxy_entity.host,
                port=proxy_entity.port,
                token=token,
                expected_fingerprint=proxy_entity.cert_fingerprint_sha256,
                attempt_id=assignment.id,
            )
            new_st = p_status.get("status")
            if new_st:
                # Active task heartbeat: renew the lease while proxy is responsive and actively running
                if new_st in ("running", "assigned", "dispatched"):
                    ExecutionRepository.renew_lease(session, assignment.id, duration_s=lease_s)

                prog = p_status.get("progress", {})
                exit_code = p_status.get("exit_code")
                error_class = p_status.get("error_class")
                error_code = p_status.get("error_code")

                # Sync logs with from_seq first so we have the latest output for AI evaluation
                from_seq = ExecutionRepository.get_max_task_log_seq(session, assignment.id) + 1
                p_logs = self.proxy_client.get_task_logs(
                    host=proxy_entity.host,
                    port=proxy_entity.port,
                    token=token,
                    expected_fingerprint=proxy_entity.cert_fingerprint_sha256,
                    attempt_id=assignment.id,
                    from_seq=from_seq,
                )
                log_lines = p_logs.get("lines", [])
                if log_lines:
                    ExecutionRepository.record_task_logs_batch(
                        session=session,
                        assignment_id=assignment.id,
                        task_id=task.id,
                        run_id=run.id,
                        lines=log_lines,
                        from_seq=from_seq,
                    )

                # AI-driven error evaluation if task failed
                ai_decision = None
                if new_st == "failed" and self.ai_evaluator.is_enabled():
                    recent_messages = (
                        [l.get("message", "") for l in log_lines[-30:]] if log_lines else []
                    )
                    ai_decision = self.ai_evaluator.evaluate_task_failure(
                        session=session,
                        task=task,
                        assignment=assignment,
                        exit_code=exit_code,
                        error_class=error_class,
                        error_code=error_code,
                        recent_log_lines=recent_messages,
                    )
                    if ai_decision:
                        if ai_decision.decision == "fail":
                            error_class = "permanent"
                        elif (
                            ai_decision.decision in ("retry", "ignore")
                            and error_class == "permanent"
                        ):
                            error_class = "transient"

                ExecutionRepository.update_assignment_status(
                    session=session,
                    assignment_id=assignment.id,
                    status=new_st,
                    exit_code=exit_code,
                    error_class=error_class,
                    error_code=error_code,
                    bytes_transferred=prog.get("bytes_transferred", 0),
                    files_transferred=prog.get("files_transferred", 0),
                    checks_count=prog.get("checks_completed") or prog.get("checks_count") or 0,
                )
                stats["tasks_updated"] += 1

                # If AI suggested a specific backoff for retry, apply it
                if (
                    ai_decision
                    and ai_decision.decision in ("retry", "ignore")
                    and ai_decision.suggested_backoff_seconds is not None
                    and task.status == TaskState.RETRY_WAIT.value
                ):
                    from datetime import timedelta

                    task.next_attempt_at = now + timedelta(
                        seconds=ai_decision.suggested_backoff_seconds
                    )

            elif p_status.get("error") == "not_found":
                # Proxy has no record of this attempt (it failed dispatch or was lost)
                logger.warning(
                    "reconcile_proxy_task_not_found",
                    proxy_id=str(proxy_entity.id),
                    assignment_id=str(assignment.id),
                )
                ExecutionRepository.update_assignment_status(
                    session=session,
                    assignment_id=assignment.id,
                    status="failed",
                    error_class="lost",
                    error_code="TASK_NOT_FOUND_ON_PROXY",
                )
                stats["tasks_updated"] += 1
        except Exception as exc:
            logger.debug(
                "reconcile_proxy_status_error", proxy_id=str(proxy_entity.id), error=str(exc)
            )
            # Proxy was unreachable during status poll: check if lease window has expired
            if assignment.lease_expires_at and assignment.lease_expires_at < now:
                logger.warning(
                    "reaping_expired_task_lease",
                    assignment_id=str(assignment.id),
                    proxy_id=str(proxy_entity.id),
                    error=str(exc),
                )
                ExecutionRepository.update_assignment_status(
                    session=session,
                    assignment_id=assignment.id,
                    status="failed",
                    error_class="lost",
                    error_code="LEASE_EXPIRED",
                )
                stats["leases_reaped"] += 1

    def _dispatch_task_to_proxy(self, session: Session, task: Any, proxy: Any) -> bool:
        run = task.run
        job = run.job
        if not job or not job.source_remote or not job.destination_remote:
            logger.warning(
                "dispatch_skipped_missing_job_or_remote",
                task_id=str(task.id),
                has_job=bool(job),
            )
            return False

        try:
            lease_s = getattr(self.settings, "assignment_timeout_s", 600)
            assignment = ExecutionRepository.create_assignment(
                session, task.id, proxy.id, lease_duration_s=lease_s
            )
            dec_token = ProxyRepository.decrypt_token(proxy.token_encrypted, proxy.id)
            src_config = RemoteRepository.get_decrypted_config(job.source_remote)
            dst_config = RemoteRepository.get_decrypted_config(job.destination_remote)

            # Resolve any referenced / upstream remotes (for alias, crypt, compress, etc.)
            src_refs = RemoteRepository.resolve_referenced_remotes(
                session=session,
                backend_type=job.source_remote.backend_type,
                config=src_config,
            )
            dst_refs = RemoteRepository.resolve_referenced_remotes(
                session=session,
                backend_type=job.destination_remote.backend_type,
                config=dst_config,
            )
            combined_refs = {**src_refs, **dst_refs}
            referenced_remotes_payload = [
                {
                    "alias": r_name,
                    "backend_type": r_data["backend_type"],
                    "config": r_data["config"],
                    "path": "",
                }
                for r_name, r_data in combined_refs.items()
            ]

            all_secret_fields = (
                list(job.source_remote.secret_field_names)
                + list(job.destination_remote.secret_field_names)
                + ["pass", "password", "password2", "secret_access_key", "client_secret", "key"]
            )

            subpath = task.spec.get("source_subpath", "")
            final_src_path = (
                f"{job.source_path.rstrip('/')}/{subpath}" if subpath else job.source_path
            )
            final_dst_path = (
                f"{job.destination_path.rstrip('/')}/{subpath}" if subpath else job.destination_path
            )

            task_options = dict(task.spec.get("options") or {})
            if task.spec.get("filters"):
                task_options["filters"] = list(task.spec.get("filters"))
            if task.spec.get("max_depth") is not None:
                task_options["max_depth"] = task.spec["max_depth"]
            elif task.scope == "root_files" or task.spec.get("include_root_files_only"):
                task_options["max_depth"] = 1

            files_from = list(task.spec.get("files_from") or [])

            payload = {
                "attempt_id": str(assignment.id),
                "task_id": str(task.id),
                "run_id": str(run.id),
                "kind": task.kind,
                "operation": task.spec.get("operation", job.operation),
                "timeout_s": task.spec.get("timeout_s", 3600),
                "source": {
                    "alias": "src",
                    "backend_type": job.source_remote.backend_type,
                    "config": src_config,
                    "path": final_src_path,
                },
                "destination": {
                    "alias": "dst",
                    "backend_type": job.destination_remote.backend_type,
                    "config": dst_config,
                    "path": final_dst_path,
                },
                "referenced_remotes": referenced_remotes_payload,
                "files_from": files_from,
                "options": task_options,
                "secret_fields": all_secret_fields,
            }

            res = self.proxy_client.dispatch_task(
                host=proxy.host,
                port=proxy.port,
                token=dec_token,
                expected_fingerprint=proxy.cert_fingerprint_sha256,
                payload=payload,
            )
            accepted = bool(res.get("status") in ("accepted", "already_known"))
            if not accepted:
                err_code = str(res.get("error") or "PROXY_DISPATCH_REJECTED")
                ExecutionRepository.update_assignment_status(
                    session=session,
                    assignment_id=assignment.id,
                    status="failed",
                    error_class="dispatch_error",
                    error_code=err_code,
                )
            return accepted
        except Exception as exc:
            logger.warning("reconciler_dispatch_failed", task_id=str(task.id), error=str(exc))
            if "assignment" in locals():
                try:
                    ExecutionRepository.update_assignment_status(
                        session=session,
                        assignment_id=assignment.id,
                        status="failed",
                        error_class="dispatch_error",
                        error_code="PROXY_DISPATCH_EXCEPTION",
                    )
                except Exception:
                    pass
            return False
