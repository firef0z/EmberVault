"""Data access repository for JobRuns, Tasks, TaskAssignments, and TaskLogs."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, selectinload

from embervault_common.contracts.enums import (
    RunState,
    TaskState,
)
from embervault_db.models.base import utc_now
from embervault_db.models.execution import JobRun, JobRunHook, Task, TaskAssignment, TaskLog
from embervault_db.models.proxy import ProxyStatus
from embervault_db.models.remotes import Job

_ACTIVE_RUN_STATES = ("queued", "planning", "awaiting_confirmation", "running")


class ExecutionRepository:
    """Repository handling JobRun lifecycle, Task materialization, and TaskAssignment leasing."""

    @staticmethod
    def resolve_default_policy(session: Session | None, key_name: str, fallback: str) -> str:
        """Resolve a default policy setting from DB settings or env var or fallback."""
        import os
        from embervault_db.models.auth import Setting

        val = None
        if session is not None:
            try:
                val = session.scalar(select(Setting.value).where(Setting.key == key_name))
            except Exception:
                val = None
        if not val:
            env_var = f"EMBERVAULT_{key_name.upper()}"
            val = os.environ.get(env_var)
        return str(val).strip().lower() if val else fallback

    @staticmethod
    def create_job_run(
        session: Session,
        job_id: UUID,
        trigger: str = "manual",
        requested_by: UUID | None = None,
    ) -> JobRun:
        """Create a new JobRun in 'planning' state after enforcing overlap policy."""
        job = session.get(Job, job_id)
        if job is None:
            raise ValueError(f"Job con ID '{job_id}' non trovato.")

        if not job.enabled:
            raise ValueError(f"Il job '{job.name}' è disabilitato e non può essere avviato.")

        # Check overlap policy
        active_run = session.scalar(
            select(JobRun)
            .where(JobRun.job_id == job_id)
            .where(JobRun.status.in_(["queued", "planning", "awaiting_confirmation", "running"]))
            .limit(1)
        )
        effective_overlap = (
            job.overlap_policy
            if job.overlap_policy in ("skip", "allow", "cancel_previous", "queue", "fail")
            else ExecutionRepository.resolve_default_policy(session, "default_overlap_policy", "skip")
        )
        if active_run is not None:
            if effective_overlap == "skip":
                raise ValueError(
                    f"Esecuzione saltata (overlap policy 'skip'): il job ha già una run attiva (ID: {active_run.id})."
                )
            elif effective_overlap == "fail":
                raise ValueError(
                    f"Esecuzione fallita (overlap policy 'fail'): il job ha già una run attiva (ID: {active_run.id})."
                )

        effective_missed = (
            job.missed_run_policy
            if job.missed_run_policy in ("skip", "run_once", "fail")
            else ExecutionRepository.resolve_default_policy(session, "default_missed_run_policy", "run_once")
        )
        effective_pending = (
            job.pending_policy
            if getattr(job, "pending_policy", None) in ("fail", "retry")
            else ExecutionRepository.resolve_default_policy(session, "default_pending_policy", "fail")
        )

        # Snapshot job configuration
        snapshot = {
            "name": job.name,
            "source_remote_id": str(job.source_remote_id),
            "source_path": job.source_path,
            "destination_remote_id": str(job.destination_remote_id),
            "destination_path": job.destination_path,
            "operation": job.operation,
            "parallelization": job.parallelization,
            "max_parallel_tasks": job.max_parallel_tasks or 4,
            "task_timeout_s": job.task_timeout_s or 3600,
            "rclone_options": job.rclone_options or {},
            "pre_run_hook": job.pre_run_hook,
            "post_run_hook": job.post_run_hook,
            "notifications_enabled": job.notifications_enabled,
            "notification_policy": job.notification_policy,
            "missed_run_policy": effective_missed,
            "overlap_policy": effective_overlap,
            "pending_policy": effective_pending,
            "max_runtime_minutes": getattr(job, "max_runtime_minutes", None),
            "missed_run_notify": bool(getattr(job, "missed_run_notify", False)),
            "overlap_notify": bool(getattr(job, "overlap_notify", False)),
            "pending_notify": bool(getattr(job, "pending_notify", False)),
            "max_runtime_notify": bool(getattr(job, "max_runtime_notify", False)),
            "assigned_proxy_ids": [str(p.id) for p in job.assigned_proxies]
            if getattr(job, "assigned_proxies", None)
            else [],
        }

        run_id = uuid4()
        run = JobRun(
            id=run_id,
            job_id=job_id,
            trigger=trigger,
            status=RunState.PLANNING.value,
            requested_by=requested_by,
            started_at=utc_now(),
            job_snapshot=snapshot,
            planned_task_count=0,
        )
        session.add(run)
        session.flush()
        return run

    @staticmethod
    def materialize_planned_tasks(
        session: Session,
        run_id: UUID,
        planned_tasks: list[Any],
    ) -> list[Task]:
        """Materialize pure PlannedTask specs into database Task rows in 'ready' state."""
        run = session.get(JobRun, run_id)
        if run is None:
            raise ValueError(f"JobRun con ID '{run_id}' non trovata.")

        task_entities: list[Task] = []
        now = utc_now()
        timeout_s = run.job_snapshot.get("task_timeout_s", 3600)

        for seq, pt in enumerate(planned_tasks):
            t_id = uuid4()
            spec: dict[str, Any] = {
                "operation": pt.operation.value
                if hasattr(pt.operation, "value")
                else str(pt.operation),
                "source_subpath": getattr(pt, "source_subpath", ""),
                "dest_subpath": getattr(pt, "dest_subpath", ""),
                "max_depth": getattr(pt, "max_depth", None),
                "include_root_files_only": getattr(pt, "include_root_files_only", False),
                "files_from": getattr(pt, "files_from", None),
                "timeout_s": timeout_s,
                "filters": getattr(pt, "filters", []),
                "options": getattr(pt, "options", {}),
                "skip_reason": getattr(pt, "skip_reason", None),
            }

            scope_val = pt.scope.value if hasattr(pt.scope, "value") else str(pt.scope)
            kind_val = pt.kind.value if hasattr(pt.kind, "value") else str(pt.kind)
            is_skipped = getattr(pt, "status", "ready") == "skipped"

            task = Task(
                id=t_id,
                run_id=run_id,
                kind=kind_val,
                scope=scope_val,
                seq=seq,
                spec=spec,
                status=TaskState.SKIPPED.value if is_skipped else TaskState.READY.value,
                attempt_count=0,
                max_attempts=int(run.job_snapshot.get("max_attempts") or 3),
                ready_at=now,
                finished_at=now if is_skipped else None,
                last_error_code="FILTER_SKIPPED" if is_skipped else None,
            )
            session.add(task)
            task_entities.append(task)

        run.planned_task_count = len(task_entities)
        run.status = RunState.RUNNING.value
        session.flush()
        # Reconcile immediately in case all tasks are skipped
        ExecutionRepository._reconcile_job_run_state(session, run)
        session.flush()
        return task_entities

    @staticmethod
    def get_run_by_id(session: Session, run_id: UUID) -> JobRun | None:
        """Retrieve JobRun by UUID with tasks and assignments eagerly loaded."""
        stmt = (
            select(JobRun)
            .where(JobRun.id == run_id)
            .options(
                selectinload(JobRun.tasks)
                .selectinload(Task.assignments)
                .joinedload(TaskAssignment.proxy)
            )
        )
        return session.scalar(stmt)

    @staticmethod
    def list_runs(
        session: Session,
        job_id: UUID | None = None,
        limit: int = 50,
    ) -> list[JobRun]:
        """List recent JobRuns ordered by start time descending."""
        stmt = select(JobRun)
        if job_id is not None:
            stmt = stmt.where(JobRun.job_id == job_id)
        stmt = stmt.order_by(desc(JobRun.created_at)).limit(limit)
        return list(session.scalars(stmt).all())

    @staticmethod
    def cancel_run(session: Session, run_id: UUID) -> tuple[bool, list[TaskAssignment]]:
        """Cancel a JobRun and all its active/pending tasks, returning cancelled active assignments."""
        run = session.get(JobRun, run_id)
        if run is None:
            return False, []

        if run.status in ("succeeded", "partially_failed", "failed", "cancelled"):
            return False, []

        now = utc_now()
        run.status = RunState.CANCELLED.value
        run.finished_at = now

        active_assignments: list[TaskAssignment] = []
        # Cancel tasks
        for task in run.tasks:
            if task.status not in ("succeeded", "failed", "cancelled"):
                task.status = TaskState.CANCELLED.value
                task.finished_at = now
                for assignment in task.assignments:
                    if assignment.status in ("assigned", "dispatched", "running"):
                        assignment.status = "cancelled"
                        assignment.finished_at = now
                        active_assignments.append(assignment)
                        proxy_status = session.get(ProxyStatus, assignment.proxy_id)
                        if proxy_status and proxy_status.running_tasks > 0:
                            proxy_status.running_tasks = max(0, proxy_status.running_tasks - 1)

        session.flush()
        return True, active_assignments

    @staticmethod
    def cancel_task(
        session: Session, task_id: UUID
    ) -> tuple[bool, Task | None, list[TaskAssignment]]:
        """Cancel an individual task and its active assignments."""
        task = session.get(Task, task_id)
        if task is None:
            return False, None, []

        if task.status in ("succeeded", "failed", "cancelled"):
            return False, task, []

        now = utc_now()
        task.status = TaskState.CANCELLED.value
        task.finished_at = now

        active_assignments: list[TaskAssignment] = []
        for assignment in task.assignments:
            if assignment.status in ("assigned", "dispatched", "running"):
                assignment.status = "cancelled"
                assignment.finished_at = now
                active_assignments.append(assignment)
                proxy_status = session.get(ProxyStatus, assignment.proxy_id)
                if proxy_status and proxy_status.running_tasks > 0:
                    proxy_status.running_tasks = max(0, proxy_status.running_tasks - 1)

        run = task.run
        if run:
            ExecutionRepository._reconcile_job_run_state(session, run)

        session.flush()
        return True, task, active_assignments

    @staticmethod
    def get_ready_tasks(session: Session, limit: int = 20) -> list[Task]:
        """Retrieve tasks ready to be assigned to proxy workers."""
        now = utc_now()
        stmt = (
            select(Task)
            .join(JobRun, Task.run_id == JobRun.id)
            .where(JobRun.status.in_(_ACTIVE_RUN_STATES))
            .where(
                (Task.status == TaskState.READY.value)
                | ((Task.status == TaskState.RETRY_WAIT.value) & (Task.next_attempt_at <= now))
            )
            .order_by(JobRun.created_at, Task.seq)
            .limit(limit)
        )
        return list(session.scalars(stmt).all())

    @staticmethod
    def get_active_assignment_counts_by_proxies(session: Session) -> dict[UUID, int]:
        """Return a mapping of proxy_id -> number of currently active assignments across all jobs.

        Only assignments whose run is still active are counted, so leftovers of finished runs
        can never consume proxy capacity.
        """
        stmt = (
            select(TaskAssignment.proxy_id, func.count(TaskAssignment.id))
            .join(Task, TaskAssignment.task_id == Task.id)
            .join(JobRun, Task.run_id == JobRun.id)
            .where(TaskAssignment.status.in_(["assigned", "dispatched", "running"]))
            .where(JobRun.status.in_(_ACTIVE_RUN_STATES))
            .group_by(TaskAssignment.proxy_id)
        )
        results = session.execute(stmt).all()
        return {p_id: int(count) for p_id, count in results}

    @staticmethod
    def get_active_runs_for_job(session: Session, job_id: UUID) -> list[JobRun]:
        """Return currently active runs for a given job ordered chronologically."""
        stmt = (
            select(JobRun)
            .where(JobRun.job_id == job_id)
            .where(JobRun.status.in_(_ACTIVE_RUN_STATES))
            .order_by(JobRun.created_at.asc())
        )
        return list(session.scalars(stmt).all())

    @staticmethod
    def create_failed_missed_run(
        session: Session,
        job: Job,
        scheduled_for: datetime | None,
        error_message: str,
    ) -> JobRun:
        """Create a failed JobRun record when a missed scheduled run is marked as failed by policy."""
        from embervault_db.models.auth import AuditLog

        now = utc_now()
        run_id = uuid4()
        snapshot = {
            "name": job.name,
            "source_remote_id": str(job.source_remote_id),
            "source_path": job.source_path,
            "destination_remote_id": str(job.destination_remote_id),
            "destination_path": job.destination_path,
            "operation": job.operation,
            "parallelization": job.parallelization,
            "max_parallel_tasks": job.max_parallel_tasks or 4,
            "task_timeout_s": job.task_timeout_s or 3600,
            "rclone_options": job.rclone_options or {},
            "missed_run_policy": (
                job.missed_run_policy
                if job.missed_run_policy in ("skip", "run_once", "fail")
                else ExecutionRepository.resolve_default_policy(session, "default_missed_run_policy", "run_once")
            ),
            "overlap_policy": (
                job.overlap_policy
                if job.overlap_policy in ("skip", "allow", "cancel_previous", "queue", "fail")
                else ExecutionRepository.resolve_default_policy(session, "default_overlap_policy", "skip")
            ),
            "pending_policy": (
                job.pending_policy
                if getattr(job, "pending_policy", None) in ("fail", "retry")
                else ExecutionRepository.resolve_default_policy(session, "default_pending_policy", "fail")
            ),
            "max_runtime_minutes": getattr(job, "max_runtime_minutes", None),
        }
        run = JobRun(
            id=run_id,
            job_id=job.id,
            trigger="schedule",
            status=RunState.FAILED.value,
            scheduled_for=scheduled_for,
            started_at=now,
            finished_at=now,
            job_snapshot=snapshot,
            planned_task_count=0,
            tasks_succeeded=0,
            tasks_failed=0,
            error_code="MISSED_RUN_FAILED",
            error_message=error_message,
            notification_sent_at=now,
        )
        session.add(run)
        session.add(
            AuditLog(
                action="job_run.missed_failed",
                actor_user_id=None,
                entity_type="job_run",
                entity_id=str(run_id),
                details={
                    "job_id": str(job.id),
                    "job_name": job.name,
                    "scheduled_for": scheduled_for.isoformat() if scheduled_for else None,
                    "message": error_message,
                },
            )
        )
        session.flush()
        return run

    @staticmethod
    def fail_run_for_max_runtime(
        session: Session,
        run_id: UUID,
        max_runtime_minutes: int,
        error_message: str,
    ) -> list[TaskAssignment]:
        """Stop an active run exceeding max_runtime_minutes and mark it as failed."""
        from embervault_db.models.auth import AuditLog

        run = session.get(JobRun, run_id)
        if run is None or run.status not in _ACTIVE_RUN_STATES:
            return []

        now = utc_now()
        run.status = RunState.FAILED.value
        run.finished_at = now
        run.error_code = "MAX_RUNTIME_EXCEEDED"
        run.error_message = error_message
        if run.notification_sent_at is None:
            run.notification_sent_at = now

        active_assignments: list[TaskAssignment] = []
        failed_tasks = 0
        for task in run.tasks:
            if task.status not in (
                TaskState.SUCCEEDED.value,
                TaskState.FAILED.value,
                TaskState.CANCELLED.value,
                TaskState.SKIPPED.value,
            ):
                task.status = TaskState.FAILED.value
                task.finished_at = now
                task.last_error_code = "MAX_RUNTIME_EXCEEDED"
                failed_tasks += 1
            for assignment in task.assignments:
                if assignment.status in ("assigned", "dispatched", "running"):
                    assignment.status = "failed"
                    assignment.finished_at = now
                    assignment.error_class = "permanent"
                    assignment.error_code = "MAX_RUNTIME_EXCEEDED"
                    active_assignments.append(assignment)
                    proxy_status = session.get(ProxyStatus, assignment.proxy_id)
                    if proxy_status and proxy_status.running_tasks > 0:
                        proxy_status.running_tasks = max(0, proxy_status.running_tasks - 1)

        if failed_tasks > 0:
            run.tasks_failed = max(run.tasks_failed, failed_tasks)

        session.add(
            AuditLog(
                action="job_run.max_runtime_exceeded",
                actor_user_id=None,
                entity_type="job_run",
                entity_id=str(run.id),
                details={
                    "job_id": str(run.job_id),
                    "run_id": str(run.id),
                    "max_runtime_minutes": max_runtime_minutes,
                    "message": error_message,
                },
            )
        )
        session.flush()
        return active_assignments

    @staticmethod
    def abort_stale_running_runs_on_startup(
        session: Session,
        policy_events_out: list[dict[str, Any]] | None = None,
    ) -> int:
        """Recover or abort active/running runs left over from prior execution upon service startup.

        Applies each job's ``pending_policy`` ('fail' or 'retry') to runs that were already in
        'queued', 'planning', 'awaiting_confirmation', or 'running' state when EmberVault stopped.

        Args:
            session: Active database session.
            policy_events_out: Optional list populated with one metadata dict per processed run so
                callers can dispatch Pending Policy notifications.

        Returns:
            Number of stale runs processed on startup.
        """
        from embervault_db.models.auth import AuditLog

        now = utc_now()
        active_runs = list(
            session.scalars(select(JobRun).where(JobRun.status.in_(_ACTIVE_RUN_STATES))).all()
        )
        if not active_runs:
            return 0

        stale_count = len(active_runs)
        fail_reason_msg = (
            "Esecuzione interrotta dal riavvio del sistema. Marcata come fallita all'avvio."
        )

        for run in active_runs:
            job = run.job
            job_pending = getattr(job, "pending_policy", None) if job is not None else None
            if not job_pending and run.job_snapshot:
                job_pending = run.job_snapshot.get("pending_policy")
            pending_policy = (
                job_pending
                if job_pending in ("fail", "retry")
                else ExecutionRepository.resolve_default_policy(session, "default_pending_policy", "fail")
            )
            job_name = job.name if job else (run.job_snapshot or {}).get("name", str(run.job_id))
            prev_started = run.started_at or run.created_at
            started_str = prev_started.isoformat() if prev_started else "-"

            # Always abort in-flight assignments from prior process lifetime
            for task in run.tasks:
                for assignment in task.assignments:
                    if assignment.status not in ("succeeded", "failed", "cancelled"):
                        assignment.status = "failed"
                        if not assignment.finished_at:
                            assignment.finished_at = now
                        assignment.error_class = "permanent"
                        assignment.error_code = (
                            "SYSTEM_RESTART_RETRY"
                            if pending_policy == "retry"
                            else "SYSTEM_RESTART_ABORTED"
                        )

            if pending_policy == "retry":
                retry_msg = (
                    f"Il job '{job_name}' aveva un'esecuzione in corso prima dell'avvio di EmberVault. "
                    "L'esecuzione è stata riavviata nuovamente dall'inizio perché la Pending Policy è impostata a RETRY."
                )
                run.started_at = now
                run.finished_at = None
                run.bytes_transferred = 0
                run.files_transferred = 0
                run.tasks_succeeded = 0
                run.tasks_failed = 0
                run.warning_code = "RETRIED_ON_STARTUP"
                run.error_code = None
                run.error_message = retry_msg
                run.notification_sent_at = None

                if run.tasks:
                    run.status = RunState.RUNNING.value
                    for task in run.tasks:
                        if task.status != TaskState.SKIPPED.value:
                            task.status = TaskState.READY.value
                            task.attempt_count = 0
                            task.started_at = None
                            task.finished_at = None
                            task.last_error_code = None
                            task.next_attempt_at = None
                            task.ready_at = now
                elif job is not None:
                    fallback_task = Task(
                        id=uuid4(),
                        run_id=run.id,
                        kind="transfer",
                        scope="whole",
                        seq=0,
                        spec={
                            "operation": job.operation,
                            "source_subpath": "",
                            "dest_subpath": "",
                            "max_depth": None,
                            "include_root_files_only": False,
                            "files_from": None,
                            "timeout_s": int(job.task_timeout_s or 3600),
                            "filters": [],
                            "options": dict(
                                (run.job_snapshot or {}).get("resolved_rclone_options")
                                or job.rclone_options
                                or {}
                            ),
                            "skip_reason": None,
                        },
                        status=TaskState.READY.value,
                        attempt_count=0,
                        max_attempts=int((run.job_snapshot or {}).get("max_attempts") or 3),
                        ready_at=now,
                    )
                    session.add(fallback_task)
                    run.planned_task_count = 1
                    run.status = RunState.RUNNING.value

                session.add(
                    AuditLog(
                        action="job_run.system_retried_on_startup",
                        actor_user_id=None,
                        entity_type="job_run",
                        entity_id=str(run.id),
                        details={
                            "job_id": str(run.job_id),
                            "run_id": str(run.id),
                            "reason": "system_startup_retry",
                            "previous_started_at": started_str,
                            "message": retry_msg,
                        },
                    )
                )
                if policy_events_out is not None:
                    policy_events_out.append(
                        {
                            "job": job,
                            "run": run,
                            "policy_type": "pending",
                            "policy_value": "retry",
                            "message": retry_msg,
                        }
                    )
            else:
                run.status = RunState.FAILED.value
                if not run.finished_at:
                    run.finished_at = now
                run.error_code = "SYSTEM_RESTART_ABORTED"
                if not run.error_message:
                    run.error_message = fail_reason_msg
                else:
                    run.error_message = f"{run.error_message} | {fail_reason_msg}"

                # Avoid generic failure alert duplication on restart
                if run.notification_sent_at is None:
                    run.notification_sent_at = now

                failed_tasks = 0
                for task in run.tasks:
                    if task.status not in (
                        TaskState.SUCCEEDED.value,
                        TaskState.FAILED.value,
                        TaskState.CANCELLED.value,
                        TaskState.SKIPPED.value,
                    ):
                        task.status = TaskState.FAILED.value
                        if not task.finished_at:
                            task.finished_at = now
                        task.last_error_code = "SYSTEM_RESTART_ABORTED"
                        failed_tasks += 1

                if failed_tasks > 0 and run.tasks_failed == 0:
                    run.tasks_failed = failed_tasks

                session.add(
                    AuditLog(
                        action="job_run.system_aborted_on_startup",
                        actor_user_id=None,
                        entity_type="job_run",
                        entity_id=str(run.id),
                        details={
                            "job_id": str(run.job_id),
                            "run_id": str(run.id),
                            "reason": "system_startup_abort",
                            "message": fail_reason_msg,
                        },
                    )
                )
                if policy_events_out is not None:
                    notify_msg = (
                        f"Il job '{job_name}' aveva un'esecuzione in corso prima dell'avvio di EmberVault. "
                        "L'esecuzione è stata segnata come fallita perché la Pending Policy è impostata a FAIL."
                    )
                    policy_events_out.append(
                        {
                            "job": job,
                            "run": run,
                            "policy_type": "pending",
                            "policy_value": "fail",
                            "message": notify_msg,
                        }
                    )

        # Reset running_tasks on all proxy statuses to eliminate phantom tasks
        proxy_statuses = list(session.scalars(select(ProxyStatus)).all())
        for ps in proxy_statuses:
            if ps.running_tasks > 0:
                ps.running_tasks = 0

        session.flush()
        return stale_count

    @staticmethod
    def release_orphaned_work(session: Session) -> int:
        """Release assignments/tasks still marked active although their run already finished."""
        now = utc_now()
        released = 0

        orphan_assignments = session.scalars(
            select(TaskAssignment)
            .join(Task, TaskAssignment.task_id == Task.id)
            .join(JobRun, Task.run_id == JobRun.id)
            .where(TaskAssignment.status.in_(["assigned", "dispatched", "running"]))
            .where(JobRun.status.notin_(_ACTIVE_RUN_STATES))
        ).all()
        for assignment in orphan_assignments:
            assignment.status = "cancelled"
            assignment.finished_at = now
            proxy_status = session.get(ProxyStatus, assignment.proxy_id)
            if proxy_status and proxy_status.running_tasks > 0:
                proxy_status.running_tasks = max(0, proxy_status.running_tasks - 1)
            released += 1

        orphan_tasks = session.scalars(
            select(Task)
            .join(JobRun, Task.run_id == JobRun.id)
            .where(
                Task.status.in_(
                    [TaskState.ASSIGNED.value, TaskState.RUNNING.value, TaskState.READY.value]
                )
            )
            .where(JobRun.status.notin_(_ACTIVE_RUN_STATES))
        ).all()
        for task in orphan_tasks:
            task.status = TaskState.CANCELLED.value
            task.finished_at = now
            released += 1

        if released:
            session.flush()
        return released

    @staticmethod
    def get_active_task_count_by_job(session: Session, job_id: UUID) -> int:
        """Return the number of currently active tasks (assigned or running) for a specific job."""
        stmt = (
            select(func.count(Task.id))
            .join(JobRun, Task.run_id == JobRun.id)
            .where(JobRun.job_id == job_id)
            .where(JobRun.status.in_(_ACTIVE_RUN_STATES))
            .where(Task.status.in_([TaskState.ASSIGNED.value, TaskState.RUNNING.value]))
        )
        count = session.scalar(stmt)
        return int(count) if count is not None else 0

    @staticmethod
    def create_assignment(
        session: Session,
        task_id: UUID,
        proxy_id: UUID,
        lease_duration_s: int = 600,
    ) -> TaskAssignment:
        """Create a new TaskAssignment and lease the task to a proxy worker."""
        task = session.get(Task, task_id)
        if task is None:
            raise ValueError(f"Task con ID '{task_id}' non trovato.")

        now = utc_now()
        attempt_no = task.attempt_count + 1
        assignment_id = uuid4()
        expires_at = now + timedelta(seconds=lease_duration_s)

        assignment = TaskAssignment(
            id=assignment_id,
            task_id=task_id,
            attempt_no=attempt_no,
            proxy_id=proxy_id,
            status="assigned",
            assigned_at=now,
            dispatched_at=now,
            lease_expires_at=expires_at,
        )
        assignment.task = task
        session.add(assignment)

        task.attempt_count = attempt_no
        task.status = TaskState.ASSIGNED.value

        # Increment proxy running_tasks count in DB
        proxy_status = session.get(ProxyStatus, proxy_id)
        if proxy_status:
            proxy_status.running_tasks += 1

        session.flush()
        return assignment

    @staticmethod
    def renew_lease(
        session: Session,
        assignment_id: UUID,
        duration_s: int = 600,
    ) -> datetime | None:
        """Extend the lease expiry timestamp of an active TaskAssignment."""
        assignment = session.get(TaskAssignment, assignment_id)
        if assignment is None:
            return None
        now = utc_now()
        new_expiry = now + timedelta(seconds=duration_s)
        assignment.lease_expires_at = new_expiry
        session.flush()
        return new_expiry

    @staticmethod
    def update_assignment_status(
        session: Session,
        assignment_id: UUID,
        status: str,
        exit_code: int | None = None,
        error_class: str | None = None,
        error_code: str | None = None,
        bytes_transferred: int = 0,
        files_transferred: int = 0,
        duration_ms: int = 0,
        checks_count: int = 0,
    ) -> TaskAssignment:
        """Update assignment status and propagate completion/failure to parent Task and JobRun."""
        assignment = session.get(TaskAssignment, assignment_id)
        if assignment is None:
            raise ValueError(f"TaskAssignment '{assignment_id}' non trovata.")

        prev_status = assignment.status
        now = utc_now()
        assignment.status = status
        if status in ("succeeded", "failed", "cancelled"):
            assignment.finished_at = now
            # Decrement proxy running_tasks count if finishing
            if (
                prev_status in ("assigned", "dispatched", "running")
                and assignment.proxy_id is not None
            ):
                proxy_status = session.get(ProxyStatus, assignment.proxy_id)
                if proxy_status and proxy_status.running_tasks > 0:
                    proxy_status.running_tasks = max(0, proxy_status.running_tasks - 1)
        elif status == "running" and not assignment.started_at:
            assignment.started_at = now

        if exit_code is not None:
            assignment.exit_code = exit_code
        if error_class is not None:
            assignment.error_class = error_class
        if error_code is not None:
            assignment.error_code = error_code
        assignment.bytes_transferred = bytes_transferred
        assignment.files_transferred = files_transferred
        assignment.duration_ms = duration_ms
        if checks_count > 0:
            assignment.checks_count = max(assignment.checks_count, checks_count)
        elif assignment.checks_count == 0 and status in ("succeeded", "failed"):
            # Fallback: check if task logs recorded checks count
            try:
                log_record = session.execute(
                    select(TaskLog.message)
                    .where(
                        TaskLog.assignment_id == assignment.id,
                        TaskLog.message.like("%Checks:%"),
                    )
                    .order_by(TaskLog.seq.desc())
                    .limit(1)
                ).scalar_one_or_none()
                if log_record:
                    m = re.search(r"Checks:\s*(\d+)\s*/", log_record)
                    if m:
                        assignment.checks_count = int(m.group(1))
            except Exception:
                pass

        task = assignment.task
        if status == "running":
            task.status = TaskState.RUNNING.value
        elif status == "succeeded":
            task.status = TaskState.SUCCEEDED.value
            task.finished_at = now
            if error_code == "FILES_EXCLUDED":
                task.last_error_code = error_code
        elif status == "failed":
            task.last_error_code = error_code
            if task.attempt_count < task.max_attempts and error_class != "permanent":
                task.status = TaskState.RETRY_WAIT.value
                task.next_attempt_at = now + timedelta(seconds=30)
            else:
                task.status = TaskState.FAILED.value
                task.finished_at = now

        # Update parent JobRun totals
        run = task.run
        ExecutionRepository._reconcile_job_run_state(session, run)

        session.flush()
        return assignment

    @staticmethod
    def _reconcile_job_run_state(_session: Session, run: JobRun) -> None:
        """Reconcile JobRun totals and final state once all tasks complete."""
        tasks = run.tasks
        total_tasks = len(tasks)
        if total_tasks == 0:
            return

        succeeded = sum(1 for t in tasks if t.status == TaskState.SUCCEEDED.value)
        failed = sum(1 for t in tasks if t.status == TaskState.FAILED.value)
        cancelled = sum(1 for t in tasks if t.status == TaskState.CANCELLED.value)
        skipped = sum(1 for t in tasks if t.status == TaskState.SKIPPED.value)

        run.tasks_succeeded = succeeded
        run.tasks_failed = failed

        # Aggregate transferred bytes and files across all successful tasks
        bytes_sum = 0
        files_sum = 0
        for t in tasks:
            for a in t.assignments:
                bytes_sum += a.bytes_transferred
                files_sum += a.files_transferred
        run.bytes_transferred = bytes_sum
        run.files_transferred = files_sum

        terminal_count = succeeded + failed + cancelled + skipped
        warned = sum(
            1
            for t in tasks
            if t.status == TaskState.SUCCEEDED.value and t.last_error_code == "FILES_EXCLUDED"
        )
        if warned:
            run.warning_code = "FILES_EXCLUDED"
        if terminal_count == total_tasks:
            run.finished_at = utc_now()
            if cancelled == total_tasks:
                run.status = RunState.CANCELLED.value
            elif failed == total_tasks:
                run.status = RunState.FAILED.value
            elif failed > 0 or cancelled > 0 or warned > 0:
                run.status = RunState.PARTIALLY_FAILED.value
            else:
                run.status = RunState.SUCCEEDED.value

    @staticmethod
    def get_max_task_log_seq(session: Session, assignment_id: UUID) -> int:
        """Get the maximum seq number recorded for a task assignment, or -1 if none."""
        max_seq = session.scalar(
            select(func.coalesce(func.max(TaskLog.seq), -1)).where(
                TaskLog.assignment_id == assignment_id
            )
        )
        return int(max_seq) if max_seq is not None else -1

    @staticmethod
    def record_task_log(
        session: Session,
        assignment_id: UUID,
        task_id: UUID,
        run_id: UUID,
        message: str,
        stream: str = "stdout",
        level: str = "info",
    ) -> TaskLog:
        """Append a log line to task_logs."""
        max_seq = session.scalar(
            select(func.coalesce(func.max(TaskLog.seq), -1)).where(
                TaskLog.assignment_id == assignment_id
            )
        )
        seq = (max_seq if max_seq is not None else -1) + 1

        log = TaskLog(
            assignment_id=assignment_id,
            task_id=task_id,
            run_id=run_id,
            seq=seq,
            stream=stream,
            level=level,
            message=message,
        )
        session.add(log)
        session.flush()
        return log

    @staticmethod
    def record_task_logs_batch(
        session: Session,
        assignment_id: UUID,
        task_id: UUID,
        run_id: UUID,
        lines: list[dict[str, Any]],
        from_seq: int = 0,
    ) -> int:
        """Batch record task logs avoiding duplicates."""
        current_seq = ExecutionRepository.get_max_task_log_seq(session, assignment_id) + 1
        inserted = 0
        for line in lines:
            line_seq = line.get("seq", 0)
            if line_seq < from_seq:
                continue
            log = TaskLog(
                assignment_id=assignment_id,
                task_id=task_id,
                run_id=run_id,
                seq=current_seq,
                stream=line.get("stream", "stdout"),
                level=line.get("level", "info"),
                message=line.get("message", ""),
            )
            session.add(log)
            current_seq += 1
            inserted += 1
        if inserted > 0:
            session.flush()
        return inserted

    @staticmethod
    def get_task_logs(
        session: Session,
        task_id: UUID,
        limit: int | None = None,
        from_seq: int = 0,
        tail: bool = False,
    ) -> list[TaskLog]:
        """Fetch logs for a task ordered chronologically."""
        stmt = select(TaskLog).where(TaskLog.task_id == task_id)
        if from_seq > 0:
            stmt = stmt.where(TaskLog.seq >= from_seq)

        if tail and limit is not None:
            stmt = stmt.order_by(TaskLog.seq.desc()).limit(limit)
            logs = list(session.scalars(stmt).all())
            logs.reverse()
            return logs

        stmt = stmt.order_by(TaskLog.seq.asc())
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(session.scalars(stmt).all())

    @staticmethod
    def get_run_proxies_activity(session: Session, run: JobRun) -> list[dict[str, Any]]:
        """Compute the current activity and status of each proxy in the context of a job run."""
        from embervault_db.repositories.proxy_repository import ProxyRepository

        proxies = ProxyRepository.get_all_proxies(session)
        result: list[dict[str, Any]] = []

        # Map active tasks of this run to their assigned proxy IDs
        proxy_active_tasks: dict[UUID, list[str]] = {}
        proxy_active_task_ids: dict[UUID, list[UUID]] = {}
        for task in run.tasks:
            if task.status in ("assigned", "running") and task.assignments:
                latest_assign = task.assignments[-1]
                if latest_assign.status in ("assigned", "dispatched", "running"):
                    p_id = latest_assign.proxy_id
                    label = (
                        task.spec.get("source_subpath")
                        if task.spec.get("source_subpath")
                        else ("ROOT FILES" if task.scope == "root_files" else task.scope)
                    )
                    proxy_active_tasks.setdefault(p_id, []).append(str(label))
                    proxy_active_task_ids.setdefault(p_id, []).append(task.id)

        # Pre-calculate progress stats if run is available
        tasks_stats = ExecutionRepository.get_run_tasks_progress_stats(session, run) if run else {}

        for p in proxies:
            p_state = p.status.state if p.status else ("online" if p.is_enabled else "offline")
            active_tasks = proxy_active_tasks.get(p.id, [])
            active_tids = proxy_active_task_ids.get(p.id, [])

            # Calculate proxy throughput from active tasks
            p_speed_bytes = sum(
                tasks_stats.get(tid, {}).get("speed_bytes_per_sec", 0.0) for tid in active_tids
            )
            if len(active_tids) == 1 and tasks_stats.get(active_tids[0], {}).get(
                "speed_display"
            ) not in (None, "-", "0 B/s"):
                p_throughput_str = tasks_stats[active_tids[0]]["speed_display"]
            else:
                p_throughput_str = ExecutionRepository.format_speed(p_speed_bytes)

            if not p.is_enabled:
                state = "disabled"
                activity = "Disabilitato"
                p_throughput_str = "0 B/s"
                p_speed_bytes = 0.0
            elif p_state in ("offline", "unknown"):
                state = "offline"
                activity = "Offline"
                p_throughput_str = "0 B/s"
                p_speed_bytes = 0.0
            elif active_tasks:
                state = "busy"
                if len(active_tasks) == 1:
                    activity = f"Eseguendo task {active_tasks[0]}"
                else:
                    activity = f"Eseguendo task: {', '.join(active_tasks)}"
            else:
                state = "idle"
                activity = "In attesa di task"
                p_throughput_str = "0 B/s"
                p_speed_bytes = 0.0

            result.append(
                {
                    "id": str(p.id),
                    "name": p.name,
                    "host": p.host,
                    "port": p.port,
                    "state": state,
                    "raw_state": p_state,
                    "activity": activity,
                    "active_tasks": active_tasks,
                    "throughput": p_throughput_str,
                    "speed_bytes_per_sec": p_speed_bytes,
                }
            )

        return result

    @staticmethod
    def format_speed(bytes_per_sec: float) -> str:
        """Format transfer throughput into human-readable speed string."""
        if bytes_per_sec <= 0:
            return "0 B/s"
        if bytes_per_sec >= 1073741824:
            return f"{bytes_per_sec / 1073741824:.2f} GiB/s"
        if bytes_per_sec >= 1048576:
            return f"{bytes_per_sec / 1048576:.2f} MiB/s"
        if bytes_per_sec >= 1024:
            return f"{bytes_per_sec / 1024:.2f} KiB/s"
        return f"{int(bytes_per_sec)} B/s"

    @staticmethod
    def get_run_tasks_progress_stats(session: Session, run: JobRun) -> dict[UUID, dict[str, Any]]:
        """Compute live or historical rclone progress stats (checks, transferred, ETA, speed) for tasks in a run."""
        result: dict[UUID, dict[str, Any]] = {}
        if not run or not run.tasks:
            return result

        task_ids = [t.id for t in run.tasks]
        stmt = (
            select(TaskLog.task_id, TaskLog.message)
            .where(
                TaskLog.task_id.in_(task_ids),
                or_(
                    TaskLog.message.like("%Checks:%"),
                    TaskLog.message.like("%Transferred:%"),
                ),
            )
            .order_by(TaskLog.task_id, TaskLog.seq.asc())
        )
        logs_records = session.execute(stmt).all()

        task_messages: dict[UUID, list[str]] = {}
        for tid, msg in logs_records:
            task_messages.setdefault(tid, []).append(msg)

        checks_re = re.compile(r"Checks:\s*(\d+)")
        files_re = re.compile(r"Transferred:\s*(\d+)\s*/\s*(\d+)(?:,\s*([\d.]+)%)?")
        speed_re = re.compile(r",\s*([\d.]+)\s*([KMGTP]?i?B/s)", re.IGNORECASE)
        eta_re = re.compile(r"\bETA\s+([^\s,]+)")

        speed_multipliers = {
            "B/S": 1.0,
            "KB/S": 1024.0,
            "KIB/S": 1024.0,
            "MB/S": 1048576.0,
            "MIB/S": 1048576.0,
            "GB/S": 1073741824.0,
            "GIB/S": 1073741824.0,
            "TB/S": 1099511627776.0,
            "TIB/S": 1099511627776.0,
        }

        for task in run.tasks:
            msgs = task_messages.get(task.id, [])
            latest_checks: str | None = None
            latest_transferred: str | None = None
            latest_speed_str: str | None = None
            latest_speed_bytes: float = 0.0
            latest_eta: str | None = None

            for m in msgs:
                mc = checks_re.search(m)
                if mc:
                    latest_checks = mc.group(1)

                mf = files_re.search(m)
                if mf:
                    f_done, f_tot, f_pct = mf.groups()
                    pct_str = (
                        f"{f_pct}%"
                        if f_pct
                        else (
                            f"{round((int(f_done) / int(f_tot)) * 100)}%"
                            if int(f_tot) > 0
                            else "0%"
                        )
                    )
                    latest_transferred = f"{f_done}/{f_tot} - {pct_str}"

                ms = speed_re.search(m)
                if ms:
                    s_val, s_unit = ms.groups()
                    mult = speed_multipliers.get(s_unit.upper(), 1.0)
                    try:
                        latest_speed_bytes = float(s_val) * mult
                        latest_speed_str = f"{s_val} {s_unit}"
                    except ValueError:
                        pass

                me = eta_re.search(m)
                if me:
                    latest_eta = me.group(1).strip()

            is_active = task.status in (TaskState.RUNNING.value, TaskState.ASSIGNED.value)
            result[task.id] = {
                "checks_display": latest_checks or "-",
                "transferred_display": latest_transferred or "-",
                "speed_display": (latest_speed_str if is_active else "0 B/s") or "0 B/s",
                "speed_bytes_per_sec": latest_speed_bytes if is_active else 0.0,
                "eta_display": (latest_eta if is_active else "-") or "-",
            }

        return result

    @staticmethod
    def record_run_hook(
        session: Session,
        run_id: UUID,
        hook_type: str,
        script_hash: str,
        status: str,
        exit_code: int | None,
        duration_ms: float,
        output: str,
    ) -> JobRunHook:
        """Persist the execution result of a pre-run or post-run hook."""
        from embervault_db.models.execution import JobRunHook

        hook = JobRunHook(
            id=uuid4(),
            run_id=run_id,
            hook_type=hook_type,
            script_hash=script_hash,
            status=status,
            exit_code=exit_code,
            duration_ms=duration_ms,
            output=output,
            executed_at=utc_now(),
        )
        session.add(hook)
        session.flush()
        return hook

    @staticmethod
    def get_run_hooks(session: Session, run_id: UUID) -> list[JobRunHook]:
        """Fetch all executed hooks for a given run ordered by execution time."""
        from embervault_db.models.execution import JobRunHook

        stmt = (
            select(JobRunHook)
            .where(JobRunHook.run_id == run_id)
            .order_by(JobRunHook.executed_at.asc())
        )
        return list(session.scalars(stmt).all())

    @staticmethod
    def cleanup_expired_task_logs(session: Session, retention_days: int) -> int:
        """Delete task_logs older than retention_days based on timestamp.

        Args:
            session: Active database session.
            retention_days: Number of days to retain logs (must be >= 1).

        Returns:
            Number of deleted task log entries.
        """
        from datetime import UTC, datetime, timedelta
        from sqlalchemy import delete
        from embervault_db.models.execution import TaskLog

        if retention_days < 1:
            return 0

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        stmt = (
            delete(TaskLog).where(TaskLog.ts < cutoff).execution_options(synchronize_session=False)
        )
        res = session.execute(stmt)
        session.flush()
        return res.rowcount or 0

    @staticmethod
    def record_throughput_sample(
        session: Session,
        bytes_per_sec: float,
        active_runs: int = 0,
        min_interval_s: float = 3.0,
    ) -> Any | None:
        """Record a throughput measurement sample, throttled by min_interval_s."""
        from datetime import UTC
        from embervault_db.models.base import utc_now
        from embervault_db.models.execution import ThroughputSample

        now = utc_now()
        latest = session.scalar(
            select(ThroughputSample).order_by(ThroughputSample.recorded_at.desc()).limit(1)
        )
        if latest and latest.recorded_at:
            lat_dt = latest.recorded_at
            if lat_dt.tzinfo is None:
                lat_dt = lat_dt.replace(tzinfo=UTC)
            diff = (now - lat_dt).total_seconds()
            if diff < min_interval_s:
                return latest

        sample = ThroughputSample(
            bytes_per_sec=float(bytes_per_sec),
            active_runs=int(active_runs),
            recorded_at=now,
        )
        session.add(sample)
        session.flush()
        return sample

    @staticmethod
    def get_throughput_history(
        session: Session,
        start_time: Any,
        end_time: Any,
        max_points: int = 120,
    ) -> list[dict[str, Any]]:
        """Query historical throughput samples in a time window and downsample if necessary."""
        from datetime import UTC, timedelta
        from embervault_db.models.execution import ThroughputSample

        def to_utc(dt: Any) -> Any:
            if dt is None:
                return dt
            if dt.tzinfo is None:
                return dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC)

        start_time = to_utc(start_time)
        end_time = to_utc(end_time)

        stmt = (
            select(ThroughputSample)
            .where(
                ThroughputSample.recorded_at >= start_time,
                ThroughputSample.recorded_at <= end_time,
            )
            .order_by(ThroughputSample.recorded_at.asc())
        )
        rows = list(session.scalars(stmt).all())
        if not rows:
            return []

        if len(rows) <= max_points:
            return [
                {
                    "timestamp": to_utc(s.recorded_at).isoformat(),
                    "bytes_per_sec": s.bytes_per_sec,
                    "speed_display": ExecutionRepository.format_speed(s.bytes_per_sec),
                    "active_runs": s.active_runs,
                }
                for s in rows
            ]

        total_duration = max(1.0, (end_time - start_time).total_seconds())
        bucket_s = total_duration / max_points
        buckets: dict[int, list[ThroughputSample]] = {}
        for s in rows:
            s_dt = to_utc(s.recorded_at)
            offset = max(0.0, (s_dt - start_time).total_seconds())
            b_idx = min(max_points - 1, int(offset // bucket_s))
            buckets.setdefault(b_idx, []).append(s)

        results: list[dict[str, Any]] = []
        for b_idx in sorted(buckets.keys()):
            b_samples = buckets[b_idx]
            avg_speed = sum(s.bytes_per_sec for s in b_samples) / len(b_samples)
            mid_time = start_time + timedelta(seconds=(b_idx + 0.5) * bucket_s)
            results.append(
                {
                    "timestamp": mid_time.isoformat(),
                    "bytes_per_sec": round(avg_speed, 2),
                    "speed_display": ExecutionRepository.format_speed(avg_speed),
                    "active_runs": max(s.active_runs for s in b_samples),
                }
            )
        return results

    @staticmethod
    def cleanup_expired_throughput_samples(session: Session, retention_days: int) -> int:
        """Delete throughput samples older than retention_days.

        Args:
            session: Active database session.
            retention_days: Number of days to retain samples (must be >= 1).

        Returns:
            Number of deleted sample records.
        """
        from datetime import UTC, datetime, timedelta
        from sqlalchemy import delete
        from embervault_db.models.execution import ThroughputSample

        if retention_days < 1:
            return 0

        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        stmt = (
            delete(ThroughputSample)
            .where(ThroughputSample.recorded_at < cutoff)
            .execution_options(synchronize_session=False)
        )
        res = session.execute(stmt)
        session.flush()
        return res.rowcount or 0
