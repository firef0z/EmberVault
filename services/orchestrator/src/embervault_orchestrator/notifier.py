"""Notification service for EmberVault Orchestrator."""

from __future__ import annotations

import time
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from embervault_common.notifications.apprise_notifier import AppriseNotifier
from embervault_common.notifications.contracts import NotificationEventType
from embervault_common.notifications.formatter import NotificationFormatter
from embervault_common.observability import get_logger
from embervault_db.models.auth import AuditLog
from embervault_db.models.base import utc_now
from embervault_db.models.execution import JobRun
from embervault_db.models.proxy import Proxy
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.repositories.notification_repository import NotificationRepository
from embervault_db.settings_store import SettingsStore
from embervault_orchestrator.ai_reporter import AIReporter

logger = get_logger("embervault_orchestrator.notifier")


class NotificationService:
    """Evaluates notification policies and dispatches alerts via configured Apprise channels."""

    def __init__(
        self,
        settings_store: SettingsStore,
        notifier: AppriseNotifier | None = None,
        ai_reporter: AIReporter | None = None,
    ) -> None:
        self.settings_store = settings_store
        self.notifier = notifier or AppriseNotifier()
        self.ai_reporter = ai_reporter or AIReporter(settings_store)
        self._last_sent_per_channel: dict[uuid.UUID, float] = {}

    def notify_job_run_completion(self, session: Session, run: JobRun) -> int:
        """Evaluate and send completion/error notifications for a finished JobRun.

        Args:
            session: Active database session.
            run: Terminal JobRun entity.

        Returns:
            Number of notification channels successfully dispatched.
        """
        if run.notification_sent_at is not None:
            return 0

        # Only terminal runs are eligible for completion notifications
        if run.status not in ("succeeded", "failed", "partially_failed", "cancelled"):
            return 0

        # Check global notifications master switch
        global_enabled = self.settings_store.get_setting("notifications_enabled")
        if global_enabled is False:
            run.notification_sent_at = utc_now()
            session.flush()
            return 0

        job = run.job
        if job is None:
            return 0

        # Check per-job notification toggle
        job_notifications_enabled = getattr(job, "notifications_enabled", None)
        if job_notifications_enabled is None and run.job_snapshot:
            job_notifications_enabled = run.job_snapshot.get("notifications_enabled", True)

        if not job_notifications_enabled:
            logger.info("job_notifications_disabled_by_job", job_name=job.name, run_id=str(run.id))
            run.notification_sent_at = utc_now()
            session.flush()
            return 0

        # Check policy: per-job notification_policy overrides global policy if specified
        job_policy = getattr(job, "notification_policy", None)
        if not job_policy and run.job_snapshot:
            job_policy = run.job_snapshot.get("notification_policy")

        if job_policy in ("always", "only_errors"):
            policy = job_policy
        else:
            policy = self.settings_store.get_setting("notification_job_policy") or "only_errors"

        if policy == "only_errors" and run.status not in ("failed", "partially_failed"):
            # Success/cancelled run without error -> policy suppressed
            run.notification_sent_at = utc_now()
            session.flush()
            return 0

        channels = NotificationRepository.list_channels(session, only_enabled=True)
        if not channels:
            run.notification_sent_at = utc_now()
            session.flush()
            return 0

        duration_s: float | None = None
        if run.started_at and run.finished_at:
            duration_s = (run.finished_at - run.started_at).total_seconds()

        # Extract detailed execution metrics for each task
        tasks_detail: list[dict[str, Any]] = []
        for task in sorted(run.tasks or [], key=lambda t: (t.seq, getattr(t, "created_at", 0))):
            assignments = task.assignments or []
            total_duration_ms = sum(a.duration_ms for a in assignments if a.duration_ms)
            total_files = sum(a.files_transferred for a in assignments if a.files_transferred)
            total_bytes = sum(a.bytes_transferred for a in assignments if a.bytes_transferred)
            last_assignment = assignments[-1] if assignments else None

            proxy_name = None
            if last_assignment and last_assignment.proxy:
                proxy_name = last_assignment.proxy.name

            subpath = None
            if isinstance(task.spec, dict):
                subpath = (
                    task.spec.get("source_subpath")
                    or task.spec.get("subpath")
                    or task.spec.get("path")
                )

            task_dur_ms = total_duration_ms or (
                last_assignment.duration_ms if last_assignment else 0
            )
            task_files = total_files or (
                last_assignment.files_transferred if last_assignment else 0
            )
            task_bytes = total_bytes or (
                last_assignment.bytes_transferred if last_assignment else 0
            )

            error_logs: list[str] = []
            ai_evaluation: dict[str, Any] | None = None
            if (
                task.status in ("failed", "partially_failed")
                or task.last_error_code
                or (last_assignment and last_assignment.error_code)
            ):
                try:
                    # Retrieve latest stderr logs for this failed task
                    t_logs = ExecutionRepository.get_task_logs(
                        session, task.id, limit=50, tail=True
                    )
                    stderr_lines = [l.message for l in t_logs if l.stream == "stderr"]
                    error_logs = (stderr_lines if stderr_lines else [l.message for l in t_logs])[
                        -10:
                    ]
                except Exception as log_err:
                    logger.debug(
                        "failed_to_fetch_task_logs_for_notification",
                        task_id=str(task.id),
                        error=str(log_err),
                    )

                try:
                    # Check for AI decision making evaluation in AuditLog
                    audit_stmt = (
                        select(AuditLog)
                        .where(
                            AuditLog.action == "ai.error_decision",
                            AuditLog.entity_id == str(task.id),
                        )
                        .order_by(AuditLog.created_at.desc())
                        .limit(1)
                    )
                    audit_entry = session.scalars(audit_stmt).first()
                    if audit_entry and isinstance(audit_entry.details, dict):
                        ai_evaluation = {
                            "decision": audit_entry.details.get("decision"),
                            "confidence": audit_entry.details.get("confidence"),
                            "interpretation": audit_entry.details.get("interpretation"),
                            "reason": audit_entry.details.get("reason"),
                            "action_taken": audit_entry.details.get("action_taken"),
                        }
                except Exception as audit_err:
                    logger.debug(
                        "failed_to_fetch_ai_decision_for_notification",
                        task_id=str(task.id),
                        error=str(audit_err),
                    )

            task_info: dict[str, Any] = {
                "task_id": str(task.id),
                "seq": task.seq,
                "kind": task.kind,
                "scope": task.scope,
                "subpath": subpath,
                "status": task.status,
                "attempt_count": task.attempt_count,
                "max_attempts": task.max_attempts,
                "duration_ms": task_dur_ms,
                "duration_s": round(task_dur_ms / 1000.0, 2),
                "files_transferred": task_files,
                "bytes_transferred": task_bytes,
                "proxy": proxy_name,
                "last_error_code": task.last_error_code
                or (last_assignment.error_code if last_assignment else None),
                "last_error_class": last_assignment.error_class if last_assignment else None,
                "exit_code": last_assignment.exit_code if last_assignment else None,
                "error_logs": error_logs,
                "ai_evaluation": ai_evaluation,
            }
            tasks_detail.append(task_info)

        context: dict[str, Any] = {
            "job_name": job.name,
            "run_id": str(run.id),
            "status": run.status,
            "operation": getattr(job, "operation", None),
            "parallelization": getattr(job, "parallelization", None),
            "max_parallel_tasks": getattr(job, "max_parallel_tasks", None),
            "files_transferred": run.files_transferred,
            "bytes_transferred": run.bytes_transferred,
            "tasks_succeeded": run.tasks_succeeded,
            "tasks_failed": run.tasks_failed,
            "total_tasks_count": len(run.tasks or []),
            "duration_s": duration_s,
            "error_message": run.error_message,
            "tasks_detail": tasks_detail,
        }

        # AI-driven report analysis & recommendations if enabled
        if self.ai_reporter.is_enabled():
            ai_summary = self.ai_reporter.generate_report_analysis(
                session=session,
                event_type=NotificationEventType.JOB_RUN_COMPLETED.value,
                context=context,
                entity_id=str(run.id),
                actor_user_id=run.requested_by,
            )
            if ai_summary:
                context["ai_analysis"] = ai_summary

        sent_count = 0
        now_ts = time.time()

        for channel in channels:
            # Evaluate channel rate limit
            interval = channel.rate_limit_interval_s
            if interval > 0:
                last_ts = self._last_sent_per_channel.get(channel.id, 0.0)
                if (now_ts - last_ts) < interval:
                    logger.warning(
                        "notification_rate_limited",
                        channel_name=channel.name,
                        channel_id=str(channel.id),
                        interval_s=interval,
                    )
                    continue

            try:
                raw_url = NotificationRepository.get_decrypted_url(channel)
                title, body, notify_fmt = NotificationFormatter.format(
                    event_type=NotificationEventType.JOB_RUN_COMPLETED,
                    context=context,
                    telegram_format=channel.telegram_format,
                )
                success = self.notifier.send(
                    url=raw_url,
                    title=title,
                    body=body,
                    body_format=notify_fmt,
                )
                if success:
                    self._last_sent_per_channel[channel.id] = now_ts
                    sent_count += 1
            except Exception as exc:
                logger.error(
                    "channel_notification_error",
                    channel_name=channel.name,
                    channel_id=str(channel.id),
                    error=str(exc),
                )

        run.notification_sent_at = utc_now()
        session.flush()
        return sent_count

    def notify_proxy_offline(
        self,
        session: Session,
        proxy: Proxy,
        reason: str,
        consecutive_failures: int,
        is_incompatible: bool = False,
        detected_version: str | None = None,
        min_version: str | None = None,
    ) -> int:
        """Send notification when a proxy node transitions to offline state or version incompatible.

        Args:
            session: Active database session.
            proxy: Proxy database model.
            reason: Error explanation or failure reason.
            consecutive_failures: Consecutive health probe failures.
            is_incompatible: Whether the failure is due to container version incompatibility.
            detected_version: Version reported by the proxy worker.
            min_version: Minimum version required by the orchestrator.

        Returns:
            Number of notification channels successfully dispatched.
        """
        global_enabled = self.settings_store.get_setting("notifications_enabled")
        if global_enabled is False:
            return 0

        proxy_alert_enabled = self.settings_store.get_setting("notification_proxy_offline_enabled")
        if proxy_alert_enabled is False:
            return 0

        channels = NotificationRepository.list_channels(session, only_enabled=True)
        if not channels:
            return 0

        last_seen = "N/D"
        if proxy.status and proxy.status.last_seen_at:
            last_seen = proxy.status.last_seen_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        context: dict[str, Any] = {
            "proxy_name": proxy.name,
            "host": proxy.host,
            "port": proxy.port,
            "consecutive_failures": consecutive_failures,
            "reason": reason,
            "last_seen_at": last_seen,
            "is_incompatible": is_incompatible,
            "detected_version": detected_version,
            "min_version": min_version,
        }

        if self.ai_reporter.is_enabled():
            ai_summary = self.ai_reporter.generate_report_analysis(
                session=session,
                event_type=NotificationEventType.PROXY_OFFLINE.value,
                context=context,
                entity_id=str(proxy.id),
            )
            if ai_summary:
                context["ai_analysis"] = ai_summary

        sent_count = 0
        now_ts = time.time()

        for channel in channels:
            interval = channel.rate_limit_interval_s
            if interval > 0:
                last_ts = self._last_sent_per_channel.get(channel.id, 0.0)
                if (now_ts - last_ts) < interval:
                    logger.warning(
                        "proxy_offline_rate_limited",
                        channel_name=channel.name,
                        channel_id=str(channel.id),
                    )
                    continue

            try:
                raw_url = NotificationRepository.get_decrypted_url(channel)
                title, body, notify_fmt = NotificationFormatter.format(
                    event_type=NotificationEventType.PROXY_OFFLINE,
                    context=context,
                    telegram_format=channel.telegram_format,
                )
                success = self.notifier.send(
                    url=raw_url,
                    title=title,
                    body=body,
                    body_format=notify_fmt,
                )
                if success:
                    self._last_sent_per_channel[channel.id] = now_ts
                    sent_count += 1
            except Exception as exc:
                logger.error(
                    "proxy_offline_notification_error",
                    channel_name=channel.name,
                    error=str(exc),
                )

        return sent_count

    def notify_proxy_untrusted(
        self,
        session: Session,
        proxy: Proxy,
        reason: str,
    ) -> int:
        """Send notification when a proxy node becomes untrusted due to TLS certificate fingerprint mismatch."""
        global_enabled = self.settings_store.get_setting("notifications_enabled")
        if global_enabled is False:
            return 0

        channels = NotificationRepository.list_channels(session, only_enabled=True)
        if not channels:
            return 0

        context: dict[str, Any] = {
            "proxy_name": proxy.name,
            "host": proxy.host,
            "port": proxy.port,
            "reason": reason,
        }

        sent_count = 0
        now_ts = time.time()
        for channel in channels:
            interval = channel.rate_limit_interval_s
            if interval > 0:
                last_ts = self._last_sent_per_channel.get(channel.id, 0.0)
                if (now_ts - last_ts) < interval:
                    continue

            try:
                raw_url = NotificationRepository.get_decrypted_url(channel)
                title, body, notify_fmt = NotificationFormatter.format(
                    event_type=NotificationEventType.PROXY_UNTRUSTED,
                    context=context,
                    telegram_format=channel.telegram_format,
                )
                success = self.notifier.send(
                    url=raw_url,
                    title=title,
                    body=body,
                    body_format=notify_fmt,
                )
                if success:
                    self._last_sent_per_channel[channel.id] = now_ts
                    sent_count += 1
            except Exception as exc:
                logger.error(
                    "proxy_untrusted_notification_error",
                    channel_name=channel.name,
                    error=str(exc),
                )

        return sent_count

    def notify_proxy_cert_expiring(
        self,
        session: Session,
        proxy: Proxy,
        days_remaining: int,
        cert_expires_at: Any,
    ) -> int:
        """Send notification when a proxy's TLS certificate is close to expiration (< 15 days)."""
        global_enabled = self.settings_store.get_setting("notifications_enabled")
        if global_enabled is False:
            return 0

        channels = NotificationRepository.list_channels(session, only_enabled=True)
        if not channels:
            return 0

        context: dict[str, Any] = {
            "proxy_name": proxy.name,
            "host": proxy.host,
            "port": proxy.port,
            "days_remaining": days_remaining,
            "cert_expires_at": str(cert_expires_at),
        }

        sent_count = 0
        now_ts = time.time()
        for channel in channels:
            interval = channel.rate_limit_interval_s
            if interval > 0:
                last_ts = self._last_sent_per_channel.get(channel.id, 0.0)
                if (now_ts - last_ts) < interval:
                    continue

            try:
                raw_url = NotificationRepository.get_decrypted_url(channel)
                title, body, notify_fmt = NotificationFormatter.format(
                    event_type=NotificationEventType.PROXY_CERT_EXPIRING,
                    context=context,
                    telegram_format=channel.telegram_format,
                )
                success = self.notifier.send(
                    url=raw_url,
                    title=title,
                    body=body,
                    body_format=notify_fmt,
                )
                if success:
                    self._last_sent_per_channel[channel.id] = now_ts
                    sent_count += 1
            except Exception as exc:
                logger.error(
                    "proxy_cert_expiring_notification_error",
                    channel_name=channel.name,
                    error=str(exc),
                )

        return sent_count

    def notify_rclone_updates_available(
        self,
        session: Session,
        proxy_names: list[str],
        latest_version: str,
    ) -> int:
        """Send a single consolidated notification when RClone updates are available on one or more proxies."""
        if not proxy_names:
            return 0

        global_enabled = self.settings_store.get_setting("notifications_enabled")
        if global_enabled is False:
            return 0

        rclone_alert_enabled = self.settings_store.get_setting("notification_rclone_update_enabled")
        if rclone_alert_enabled is False:
            return 0

        channels = NotificationRepository.list_channels(session, only_enabled=True)
        if not channels:
            return 0

        context: dict[str, Any] = {
            "proxies": proxy_names,
            "latest_version": latest_version,
        }

        sent_count = 0
        now_ts = time.time()

        for channel in channels:
            interval = channel.rate_limit_interval_s
            if interval > 0:
                last_ts = self._last_sent_per_channel.get(channel.id, 0.0)
                if (now_ts - last_ts) < interval:
                    logger.warning(
                        "rclone_update_notification_rate_limited",
                        channel_name=channel.name,
                        channel_id=str(channel.id),
                    )
                    continue

            try:
                raw_url = NotificationRepository.get_decrypted_url(channel)
                title, body, notify_fmt = NotificationFormatter.format(
                    event_type=NotificationEventType.RCLONE_UPDATE_AVAILABLE,
                    context=context,
                    telegram_format=channel.telegram_format,
                )
                success = self.notifier.send(
                    url=raw_url,
                    title=title,
                    body=body,
                    body_format=notify_fmt,
                )
                if success:
                    self._last_sent_per_channel[channel.id] = now_ts
                    sent_count += 1
            except Exception as exc:
                logger.error(
                    "rclone_update_notification_error",
                    channel_name=channel.name,
                    error=str(exc),
                )

        return sent_count

    def notify_hook_failure(
        self,
        session: Session,
        run: JobRun,
        hook_type: str,
        status: str,
        exit_code: int | None = None,
        duration_ms: float | None = None,
        output: str | None = None,
        job_name: str | None = None,
    ) -> int:
        """Send notification when a pre-run or post-run bash hook execution fails.

        Args:
            session: Active database session.
            run: JobRun entity associated with the hook.
            hook_type: Hook category ('pre_run' or 'post_run').
            status: Hook execution status ('failed', 'timed_out', etc.).
            exit_code: Process exit code if available.
            duration_ms: Execution duration in milliseconds.
            output: Error output or failure snippet.
            job_name: Optional explicit job name override.

        Returns:
            Number of notification channels successfully dispatched.
        """
        global_enabled = self.settings_store.get_setting("notifications_enabled")
        if global_enabled is False:
            return 0

        job = run.job
        if job is not None and not getattr(job, "notifications_enabled", True):
            logger.info(
                "hook_failure_notification_disabled_by_job", job_name=job.name, run_id=str(run.id)
            )
            return 0

        snap = run.job_snapshot or {}
        if job is None and snap.get("notifications_enabled") is False:
            return 0

        channels = NotificationRepository.list_channels(session, only_enabled=True)
        if not channels:
            return 0

        resolved_job_name = job_name or (job.name if job else snap.get("name", "Job"))
        context: dict[str, Any] = {
            "job_name": resolved_job_name,
            "run_id": str(run.id),
            "hook_type": hook_type,
            "status": status,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "output": output,
        }

        sent_count = 0
        now_ts = time.time()

        for channel in channels:
            interval = channel.rate_limit_interval_s
            if interval > 0:
                last_ts = self._last_sent_per_channel.get(channel.id, 0.0)
                if (now_ts - last_ts) < interval:
                    logger.warning(
                        "hook_failure_rate_limited",
                        channel_name=channel.name,
                        channel_id=str(channel.id),
                        interval_s=interval,
                    )
                    continue

            try:
                raw_url = NotificationRepository.get_decrypted_url(channel)
                title, body, notify_fmt = NotificationFormatter.format(
                    event_type=NotificationEventType.HOOK_FAILED,
                    context=context,
                    telegram_format=channel.telegram_format,
                )
                success = self.notifier.send(
                    url=raw_url,
                    title=title,
                    body=body,
                    body_format=notify_fmt,
                )
                if success:
                    self._last_sent_per_channel[channel.id] = now_ts
                    sent_count += 1
            except Exception as exc:
                logger.error(
                    "hook_failure_notification_error",
                    channel_name=channel.name,
                    channel_id=str(channel.id),
                    error=str(exc),
                )

        return sent_count

    def notify_job_policy_executed(
        self,
        session: Session,
        job: Any,
        *,
        policy_type: str,
        policy_value: str,
        message: str,
        run_id: uuid.UUID | str | None = None,
    ) -> int:
        """Send notification when a job execution policy is triggered and its Notify flag is enabled.

        Args:
            session: Active database session.
            job: Job entity on which the policy triggered.
            policy_type: One of 'missed_run', 'overlap', 'pending', 'max_runtime'.
            policy_value: The configured policy option/value that executed.
            message: Detailed human-readable description of what happened.
            run_id: Optional associated JobRun UUID.

        Returns:
            Number of notification channels successfully dispatched.
        """
        global_enabled = self.settings_store.get_setting("notifications_enabled")
        if global_enabled is False:
            return 0

        flag_map = {
            "missed_run": "missed_run_notify",
            "overlap": "overlap_notify",
            "pending": "pending_notify",
            "max_runtime": "max_runtime_notify",
        }
        flag_attr = flag_map.get(policy_type)
        if not flag_attr or not bool(getattr(job, flag_attr, False)):
            return 0

        label_map = {
            "missed_run": "Missed Run Policy",
            "overlap": "Overlap Policy",
            "pending": "Pending Policy",
            "max_runtime": "Max Runtime Policy",
        }
        policy_label = label_map.get(policy_type, policy_type)

        channels = NotificationRepository.list_channels(session, only_enabled=True)
        if not channels:
            return 0

        context: dict[str, Any] = {
            "job_name": getattr(job, "name", str(getattr(job, "id", "Job"))),
            "policy_type": policy_type,
            "policy_label": policy_label,
            "policy_value": policy_value,
            "message": message,
            "run_id": str(run_id) if run_id else None,
        }

        sent_count = 0
        now_ts = time.time()

        for channel in channels:
            interval = channel.rate_limit_interval_s
            if interval > 0:
                last_ts = self._last_sent_per_channel.get(channel.id, 0.0)
                if (now_ts - last_ts) < interval:
                    logger.warning(
                        "job_policy_notification_rate_limited",
                        channel_name=channel.name,
                        channel_id=str(channel.id),
                        interval_s=interval,
                    )
                    continue

            try:
                raw_url = NotificationRepository.get_decrypted_url(channel)
                title, body, notify_fmt = NotificationFormatter.format(
                    event_type=NotificationEventType.JOB_POLICY_EXECUTED,
                    context=context,
                    telegram_format=channel.telegram_format,
                )
                success = self.notifier.send(
                    url=raw_url,
                    title=title,
                    body=body,
                    body_format=notify_fmt,
                )
                if success:
                    self._last_sent_per_channel[channel.id] = now_ts
                    sent_count += 1
            except Exception as exc:
                logger.error(
                    "job_policy_notification_error",
                    channel_name=channel.name,
                    channel_id=str(channel.id),
                    error=str(exc),
                )

        if sent_count > 0:
            session.add(
                AuditLog(
                    action="notification.policy_sent",
                    actor_user_id=None,
                    entity_type="job",
                    entity_id=str(getattr(job, "id", "")),
                    details={
                        "job_id": str(getattr(job, "id", "")),
                        "job_name": context["job_name"],
                        "policy_type": policy_type,
                        "policy_value": policy_value,
                        "run_id": context["run_id"],
                        "channels_sent": sent_count,
                        "message": message,
                    },
                )
            )
            session.flush()

        return sent_count
