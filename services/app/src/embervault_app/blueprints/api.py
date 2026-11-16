"""JSON API Blueprint for frontend polling, proxy probe, and proxy registration."""

from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.parse
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from flask import (
    Blueprint,
    Response,
    current_app,
    g,
    jsonify,
    make_response,
    request,
    send_file,
    stream_with_context,
)
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.auth import get_current_user, is_admin_user, require_auth, require_permission
from embervault_app.i18n import translate as _
from embervault_app.orchestrator_client import OrchestratorClient
from embervault_app.timezones import get_user_timezone
from embervault_common.cron import validate_cron_expression, validate_timezone_name
from embervault_common.notifications import (
    AppriseNotifier,
    NotificationEventType,
    NotificationFormatter,
    build_email_url,
    build_telegram_url,
    validate_apprise_url,
)
from embervault_common.observability import get_logger
from embervault_common.ai.prompts import (
    get_default_error_system_prompt,
    get_default_reporting_system_prompt,
)
from embervault_common.remotes.catalog import (
    RemoteConfigValidationError,
    get_backend_catalog,
    get_backend_spec,
    validate_and_split_remote_config,
)
from embervault_db import rotate_all_credentials
from embervault_db.models import AuditLog, JobRun, Proxy, ProxyStatus, TaskAssignment, TaskLog, User
from embervault_db.models.base import utc_now
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.repositories.job_repository import _UNSET, JobRepository
from embervault_db.repositories.notification_repository import NotificationRepository
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.repositories.user_repository import UserRepository

logger = get_logger("embervault_app.api")
api_bp = Blueprint("api", __name__, url_prefix="/api/ui")


def _parse_bool_flag(val: Any, default: bool = True) -> bool:
    """Parse boolean flags from JSON payloads safely."""
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        clean = val.strip().lower()
        if clean in {"true", "1", "yes", "on"}:
            return True
        if clean in {"false", "0", "no", "off"}:
            return False
    return bool(val)


def _parse_job_run_policies(
    data: dict[str, Any], is_update: bool = False
) -> tuple[dict[str, Any], str | None]:
    """Parse and validate job run policy fields from create/update JSON payloads."""
    from embervault_db.repositories.job_repository import (
        VALID_MISSED_RUN_POLICIES,
        VALID_OVERLAP_POLICIES,
        VALID_PENDING_POLICIES,
    )

    out: dict[str, Any] = {}

    if not is_update or "missed_run_policy" in data:
        raw_missed = data.get("missed_run_policy")
        if raw_missed is None or str(raw_missed).strip() in ("", "default"):
            out["missed_run_policy"] = None
        else:
            missed_val = str(raw_missed).strip()
            if missed_val not in VALID_MISSED_RUN_POLICIES:
                return {}, _("err_job_policy_invalid", policy=missed_val)
            out["missed_run_policy"] = missed_val

    if not is_update or "overlap_policy" in data:
        raw_overlap = data.get("overlap_policy")
        if raw_overlap is None or str(raw_overlap).strip() in ("", "default"):
            out["overlap_policy"] = None
        else:
            overlap_val = str(raw_overlap).strip()
            if overlap_val not in VALID_OVERLAP_POLICIES:
                return {}, _("err_job_policy_invalid", policy=overlap_val)
            out["overlap_policy"] = overlap_val

    if not is_update or "pending_policy" in data:
        raw_pending = data.get("pending_policy")
        if raw_pending is None or str(raw_pending).strip() in ("", "default"):
            out["pending_policy"] = None
        else:
            pending_val = str(raw_pending).strip()
            if pending_val not in VALID_PENDING_POLICIES:
                return {}, _("err_job_policy_invalid", policy=pending_val)
            out["pending_policy"] = pending_val

    has_rt_keys = any(
        k in data
        for k in (
            "max_runtime_enabled",
            "max_runtime_minutes",
            "max_runtime_hours",
            "max_runtime_mins",
        )
    )
    if not is_update or has_rt_keys:
        rt_enabled = (
            _parse_bool_flag(data.get("max_runtime_enabled"), default=False)
            if "max_runtime_enabled" in data
            else (data.get("max_runtime_minutes") is not None)
        )
        if rt_enabled:
            try:
                if "max_runtime_minutes" in data and data.get("max_runtime_minutes") is not None:
                    total_minutes = int(data["max_runtime_minutes"])
                elif "max_runtime_hours" in data or "max_runtime_mins" in data:
                    h = int(data.get("max_runtime_hours") or 0)
                    m = int(data.get("max_runtime_mins") or 0)
                    if h < 0 or m < 0:
                        return {}, _("err_job_max_runtime_invalid")
                    total_minutes = h * 60 + m
                else:
                    total_minutes = 0
            except (TypeError, ValueError):
                return {}, _("err_job_max_runtime_invalid")
            if total_minutes < 1:
                return {}, _("err_job_max_runtime_invalid")
            out["max_runtime_minutes"] = total_minutes
            if is_update:
                out["clear_max_runtime"] = False
        else:
            out["max_runtime_minutes"] = None
            if is_update and has_rt_keys:
                out["clear_max_runtime"] = True

    for notify_key in (
        "missed_run_notify",
        "overlap_notify",
        "pending_notify",
        "max_runtime_notify",
    ):
        if not is_update or notify_key in data:
            out[notify_key] = _parse_bool_flag(data.get(notify_key), default=False)

    return out, None


def get_db() -> sessionmaker[Session]:
    return cast(sessionmaker[Session], current_app.config["SESSION_FACTORY"])


def get_orchestrator() -> OrchestratorClient:
    return cast(OrchestratorClient, current_app.config["ORCHESTRATOR_CLIENT"])


@api_bp.route("/status", methods=["GET"])
@require_auth
def system_status() -> Response:
    """Lightweight JSON status endpoint for frontend 10s polling."""
    session_factory = get_db()
    with session_factory() as session:
        total_proxies = session.scalar(select(func.count(Proxy.id))) or 0
        online_proxies = (
            session.scalar(
                select(func.count(Proxy.id))
                .join(ProxyStatus, Proxy.id == ProxyStatus.proxy_id)
                .where(Proxy.is_enabled.is_(True), ProxyStatus.state == "online")
            )
            or 0
        )
        offline_proxies = (
            session.scalar(
                select(func.count(Proxy.id))
                .outerjoin(ProxyStatus, Proxy.id == ProxyStatus.proxy_id)
                .where(
                    (Proxy.is_enabled.is_(False))
                    | (ProxyStatus.state == "offline")
                    | (ProxyStatus.state.is_(None))
                )
            )
            or 0
        )
        other_proxies = max(0, total_proxies - (online_proxies + offline_proxies))

        active_runs = (
            session.scalar(
                select(func.count(JobRun.id)).where(JobRun.status.in_(["pending", "running"]))
            )
            or 0
        )
        completed_runs = (
            session.scalar(select(func.count(JobRun.id)).where(JobRun.status == "completed")) or 0
        )
        failed_runs = (
            session.scalar(
                select(func.count(JobRun.id)).where(
                    JobRun.status.in_(["failed", "partially_failed", "cancelled"])
                )
            )
            or 0
        )

    settings = current_app.config["SETTINGS"]

    return jsonify(
        {
            "status": "ok",
            "version": "1.0.0",
            "milestone": "M7",
            "env": settings.env,
            "dev_noauth": getattr(settings, "dev_noauth", False),
            "proxies": {
                "total": total_proxies,
                "online": online_proxies,
                "offline": offline_proxies,
                "other": max(0, other_proxies),
            },
            "runs": {
                "active": active_runs,
                "completed": completed_runs,
                "failed": failed_runs,
            },
            "timestamp": utc_now().isoformat(),
        }
    )


# ==============================================================================
# REALTIME DASHBOARD & RUN SSE STREAMS (Milestone M7)
# ==============================================================================


def _build_dashboard_snapshot(session: Session) -> dict[str, Any]:
    """Compile comprehensive realtime metrics snapshot for the dashboard and charts."""
    # 1. Proxies count (disabled proxies are counted as offline)
    total_proxies = session.scalar(select(func.count(Proxy.id))) or 0
    online_proxies = (
        session.scalar(
            select(func.count(Proxy.id))
            .join(ProxyStatus, Proxy.id == ProxyStatus.proxy_id)
            .where(Proxy.is_enabled.is_(True), ProxyStatus.state == "online")
        )
        or 0
    )
    offline_proxies = (
        session.scalar(
            select(func.count(Proxy.id))
            .outerjoin(ProxyStatus, Proxy.id == ProxyStatus.proxy_id)
            .where(
                (Proxy.is_enabled.is_(False))
                | (ProxyStatus.state == "offline")
                | (ProxyStatus.state.is_(None))
            )
        )
        or 0
    )
    other_proxies = max(0, total_proxies - (online_proxies + offline_proxies))

    # 2. Runs counts (last 72h)
    cutoff_72h = utc_now() - timedelta(hours=72)
    active_runs = (
        session.scalar(
            select(func.count(JobRun.id)).where(
                JobRun.status.in_(["pending", "running"]),
                JobRun.created_at >= cutoff_72h,
            )
        )
        or 0
    )
    completed_runs = (
        session.scalar(
            select(func.count(JobRun.id)).where(
                JobRun.status.in_(["completed", "succeeded"]),
                JobRun.created_at >= cutoff_72h,
            )
        )
        or 0
    )
    failed_runs = (
        session.scalar(
            select(func.count(JobRun.id)).where(
                JobRun.status.in_(["failed", "partially_failed", "cancelled"]),
                JobRun.created_at >= cutoff_72h,
            )
        )
        or 0
    )
    queued_runs = (
        session.scalar(
            select(func.count(JobRun.id)).where(
                JobRun.status.in_(["queued", "planning", "awaiting_confirmation"]),
                JobRun.created_at >= cutoff_72h,
            )
        )
        or 0
    )
    total_runs = active_runs + completed_runs + failed_runs + queued_runs
    finished_runs = completed_runs + failed_runs
    success_rate = round((completed_runs / finished_runs) * 100, 1) if finished_runs > 0 else 100.0

    # 3. Recent errors (last 24h)
    cutoff_24h = utc_now() - timedelta(hours=24)
    recent_errors = (
        session.scalar(
            select(func.count(AuditLog.id)).where(
                AuditLog.action.like("%error%"),
                AuditLog.ts >= cutoff_24h,
            )
        )
        or 0
    )

    # 4. Proxy fleet details & slots
    proxies_stmt = select(Proxy).where(Proxy.is_enabled.is_(True)).order_by(Proxy.name).limit(10)
    proxies_rows = list(session.scalars(proxies_stmt).unique().all())
    proxies_list = []
    total_fleet_slots = 0
    used_fleet_slots = 0

    for p in proxies_rows:
        state = p.status.state if p.status else "offline"
        running_tasks = p.status.running_tasks if p.status else 0
        max_concurrent = p.max_concurrent_tasks or 4
        total_fleet_slots += max_concurrent
        used_fleet_slots += running_tasks
        proxies_list.append(
            {
                "id": str(p.id),
                "name": p.name,
                "host": p.host,
                "port": p.port,
                "state": state,
                "running_tasks": running_tasks,
                "max_concurrent": max_concurrent,
                "latency_ms": p.status.latency_ms if p.status else 0,
                "cert_fingerprint": (p.cert_fingerprint_sha256[:16] + "...")
                if p.cert_fingerprint_sha256
                else "",
            }
        )

    fleet_utilization = (
        round((used_fleet_slots / total_fleet_slots) * 100, 1) if total_fleet_slots > 0 else 0.0
    )

    # 5. Recent runs list & active throughput
    runs_stmt = select(JobRun).order_by(desc(JobRun.created_at)).limit(5)
    recent_runs_rows = list(session.scalars(runs_stmt).all())
    recent_runs_list = []
    total_current_speed_bytes = 0.0

    for r in recent_runs_rows:
        run_speed_bytes = 0.0
        if r.status in ("running", "planning", "queued"):
            tasks_stats = ExecutionRepository.get_run_tasks_progress_stats(session, r)
            run_speed_bytes = sum(s.get("speed_bytes_per_sec", 0.0) for s in tasks_stats.values())
            total_current_speed_bytes += run_speed_bytes

        job_name = (
            r.job.name if r.job else (r.job_snapshot.get("name") if r.job_snapshot else "Job")
        )
        tasks_done = getattr(r, "tasks_succeeded", 0) or getattr(r, "tasks_completed", 0) or 0
        total_t = (
            getattr(r, "planned_task_count", 0)
            or (len(r.tasks) if getattr(r, "tasks", None) else 0)
            or getattr(r, "task_count_actual", 0)
            or 0
        )
        recent_runs_list.append(
            {
                "id": str(r.id),
                "short_id": str(r.id)[:8],
                "job_name": job_name,
                "job_id": str(r.job_id)[:8] if r.job_id else "",
                "status": r.status,
                "trigger": getattr(r, "trigger", "manual") or "manual",
                "planning_mode": getattr(r, "planning_mode", "pure") or "pure",
                "tasks_completed": tasks_done,
                "task_count_actual": total_t,
                "created_at": (
                    (
                        r.created_at
                        if r.created_at.tzinfo is not None
                        else r.created_at.replace(tzinfo=UTC)
                    ).isoformat()
                    if r.created_at
                    else ""
                ),
                "speed_bytes_per_sec": run_speed_bytes,
                "speed_display": ExecutionRepository.format_speed(run_speed_bytes),
            }
        )

    throughput_display = ExecutionRepository.format_speed(total_current_speed_bytes)

    # Persist throughput sample (throttled)
    try:
        ExecutionRepository.record_throughput_sample(
            session,
            bytes_per_sec=total_current_speed_bytes,
            active_runs=active_runs,
            min_interval_s=3.0,
        )
        session.commit()
    except Exception:
        pass

    return {
        "status": "ok",
        "timestamp": utc_now().isoformat(),
        "proxies_count": {
            "total": total_proxies,
            "online": online_proxies,
            "offline": offline_proxies,
            "other": other_proxies,
        },
        "runs_count": {
            "active": active_runs,
            "completed": completed_runs,
            "failed": failed_runs,
            "queued": queued_runs,
            "total": total_runs,
            "success_rate": success_rate,
        },
        "fleet_capacity": {
            "total_slots": total_fleet_slots,
            "used_slots": used_fleet_slots,
            "utilization_pct": fleet_utilization,
        },
        "throughput": {
            "speed_bytes_per_sec": total_current_speed_bytes,
            "speed_display": throughput_display,
        },
        "recent_errors": recent_errors,
        "proxies": proxies_list,
        "recent_runs": recent_runs_list,
    }


def _build_run_snapshot(session: Session, run: JobRun) -> dict[str, Any]:
    """Compile realtime execution progress and proxy activity for a single JobRun."""
    from embervault_app.i18n import localize_proxies_activity

    tasks_stats = ExecutionRepository.get_run_tasks_progress_stats(session, run) if run else {}
    proxies_activity = localize_proxies_activity(
        ExecutionRepository.get_run_proxies_activity(session, run) if run else []
    )
    total_speed_bytes = sum(p.get("speed_bytes_per_sec", 0.0) for p in proxies_activity)
    total_throughput_str = ExecutionRepository.format_speed(total_speed_bytes)

    tasks_completed = getattr(run, "tasks_succeeded", 0) or getattr(run, "tasks_completed", 0) or 0
    total_tasks = (
        getattr(run, "planned_task_count", 0)
        or (len(run.tasks) if run.tasks else 0)
        or getattr(run, "task_count_actual", 0)
        or 0
    )
    pct = round((tasks_completed / total_tasks) * 100, 1) if total_tasks > 0 else 0.0

    job_name = (
        run.job.name if run.job else (run.job_snapshot.get("name") if run.job_snapshot else "Job")
    )

    hooks_list = []
    for h in run.hooks or []:
        hooks_list.append(
            {
                "id": str(h.id),
                "hook_type": h.hook_type,
                "script_hash": h.script_hash,
                "status": h.status,
                "exit_code": h.exit_code,
                "duration_ms": h.duration_ms,
                "output": h.output,
                "executed_at": h.executed_at.isoformat() if h.executed_at else None,
            }
        )

    return {
        "run_id": str(run.id),
        "job_id": str(run.job_id) if run.job_id else "",
        "job_name": job_name,
        "status": run.status,
        "planning_mode": getattr(run, "planning_mode", "pure") or "pure",
        "tasks_completed": tasks_completed,
        "task_count_actual": total_tasks,
        "progress_pct": pct,
        "speed_bytes_per_sec": total_speed_bytes,
        "throughput_display": total_throughput_str,
        "proxies_activity": proxies_activity,
        "hooks": hooks_list,
        "error_code": getattr(run, "error_code", None),
        "error_message": getattr(run, "error_message", None),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    }


@api_bp.route("/metrics/throughput", methods=["GET"])
@require_auth
def metrics_throughput_history() -> Response:
    """Historical and realtime throughput measurements with selectable range."""
    user_perms: set[str] = getattr(g, "permissions", set())
    settings = current_app.config["SETTINGS"]
    dev_noauth = getattr(settings, "dev_noauth", False)
    if not dev_noauth and not (
        "job.read" in user_perms or "proxy.read" in user_perms or "metrics.read" in user_perms
    ):
        return make_response(
            jsonify({"error": "forbidden", "message": _("api_err_insufficient_permission")}),
            403,
        )

    range_param = request.args.get("range", "24h").strip().lower()
    now = datetime.now(UTC)

    if range_param == "5m":
        start_time = now - timedelta(minutes=5)
        end_time = now
        max_points = 60
    elif range_param == "1h":
        start_time = now - timedelta(hours=1)
        end_time = now
        max_points = 60
    elif range_param == "6h":
        start_time = now - timedelta(hours=6)
        end_time = now
        max_points = 72
    elif range_param == "24h":
        start_time = now - timedelta(hours=24)
        end_time = now
        max_points = 96
    elif range_param == "custom":
        start_str = request.args.get("start")
        end_str = request.args.get("end")
        try:
            if start_str:
                start_str = urllib.parse.unquote(start_str).replace(" ", "+")
                start_time = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
                if start_time.tzinfo is None:
                    start_time = start_time.replace(tzinfo=UTC)
            else:
                start_time = now - timedelta(hours=24)

            if end_str:
                end_str = urllib.parse.unquote(end_str).replace(" ", "+")
                end_time = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
                if end_time.tzinfo is None:
                    end_time = end_time.replace(tzinfo=UTC)
            else:
                end_time = now
        except (ValueError, TypeError):
            start_time = now - timedelta(hours=24)
            end_time = now

        if start_time > end_time:
            start_time, end_time = end_time, start_time
        max_points = 120
    else:
        range_param = "24h"
        start_time = now - timedelta(hours=24)
        end_time = now
        max_points = 96

    session_factory = get_db()
    with session_factory() as session:
        samples = ExecutionRepository.get_throughput_history(
            session, start_time=start_time, end_time=end_time, max_points=max_points
        )

        runs_stmt = select(JobRun).where(JobRun.status.in_(["pending", "running"]))
        running_runs = list(session.scalars(runs_stmt).all())
        current_speed_bytes = 0.0
        for r in running_runs:
            tasks_stats = ExecutionRepository.get_run_tasks_progress_stats(session, r)
            current_speed_bytes += sum(
                s.get("speed_bytes_per_sec", 0.0) for s in tasks_stats.values()
            )

        if not samples:
            samples = [
                {
                    "timestamp": now.isoformat(),
                    "bytes_per_sec": current_speed_bytes,
                    "speed_display": ExecutionRepository.format_speed(current_speed_bytes),
                    "active_runs": len(running_runs),
                }
            ]

    return make_response(
        jsonify(
            {
                "range": range_param,
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "current_speed_bytes": current_speed_bytes,
                "current_speed_display": ExecutionRepository.format_speed(current_speed_bytes),
                "samples": samples,
            }
        ),
        200,
    )


@api_bp.route("/events", methods=["GET"])
@require_auth
def realtime_events_stream() -> Response:
    """Server-Sent Events (SSE) stream for real-time dashboard status and metrics (M7)."""
    user_perms: set[str] = getattr(g, "permissions", set())
    settings = current_app.config["SETTINGS"]
    dev_noauth = getattr(settings, "dev_noauth", False)
    if not dev_noauth and not (
        "job.read" in user_perms or "proxy.read" in user_perms or "metrics.read" in user_perms
    ):
        return make_response(
            jsonify(
                {
                    "error": "forbidden",
                    "message": _("api_err_sse_insufficient_permission"),
                }
            ),
            403,
        )

    try:
        max_duration = float(request.args.get("duration", 300.0))
        poll_interval = float(request.args.get("interval", 2.0))
    except (ValueError, TypeError):
        max_duration = 300.0
        poll_interval = 2.0

    session_factory = get_db()

    def event_stream():
        start_time = time.monotonic()
        last_ping = time.monotonic()

        try:
            with session_factory() as session:
                snapshot = _build_dashboard_snapshot(session)
            yield f"event: connected\ndata: {json.dumps(snapshot)}\n\n"
        except GeneratorExit:
            return
        except Exception as exc:
            logger.warning("sse_snapshot_error", error=str(exc))
            return

        while True:
            now = time.monotonic()
            if now - start_time >= max_duration:
                yield "event: reconnect\ndata: {}\n\n"
                break

            time.sleep(poll_interval)

            now = time.monotonic()
            if now - last_ping >= 15.0:
                yield ": ping\n\n"
                last_ping = now

            try:
                with session_factory() as session:
                    update_data = _build_dashboard_snapshot(session)
                yield f"event: status\ndata: {json.dumps(update_data)}\n\n"
            except GeneratorExit:
                logger.debug("sse_client_disconnected")
                break
            except Exception as exc:
                logger.warning("sse_poll_error", error=str(exc))
                yield ": poll_error\n\n"

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Content-Type": "text/event-stream; charset=utf-8",
        },
    )


@api_bp.route("/runs/<uuid:run_id>/events", methods=["GET"])
@require_auth
@require_permission("job.read")
def run_realtime_events_stream(run_id: UUID) -> Response:
    """Server-Sent Events (SSE) stream for real-time progress and logs of a specific JobRun (M7)."""
    try:
        max_duration = float(request.args.get("duration", 600.0))
        poll_interval = float(request.args.get("interval", 1.5))
    except (ValueError, TypeError):
        max_duration = 600.0
        poll_interval = 1.5

    session_factory = get_db()

    def run_stream():
        start_time = time.monotonic()
        last_ping = time.monotonic()
        last_log_id = 0

        try:
            with session_factory() as session:
                run = ExecutionRepository.get_run_by_id(session, run_id)
                if not run:
                    yield f"event: error\ndata: {json.dumps({'message': _('api_err_run_not_found')})}\n\n"
                    return
                snapshot = _build_run_snapshot(session, run)
                if run.tasks:
                    max_id = session.scalar(
                        select(func.max(TaskLog.id)).where(
                            TaskLog.task_id.in_([t.id for t in run.tasks])
                        )
                    )
                    last_log_id = max_id or 0
            yield f"event: run_snapshot\ndata: {json.dumps(snapshot)}\n\n"
        except GeneratorExit:
            return
        except Exception as exc:
            logger.warning("sse_run_snapshot_error", run_id=str(run_id), error=str(exc))
            return

        while True:
            now = time.monotonic()
            if now - start_time >= max_duration:
                yield "event: reconnect\ndata: {}\n\n"
                break

            time.sleep(poll_interval)

            now = time.monotonic()
            if now - last_ping >= 15.0:
                yield ": ping\n\n"
                last_ping = now

            try:
                with session_factory() as session:
                    run = ExecutionRepository.get_run_by_id(session, run_id)
                    if not run:
                        break

                    progress_data = _build_run_snapshot(session, run)
                    yield f"event: run_progress\ndata: {json.dumps(progress_data)}\n\n"

                    # Poll newly appended logs
                    if run.tasks:
                        task_ids = [t.id for t in run.tasks]
                        stmt = (
                            select(TaskLog)
                            .where(TaskLog.task_id.in_(task_ids), TaskLog.id > last_log_id)
                            .order_by(TaskLog.id.asc())
                            .limit(100)
                        )
                        new_logs = list(session.scalars(stmt).all())
                        if new_logs:
                            last_log_id = new_logs[-1].id
                            logs_payload = [
                                {
                                    "id": l.id,
                                    "seq": l.seq,
                                    "task_id": str(l.task_id),
                                    "level": l.level,
                                    "message": l.message,
                                    "created_at": (
                                        (
                                            l.ts
                                            if l.ts.tzinfo is not None
                                            else l.ts.replace(tzinfo=UTC)
                                        ).isoformat()
                                        if getattr(l, "ts", None)
                                        else (
                                            (
                                                l.created_at
                                                if l.created_at.tzinfo is not None
                                                else l.created_at.replace(tzinfo=UTC)
                                            ).isoformat()
                                            if getattr(l, "created_at", None)
                                            else ""
                                        )
                                    ),
                                    "ts": (
                                        (
                                            l.ts
                                            if l.ts.tzinfo is not None
                                            else l.ts.replace(tzinfo=UTC)
                                        ).isoformat()
                                        if getattr(l, "ts", None)
                                        else (
                                            (
                                                l.created_at
                                                if l.created_at.tzinfo is not None
                                                else l.created_at.replace(tzinfo=UTC)
                                            ).isoformat()
                                            if getattr(l, "created_at", None)
                                            else ""
                                        )
                                    ),
                                }
                                for l in new_logs
                            ]
                            yield f"event: run_logs\ndata: {json.dumps(logs_payload)}\n\n"

                    # Check terminal run state
                    if run.status in (
                        "completed",
                        "succeeded",
                        "failed",
                        "partially_failed",
                        "cancelled",
                    ):
                        yield f"event: run_completed\ndata: {json.dumps({'status': run.status, 'finished_at': run.finished_at.isoformat() if run.finished_at else None})}\n\n"
                        break
            except GeneratorExit:
                logger.debug("sse_run_client_disconnected", run_id=str(run_id))
                break
            except Exception as exc:
                logger.warning("sse_run_poll_error", run_id=str(run_id), error=str(exc))
                yield ": poll_error\n\n"

    return Response(
        run_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Content-Type": "text/event-stream; charset=utf-8",
        },
    )


@api_bp.route("/proxies/probe", methods=["POST"])
def probe_proxy() -> Response:
    """Probe a proxy via Orchestrator internal API. Dev-gated or admin authenticated."""
    user = get_current_user()
    settings = current_app.config["SETTINGS"]
    dev_noauth = getattr(settings, "dev_noauth", False)
    user_perms = getattr(g, "permissions", set())
    has_perm = bool(
        dev_noauth or (user and ("proxy.manage" in user_perms or "proxy.create" in user_perms))
    )

    if not has_perm:
        return make_response(
            jsonify(
                {
                    "error": "forbidden",
                    "message": "Proxy probe/registration is disabled in production without admin authentication (M1.1). Set EMBERVAULT_DEV_NOAUTH=true to enable.",
                }
            ),
            403,
        )

    payload = request.get_json(silent=True) or {}
    host = str(payload.get("host", "")).strip()
    port = int(payload.get("port", 8443))
    token = str(payload.get("token", "")).strip()

    if not host or not token:
        return make_response(
            jsonify({"error": "validation_error", "message": "Host and token are required."}),
            400,
        )

    if port < 1 or port > 65535:
        return make_response(
            jsonify({"error": "validation_error", "message": "Port must be between 1 and 65535."}),
            400,
        )

    orch_client = get_orchestrator()
    try:
        probe_res = orch_client.probe_proxy(host=host, port=port, token=token)
        return jsonify(probe_res.model_dump(mode="json"))
    except Exception as exc:
        logger.warning("proxy_probe_failed", host=host, port=port, error=str(exc))
        return make_response(
            jsonify(
                {
                    "error": "probe_failed",
                    "message": str(exc),
                }
            ),
            502,
        )


@api_bp.route("/proxies/register", methods=["POST"])
def register_proxy() -> Response:
    """Register and persist a new proxy with confirmed TLS certificate fingerprint."""
    user = get_current_user()
    settings = current_app.config["SETTINGS"]
    dev_noauth = getattr(settings, "dev_noauth", False)
    user_perms = getattr(g, "permissions", set())
    has_perm = bool(
        dev_noauth or (user and ("proxy.manage" in user_perms or "proxy.create" in user_perms))
    )

    if not has_perm:
        return make_response(
            jsonify(
                {
                    "error": "forbidden",
                    "message": "Proxy registration is disabled without authentication (M1.1). Set EMBERVAULT_DEV_NOAUTH=true to enable.",
                }
            ),
            403,
        )

    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    host = str(payload.get("host", "")).strip()
    port = int(payload.get("port", 8443))
    token = str(payload.get("token", "")).strip()
    fingerprint = str(payload.get("cert_fingerprint_sha256", "")).strip().lower()
    raw_remotes = payload.get("reachable_remote_ids")
    reachable_remote_ids = (
        [uuid.UUID(str(rid)) for rid in raw_remotes if rid] if raw_remotes is not None else None
    )

    if not name or not host or not token or not fingerprint:
        return make_response(
            jsonify({"error": "validation_error", "message": "All fields are required."}),
            400,
        )

    if len(token) < 32:
        return make_response(
            jsonify(
                {
                    "error": "validation_error",
                    "message": "Proxy token must be at least 32 characters long.",
                }
            ),
            400,
        )

    if len(fingerprint) != 64:
        return make_response(
            jsonify(
                {
                    "error": "validation_error",
                    "message": "Fingerprint must be a 64-character SHA-256 hex string.",
                }
            ),
            400,
        )

    session_factory = get_db()
    with session_factory() as session:
        # Check uniqueness of name and (host, port)
        existing = session.scalar(
            select(Proxy).where(
                (Proxy.name == name) | ((Proxy.host == host) & (Proxy.port == port))
            )
        )
        if existing is not None:
            return make_response(
                jsonify(
                    {
                        "error": "conflict",
                        "message": f"A proxy with name '{name}' or host:port '{host}:{port}' already exists.",
                    }
                ),
                409,
            )

        proxy_id = uuid.uuid4()
        encrypted_token = ProxyRepository.encrypt_token(token, proxy_id)

        cert_expires_str = payload.get("cert_expires_at")
        cert_expires_dt = None
        if cert_expires_str:
            try:
                cert_expires_dt = datetime.datetime.fromisoformat(str(cert_expires_str))
            except Exception:
                pass

        proxy = Proxy(
            id=proxy_id,
            name=name,
            host=host,
            port=port,
            token_encrypted=encrypted_token,
            cert_fingerprint_sha256=fingerprint,
            cert_expires_at=cert_expires_dt,
            fingerprint_confirmed_at=utc_now(),
            is_enabled=True,
            max_concurrent_tasks=1,
        )
        ProxyRepository.set_reachable_remotes(session, proxy, reachable_remote_ids)
        session.add(proxy)

        # Initialize ProxyStatus
        ProxyRepository.get_or_create_status(session, proxy_id)

        # Record AuditLog
        audit = AuditLog(
            action="proxy.register",
            entity_type="proxy",
            entity_id=str(proxy_id),
            details={"name": name, "host": host, "port": port, "fingerprint": fingerprint},
            ip=request.remote_addr,
        )
        session.add(audit)
        session.commit()

        logger.info("proxy_registered_successfully", proxy_id=str(proxy_id), name=name, host=host)

    return make_response(
        jsonify(
            {
                "status": "created",
                "proxy_id": str(proxy_id),
                "name": name,
                "message": "Proxy successfully registered with pinned TLS fingerprint.",
            }
        ),
        201,
    )


@api_bp.route("/proxies/<uuid:proxy_id>", methods=["PUT"])
def update_proxy(proxy_id: uuid.UUID) -> Response:
    """Update an existing proxy's configuration."""
    user = get_current_user()
    settings = current_app.config["SETTINGS"]
    dev_noauth = getattr(settings, "dev_noauth", False)
    user_perms = getattr(g, "permissions", set())
    has_perm = bool(
        dev_noauth or (user and ("proxy.manage" in user_perms or "proxy.update" in user_perms))
    )

    if not has_perm:
        return make_response(
            jsonify(
                {
                    "error": "forbidden",
                    "message": _("api_err_proxy_manage_required"),
                }
            ),
            403,
        )

    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    host = str(payload.get("host", "")).strip()
    port = int(payload.get("port", 8443))
    max_concurrent_tasks = int(payload.get("max_concurrent_tasks", 1))
    is_enabled = bool(payload.get("is_enabled", True))
    token = str(payload.get("token", "")).strip() or None
    fingerprint = str(payload.get("cert_fingerprint_sha256", "")).strip().lower() or None
    raw_remotes = payload.get("reachable_remote_ids")
    reachable_remote_ids = (
        [uuid.UUID(str(rid)) for rid in raw_remotes if rid] if raw_remotes is not None else None
    )

    if not name or not host:
        return make_response(
            jsonify(
                {"error": "validation_error", "message": _("api_err_proxy_name_host_required")}
            ),
            400,
        )

    if port < 1 or port > 65535:
        return make_response(
            jsonify(
                {
                    "error": "validation_error",
                    "message": _("api_err_proxy_port_range"),
                }
            ),
            400,
        )

    if max_concurrent_tasks < 1:
        return make_response(
            jsonify({"error": "validation_error", "message": _("api_err_proxy_concurrency_min")}),
            400,
        )

    if token is not None and len(token) < 32:
        return make_response(
            jsonify(
                {
                    "error": "validation_error",
                    "message": _("api_err_proxy_token_min_len"),
                }
            ),
            400,
        )

    if fingerprint is not None and len(fingerprint) != 64:
        return make_response(
            jsonify(
                {
                    "error": "validation_error",
                    "message": _("api_err_proxy_fingerprint_len"),
                }
            ),
            400,
        )

    session_factory = get_db()
    with session_factory() as session:
        proxy = session.get(Proxy, proxy_id)
        if proxy is None:
            return make_response(
                jsonify({"error": "not_found", "message": _("api_err_proxy_not_found")}),
                404,
            )

        # Check uniqueness of name and (host, port) excluding this proxy
        conflict = session.scalar(
            select(Proxy).where(
                Proxy.id != proxy_id,
                (Proxy.name == name) | ((Proxy.host == host) & (Proxy.port == port)),
            )
        )
        if conflict is not None:
            return make_response(
                jsonify(
                    {
                        "error": "conflict",
                        "message": _("api_err_proxy_conflict", name=name, host=host, port=port),
                    }
                ),
                409,
            )

        try:
            ProxyRepository.update_proxy(
                session=session,
                proxy_id=proxy_id,
                name=name,
                host=host,
                port=port,
                max_concurrent_tasks=max_concurrent_tasks,
                is_enabled=is_enabled,
                token=token,
                cert_fingerprint_sha256=fingerprint,
                reachable_remote_ids=reachable_remote_ids,
            )
        except ValueError as err:
            return make_response(
                jsonify({"error": "validation_error", "message": _localize_remote_error(err)}),
                400,
            )

        active_assignments_count = (
            session.scalar(
                select(func.count(TaskAssignment.id)).where(
                    TaskAssignment.proxy_id == proxy_id,
                    TaskAssignment.status.in_(["assigned", "dispatched", "running"]),
                )
            )
            or 0
        )
        running_tasks_count = proxy.status.running_tasks if proxy.status else 0
        has_active_tasks = running_tasks_count > 0 or active_assignments_count > 0

        warning_message: str | None = None
        if not is_enabled and has_active_tasks:
            warning_message = _("proxy_deactivate_active_tasks_warning")

        audit_details = {
            "name": name,
            "host": host,
            "port": port,
            "max_concurrent_tasks": max_concurrent_tasks,
            "is_enabled": is_enabled,
        }
        if warning_message:
            audit_details["warning"] = warning_message

        audit = AuditLog(
            action="proxy.update",
            entity_type="proxy",
            entity_id=str(proxy_id),
            details=audit_details,
            ip=request.remote_addr,
        )
        session.add(audit)
        session.commit()

        logger.info("proxy_updated_successfully", proxy_id=str(proxy_id), name=name, host=host)

    response_data = {
        "status": "updated",
        "proxy_id": str(proxy_id),
        "name": name,
        "message": warning_message or _("api_msg_proxy_updated"),
    }
    if warning_message:
        response_data["warning"] = warning_message

    return jsonify(response_data)


@api_bp.route("/proxies/rclone/versions", methods=["GET"])
def get_available_rclone_versions() -> Response:
    """Fetch available RClone releases and latest release."""
    user = get_current_user()
    settings = current_app.config["SETTINGS"]
    dev_noauth = getattr(settings, "dev_noauth", False)
    has_perm = bool(
        dev_noauth
        or (
            user
            and (
                "proxy.read" in getattr(g, "permissions", set())
                or "proxy.manage" in getattr(g, "permissions", set())
            )
        )
    )
    if not has_perm:
        return make_response(
            jsonify({"error": "forbidden", "message": _("api_err_insufficient_permission")}), 403
        )

    from embervault_common.rclone_version import (
        fetch_available_rclone_versions,
        get_latest_rclone_version,
    )

    force = request.args.get("refresh", "false").lower() == "true"
    versions = fetch_available_rclone_versions(force_refresh=force)
    latest = get_latest_rclone_version()
    return jsonify(
        {
            "status": "ok",
            "latest": latest,
            "versions": versions,
        }
    )


@api_bp.route("/proxies/<uuid:proxy_id>/rclone/status", methods=["GET"])
def get_proxy_rclone_status(proxy_id: uuid.UUID) -> Response:
    """Check installed RClone version and update availability for a specific proxy."""
    user = get_current_user()
    settings = current_app.config["SETTINGS"]
    dev_noauth = getattr(settings, "dev_noauth", False)
    has_perm = bool(
        dev_noauth
        or (
            user
            and (
                "proxy.read" in getattr(g, "permissions", set())
                or "proxy.manage" in getattr(g, "permissions", set())
            )
        )
    )
    if not has_perm:
        return make_response(
            jsonify({"error": "forbidden", "message": _("api_err_insufficient_permission")}), 403
        )

    session_factory = get_db()
    with session_factory() as session:
        proxy = session.get(Proxy, proxy_id)
        if not proxy:
            return make_response(
                jsonify({"error": "not_found", "message": _("api_err_proxy_not_found")}), 404
            )
        installed = proxy.rclone_version
        proxy_name = proxy.name

    from embervault_common.rclone_version import (
        fetch_available_rclone_versions,
        format_clean_version,
        get_latest_rclone_version,
        is_rclone_update_available,
    )

    force = request.args.get("refresh", "false").lower() == "true"
    versions = fetch_available_rclone_versions(force_refresh=force)
    latest = get_latest_rclone_version()
    is_outdated, target_ver = is_rclone_update_available(installed, latest)

    return jsonify(
        {
            "status": "ok",
            "proxy_id": str(proxy_id),
            "proxy_name": proxy_name,
            "installed_version": format_clean_version(installed) or installed or "sconosciuta",
            "latest_version": latest,
            "update_available": is_outdated,
            "versions": versions,
        }
    )


@api_bp.route("/proxies/<uuid:proxy_id>/rclone/upgrade", methods=["POST"])
def upgrade_proxy_rclone(proxy_id: uuid.UUID) -> Response:
    """Trigger remote RClone upgrade on proxy to latest or selected version."""
    user = get_current_user()
    settings = current_app.config["SETTINGS"]
    dev_noauth = getattr(settings, "dev_noauth", False)
    user_perms = getattr(g, "permissions", set())
    has_manage_perm = bool(
        dev_noauth or (user and ("proxy.manage" in user_perms or "proxy.upgrade" in user_perms))
    )
    if not has_manage_perm:
        return make_response(
            jsonify({"error": "forbidden", "message": _("api_err_proxy_manage_required")}), 403
        )

    payload = request.get_json(silent=True) or {}
    raw_version = str(payload.get("version", "")).strip() or "latest"

    from embervault_common.rclone_version import (
        format_clean_version,
        get_latest_rclone_version,
        parse_rclone_version,
    )

    if raw_version.lower() == "latest":
        target_version = get_latest_rclone_version()
    else:
        target_version = format_clean_version(raw_version)

    if parse_rclone_version(target_version) == (0, 0, 0):
        return make_response(
            jsonify({"error": "invalid_version", "message": _("err_invalid_rclone_version")}),
            400,
        )

    orch_client = get_orchestrator()
    try:
        res = orch_client.upgrade_proxy_rclone(proxy_id=proxy_id, version=target_version)
        new_version = res.get("version") or target_version

        session_factory = get_db()
        with session_factory() as session:
            p_entity = session.get(Proxy, proxy_id)
            if p_entity:
                p_entity.rclone_version = new_version
            audit = AuditLog(
                action="proxy.rclone_upgrade",
                entity_type="proxy",
                entity_id=str(proxy_id),
                actor_user_id=user.id if user else None,
                ip=request.remote_addr,
                details={"version": new_version, "target": target_version},
            )
            session.add(audit)
            session.commit()

        return jsonify(
            {
                "status": "ok",
                "message": _("rclone_upgrade_success_msg", version=new_version),
                "version": new_version,
                "details": res,
            }
        )
    except Exception as exc:
        logger.error("proxy_rclone_upgrade_failed", proxy_id=str(proxy_id), error=str(exc))
        return make_response(
            jsonify(
                {
                    "error": "upgrade_failed",
                    "message": str(exc),
                }
            ),
            502,
        )


@api_bp.route("/proxies/<uuid:proxy_id>/renew-cert", methods=["POST"])
def renew_proxy_certificate_endpoint(proxy_id: uuid.UUID) -> Response:
    """Trigger remote TLS certificate renewal on a proxy."""
    user = get_current_user()
    settings = current_app.config["SETTINGS"]
    dev_noauth = getattr(settings, "dev_noauth", False)
    user_perms = getattr(g, "permissions", set())
    has_renew_perm = bool(
        dev_noauth or (user and ("proxy.manage" in user_perms or "proxy.renew_cert" in user_perms))
    )

    if not has_renew_perm:
        return make_response(
            jsonify(
                {
                    "error": "forbidden",
                    "message": _("api_err_proxy_manage_required"),
                }
            ),
            403,
        )

    session_factory = get_db()
    with session_factory() as session:
        proxy = session.get(Proxy, proxy_id)
        if proxy is None:
            return make_response(
                jsonify({"error": "not_found", "message": _("api_err_proxy_not_found")}),
                404,
            )
        proxy_name = proxy.name

    orch_client = get_orchestrator()
    try:
        res = orch_client.renew_proxy_certificate(proxy_id=proxy_id)
        with session_factory() as session:
            audit = AuditLog(
                action="proxy.renew_cert",
                entity_type="proxy",
                entity_id=str(proxy_id),
                actor_user_id=user.id if user else None,
                ip=request.remote_addr,
                details={"proxy_name": proxy_name, "outcome": res},
            )
            session.add(audit)
            session.commit()

        return jsonify(
            {
                "status": "ok",
                "message": _("proxy_renew_cert_success_msg"),
                "details": res,
            }
        )
    except Exception as exc:
        logger.error("proxy_renew_cert_failed", proxy_id=str(proxy_id), error=str(exc))
        return make_response(
            jsonify(
                {
                    "error": "renew_failed",
                    "message": str(exc),
                }
            ),
            502,
        )


@api_bp.route("/proxies/<uuid:proxy_id>/retrust-probe", methods=["POST"])
def probe_retrust_proxy(proxy_id: uuid.UUID) -> Response:
    """Probe an existing proxy using its stored credentials to retrieve its current TLS fingerprint."""
    user = get_current_user()
    settings = current_app.config["SETTINGS"]
    dev_noauth = getattr(settings, "dev_noauth", False)
    user_perms = getattr(g, "permissions", set())
    has_manage_perm = bool(
        dev_noauth or (user and ("proxy.manage" in user_perms or "proxy.retrust" in user_perms))
    )

    if not has_manage_perm:
        return make_response(
            jsonify(
                {
                    "error": "forbidden",
                    "message": _("api_err_proxy_manage_required"),
                }
            ),
            403,
        )

    session_factory = get_db()
    with session_factory() as session:
        proxy = session.get(Proxy, proxy_id)
        if proxy is None:
            return make_response(
                jsonify({"error": "not_found", "message": _("api_err_proxy_not_found")}),
                404,
            )

        host = proxy.host
        port = proxy.port
        try:
            token = ProxyRepository.decrypt_token(proxy.token_encrypted, proxy.id)
        except Exception as exc:
            logger.error("proxy_token_decrypt_failed", proxy_id=str(proxy_id), error=str(exc))
            return make_response(
                jsonify(
                    {
                        "error": "decrypt_failed",
                        "message": _("api_err_proxy_token_decrypt_failed"),
                    }
                ),
                500,
            )

        old_fingerprint = proxy.cert_fingerprint_sha256

    orch_client = get_orchestrator()
    try:
        probe_res = orch_client.probe_proxy(host=host, port=port, token=token)
        return jsonify(
            {
                "proxy_id": str(proxy_id),
                "host": host,
                "port": port,
                "old_fingerprint": old_fingerprint,
                "new_fingerprint": probe_res.cert_fingerprint_sha256,
                "status": probe_res.status,
                "proxy_version": probe_res.proxy_version,
                "rclone_version": probe_res.rclone_version,
            }
        )
    except Exception as exc:
        logger.warning("proxy_retrust_probe_failed", proxy_id=str(proxy_id), error=str(exc))
        return make_response(
            jsonify(
                {
                    "error": "probe_failed",
                    "message": str(exc),
                }
            ),
            502,
        )


@api_bp.route("/proxies/<uuid:proxy_id>/retrust-confirm", methods=["POST"])
def confirm_retrust_proxy(proxy_id: uuid.UUID) -> Response:
    """Confirm a new TLS certificate fingerprint for an existing proxy, resetting its untrusted status."""
    user = get_current_user()
    settings = current_app.config["SETTINGS"]
    dev_noauth = getattr(settings, "dev_noauth", False)
    user_perms = getattr(g, "permissions", set())
    has_manage_perm = bool(
        dev_noauth or (user and ("proxy.manage" in user_perms or "proxy.retrust" in user_perms))
    )

    if not dev_noauth and not has_manage_perm:
        return make_response(
            jsonify(
                {
                    "error": "forbidden",
                    "message": _("api_err_proxy_manage_required"),
                }
            ),
            403,
        )

    payload = request.get_json(silent=True) or {}
    fingerprint = str(payload.get("cert_fingerprint_sha256", "")).strip().lower()

    if not fingerprint or len(fingerprint) != 64:
        return make_response(
            jsonify(
                {
                    "error": "validation_error",
                    "message": _("api_err_proxy_fingerprint_len"),
                }
            ),
            400,
        )

    session_factory = get_db()
    with session_factory() as session:
        proxy = session.get(Proxy, proxy_id)
        if proxy is None:
            return make_response(
                jsonify({"error": "not_found", "message": _("api_err_proxy_not_found")}),
                404,
            )

        old_fingerprint = proxy.cert_fingerprint_sha256
        proxy.cert_fingerprint_sha256 = fingerprint
        proxy.fingerprint_confirmed_at = utc_now()
        cert_expires_str = payload.get("cert_expires_at")
        if cert_expires_str:
            try:
                proxy.cert_expires_at = datetime.datetime.fromisoformat(str(cert_expires_str))
            except Exception:
                pass

        # Reset proxy status from untrusted to unknown with 0 failures to allow immediate re-evaluation
        status = ProxyRepository.get_or_create_status(session, proxy_id)
        prev_state = status.state
        status.state = "unknown"
        status.consecutive_failures = 0
        status.consecutive_successes = 0
        status.last_error_code = None

        ProxyRepository.record_state_transition(
            session=session,
            proxy_id=proxy_id,
            from_state=prev_state,
            to_state="unknown",
            reason=f"Fingerprint manual trust renewal by admin ({old_fingerprint[:12]}... -> {fingerprint[:12]}...)",
        )

        audit = AuditLog(
            action="proxy.retrust",
            entity_type="proxy",
            entity_id=str(proxy_id),
            details={
                "name": proxy.name,
                "host": proxy.host,
                "old_fingerprint": old_fingerprint,
                "new_fingerprint": fingerprint,
            },
            ip=request.remote_addr,
        )
        session.add(audit)
        session.commit()

        logger.info(
            "proxy_retrusted_successfully",
            proxy_id=str(proxy_id),
            name=proxy.name,
            new_fingerprint=fingerprint,
        )

    return jsonify(
        {
            "status": "retrusted",
            "proxy_id": str(proxy_id),
            "message": _("api_msg_proxy_fingerprint_updated"),
        }
    )


@api_bp.route("/proxies/<uuid:proxy_id>", methods=["DELETE"])
@api_bp.route("/proxies/<uuid:proxy_id>/delete", methods=["POST"])
def delete_proxy(proxy_id: uuid.UUID) -> Response:
    """Delete a registered proxy node if no active tasks or attempts block deletion."""
    user = get_current_user()
    settings = current_app.config["SETTINGS"]
    dev_noauth = getattr(settings, "dev_noauth", False)
    user_perms = getattr(g, "permissions", set())
    has_manage_perm = bool(
        dev_noauth or (user and ("proxy.manage" in user_perms or "proxy.delete" in user_perms))
    )

    if not has_manage_perm:
        return make_response(
            jsonify(
                {
                    "error": "forbidden",
                    "message": _("api_err_proxy_manage_required"),
                }
            ),
            403,
        )

    session_factory = get_db()
    with session_factory() as session:
        proxy = session.get(Proxy, proxy_id)
        if proxy is None:
            return make_response(
                jsonify({"error": "not_found", "message": _("api_err_proxy_not_found")}),
                404,
            )

        # Check if proxy currently reports running tasks
        if proxy.status and proxy.status.running_tasks > 0:
            return make_response(
                jsonify(
                    {
                        "error": "conflict",
                        "message": _(
                            "api_err_proxy_delete_active_tasks",
                            name=proxy.name,
                            count=proxy.status.running_tasks,
                        ),
                    }
                ),
                409,
            )

        name = proxy.name
        host = proxy.host
        ProxyRepository.delete_proxy(session, proxy_id)

        audit = AuditLog(
            action="proxy.delete",
            entity_type="proxy",
            entity_id=str(proxy_id),
            details={"name": name, "host": host},
            ip=request.remote_addr,
        )
        session.add(audit)
        session.commit()

        logger.info("proxy_deleted_successfully", proxy_id=str(proxy_id), name=name)

    return jsonify(
        {
            "status": "deleted",
            "proxy_id": str(proxy_id),
            "message": _("api_msg_proxy_deleted", name=name),
        }
    )


# =========================================================================
# RClone Remotes Management (M1.2)
# =========================================================================


@api_bp.route("/remotes/catalog", methods=["GET"])
@require_auth
def list_remote_catalog() -> Response:
    """Return catalog of all supported RClone backend providers and their field schemas."""
    catalog = get_backend_catalog()
    return jsonify({"status": "ok", "backends": [b.to_dict() for b in catalog]})


@api_bp.route("/remotes", methods=["GET"])
@require_permission("remote.read")
def list_remotes() -> Response:
    """List all configured RClone remotes with masked sensitive secrets."""
    current_user = get_current_user()
    is_admin = is_admin_user()
    session_factory = get_db()
    with session_factory() as session:
        remotes = RemoteRepository.list_remotes_for_user(
            session, current_user, is_admin=is_admin
        )
        data = []
        for r in remotes:
            spec = get_backend_spec(r.backend_type)
            data.append(
                {
                    "id": str(r.id),
                    "name": r.name,
                    "backend_type": r.backend_type,
                    "backend_label": spec.label if spec else r.backend_type,
                    "backend_icon": spec.icon if spec else "cloud",
                    "public_params": r.public_params,
                    "secret_field_names": r.secret_field_names,
                    "version": r.version,
                    "is_enabled": r.is_enabled,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "updated_at": r.updated_at.isoformat() if r.updated_at else None,
                }
            )
        return jsonify({"status": "ok", "remotes": data})


@api_bp.route("/remotes", methods=["POST"])
@require_permission("remote.write")
def create_remote() -> Response:
    """Create a new RClone remote with envelope encryption."""
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    backend_type = str(payload.get("backend_type", "")).strip()
    config = payload.get("config", {})
    is_enabled = bool(payload.get("is_enabled", True))
    raw_proxies = payload.get("reachable_proxy_ids")
    reachable_proxy_ids = (
        [uuid.UUID(str(pid)) for pid in raw_proxies if pid] if raw_proxies is not None else None
    )
    raw_roles = payload.get("allowed_role_ids")
    allowed_role_ids = (
        [uuid.UUID(str(rid)) for rid in raw_roles if rid] if raw_roles is not None else None
    )

    if not name or not backend_type:
        return make_response(
            jsonify(
                {"error": "validation_error", "message": _("api_err_remote_name_type_required")}
            ),
            400,
        )

    current_user = get_current_user()
    session_factory = get_db()
    try:
        with session_factory() as session:
            remote = RemoteRepository.create_remote(
                session=session,
                name=name,
                backend_type=backend_type,
                raw_config=config,
                created_by=current_user.id if current_user else None,
                is_enabled=is_enabled,
                reachable_proxy_ids=reachable_proxy_ids,
                allowed_role_ids=allowed_role_ids,
            )

            audit = AuditLog(
                action="remote.create",
                actor_user_id=current_user.id if current_user else None,
                entity_type="remote",
                entity_id=str(remote.id),
                details={"name": name, "backend_type": backend_type},
                ip=request.remote_addr,
            )
            session.add(audit)
            session.commit()

            return make_response(
                jsonify(
                    {
                        "status": "created",
                        "remote_id": str(remote.id),
                        "name": remote.name,
                        "backend_type": remote.backend_type,
                        "message": _("api_msg_remote_created", name=remote.name),
                    }
                ),
                201,
            )
    except ValueError as exc:
        return make_response(
            jsonify({"error": "validation_error", "message": _localize_remote_error(exc)}),
            400,
        )
    except Exception as exc:
        logger.error("remote_creation_failed", error=str(exc))
        return make_response(
            jsonify({"error": "internal_error", "message": _("api_err_internal", error=str(exc))}),
            500,
        )


@api_bp.route("/remotes/<uuid:remote_id>", methods=["GET"])
@require_permission("remote.read")
def get_remote_details(remote_id: uuid.UUID) -> Response:
    """Get remote configuration with masked secrets and schema metadata."""
    session_factory = get_db()
    with session_factory() as session:
        remote = RemoteRepository.get_remote_by_id(session, remote_id)
        if remote is None:
            return make_response(
                jsonify({"error": "not_found", "message": _("api_err_remote_not_found")}),
                404,
            )

        current_user = get_current_user()
        is_admin = is_admin_user()
        if not RemoteRepository.can_user_view_remote(remote, current_user, is_admin=is_admin):
            return make_response(
                jsonify({"error": "forbidden", "message": _("err_remote_not_permitted")}),
                403,
            )

        spec = get_backend_spec(remote.backend_type)
        masked_config = RemoteRepository.get_masked_config(remote)
        return jsonify(
            {
                "status": "ok",
                "remote": {
                    "id": str(remote.id),
                    "name": remote.name,
                    "backend_type": remote.backend_type,
                    "backend_label": spec.label if spec else remote.backend_type,
                    "backend_icon": spec.icon if spec else "cloud",
                    "config": masked_config,
                    "secret_field_names": remote.secret_field_names,
                    "version": remote.version,
                    "is_enabled": remote.is_enabled,
                    "reachable_proxy_ids": [str(p.id) for p in remote.proxies],
                    "allowed_role_ids": [str(r.id) for r in remote.roles],
                    "created_at": remote.created_at.isoformat() if remote.created_at else None,
                    "updated_at": remote.updated_at.isoformat() if remote.updated_at else None,
                },
                "spec": spec.to_dict() if spec else None,
            }
        )


@api_bp.route("/remotes/<uuid:remote_id>", methods=["PUT"])
@require_permission("remote.write")
def update_remote(remote_id: uuid.UUID) -> Response:
    """Update remote configuration preserving existing secrets if masked."""
    payload = request.get_json(silent=True) or {}
    name = payload.get("name")
    config = payload.get("config")
    is_enabled = payload.get("is_enabled")
    raw_proxies = payload.get("reachable_proxy_ids")
    reachable_proxy_ids = (
        [uuid.UUID(str(pid)) for pid in raw_proxies if pid] if raw_proxies is not None else None
    )
    raw_roles = payload.get("allowed_role_ids")
    allowed_role_ids = (
        [uuid.UUID(str(rid)) for rid in raw_roles if rid] if raw_roles is not None else None
    )

    current_user = get_current_user()
    is_admin = is_admin_user()
    session_factory = get_db()
    try:
        with session_factory() as session:
            existing = RemoteRepository.get_remote_by_id(session, remote_id)
            if existing is None:
                return make_response(
                    jsonify({"error": "not_found", "message": _("api_err_remote_not_found")}),
                    404,
                )
            if not RemoteRepository.can_user_view_remote(existing, current_user, is_admin=is_admin):
                return make_response(
                    jsonify({"error": "forbidden", "message": _("err_remote_not_permitted")}),
                    403,
                )

            remote = RemoteRepository.update_remote(
                session=session,
                remote_id=remote_id,
                name=name,
                raw_config=config,
                is_enabled=is_enabled,
                reachable_proxy_ids=reachable_proxy_ids,
                allowed_role_ids=allowed_role_ids,
            )

            audit = AuditLog(
                action="remote.update",
                actor_user_id=current_user.id if current_user else None,
                entity_type="remote",
                entity_id=str(remote.id),
                details={"name": remote.name, "version": remote.version},
                ip=request.remote_addr,
            )
            session.add(audit)
            session.commit()

            return jsonify(
                {
                    "status": "updated",
                    "remote_id": str(remote.id),
                    "name": remote.name,
                    "version": remote.version,
                    "message": _("api_msg_remote_updated", name=remote.name),
                }
            )
    except ValueError as exc:
        return make_response(
            jsonify({"error": "validation_error", "message": _localize_remote_error(exc)}),
            400,
        )
    except Exception as exc:
        logger.error("remote_update_failed", remote_id=str(remote_id), error=str(exc))
        return make_response(
            jsonify({"error": "internal_error", "message": _("api_err_internal", error=str(exc))}),
            500,
        )


@api_bp.route("/remotes/<uuid:remote_id>", methods=["DELETE"])
@require_permission("remote.write")
def delete_remote(remote_id: uuid.UUID) -> Response:
    """Delete remote if not referenced by active jobs."""
    current_user = get_current_user()
    is_admin = is_admin_user()
    session_factory = get_db()
    with session_factory() as session:
        remote = RemoteRepository.get_remote_by_id(session, remote_id)
        if remote is None:
            return make_response(
                jsonify({"error": "not_found", "message": _("api_err_remote_not_found")}),
                404,
            )
        if not RemoteRepository.can_user_view_remote(remote, current_user, is_admin=is_admin):
            return make_response(
                jsonify({"error": "forbidden", "message": _("err_remote_not_permitted")}),
                403,
            )
        remote_name = remote.name
        ok, err = RemoteRepository.delete_remote(session, remote_id)
        if not ok:
            return make_response(
                jsonify({"error": "conflict", "message": err}),
                409,
            )

        audit = AuditLog(
            action="remote.delete",
            actor_user_id=current_user.id if current_user else None,
            entity_type="remote",
            entity_id=str(remote_id),
            details={"name": remote_name},
            ip=request.remote_addr,
        )
        session.add(audit)
        session.commit()

        return jsonify(
            {
                "status": "deleted",
                "remote_id": str(remote_id),
                "message": _("api_msg_remote_deleted", name=remote_name),
            }
        )


def _localize_remote_error(exc: Exception | str) -> str:
    """Localize remote validation or execution error into the active user locale."""
    prefix = _("invalid_config_prefix", "Configurazione non valida")

    if isinstance(exc, RemoteConfigValidationError):
        label = _(exc.field_label, exc.field_label) if exc.field_label else exc.field_name
        if exc.error_type == "required":
            msg = _(
                "error_field_required", "Il campo obbligatorio '{field}' non è stato specificato."
            ).format(field=label)
            return f"{prefix}: {msg}"
        if exc.error_type == "invalid_number":
            msg = _(
                "error_field_must_be_integer",
                "Il campo '{field}' deve essere un numero intero valido.",
            ).format(field=label)
            return f"{prefix}: {msg}"
        if exc.error_type == "unsupported_backend":
            return f"{prefix}: {exc}"

    raw = str(exc).strip()

    req_match = re.search(r"Il campo obbligatorio ['\"](.*?)['\"] non è stato specificato\.", raw)
    if req_match:
        raw_label = req_match.group(1)
        translated_label = _(raw_label, raw_label)
        msg = _(
            "error_field_required", "Il campo obbligatorio '{field}' non è stato specificato."
        ).format(field=translated_label)
        return f"{prefix}: {msg}"

    num_match = re.search(r"Il campo ['\"](.*?)['\"] deve essere un numero intero valido\.", raw)
    if num_match:
        raw_label = num_match.group(1)
        translated_label = _(raw_label, raw_label)
        msg = _(
            "error_field_must_be_integer", "Il campo '{field}' deve essere un numero intero valido."
        ).format(field=translated_label)
        return f"{prefix}: {msg}"

    unsupported_match = re.search(r"Tipo di backend ['\"](.*?)['\"] non supportato\.", raw)
    if unsupported_match:
        backend_name = unsupported_match.group(1)
        msg = _("error_unsupported_backend", "Tipo di backend '{backend}' non supportato.").format(
            backend=backend_name
        )
        return f"{prefix}: {msg}"

    if "Nessun proxy online abilitato" in raw and (
        "download" in raw or "in grado di raggiungere" in raw
    ):
        return _(
            "err_no_online_proxy_for_download",
            "Nessun proxy online abilitato è in grado di raggiungere questo remote per il download.",
        )

    if "Nessun proxy online abilitato" in raw and "raggiungere questo remote" in raw:
        return _(
            "err_no_online_proxy_for_remote",
            "Nessun proxy online abilitato è configurato per raggiungere questo remote.",
        )

    m_rem_cluster = re.search(
        r"Impossibile rimuovere il remote ['\"](.*?)['\"]: il job ['\"](.*?)['\"] utilizza tutti i proxy del cluster e richiede questo remote\.",
        raw,
    )
    if m_rem_cluster:
        return _(
            "proxy_cannot_remove_remote_cluster_job_conflict",
            "Impossibile rimuovere il remote '{remote}': il job '{job}' utilizza tutti i proxy del cluster e richiede questo remote.",
        ).format(remote=m_rem_cluster.group(1), job=m_rem_cluster.group(2))

    m_rem_proxy = re.search(
        r"Impossibile rimuovere il remote ['\"](.*?)['\"]: il proxy ['\"](.*?)['\"] è attivato per il job ['\"](.*?)['\"] che richiede questo remote\.",
        raw,
    )
    if m_rem_proxy:
        return _(
            "proxy_cannot_remove_remote_job_conflict",
            "Impossibile rimuovere il remote '{remote}': è richiesto dal job '{job}' per cui questo proxy è attivo.",
        ).format(remote=m_rem_proxy.group(1), proxy=m_rem_proxy.group(2), job=m_rem_proxy.group(3))

    m_proxy_cluster = re.search(
        r"Impossibile rimuovere il proxy ['\"](.*?)['\"]: il job ['\"](.*?)['\"] utilizza tutti i proxy del cluster e richiede questo remote\.",
        raw,
    )
    if m_proxy_cluster:
        return _(
            "remote_cannot_remove_proxy_cluster_job_conflict",
            "Impossibile rimuovere il proxy '{proxy}': il job '{job}' utilizza tutti i proxy del cluster e richiede questo remote.",
        ).format(proxy=m_proxy_cluster.group(1), job=m_proxy_cluster.group(2))

    m_proxy_job = re.search(
        r"Impossibile rimuovere il proxy ['\"](.*?)['\"]: è attivato per il job ['\"](.*?)['\"] che richiede questo remote\.",
        raw,
    )
    if m_proxy_job:
        return _(
            "remote_cannot_remove_proxy_job_conflict",
            "Impossibile rimuovere il proxy '{proxy}': è attivato per il job '{job}' che richiede questo remote.",
        ).format(proxy=m_proxy_job.group(1), job=m_proxy_job.group(2))

    m_job_src = re.search(
        r"Il proxy ['\"](.*?)['\"] attivato per questo job non può raggiungere il remote sorgente ['\"](.*?)['\"]",
        raw,
    )
    if m_job_src:
        return _(
            "job_proxy_cannot_reach_source_named_with_remote",
            "Il proxy '{proxy}' attivato per questo job non può raggiungere il remote sorgente '{remote}'.",
        ).format(proxy=m_job_src.group(1), remote=m_job_src.group(2))

    m_job_dst = re.search(
        r"Il proxy ['\"](.*?)['\"] attivato per questo job non può raggiungere il remote di destinazione ['\"](.*?)['\"]",
        raw,
    )
    if m_job_dst:
        return _(
            "job_proxy_cannot_reach_dest_named_with_remote",
            "Il proxy '{proxy}' attivato per questo job non può raggiungere il remote di destinazione '{remote}'.",
        ).format(proxy=m_job_dst.group(1), remote=m_job_dst.group(2))

    m_job_src_fallback = re.search(
        r"Il proxy ['\"](.*?)['\"] non può raggiungere il remote sorgente", raw
    )
    if m_job_src_fallback:
        return _(
            "job_proxy_cannot_reach_source_named",
            "Il proxy '{proxy}' non può raggiungere il remote sorgente selezionato.",
        ).format(proxy=m_job_src_fallback.group(1))

    m_job_dst_fallback = re.search(
        r"Il proxy ['\"](.*?)['\"] non può raggiungere il remote destinazione", raw
    )
    if m_job_dst_fallback:
        return _(
            "job_proxy_cannot_reach_dest_named",
            "Il proxy '{proxy}' non può raggiungere il remote destinazione selezionato.",
        ).format(proxy=m_job_dst_fallback.group(1))

    return raw


def _localize_remote_success_message(message: str, items_found: int | None = None) -> str:
    """Localize remote test success message with detected folder count."""
    count = items_found
    if count is None:
        m = re.search(r"(\d+)\s+cartell", message)
        if m:
            count = int(m.group(1))

    if count is not None:
        if count == 0:
            return _(
                "remote_test_success_no_folders", "Connessione riuscita. Nessuna cartella rilevata."
            )
        if count == 1:
            return _(
                "remote_test_success_single_folder", "Connessione riuscita. 1 cartella rilevata."
            )
        return _(
            "remote_test_success_folders", "Connessione riuscita. {count} cartelle rilevate."
        ).format(count=count)

    if "Connessione riuscita" in message:
        return _("remote_operational_reachable", "Remote operativo e raggiungibile.")

    return message


@api_bp.route("/remotes/test", methods=["POST"])
@require_permission("remote.test")
def test_remote_connection() -> Response:
    """Test connection to a remote before saving or on an existing remote."""
    payload = request.get_json(silent=True) or {}
    remote_id_str = payload.get("remote_id")
    backend_type = str(payload.get("backend_type", "")).strip()
    raw_config = payload.get("config", {})
    path = str(payload.get("path", "")).strip()

    from embervault_common.config import is_demo_mode
    if is_demo_mode(current_app.config.get("SETTINGS")):
        return jsonify(
            {
                "status": "ok",
                "message": _("demo_mode_remote_test_success"),
                "entries_count": 6,
            }
        )

    session_factory = get_db()
    referenced_remotes: dict[str, dict[str, Any]] = {}
    if remote_id_str:
        # Load from existing remote in DB
        try:
            remote_id = uuid.UUID(remote_id_str)
        except ValueError:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_invalid_remote_id")}),
                400,
            )

        with session_factory() as session:
            remote = RemoteRepository.get_remote_by_id(session, remote_id)
            if remote is None:
                return make_response(
                    jsonify({"status": "error", "message": _("api_err_remote_not_found")}),
                    404,
                )
            current_user = get_current_user()
            is_admin = is_admin_user()
            if not RemoteRepository.can_user_view_remote(remote, current_user, is_admin=is_admin):
                return make_response(
                    jsonify({"status": "error", "message": _("err_remote_not_permitted")}),
                    403,
                )
            backend_type = remote.backend_type
            full_config = RemoteRepository.get_decrypted_config(remote)
            referenced_remotes = RemoteRepository.resolve_referenced_remotes(
                session=session,
                backend_type=backend_type,
                config=full_config,
            )
    else:
        # If test payload was sent directly from creation/edit form
        if not backend_type:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_backend_type_required_test")}),
                400,
            )
        try:
            pub, sec, _schema = validate_and_split_remote_config(backend_type, raw_config)
            full_config = {**pub, **sec}
        except ValueError as exc:
            return make_response(
                jsonify({"status": "error", "message": _localize_remote_error(exc)}),
                400,
            )
        with session_factory() as session:
            referenced_remotes = RemoteRepository.resolve_referenced_remotes(
                session=session,
                backend_type=backend_type,
                config=full_config,
            )

    orch_client = get_orchestrator()
    try:
        candidate_proxy_ids = payload.get("candidate_proxy_ids")
        res = orch_client.test_remote(
            backend_type=backend_type,
            config=full_config,
            path=path,
            referenced_remotes=referenced_remotes,
            remote_id=str(remote_id) if remote_id_str else None,
            candidate_proxy_ids=candidate_proxy_ids,
        )
        if isinstance(res, dict):
            if res.get("status") == "ok":
                res["message"] = _localize_remote_success_message(
                    str(res.get("message", "")), res.get("items_found")
                )
            elif res.get("status") == "error":
                res["message"] = _localize_remote_error(str(res.get("message", "")))
        return jsonify(res)
    except Exception as exc:
        logger.warning("remote_test_forward_failed", error=str(exc))
        return jsonify(
            {
                "status": "error",
                "message": _("api_err_remote_test_failed", error=str(exc)),
            }
        )


@api_bp.route("/remotes/browse", methods=["POST"])
@require_permission("remote.browse")
def browse_remote_directory() -> Response:
    """Browse directories and files inside a remote storage location."""
    payload = request.get_json(silent=True) or {}
    remote_id_str = payload.get("remote_id")
    backend_type = str(payload.get("backend_type", "")).strip()
    raw_config = payload.get("config", {})
    path = str(payload.get("path", "")).strip()

    from embervault_common.config import get_demo_browse_listing, is_demo_mode
    if is_demo_mode(current_app.config.get("SETTINGS")):
        return jsonify(get_demo_browse_listing(path))

    session_factory = get_db()
    referenced_remotes: dict[str, dict[str, Any]] = {}
    if remote_id_str:
        try:
            remote_id = uuid.UUID(remote_id_str)
        except ValueError:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_invalid_remote_id")}),
                400,
            )

        with session_factory() as session:
            remote = RemoteRepository.get_remote_by_id(session, remote_id)
            if remote is None:
                return make_response(
                    jsonify({"status": "error", "message": _("api_err_remote_not_found")}),
                    404,
                )
            current_user = get_current_user()
            is_admin = is_admin_user()
            if not RemoteRepository.can_user_view_remote(remote, current_user, is_admin=is_admin):
                return make_response(
                    jsonify({"status": "error", "message": _("err_remote_not_permitted")}),
                    403,
                )
            backend_type = remote.backend_type
            full_config = RemoteRepository.get_decrypted_config(remote)
            # If the user changed/entered credentials in the form during edit, merge them
            if raw_config:
                try:
                    pub, sec, _schema = validate_and_split_remote_config(backend_type, raw_config)
                    # Don't overwrite existing secrets if value is masked '***'
                    for k, v in {**pub, **sec}.items():
                        if v != "***":
                            full_config[k] = v
                except Exception:
                    pass

            referenced_remotes = RemoteRepository.resolve_referenced_remotes(
                session=session,
                backend_type=backend_type,
                config=full_config,
            )
    else:
        if not backend_type:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_backend_type_required_browse")}),
                400,
            )
        try:
            pub, sec, _schema = validate_and_split_remote_config(backend_type, raw_config)
            full_config = {**pub, **sec}
        except ValueError as exc:
            return make_response(
                jsonify({"status": "error", "message": _localize_remote_error(exc)}),
                400,
            )
        with session_factory() as session:
            referenced_remotes = RemoteRepository.resolve_referenced_remotes(
                session=session,
                backend_type=backend_type,
                config=full_config,
            )

    orch_client = get_orchestrator()
    try:
        candidate_proxy_ids = payload.get("candidate_proxy_ids")
        res = orch_client.browse_remote(
            backend_type=backend_type,
            config=full_config,
            path=path,
            referenced_remotes=referenced_remotes,
            remote_id=str(remote_id) if remote_id_str else None,
            candidate_proxy_ids=candidate_proxy_ids,
        )
        if isinstance(res, dict) and res.get("status") == "error":
            res["message"] = _localize_remote_error(str(res.get("message", "")))
        return jsonify(res)
    except Exception as exc:
        logger.warning("remote_browse_forward_failed", error=str(exc))
        return jsonify(
            {
                "status": "error",
                "message": _("api_err_remote_browse_failed", error=str(exc)),
                "path": path,
                "directories": [],
                "files": [],
            }
        )


# =========================================================================
# Backup Jobs Management (M1.3)
# =========================================================================


@api_bp.route("/remotes/download", methods=["POST"])
@require_permission("remote.download")
def download_remote_items() -> Response:
    """Download selected files or on-the-fly zip archive of a remote directory."""
    if request.is_json:
        payload = request.get_json(silent=True) or {}
    else:
        payload = request.form.to_dict()

    remote_id_str = payload.get("remote_id")
    base_path = str(payload.get("base_path", "")).strip()
    raw_items = payload.get("items")
    items: list[dict[str, Any]] = []
    if isinstance(raw_items, str):
        try:
            items = json.loads(raw_items)
        except Exception:
            items = []
    elif isinstance(raw_items, list):
        items = raw_items

    if not items:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _(
                        "browse_no_items_selected", "Nessun elemento selezionato per il download."
                    ),
                }
            ),
            400,
        )

    from embervault_common.config import is_demo_mode
    if is_demo_mode(current_app.config.get("SETTINGS")):
        import io
        import zipfile
        from flask import send_file

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "demo_simulated_file.txt",
                "EmberVault Demo Mode - Simulated file download.\nNo real operations were performed on remotes.\n",
            )
        buf.seek(0)
        return send_file(
            buf,
            mimetype="application/zip",
            as_attachment=True,
            download_name="demo_download.zip",
        )

    if not remote_id_str:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_invalid_remote_id")}),
            400,
        )

    try:
        remote_id = uuid.UUID(str(remote_id_str))
    except ValueError:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_invalid_remote_id")}),
            400,
        )

    session_factory = get_db()
    with session_factory() as session:
        remote = RemoteRepository.get_remote_by_id(session, remote_id)
        if remote is None:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_remote_not_found")}),
                404,
            )
        current_user = get_current_user()
        is_admin = is_admin_user()
        if not RemoteRepository.can_user_view_remote(remote, current_user, is_admin=is_admin):
            return make_response(
                jsonify({"status": "error", "message": _("err_remote_not_permitted")}),
                403,
            )
        backend_type = remote.backend_type
        full_config = RemoteRepository.get_decrypted_config(remote)
        referenced_remotes = RemoteRepository.resolve_referenced_remotes(
            session=session,
            backend_type=backend_type,
            config=full_config,
        )

    orch_client = get_orchestrator()
    try:
        resp = orch_client.download_remote(
            backend_type=backend_type,
            config=full_config,
            base_path=base_path,
            items=items,
            referenced_remotes=referenced_remotes,
            remote_id=str(remote.id),
        )
        if resp.status_code != 200:
            err_msg = resp.text
            try:
                err_json = resp.json()
                if isinstance(err_json, dict) and "message" in err_json:
                    err_msg = err_json["message"]
            except Exception:
                pass
            return make_response(
                jsonify({"status": "error", "message": err_msg}),
                resp.status_code,
            )

        headers: dict[str, str] = {}
        if "Content-Disposition" in resp.headers:
            headers["Content-Disposition"] = resp.headers["Content-Disposition"]
        else:
            headers["Content-Disposition"] = 'attachment; filename="download"'

        content_type = resp.headers.get("Content-Type", "application/octet-stream")

        def forward_stream():
            if hasattr(resp, "iter_content"):
                for chunk in resp.iter_content(chunk_size=65536):
                    if chunk:
                        yield chunk
            elif hasattr(resp, "raw"):
                while True:
                    chunk = resp.raw.read(65536)
                    if not chunk:
                        break
                    yield chunk

        return Response(
            stream_with_context(forward_stream()),
            status=200,
            mimetype=content_type,
            headers=headers,
        )
    except Exception as exc:
        logger.error("remote_download_failed", error=str(exc))
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _("api_err_remote_download_failed", error=str(exc)),
                }
            ),
            500,
        )


@api_bp.route("/jobs", methods=["GET"])
@require_permission("job.read")
def list_jobs() -> Response:
    """List all configured backup jobs."""
    session_factory = get_db()
    with session_factory() as session:
        jobs = JobRepository.list_jobs(session)
        data = []
        for j in jobs:
            data.append(
                {
                    "id": str(j.id),
                    "name": j.name,
                    "enabled": j.enabled,
                    "source_remote_id": str(j.source_remote_id),
                    "source_remote_name": j.source_remote.name if j.source_remote else "Unknown",
                    "source_path": j.source_path,
                    "destination_remote_id": str(j.destination_remote_id),
                    "destination_remote_name": (
                        j.destination_remote.name if j.destination_remote else "Unknown"
                    ),
                    "destination_path": j.destination_path,
                    "operation": j.operation,
                    "parallelization": j.parallelization,
                    "discovery_status": j.discovery_status,
                    "last_discovery_id": str(j.last_discovery_id) if j.last_discovery_id else None,
                    "schedule_cron": j.schedule_cron,
                    "timezone": j.timezone,
                    "follow_dst": bool(getattr(j, "follow_dst", True)),
                    "next_run_at": j.next_run_at.isoformat() if j.next_run_at else None,
                    "created_at": j.created_at.isoformat() if j.created_at else None,
                    "assigned_proxy_ids": [str(p.id) for p in j.assigned_proxies],
                    "assigned_proxies": [
                        {"id": str(p.id), "name": p.name} for p in j.assigned_proxies
                    ],
                }
            )
        return jsonify({"status": "ok", "jobs": data})


@api_bp.route("/jobs", methods=["POST"])
@require_permission("job.write")
def create_job() -> Response:
    """Create a new backup job."""
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    source_remote_id_str = payload.get("source_remote_id")
    source_path = str(payload.get("source_path", "")).strip()
    destination_remote_id_str = payload.get("destination_remote_id")
    destination_path = str(payload.get("destination_path", "")).strip()
    operation = str(payload.get("operation", "copy")).strip()
    parallelization = str(payload.get("parallelization", "none")).strip()
    schedule_cron = payload.get("schedule_cron")
    max_parallel_tasks = payload.get("max_parallel_tasks")
    rclone_options = payload.get("rclone_options")
    if isinstance(rclone_options, dict) and (
        "additional_args" in rclone_options or "additional_params" in rclone_options
    ):
        from embervault_common.rclone.validator import sanitize_rclone_parameters

        raw_add = (
            rclone_options.get("additional_args")
            if "additional_args" in rclone_options
            else rclone_options.get("additional_params")
        )
        rclone_options["additional_args"] = sanitize_rclone_parameters(raw_add)
    is_enabled = bool(payload.get("enabled", True))
    notifications_enabled = bool(payload.get("notifications_enabled", True))
    notification_policy = payload.get("notification_policy")
    last_discovery_id_str = payload.get("last_discovery_id")
    assigned_proxy_ids_raw = payload.get("assigned_proxy_ids")
    pre_run_hook = payload.get("pre_run_hook")
    post_run_hook = payload.get("post_run_hook")
    raw_tz = payload.get("timezone")
    tz_candidate = str(raw_tz).strip() if raw_tz and str(raw_tz).strip() else str(get_user_timezone())
    try:
        timezone = validate_timezone_name(tz_candidate)
    except ValueError as exc:
        return make_response(
            jsonify(
                {
                    "error": "validation_error",
                    "message": _("api_err_invalid_timezone", error=str(exc)),
                }
            ),
            400,
        )
    follow_dst = _parse_bool_flag(payload.get("follow_dst"), default=True)
    parsed_policies, policy_err = _parse_job_run_policies(payload, is_update=False)
    if policy_err:
        return make_response(
            jsonify({"error": "validation_error", "message": policy_err}),
            400,
        )

    if schedule_cron and str(schedule_cron).strip():
        try:
            schedule_cron = validate_cron_expression(str(schedule_cron).strip())
        except Exception as exc:
            return make_response(
                jsonify(
                    {
                        "error": "validation_error",
                        "message": _("api_err_invalid_cron", error=str(exc)),
                    }
                ),
                400,
            )

    if not name or not source_remote_id_str or not destination_remote_id_str:
        return make_response(
            jsonify(
                {
                    "error": "validation_error",
                    "message": _("api_err_job_required_fields"),
                }
            ),
            400,
        )

    try:
        source_remote_id = uuid.UUID(str(source_remote_id_str))
        destination_remote_id = uuid.UUID(str(destination_remote_id_str))
        last_discovery_id = uuid.UUID(str(last_discovery_id_str)) if last_discovery_id_str else None
        assigned_proxy_ids: list[uuid.UUID] | None = None
        if assigned_proxy_ids_raw is not None:
            if isinstance(assigned_proxy_ids_raw, list):
                assigned_proxy_ids = [uuid.UUID(str(pid)) for pid in assigned_proxy_ids_raw]
            else:
                assigned_proxy_ids = []
    except ValueError:
        return make_response(
            jsonify({"error": "validation_error", "message": _("api_err_invalid_uuid")}),
            400,
        )

    current_user = get_current_user()
    session_factory = get_db()
    try:
        with session_factory() as session:
            is_admin = is_admin_user()
            src_remote = RemoteRepository.get_remote_by_id(session, source_remote_id)
            if src_remote is None or not RemoteRepository.can_user_view_remote(
                src_remote, current_user, is_admin=is_admin
            ):
                return make_response(
                    jsonify({"error": "forbidden", "message": _("err_remote_not_permitted")}),
                    403,
                )
            dst_remote = RemoteRepository.get_remote_by_id(session, destination_remote_id)
            if dst_remote is None or not RemoteRepository.can_user_view_remote(
                dst_remote, current_user, is_admin=is_admin
            ):
                return make_response(
                    jsonify({"error": "forbidden", "message": _("err_remote_not_permitted")}),
                    403,
                )

            job = JobRepository.create_job(
                session=session,
                name=name,
                source_remote_id=source_remote_id,
                source_path=source_path,
                destination_remote_id=destination_remote_id,
                destination_path=destination_path,
                operation=operation,
                parallelization=parallelization,
                discovery_status="verified" if last_discovery_id else "not_required",
                last_discovery_id=last_discovery_id,
                schedule_cron=schedule_cron,
                timezone=timezone,
                follow_dst=follow_dst,
                missed_run_policy=parsed_policies["missed_run_policy"],
                overlap_policy=parsed_policies["overlap_policy"],
                pending_policy=parsed_policies["pending_policy"],
                max_runtime_minutes=parsed_policies["max_runtime_minutes"],
                missed_run_notify=parsed_policies["missed_run_notify"],
                overlap_notify=parsed_policies["overlap_notify"],
                pending_notify=parsed_policies["pending_notify"],
                max_runtime_notify=parsed_policies["max_runtime_notify"],
                max_parallel_tasks=int(max_parallel_tasks) if max_parallel_tasks else None,
                rclone_options=rclone_options or {},
                created_by=current_user.id if current_user else None,
                is_enabled=is_enabled,
                notifications_enabled=notifications_enabled,
                notification_policy=notification_policy,
                assigned_proxy_ids=assigned_proxy_ids,
                pre_run_hook=str(pre_run_hook) if pre_run_hook is not None else None,
                post_run_hook=str(post_run_hook) if post_run_hook is not None else None,
            )

            audit = AuditLog(
                action="job.create",
                actor_user_id=current_user.id if current_user else None,
                entity_type="job",
                entity_id=str(job.id),
                details={
                    "name": name,
                    "operation": operation,
                    "parallelization": parallelization,
                    "assigned_proxy_ids": [str(pid) for pid in assigned_proxy_ids]
                    if assigned_proxy_ids
                    else [],
                },
                ip=request.remote_addr,
            )
            session.add(audit)
            session.commit()

            return make_response(
                jsonify(
                    {
                        "status": "created",
                        "job_id": str(job.id),
                        "name": job.name,
                        "message": _("api_msg_job_created", name=job.name),
                    }
                ),
                201,
            )
    except ValueError as exc:
        return make_response(
            jsonify({"error": "validation_error", "message": _localize_remote_error(exc)}), 400
        )
    except Exception as exc:
        logger.error("job_creation_failed", error=str(exc))
        return make_response(jsonify({"error": "internal_error", "message": str(exc)}), 500)


@api_bp.route("/jobs/<uuid:job_id>", methods=["GET"])
@require_permission("job.read")
def get_job_details(job_id: uuid.UUID) -> Response:
    """Retrieve full details of a backup job."""
    session_factory = get_db()
    with session_factory() as session:
        job = JobRepository.get_job_by_id(session, job_id)
        if job is None:
            return make_response(
                jsonify({"error": "not_found", "message": _("api_err_job_not_found")}), 404
            )

        return jsonify(
            {
                "status": "ok",
                "job": {
                    "id": str(job.id),
                    "name": job.name,
                    "enabled": job.enabled,
                    "source_remote_id": str(job.source_remote_id),
                    "source_remote_name": job.source_remote.name if job.source_remote else None,
                    "source_path": job.source_path,
                    "destination_remote_id": str(job.destination_remote_id),
                    "destination_remote_name": (
                        job.destination_remote.name if job.destination_remote else None
                    ),
                    "destination_path": job.destination_path,
                    "operation": job.operation,
                    "parallelization": job.parallelization,
                    "discovery_status": job.discovery_status,
                    "last_discovery_id": str(job.last_discovery_id)
                    if job.last_discovery_id
                    else None,
                    "schedule_cron": job.schedule_cron,
                    "timezone": job.timezone,
                    "follow_dst": bool(getattr(job, "follow_dst", True)),
                    "missed_run_policy": job.missed_run_policy,
                    "overlap_policy": job.overlap_policy,
                    "pending_policy": getattr(job, "pending_policy", "fail"),
                    "max_runtime_minutes": getattr(job, "max_runtime_minutes", None),
                    "missed_run_notify": bool(getattr(job, "missed_run_notify", False)),
                    "overlap_notify": bool(getattr(job, "overlap_notify", False)),
                    "pending_notify": bool(getattr(job, "pending_notify", False)),
                    "max_runtime_notify": bool(getattr(job, "max_runtime_notify", False)),
                    "max_parallel_tasks": job.max_parallel_tasks,
                    "task_timeout_s": job.task_timeout_s,
                    "rclone_options": job.rclone_options,
                    "notifications_enabled": job.notifications_enabled,
                    "notification_policy": job.notification_policy,
                    "created_at": job.created_at.isoformat() if job.created_at else None,
                    "updated_at": job.updated_at.isoformat() if job.updated_at else None,
                    "assigned_proxy_ids": [str(p.id) for p in job.assigned_proxies],
                    "assigned_proxies": [
                        {"id": str(p.id), "name": p.name} for p in job.assigned_proxies
                    ],
                },
            }
        )


@api_bp.route("/jobs/<uuid:job_id>", methods=["PUT"])
@require_permission("job.write")
def update_job(job_id: uuid.UUID) -> Response:
    """Update an existing backup job."""
    payload = request.get_json(silent=True) or {}
    name = payload.get("name")
    source_remote_id = (
        uuid.UUID(payload["source_remote_id"]) if "source_remote_id" in payload else None
    )
    source_path = payload.get("source_path")
    destination_remote_id = (
        uuid.UUID(payload["destination_remote_id"]) if "destination_remote_id" in payload else None
    )
    destination_path = payload.get("destination_path")
    operation = payload.get("operation")
    parallelization = payload.get("parallelization")
    schedule_cron = payload.get("schedule_cron")
    max_parallel_tasks = payload.get("max_parallel_tasks")
    is_enabled = payload.get("enabled")
    notifications_enabled = payload.get("notifications_enabled")
    notification_policy = (
        payload.get("notification_policy") if "notification_policy" in payload else _UNSET
    )
    last_discovery_id = (
        uuid.UUID(payload["last_discovery_id"]) if payload.get("last_discovery_id") else None
    )

    assigned_proxy_ids: list[uuid.UUID] | None = None
    if "assigned_proxy_ids" in payload:
        raw_list = payload["assigned_proxy_ids"]
        if raw_list is None:
            assigned_proxy_ids = []
        elif isinstance(raw_list, list):
            try:
                assigned_proxy_ids = [uuid.UUID(str(pid)) for pid in raw_list]
            except ValueError:
                return make_response(
                    jsonify(
                        {"error": "validation_error", "message": _("api_err_invalid_proxy_uuid")}
                    ),
                    400,
                )
        else:
            assigned_proxy_ids = []

    pre_run_hook = payload.get("pre_run_hook") if "pre_run_hook" in payload else None
    post_run_hook = payload.get("post_run_hook") if "post_run_hook" in payload else None
    rclone_options = payload.get("rclone_options") if "rclone_options" in payload else None
    if isinstance(rclone_options, dict) and (
        "additional_args" in rclone_options or "additional_params" in rclone_options
    ):
        from embervault_common.rclone.validator import sanitize_rclone_parameters

        raw_add = (
            rclone_options.get("additional_args")
            if "additional_args" in rclone_options
            else rclone_options.get("additional_params")
        )
        rclone_options["additional_args"] = sanitize_rclone_parameters(raw_add)
    raw_tz = payload.get("timezone") if "timezone" in payload else None
    timezone: str | None = None
    if raw_tz is not None:
        try:
            timezone = validate_timezone_name(str(raw_tz))
        except ValueError as exc:
            return make_response(
                jsonify(
                    {
                        "error": "validation_error",
                        "message": _("api_err_invalid_timezone", error=str(exc)),
                    }
                ),
                400,
            )
    follow_dst: bool | None = (
        _parse_bool_flag(payload.get("follow_dst"), default=True)
        if "follow_dst" in payload and payload.get("follow_dst") is not None
        else None
    )
    parsed_policies, policy_err = _parse_job_run_policies(payload, is_update=True)
    if policy_err:
        return make_response(
            jsonify({"error": "validation_error", "message": policy_err}),
            400,
        )

    if schedule_cron and str(schedule_cron).strip():
        try:
            schedule_cron = validate_cron_expression(str(schedule_cron).strip())
        except Exception as exc:
            return make_response(
                jsonify(
                    {
                        "error": "validation_error",
                        "message": _("api_err_invalid_cron", error=str(exc)),
                    }
                ),
                400,
            )

    current_user = get_current_user()
    session_factory = get_db()
    try:
        with session_factory() as session:
            existing_job = JobRepository.get_job_by_id(session, job_id)
            if existing_job is None:
                return make_response(
                    jsonify({"error": "not_found", "message": _("api_err_job_not_found")}),
                    404,
                )
            is_admin = is_admin_user()
            # If changing source remote, user must have access to both original and new remote
            if source_remote_id is not None and source_remote_id != existing_job.source_remote_id:
                if existing_job.source_remote and not RemoteRepository.can_user_view_remote(
                    existing_job.source_remote, current_user, is_admin=is_admin
                ):
                    return make_response(
                        jsonify({"error": "forbidden", "message": _("job_remote_locked_notice")}),
                        403,
                    )
                new_src = RemoteRepository.get_remote_by_id(session, source_remote_id)
                if new_src is None or not RemoteRepository.can_user_view_remote(
                    new_src, current_user, is_admin=is_admin
                ):
                    return make_response(
                        jsonify({"error": "forbidden", "message": _("err_remote_not_permitted")}),
                        403,
                    )
            # If changing destination remote, user must have access to both original and new remote
            if (
                destination_remote_id is not None
                and destination_remote_id != existing_job.destination_remote_id
            ):
                if existing_job.destination_remote and not RemoteRepository.can_user_view_remote(
                    existing_job.destination_remote, current_user, is_admin=is_admin
                ):
                    return make_response(
                        jsonify({"error": "forbidden", "message": _("job_remote_locked_notice")}),
                        403,
                    )
                new_dst = RemoteRepository.get_remote_by_id(session, destination_remote_id)
                if new_dst is None or not RemoteRepository.can_user_view_remote(
                    new_dst, current_user, is_admin=is_admin
                ):
                    return make_response(
                        jsonify({"error": "forbidden", "message": _("err_remote_not_permitted")}),
                        403,
                    )

            job = JobRepository.update_job(
                session=session,
                job_id=job_id,
                name=name,
                source_remote_id=source_remote_id,
                source_path=source_path,
                destination_remote_id=destination_remote_id,
                destination_path=destination_path,
                operation=operation,
                parallelization=parallelization,
                discovery_status="verified" if last_discovery_id else None,
                last_discovery_id=last_discovery_id,
                schedule_cron=schedule_cron,
                timezone=timezone,
                follow_dst=follow_dst,
                missed_run_policy=parsed_policies.get("missed_run_policy", _UNSET),
                overlap_policy=parsed_policies.get("overlap_policy", _UNSET),
                pending_policy=parsed_policies.get("pending_policy", _UNSET),
                max_runtime_minutes=parsed_policies.get("max_runtime_minutes"),
                clear_max_runtime=bool(parsed_policies.get("clear_max_runtime", False)),
                missed_run_notify=parsed_policies.get("missed_run_notify"),
                overlap_notify=parsed_policies.get("overlap_notify"),
                pending_notify=parsed_policies.get("pending_notify"),
                max_runtime_notify=parsed_policies.get("max_runtime_notify"),
                max_parallel_tasks=int(max_parallel_tasks) if max_parallel_tasks else None,
                rclone_options=rclone_options,
                is_enabled=is_enabled,
                notifications_enabled=notifications_enabled,
                notification_policy=notification_policy,
                assigned_proxy_ids=assigned_proxy_ids,
                pre_run_hook=str(pre_run_hook) if pre_run_hook is not None else None,
                post_run_hook=str(post_run_hook) if post_run_hook is not None else None,
            )

            audit = AuditLog(
                action="job.update",
                actor_user_id=current_user.id if current_user else None,
                entity_type="job",
                entity_id=str(job.id),
                details={"name": job.name},
                ip=request.remote_addr,
            )
            session.add(audit)
            session.commit()

            return jsonify(
                {
                    "status": "updated",
                    "job_id": str(job.id),
                    "name": job.name,
                    "message": _("api_msg_job_updated", name=job.name),
                }
            )
    except ValueError as exc:
        return make_response(
            jsonify({"error": "validation_error", "message": _localize_remote_error(exc)}), 400
        )
    except Exception as exc:
        logger.error("job_update_failed", job_id=str(job_id), error=str(exc))
        return make_response(jsonify({"error": "internal_error", "message": str(exc)}), 500)


@api_bp.route("/jobs/<uuid:job_id>", methods=["DELETE"])
@require_permission("job.write")
def delete_job(job_id: uuid.UUID) -> Response:
    """Delete a backup job if not executing."""
    current_user = get_current_user()
    session_factory = get_db()
    with session_factory() as session:
        job = JobRepository.get_job_by_id(session, job_id)
        if job is None:
            return make_response(
                jsonify({"error": "not_found", "message": _("api_err_job_not_found")}), 404
            )
        job_name = job.name
        ok, err = JobRepository.delete_job(session, job_id)
        if not ok:
            return make_response(jsonify({"error": "conflict", "message": err}), 409)

        audit = AuditLog(
            action="job.delete",
            actor_user_id=current_user.id if current_user else None,
            entity_type="job",
            entity_id=str(job_id),
            details={"name": job_name},
            ip=request.remote_addr,
        )
        session.add(audit)
        session.commit()

        return jsonify(
            {
                "status": "deleted",
                "job_id": str(job_id),
                "message": _("api_msg_job_deleted", name=job_name),
            }
        )


@api_bp.route("/jobs/discover", methods=["POST"])
@require_permission("job.read")
def discover_job_source() -> Response:
    """Trigger immediate root folder discovery and estimation for subfolder parallelization."""
    payload = request.get_json(silent=True) or {}
    source_remote_id_str = payload.get("source_remote_id")
    source_path = str(payload.get("source_path", "")).strip()
    assigned_proxy_ids_raw = payload.get("assigned_proxy_ids")

    if not source_remote_id_str:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_source_remote_required")}),
            400,
        )

    try:
        source_remote_id = uuid.UUID(str(source_remote_id_str))
        assigned_proxy_ids: list[uuid.UUID] | None = None
        if assigned_proxy_ids_raw is not None and isinstance(assigned_proxy_ids_raw, list):
            assigned_proxy_ids = [uuid.UUID(str(pid)) for pid in assigned_proxy_ids_raw]
    except ValueError:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_invalid_source_or_proxy_id")}),
            400,
        )

    session_factory = get_db()
    with session_factory() as session:
        remote = RemoteRepository.get_remote_by_id(session, source_remote_id)
        if remote is None:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_remote_not_found")}),
                404,
            )
        current_user = get_current_user()
        is_admin = is_admin_user()
        if not RemoteRepository.can_user_view_remote(remote, current_user, is_admin=is_admin):
            return make_response(
                jsonify({"status": "error", "message": _("err_remote_not_permitted")}),
                403,
            )

    orch_client = get_orchestrator()
    try:
        res = orch_client.create_discovery(
            source_remote_id=source_remote_id,
            source_path=source_path,
            assigned_proxy_ids=assigned_proxy_ids,
        )
        if res.get("status") == "ok" and "discovery" in res:
            return jsonify(res)

        if res.get("status") == "error":
            raw_msg = res.get("message") or res.get("error")
            return jsonify(
                {
                    "status": "error",
                    "message": (
                        _localize_orchestrator_message(str(raw_msg))
                        if raw_msg
                        else _("api_err_discovery_unsuccessful")
                    ),
                }
            )

        subfolders = res.get("subfolders") or []
        root_files = res.get("root_files") or []
        disc_id = res.get("id")
        folder_count = res.get("total_subfolders", res.get("folder_count", len(subfolders)))
        root_file_count = res.get("total_root_files", res.get("root_file_count", len(root_files)))
        task_count_estimate = res.get(
            "task_count_estimate",
            max(1, (1 if root_file_count > 0 else 0) + folder_count),
        )
        level = res.get("status_level") or res.get("level") or "ok"

        return jsonify(
            {
                "status": "ok",
                "discovery": {
                    "id": str(disc_id) if disc_id else None,
                    "source_remote_id": str(source_remote_id),
                    "source_path": source_path,
                    "folder_count": folder_count,
                    "root_file_count": root_file_count,
                    "task_count_estimate": task_count_estimate,
                    "level": level,
                    "entries": {
                        "folders": subfolders,
                        "subfolders": subfolders,
                        "root_files": root_files,
                    },
                },
            }
        )
    except Exception as exc:
        logger.warning("job_discovery_failed", error=str(exc))
        return jsonify(
            {
                "status": "error",
                "message": _("api_err_discovery_failed", error=str(exc)),
            }
        )


def _localize_orchestrator_message(msg: str) -> str:
    """Localize status/error messages returned by the internal Orchestrator API."""
    if not msg:
        return msg

    exact_map = {
        "Run annullata.": "orch_msg_run_cancelled",
        "Impossibile annullare: la run non esiste o è già terminata.": "orch_err_cancel_run_not_found_or_finished",
        "Task annullato con successo.": "orch_msg_task_cancelled",
        "Task non trovato.": "orch_err_task_not_found",
        "Nessun proxy online disponibile per effettuare la discovery delle cartelle.": "orch_err_no_online_proxy_discovery",
        "Nessun proxy online ha risposto con successo alla discovery.": "orch_err_no_online_proxy_responded_discovery",
        "Errore durante la discovery sul proxy": "orch_err_proxy_discovery_generic",
        "Nessun proxy abilitato disponibile nel sistema.": "orch_err_no_enabled_proxy",
        "Nessun proxy ha risposto con successo alla scansione.": "orch_err_no_proxy_responded_scan",
        "Nessun proxy online abilitato è configurato per raggiungere questo remote.": "err_no_online_proxy_for_remote",
        "Nessun proxy online abilitato è in grado di raggiungere questo remote per il download.": "err_no_online_proxy_for_download",
    }
    if msg in exact_map:
        return _(exact_map[msg])

    m = re.match(r"^Run per '(.*)' avviata \((\d+) task pianificati, (\d+) inviati\)\.$", msg)
    if m:
        return _(
            "orch_msg_job_run_dispatched_tpl",
            job_name=m.group(1),
            planned=m.group(2),
            dispatched=m.group(3),
        )

    m = re.match(r"^Impossibile annullare: il task è già in stato '(.*)'\.$", msg)
    if m:
        return _("orch_err_cancel_task_already_state_tpl", status=m.group(1))

    m = re.match(r"^Job (.*) non trovato\.$", msg)
    if m:
        return _("orch_err_job_not_found_tpl", job_id=m.group(1))

    m = re.match(r"^Il job '(.*)' è disabilitato\.$", msg)
    if m:
        return _("orch_err_job_disabled_tpl", job_name=m.group(1))

    m = re.match(r"^Remote sorgente non configurato o non trovato per il job '(.*)'\.$", msg)
    if m:
        return _("orch_err_source_remote_missing_tpl", job_name=m.group(1))

    m = re.match(r"^Nessun proxy assegnato \((\d+)\) risulta abilitato\.$", msg)
    if m:
        return _("orch_err_no_assigned_proxy_enabled_tpl", count=m.group(1))

    m = re.match(
        r"^Impossibile eseguire la discovery live delle cartelle sorgente all'avvio del job '(.*)': (.*)$",
        msg,
    )
    if m:
        inner_err = _localize_orchestrator_message(m.group(2))
        return _("orch_err_live_discovery_failed_tpl", job_name=m.group(1), err=inner_err)

    return msg


@api_bp.route("/jobs/<uuid:job_id>/run", methods=["POST"])
@require_permission("job.run")
def run_job_manually(job_id: uuid.UUID) -> Response:
    """Manually dispatch a job run."""
    orch = get_orchestrator()
    try:
        res = orch.trigger_job_run(job_id=job_id, trigger="manual")
        if isinstance(res, dict):
            if res.get("status") in ("dispatched", "completed") and "job_name" in res:
                if res.get("status") == "completed" and "demo" in str(res.get("message", "")).lower():
                    pass
                else:
                    res["message"] = _(
                        "orch_msg_job_run_dispatched_tpl",
                        job_name=res.get("job_name", ""),
                        planned=res.get("planned_task_count", 0),
                        dispatched=res.get("dispatched_count", 0),
                    )
            elif "message" in res and isinstance(res["message"], str):
                res["message"] = _localize_orchestrator_message(res["message"])
        return jsonify(res)
    except Exception as exc:
        logger.warning("run_job_failed", job_id=str(job_id), error=str(exc))
        return make_response(
            jsonify({"status": "error", "message": _("api_err_job_run_failed", error=str(exc))}),
            500,
        )


@api_bp.route("/runs/<uuid:run_id>/cancel", methods=["POST"])
@require_permission("job.run")
def cancel_job_run(run_id: uuid.UUID) -> Response:
    """Cancel a running or queued job run."""
    orch = get_orchestrator()
    try:
        res = orch.cancel_run(run_id)
        if isinstance(res, dict) and "message" in res and isinstance(res["message"], str):
            res["message"] = _localize_orchestrator_message(res["message"])
        return jsonify(res)
    except Exception as exc:
        logger.warning("cancel_run_failed", run_id=str(run_id), error=str(exc))
        return make_response(
            jsonify({"status": "error", "message": _("api_err_cancel_failed", error=str(exc))}),
            500,
        )


@api_bp.route("/runs", methods=["GET"])
@require_permission("job.read")
def list_job_runs() -> Response:
    """List execution history."""
    orch = get_orchestrator()
    try:
        res = orch.list_runs()
        return jsonify(res)
    except Exception as exc:
        logger.warning("list_runs_failed", error=str(exc))
        return jsonify({"status": "error", "runs": [], "message": str(exc)})


@api_bp.route("/runs/<uuid:run_id>", methods=["GET"])
@require_permission("job.read")
def get_run_details(run_id: uuid.UUID) -> Response:
    """Get run details and task progress."""
    from embervault_app.i18n import localize_proxies_activity

    orch = get_orchestrator()
    try:
        res = orch.get_run(run_id)
        if isinstance(res, dict) and isinstance(res.get("run"), dict):
            run_dict = res["run"]
            if isinstance(run_dict.get("proxies"), list):
                run_dict["proxies"] = localize_proxies_activity(run_dict["proxies"])
        return jsonify(res)
    except Exception as exc:
        logger.warning("get_run_failed", run_id=str(run_id), error=str(exc))
        return make_response(jsonify({"status": "error", "message": str(exc)}), 404)


@api_bp.route("/tasks/<uuid:task_id>/logs", methods=["GET"])
@require_permission("job.read")
def get_task_execution_logs(task_id: uuid.UUID) -> Response:
    """Get stored logs for a specific task."""
    orch = get_orchestrator()
    limit_param = request.args.get("limit")
    limit = int(limit_param) if limit_param and limit_param.isdigit() else None
    from_seq_param = request.args.get("from_seq")
    from_seq = int(from_seq_param) if from_seq_param and from_seq_param.isdigit() else None
    tail = request.args.get("tail", "false").lower() in ("true", "1")
    try:
        res = orch.get_task_logs(task_id, limit=limit, from_seq=from_seq, tail=tail)
        return jsonify(res)
    except Exception as exc:
        logger.warning("get_task_logs_failed", task_id=str(task_id), error=str(exc))
        return jsonify({"status": "error", "task_id": str(task_id), "lines": []})


@api_bp.route("/tasks/<uuid:task_id>/cancel", methods=["POST"])
@require_permission("job.run")
def cancel_task_execution(task_id: uuid.UUID) -> Response:
    """Cancel an individual running or queued task."""
    orch = get_orchestrator()
    try:
        res = orch.cancel_task(task_id)
        if isinstance(res, dict) and "message" in res and isinstance(res["message"], str):
            res["message"] = _localize_orchestrator_message(res["message"])
        return jsonify(res)
    except Exception as exc:
        logger.warning("cancel_task_failed", task_id=str(task_id), error=str(exc))
        return make_response(
            jsonify(
                {"status": "error", "message": _("api_err_cancel_task_failed", error=str(exc))}
            ),
            500,
        )


@api_bp.route("/users", methods=["GET"])
@require_permission("user.read")
def list_users_api() -> Response:
    """List all registered users."""
    session_factory = get_db()
    with session_factory() as session:
        users = UserRepository.list_users(session)
        data = [
            {
                "id": str(u.id),
                "username": u.username,
                "email": u.email,
                "display_name": u.display_name,
                "role_id": str(u.role_id),
                "role_name": u.role.name if u.role else None,
                "is_active": u.is_active,
                "must_change_password": u.must_change_password,
                "theme": getattr(u, "theme", "embervault"),
                "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            }
            for u in users
        ]
    return jsonify({"status": "ok", "users": data})


@api_bp.route("/users", methods=["POST"])
@require_permission("user.manage")
def create_user_api() -> Response:
    """Create a new local user."""
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    role_id_str = str(data.get("role_id", ""))
    email = data.get("email")
    display_name = data.get("display_name")
    is_active = bool(data.get("is_active", True))
    must_change = bool(data.get("must_change_password", False))
    theme = data.get("theme", "embervault")

    if not username or not password or not role_id_str:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_user_required_fields")}),
            400,
        )

    try:
        role_id = uuid.UUID(role_id_str)
    except ValueError:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_invalid_role_id")}), 400
        )

    actor = get_current_user()
    actor_id = actor.id if actor else None
    session_factory = get_db()
    with session_factory() as session:
        try:
            user = UserRepository.create_user(
                session=session,
                username=username,
                password=password,
                role_id=role_id,
                email=email,
                display_name=display_name,
                is_active=is_active,
                must_change_password=must_change,
                theme=theme,
                actor_user_id=actor_id,
                ip=request.remote_addr,
            )
            session.commit()
            return make_response(
                jsonify(
                    {
                        "status": "created",
                        "user": {
                            "id": str(user.id),
                            "username": user.username,
                            "role_name": user.role.name if user.role else None,
                            "theme": user.theme,
                        },
                        "message": _("api_msg_user_created", username=user.username),
                    }
                ),
                201,
            )
        except ValueError as err:
            return make_response(jsonify({"status": "error", "message": str(err)}), 400)


@api_bp.route("/users/<uuid:user_id>", methods=["PUT", "PATCH"])
@require_auth
def update_user_api(user_id: uuid.UUID) -> Response:
    """Update user properties, role, or reset password."""
    actor = get_current_user()
    user_perms: set[str] = getattr(g, "permissions", set())
    is_admin = "user.manage" in user_perms
    is_self = actor is not None and actor.id == user_id

    if not is_admin and not is_self:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "error": "forbidden",
                    "message": _("api_err_user_edit_forbidden"),
                }
            ),
            403,
        )

    data = request.get_json(silent=True) or {}

    role_id: uuid.UUID | None = None
    if "role_id" in data and data["role_id"]:
        if not is_admin:
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "error": "forbidden",
                        "message": _("api_err_role_change_admin_only"),
                    }
                ),
                403,
            )
        try:
            role_id = uuid.UUID(str(data["role_id"]))
        except ValueError:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_invalid_role_id")}), 400
            )

    email = data.get("email")
    display_name = data.get("display_name")
    theme = data.get("theme")
    is_active = data.get("is_active")
    if is_active is not None and not is_admin:
        # Non-admins cannot alter their own active status
        is_active = None

    must_change = data.get("must_change_password")
    new_password = data.get("password")

    actor_id = actor.id if actor else None
    session_factory = get_db()
    with session_factory() as session:
        try:
            user = UserRepository.update_user(
                session=session,
                user_id=user_id,
                role_id=role_id,
                email=email,
                display_name=display_name,
                is_active=is_active,
                must_change_password=must_change,
                new_password=new_password,
                theme=theme,
                actor_user_id=actor_id,
                ip=request.remote_addr,
            )
            session.commit()
            return jsonify(
                {
                    "status": "updated",
                    "user": {
                        "id": str(user.id),
                        "username": user.username,
                        "role_name": user.role.name if user.role else None,
                        "is_active": user.is_active,
                        "theme": user.theme,
                    },
                    "message": _("api_msg_user_updated", username=user.username),
                }
            )
        except ValueError as err:
            return make_response(jsonify({"status": "error", "message": str(err)}), 400)


@api_bp.route("/users/<uuid:user_id>", methods=["DELETE"])
@require_permission("user.manage")
def delete_user_api(user_id: uuid.UUID) -> Response:
    """Delete a user account."""
    actor = get_current_user()
    actor_id = actor.id if actor else None
    session_factory = get_db()
    with session_factory() as session:
        try:
            ok = UserRepository.delete_user(
                session=session,
                user_id=user_id,
                actor_user_id=actor_id,
                ip=request.remote_addr,
            )
            if not ok:
                return make_response(
                    jsonify({"status": "error", "message": _("api_err_user_not_found")}), 404
                )
            session.commit()
            return jsonify({"status": "deleted", "message": _("api_msg_user_deleted")})
        except ValueError as err:
            return make_response(jsonify({"status": "error", "message": str(err)}), 400)


# =========================================================================
# Milestone M3: 2FA & TOTP Management Endpoints
# =========================================================================


@api_bp.route("/2fa/status", methods=["GET"])
@require_auth
def get_2fa_status() -> Response:
    """Return 2FA status, confirmed factors, recovery codes count, and role enforcement."""
    actor = get_current_user()
    assert actor is not None

    session_factory = get_db()
    with session_factory() as session:
        factor = UserRepository.get_user_mfa_factor(session, actor.id, "totp")
        totp_enabled = factor is not None and factor.confirmed_at is not None
        recovery_count = UserRepository.get_remaining_recovery_codes_count(session, actor.id)
        role = UserRepository.get_role_by_id(session, actor.role_id)
        enforce_2fa = role.enforce_2fa if role else False

    return jsonify(
        {
            "status": "ok",
            "totp_enabled": totp_enabled,
            "enforce_2fa": enforce_2fa,
            "remaining_recovery_codes": recovery_count,
            "factor_label": factor.label if factor else None,
        }
    )


@api_bp.route("/2fa/setup", methods=["POST"])
@require_auth
def setup_2fa_totp() -> Response:
    """Initialize or rotate pending TOTP secret, generating secret and SVG/PNG QR code."""
    from embervault_common.security import (
        decrypt_blob,
        encrypt_blob,
        generate_totp_qr_png_data_uri,
        generate_totp_qr_svg,
        generate_totp_secret,
        hash_recovery_code,
        verify_password,
        verify_totp_code,
    )

    actor = get_current_user()
    assert actor is not None

    data = request.get_json(silent=True) or {}
    password = data.get("password")
    code = (data.get("code") or "").strip()

    session_factory = get_db()
    with session_factory() as session:
        # Check if user already has an active (confirmed) 2FA factor
        existing_factor = UserRepository.get_user_mfa_factor(session, actor.id, "totp")
        if existing_factor is not None and existing_factor.confirmed_at is not None:
            # Reconfiguring an active 2FA factor requires verifying password and current 2FA (or recovery code)
            if not password:
                return make_response(
                    jsonify(
                        {
                            "status": "error",
                            "message": _("api_err_2fa_reset_pwd_required"),
                        }
                    ),
                    400,
                )
            actor_user = UserRepository.get_user_by_id(session, actor.id)
            if actor_user is None or not verify_password(actor_user.password_hash or "", password):
                return make_response(
                    jsonify({"status": "error", "message": _("api_err_wrong_password")}),
                    400,
                )
            if not code:
                return make_response(
                    jsonify(
                        {
                            "status": "error",
                            "message": _("api_err_2fa_reset_code_required"),
                        }
                    ),
                    400,
                )

            is_code_valid = False
            clean_code = code.replace(" ", "").replace("-", "")
            if clean_code.isdigit() and len(clean_code) == 6:
                try:
                    raw_secret = decrypt_blob(
                        existing_factor.secret_encrypted, aad=f"user-totp:{actor.id}"
                    ).decode("utf-8")
                    is_code_valid = verify_totp_code(raw_secret, clean_code)
                except Exception:
                    is_code_valid = False

            if not is_code_valid:
                hashed_rec = hash_recovery_code(code)
                if UserRepository.verify_and_consume_recovery_code(
                    session, actor.id, hashed_rec, ip=request.remote_addr
                ):
                    is_code_valid = True

            if not is_code_valid:
                return make_response(
                    jsonify(
                        {
                            "status": "error",
                            "message": _("api_err_2fa_invalid_code"),
                        }
                    ),
                    400,
                )

        secret = generate_totp_secret()
        qr_svg = generate_totp_qr_svg(secret=secret, username=actor.username)
        qr_png = generate_totp_qr_png_data_uri(secret=secret, username=actor.username)

        # Encrypt secret with Envelope encryption bound to user_id AAD
        encrypted_secret = encrypt_blob(plaintext=secret, aad=f"user-totp:{actor.id}")

        UserRepository.set_user_totp_factor(
            session=session,
            user_id=actor.id,
            secret_encrypted=encrypted_secret,
            label="Authenticator App",
            confirmed=False,
            actor_user_id=actor.id,
            ip=request.remote_addr,
        )
        session.commit()

    return jsonify(
        {
            "status": "ok",
            "secret": secret,
            "qr_svg": qr_svg,
            "qr_png": qr_png,
            "message": _("api_msg_2fa_scan_qr"),
        }
    )


@api_bp.route("/2fa/confirm", methods=["POST"])
@require_auth
def confirm_2fa_totp() -> Response:
    """Confirm pending TOTP factor with user-provided code, generating recovery codes."""
    from embervault_common.security import (
        decrypt_blob,
        generate_recovery_codes,
        hash_recovery_code,
        verify_totp_code,
    )

    actor = get_current_user()
    assert actor is not None

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", "")).strip()
    if not code:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_totp_code_required")}),
            400,
        )

    session_factory = get_db()
    with session_factory() as session:
        factor = UserRepository.get_user_mfa_factor(session, actor.id, "totp")
        if factor is None:
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": _("api_err_totp_no_pending"),
                    }
                ),
                400,
            )

        try:
            raw_secret = decrypt_blob(factor.secret_encrypted, aad=f"user-totp:{actor.id}").decode(
                "utf-8"
            )
        except Exception:
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": _("api_err_totp_decrypt_failed"),
                    }
                ),
                500,
            )

        if not verify_totp_code(raw_secret, code):
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": _("api_err_totp_invalid_or_expired"),
                    }
                ),
                400,
            )

        # Confirm factor
        UserRepository.confirm_user_totp_factor(
            session=session,
            user_id=actor.id,
            actor_user_id=actor.id,
            ip=request.remote_addr,
        )

        # Generate 10 one-time recovery codes
        plain_recovery_codes = generate_recovery_codes(10)
        hashed_codes = [hash_recovery_code(c) for c in plain_recovery_codes]
        UserRepository.set_user_recovery_codes(
            session=session,
            user_id=actor.id,
            hashed_codes=hashed_codes,
            actor_user_id=actor.id,
            ip=request.remote_addr,
        )
        session.commit()

    return jsonify(
        {
            "status": "confirmed",
            "message": _("api_msg_2fa_enabled"),
            "recovery_codes": plain_recovery_codes,
        }
    )


@api_bp.route("/2fa/disable", methods=["POST"])
@require_auth
def disable_2fa() -> Response:
    """Disable 2FA for user. Requires current password AND valid 2FA verification (TOTP or recovery code)."""
    from embervault_common.security import (
        decrypt_blob,
        hash_recovery_code,
        verify_totp_code,
    )
    from embervault_common.security.passwords import verify_password

    actor = get_current_user()
    assert actor is not None

    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))
    code = str(data.get("code", "")).strip()
    target_user_id_str = data.get("user_id")

    user_perms: set[str] = getattr(g, "permissions", set())
    is_admin = "user.manage" in user_perms

    target_user_id = actor.id
    if target_user_id_str and is_admin:
        try:
            target_user_id = uuid.UUID(str(target_user_id_str))
        except ValueError:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_invalid_user_id")}), 400
            )

    session_factory = get_db()
    with session_factory() as session:
        target_user = UserRepository.get_user_by_id(session, target_user_id)
        if target_user is None:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_user_not_found")}), 404
            )

        if target_user.role and target_user.role.enforce_2fa:
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": _("api_err_2fa_enforced_by_role", role=target_user.role.name),
                    }
                ),
                400,
            )

        # Require current actor password verification
        actor_user = UserRepository.get_user_by_id(session, actor.id)
        if actor_user is None or not verify_password(actor_user.password_hash or "", password):
            return make_response(
                jsonify({"status": "error", "message": _("api_err_wrong_password")}),
                400,
            )

        # If user is disabling their own 2FA (or non-admin target), require 2FA proof (TOTP or recovery code)
        factor = UserRepository.get_user_mfa_factor(session, target_user_id, "totp")
        if factor is not None and factor.confirmed_at is not None and target_user_id == actor.id:
            if not code:
                return make_response(
                    jsonify(
                        {
                            "status": "error",
                            "message": _("api_err_2fa_disable_code_required"),
                        }
                    ),
                    400,
                )

            is_code_valid = False
            clean_code = code.replace(" ", "").replace("-", "")
            if clean_code.isdigit() and len(clean_code) == 6:
                try:
                    raw_secret = decrypt_blob(
                        factor.secret_encrypted, aad=f"user-totp:{actor.id}"
                    ).decode("utf-8")
                    is_code_valid = verify_totp_code(raw_secret, clean_code)
                except Exception:
                    is_code_valid = False

            if not is_code_valid:
                hashed_rec = hash_recovery_code(code)
                if UserRepository.verify_and_consume_recovery_code(
                    session, actor.id, hashed_rec, ip=request.remote_addr
                ):
                    is_code_valid = True

            if not is_code_valid:
                return make_response(
                    jsonify(
                        {
                            "status": "error",
                            "message": _("api_err_2fa_disable_invalid_code"),
                        }
                    ),
                    400,
                )

        UserRepository.disable_user_2fa(
            session=session,
            user_id=target_user_id,
            actor_user_id=actor.id,
            ip=request.remote_addr,
        )
        session.commit()

    return jsonify({"status": "disabled", "message": _("api_msg_2fa_disabled")})


@api_bp.route("/roles", methods=["GET"])
@require_permission("role.read")
def list_roles_api() -> Response:
    """Return all system and custom roles."""
    session_factory = get_db()
    with session_factory() as session:
        roles = UserRepository.list_roles(session)
        user_counts: dict[uuid.UUID, int] = dict(
            session.execute(select(User.role_id, func.count(User.id)).group_by(User.role_id)).all()
        )
        data = [
            {
                "id": str(r.id),
                "name": r.name,
                "description": r.description or "",
                "is_system": r.is_system,
                "enforce_2fa": r.enforce_2fa,
                "users_count": user_counts.get(r.id, 0),
                "permissions": [p.code for p in r.permissions],
            }
            for r in roles
        ]
        return jsonify({"roles": data})


@api_bp.route("/roles", methods=["POST"])
@require_permission("role.manage")
def create_role_api() -> Response:
    """Create a new custom role."""
    actor = get_current_user()
    actor_id = actor.id if actor else None
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()
    description = str(data.get("description") or "").strip() or None
    copy_from_str = data.get("copy_from_role_id")
    copy_from_id = uuid.UUID(copy_from_str) if copy_from_str else None
    perms = data.get("permissions")
    if perms is not None and not isinstance(perms, list):
        perms = None

    session_factory = get_db()
    with session_factory() as session:
        try:
            role = UserRepository.create_role(
                session=session,
                name=name,
                description=description,
                copy_from_role_id=copy_from_id,
                permission_codes=perms,
                actor_user_id=actor_id,
                ip=request.remote_addr,
            )
            session.commit()
            return (
                jsonify(
                    {
                        "status": "created",
                        "role": {
                            "id": str(role.id),
                            "name": role.name,
                            "description": role.description,
                            "is_system": role.is_system,
                            "enforce_2fa": role.enforce_2fa,
                            "permissions": [p.code for p in role.permissions],
                        },
                        "message": _("api_msg_role_created", name=role.name),
                    }
                ),
                201,
            )
        except ValueError as err:
            return make_response(jsonify({"status": "error", "message": str(err)}), 400)


@api_bp.route("/roles/matrix", methods=["GET"])
@require_permission("role.read")
def get_roles_matrix_api() -> Response:
    """Return permissions matrix data for roles vs permissions grouped by category."""
    session_factory = get_db()
    with session_factory() as session:
        matrix_data = UserRepository.get_permissions_matrix(session)
        return jsonify(matrix_data)


@api_bp.route("/roles/<uuid:role_id>", methods=["GET"])
@require_permission("role.read")
def get_role_detail_api(role_id: uuid.UUID) -> Response:
    """Return single role detail."""
    session_factory = get_db()
    with session_factory() as session:
        role = UserRepository.get_role_by_id(session, role_id)
        if not role:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_role_not_found")}), 404
            )
        users_count = (
            session.scalar(select(func.count(User.id)).where(User.role_id == role.id)) or 0
        )
        return jsonify(
            {
                "id": str(role.id),
                "name": role.name,
                "description": role.description or "",
                "is_system": role.is_system,
                "enforce_2fa": role.enforce_2fa,
                "users_count": users_count,
                "permissions": [p.code for p in role.permissions],
            }
        )


@api_bp.route("/roles/<uuid:role_id>", methods=["PUT"])
@require_permission("role.manage")
def update_role_api(role_id: uuid.UUID) -> Response:
    """Update role name and/or description."""
    actor = get_current_user()
    actor_id = actor.id if actor else None
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    description = data.get("description")

    session_factory = get_db()
    with session_factory() as session:
        try:
            role = UserRepository.update_role(
                session=session,
                role_id=role_id,
                name=str(name).strip() if name is not None else None,
                description=str(description).strip() if description is not None else None,
                actor_user_id=actor_id,
                ip=request.remote_addr,
            )
            session.commit()
            return jsonify(
                {
                    "status": "updated",
                    "role": {
                        "id": str(role.id),
                        "name": role.name,
                        "description": role.description,
                        "is_system": role.is_system,
                        "enforce_2fa": role.enforce_2fa,
                    },
                    "message": _("api_msg_role_updated", name=role.name),
                }
            )
        except ValueError as err:
            return make_response(jsonify({"status": "error", "message": str(err)}), 400)


@api_bp.route("/roles/<uuid:role_id>", methods=["DELETE"])
@require_permission("role.manage")
def delete_role_api(role_id: uuid.UUID) -> Response:
    """Delete a custom role if not system and not in use."""
    actor = get_current_user()
    actor_id = actor.id if actor else None

    session_factory = get_db()
    with session_factory() as session:
        try:
            UserRepository.delete_role(
                session=session,
                role_id=role_id,
                actor_user_id=actor_id,
                ip=request.remote_addr,
            )
            session.commit()
            return jsonify({"status": "deleted", "message": _("api_msg_role_deleted")})
        except ValueError as err:
            return make_response(jsonify({"status": "error", "message": str(err)}), 400)


@api_bp.route("/roles/<uuid:role_id>/permissions/<path:permission_code>/toggle", methods=["POST"])
@require_permission("role.manage")
def toggle_role_permission_api(role_id: uuid.UUID, permission_code: str) -> Response:
    """Toggle or explicitly set a single permission on a role (synchronizes 2FA enforcement if auth.enforce_2fa)."""
    actor = get_current_user()
    actor_id = actor.id if actor else None
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled")
    if enabled is not None:
        enabled = bool(enabled)

    session_factory = get_db()
    with session_factory() as session:
        try:
            role, new_state = UserRepository.toggle_role_permission(
                session=session,
                role_id=role_id,
                permission_code=permission_code,
                enabled=enabled,
                actor_user_id=actor_id,
                ip=request.remote_addr,
            )
            session.commit()
            msg = (
                _("api_msg_role_perm_enabled", code=permission_code, role=role.name)
                if new_state
                else _("api_msg_role_perm_disabled", code=permission_code, role=role.name)
            )
            if permission_code == "auth.enforce_2fa":
                msg = (
                    _("api_msg_role_2fa_set_mandatory", role=role.name)
                    if new_state
                    else _("api_msg_role_2fa_set_optional", role=role.name)
                )

            return jsonify(
                {
                    "status": "updated",
                    "role_id": str(role.id),
                    "role_name": role.name,
                    "permission_code": permission_code,
                    "enabled": new_state,
                    "enforce_2fa": role.enforce_2fa,
                    "message": msg,
                }
            )
        except ValueError as err:
            return make_response(jsonify({"status": "error", "message": str(err)}), 400)


@api_bp.route("/roles/<uuid:role_id>/permissions", methods=["PUT"])
@require_permission("role.manage")
def set_role_permissions_api(role_id: uuid.UUID) -> Response:
    """Replace entire permission set for a role."""
    actor = get_current_user()
    actor_id = actor.id if actor else None
    data = request.get_json(silent=True) or {}
    permission_codes = data.get("permissions")
    if not isinstance(permission_codes, list):
        return make_response(
            jsonify({"status": "error", "message": _("api_err_permissions_must_be_list")}),
            400,
        )

    session_factory = get_db()
    with session_factory() as session:
        try:
            role = UserRepository.set_role_permissions(
                session=session,
                role_id=role_id,
                permission_codes=permission_codes,
                actor_user_id=actor_id,
                ip=request.remote_addr,
            )
            session.commit()
            return jsonify(
                {
                    "status": "updated",
                    "role_id": str(role.id),
                    "role_name": role.name,
                    "permissions": [p.code for p in role.permissions],
                    "enforce_2fa": role.enforce_2fa,
                    "message": _("api_msg_role_perms_saved", role=role.name),
                }
            )
        except ValueError as err:
            return make_response(jsonify({"status": "error", "message": str(err)}), 400)


@api_bp.route("/roles/<uuid:role_id>/enforce-2fa", methods=["POST"])
@require_permission("role.manage")
def toggle_role_enforce_2fa(role_id: uuid.UUID) -> Response:
    """Legacy toggle mandatory 2FA enforcement for a given role (Admin only)."""
    actor = get_current_user()
    actor_id = actor.id if actor else None

    data = request.get_json(silent=True) or {}
    enforce = bool(data.get("enforce_2fa", False))

    session_factory = get_db()
    with session_factory() as session:
        try:
            role = UserRepository.update_role(
                session=session,
                role_id=role_id,
                enforce_2fa=enforce,
                actor_user_id=actor_id,
                ip=request.remote_addr,
            )
            session.commit()
            return jsonify(
                {
                    "status": "updated",
                    "role_id": str(role.id),
                    "role_name": role.name,
                    "enforce_2fa": role.enforce_2fa,
                    "message": _("api_msg_role_2fa_updated_mandatory", role=role.name)
                    if role.enforce_2fa
                    else _("api_msg_role_2fa_updated_optional", role=role.name),
                }
            )
        except ValueError as err:
            return make_response(jsonify({"status": "error", "message": str(err)}), 400)


@api_bp.route("/ldap/config", methods=["GET"])
@require_permission("identity.read")
def get_ldap_configuration() -> Response:
    """Return resolved LDAP configuration with masked bind password."""
    from embervault_app.ldap_service import get_ldap_config

    session_factory = get_db()
    with session_factory() as session:
        enabled, config = get_ldap_config(session)

    return jsonify(
        {
            "status": "ok",
            "ldap_enabled": enabled,
            "ldap_server_url": config.server_url,
            "ldap_require_tls": config.require_tls,
            "ldap_bind_dn": config.bind_dn,
            "ldap_bind_password_set": bool(config.bind_password),
            "ldap_base_dn": config.base_dn,
            "ldap_user_filter": config.user_filter,
            "ldap_group_attribute": config.group_attribute,
            "ldap_admin_group": config.admin_group,
            "ldap_operator_group": config.operator_group,
            "ldap_viewer_group": config.viewer_group,
            "ldap_connect_timeout_s": config.connect_timeout_s,
            "ldap_validate_cert": config.validate_cert,
            "ldap_ca_cert_pem": config.ca_cert_pem,
        }
    )


@api_bp.route("/ldap/config", methods=["PUT"])
@require_permission("identity.write")
def update_ldap_configuration() -> Response:
    """Update LDAP configuration parameters in SettingsStore."""
    actor = get_current_user()
    actor_id = actor.id if actor else None
    data = request.get_json(silent=True) or {}

    from embervault_app.ldap_service import save_ldap_config

    session_factory = get_db()
    with session_factory() as session:
        save_ldap_config(
            session=session,
            data=data,
            user_id=actor_id,
            ip=request.remote_addr,
        )
        session.commit()

    return jsonify({"status": "updated", "message": _("api_msg_ldap_saved")})


@api_bp.route("/ldap/test", methods=["POST"])
@require_permission("identity.write")
def test_ldap_endpoint() -> Response:
    """Test connectivity, TLS, and service account bind to LDAP server."""
    overrides = request.get_json(silent=True) or {}

    from embervault_app.ldap_service import test_ldap_from_settings

    session_factory = get_db()
    with session_factory() as session:
        ok, msg, details = test_ldap_from_settings(session, overrides=overrides)

    status_code = 200 if ok else 400
    return make_response(
        jsonify(
            {
                "status": "ok" if ok else "error",
                "message": msg,
                "details": details,
            }
        ),
        status_code,
    )


@api_bp.route("/oidc/config", methods=["GET"])
@require_permission("identity.read")
def get_oidc_configuration() -> Response:
    """Retrieve current OIDC configuration from SettingsStore."""
    from embervault_app.oidc_service import get_oidc_config

    session_factory = get_db()
    with session_factory() as session:
        enabled, config = get_oidc_config(session)

    return jsonify(
        {
            "status": "ok",
            "oidc_enabled": enabled,
            "oidc_provider_name": config.provider_name,
            "oidc_issuer_url": config.issuer_url,
            "oidc_client_id": config.client_id,
            "oidc_client_secret_set": bool(config.client_secret),
            "oidc_scopes": config.scopes,
            "oidc_username_claim": config.username_claim,
            "oidc_groups_claim": config.groups_claim,
            "oidc_admin_group": config.admin_group,
            "oidc_operator_group": config.operator_group,
            "oidc_viewer_group": config.viewer_group,
            "oidc_validate_cert": config.validate_cert,
            "oidc_ca_cert_pem": config.ca_cert_pem,
            "oidc_enforce_mfa": config.enforce_mfa,
        }
    )


@api_bp.route("/oidc/config", methods=["PUT"])
@require_permission("identity.write")
def update_oidc_configuration() -> Response:
    """Update OIDC configuration parameters in SettingsStore."""
    actor = get_current_user()
    actor_id = actor.id if actor else None
    data = request.get_json(silent=True) or {}

    from embervault_app.oidc_service import save_oidc_config

    session_factory = get_db()
    with session_factory() as session:
        save_oidc_config(
            session=session,
            data=data,
            user_id=actor_id,
            ip=request.remote_addr,
        )
        session.commit()

    return jsonify({"status": "updated", "message": _("api_msg_oidc_saved")})


@api_bp.route("/oidc/test", methods=["POST"])
@require_permission("identity.write")
def test_oidc_endpoint() -> Response:
    """Test connectivity and discovery document retrieval from OIDC provider."""
    overrides = request.get_json(silent=True) or {}

    from embervault_app.oidc_service import test_oidc_from_settings

    session_factory = get_db()
    with session_factory() as session:
        ok, msg, details = test_oidc_from_settings(session, overrides=overrides)

    status_code = 200 if ok else 400
    return make_response(
        jsonify(
            {
                "status": "ok" if ok else "error",
                "message": msg,
                "details": details,
            }
        ),
        status_code,
    )


@api_bp.route("/settings/login-background", methods=["GET"])
def get_login_background() -> Response:
    """Retrieve the custom login background image or return 404 if default gradient is used."""
    store = current_app.config.get("SETTINGS_STORE")
    raw_val = store.get_setting("login_custom_background") if store else ""
    if not raw_val or not str(raw_val).strip():
        return make_response(
            jsonify({"status": "error", "message": _("api_err_no_custom_bg")}),
            404,
        )

    val_str = str(raw_val).strip()
    if val_str.startswith("data:"):
        try:
            # Format: data:<mimetype>;base64,<payload>
            header, payload = val_str.split(",", 1)
            mimetype = header.split(";")[0].replace("data:", "").strip() or "image/jpeg"
            img_bytes = base64.b64decode(payload)
            resp = make_response(img_bytes)
            resp.headers["Content-Type"] = mimetype
            resp.headers["Cache-Control"] = "public, max-age=3600"
            return resp
        except Exception as exc:
            logger.warning("login_bg_decode_failed", error=str(exc))
            return make_response(
                jsonify({"status": "error", "message": _("api_err_invalid_bg_image")}),
                500,
            )

    from flask import redirect

    return cast(Response, redirect(val_str))


@api_bp.route("/settings/login-background", methods=["POST"])
@require_auth
@require_permission("appearance.write")
def upload_login_background() -> Response:
    """Upload or update custom login background image."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}),
            500,
        )

    actor = get_current_user()
    actor_id = actor.id if actor else None

    # Check for file upload first
    uploaded_file = request.files.get("image") or request.files.get("file")
    if uploaded_file and uploaded_file.filename:
        file_bytes = uploaded_file.read()
        if len(file_bytes) > 5 * 1024 * 1024:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_bg_image_max_5mb")}),
                400,
            )
        content_type = uploaded_file.content_type or "image/jpeg"
        if not (
            content_type.startswith("image/")
            or uploaded_file.filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".svg"))
        ):
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": _("api_err_bg_unsupported_format"),
                    }
                ),
                400,
            )
        b64_data = base64.b64encode(file_bytes).decode("ascii")
        data_uri = f"data:{content_type};base64,{b64_data}"
        store.set_setting(
            "login_custom_background", data_uri, user_id=actor_id, ip=request.remote_addr
        )
        return jsonify({"status": "ok", "message": _("api_msg_bg_updated")})

    # Otherwise check JSON payload
    payload = request.get_json(silent=True) or {}
    raw_image = payload.get("image") or payload.get("data")
    if not raw_image or not str(raw_image).strip():
        return make_response(
            jsonify({"status": "error", "message": _("api_err_bg_no_payload")}),
            400,
        )

    raw_str = str(raw_image).strip()
    if len(raw_str) > 7 * 1024 * 1024:  # roughly 5MB in base64
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _("api_err_bg_max_allowed_5mb"),
                }
            ),
            400,
        )

    store.set_setting("login_custom_background", raw_str, user_id=actor_id, ip=request.remote_addr)
    return jsonify({"status": "ok", "message": _("api_msg_bg_updated")})


@api_bp.route("/settings/login-background", methods=["DELETE"])
@require_auth
@require_permission("appearance.write")
def delete_login_background() -> Response:
    """Reset the login background to the default palette gradient."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}),
            500,
        )

    actor = get_current_user()
    actor_id = actor.id if actor else None
    store.delete_setting("login_custom_background", user_id=actor_id, ip=request.remote_addr)
    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_bg_removed"),
        }
    )


# ==============================================================================
# WHITELABEL & BRANDING API
# ==============================================================================


@api_bp.route("/settings/whitelabel", methods=["GET"])
@require_auth
@require_permission("appearance.read")
def get_whitelabel_settings() -> Response:
    """Retrieve current whitelabel settings (application name and logo status)."""
    from embervault_app.whitelabel import get_whitelabel_config

    app_name, custom_app_name, has_custom_logo = get_whitelabel_config()
    return jsonify(
        {
            "status": "ok",
            "app_name": app_name,
            "custom_app_name": custom_app_name,
            "has_custom_logo": has_custom_logo,
            "logo_url": "/app-logo",
        }
    )


@api_bp.route("/settings/whitelabel/logo", methods=["POST"])
@require_auth
@require_permission("appearance.write")
def upload_whitelabel_logo() -> Response:
    """Upload or update custom whitelabel logo (PNG, JPG, WebP, SVG, max 5MB)."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}),
            500,
        )

    actor = get_current_user()
    actor_id = actor.id if actor else None

    # Check for file upload first
    uploaded_file = (
        request.files.get("logo") or request.files.get("file") or request.files.get("image")
    )
    if uploaded_file and uploaded_file.filename:
        file_bytes = uploaded_file.read()
        if len(file_bytes) > 5 * 1024 * 1024:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_logo_max_5mb")}),
                400,
            )
        content_type = uploaded_file.content_type or "image/png"
        lower_name = uploaded_file.filename.lower()
        if not (
            content_type in ("image/png", "image/jpeg", "image/jpg", "image/webp", "image/svg+xml")
            or lower_name.endswith((".png", ".jpg", ".jpeg", ".webp", ".svg"))
        ):
            return make_response(
                jsonify({"status": "error", "message": _("api_err_logo_unsupported_format")}),
                400,
            )
        if lower_name.endswith(".svg") and not content_type.startswith("image/"):
            content_type = "image/svg+xml"
        b64_data = base64.b64encode(file_bytes).decode("ascii")
        data_uri = f"data:{content_type};base64,{b64_data}"
        store.set_setting("custom_logo", data_uri, user_id=actor_id, ip=request.remote_addr)
        return jsonify(
            {
                "status": "ok",
                "message": _("api_msg_logo_updated"),
                "logo_url": "/app-logo",
                "has_custom_logo": True,
            }
        )

    # Otherwise check JSON payload
    payload = request.get_json(silent=True) or {}
    raw_image = payload.get("logo") or payload.get("image") or payload.get("data")
    if not raw_image or not str(raw_image).strip():
        return make_response(
            jsonify({"status": "error", "message": _("api_err_logo_no_payload")}),
            400,
        )

    raw_str = str(raw_image).strip()
    if len(raw_str) > 7 * 1024 * 1024:  # roughly 5MB in base64
        return make_response(
            jsonify({"status": "error", "message": _("api_err_logo_max_5mb")}),
            400,
        )

    store.set_setting("custom_logo", raw_str, user_id=actor_id, ip=request.remote_addr)
    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_logo_updated"),
            "logo_url": "/app-logo",
            "has_custom_logo": True,
        }
    )


@api_bp.route("/settings/whitelabel/logo", methods=["DELETE"])
@require_auth
@require_permission("appearance.write")
def delete_whitelabel_logo() -> Response:
    """Reset the application logo to the default EmberVault logo."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}),
            500,
        )

    actor = get_current_user()
    actor_id = actor.id if actor else None
    store.delete_setting("custom_logo", user_id=actor_id, ip=request.remote_addr)
    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_logo_removed"),
            "logo_url": "/app-logo",
            "has_custom_logo": False,
        }
    )


@api_bp.route("/settings/whitelabel/app-name", methods=["PUT", "POST"])
@require_auth
@require_permission("appearance.write")
def update_whitelabel_app_name() -> Response:
    """Update or reset the custom application name."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}),
            500,
        )

    actor = get_current_user()
    actor_id = actor.id if actor else None
    data = request.get_json(silent=True) or {}

    raw_name = data.get("custom_app_name")
    if raw_name is None:
        raw_name = data.get("app_name")

    should_reset = data.get("reset", False) or raw_name is None or not str(raw_name).strip()

    if should_reset:
        store.delete_setting("custom_app_name", user_id=actor_id, ip=request.remote_addr)
        return jsonify(
            {
                "status": "ok",
                "message": _("api_msg_app_name_restored"),
                "app_name": "EmberVault",
                "custom_app_name": "",
            }
        )

    custom_name = str(raw_name).strip()
    if len(custom_name) > 64:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_app_name_too_long")}),
            400,
        )

    store.set_setting("custom_app_name", custom_name, user_id=actor_id, ip=request.remote_addr)
    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_app_name_updated"),
            "app_name": custom_name,
            "custom_app_name": custom_name,
        }
    )


# ==============================================================================
# PUBLIC PORTAL WHITELABEL API
# ==============================================================================


@api_bp.route("/settings/whitelabel/portal", methods=["GET"])
@require_auth
@require_permission("appearance.read")
def get_portal_whitelabel_settings() -> Response:
    """Retrieve current portal whitelabel settings (application name and logo status)."""
    from embervault_app.whitelabel import get_portal_whitelabel_config

    app_name, custom_app_name, has_custom_logo = get_portal_whitelabel_config()
    return jsonify(
        {
            "status": "ok",
            "app_name": app_name,
            "custom_app_name": custom_app_name,
            "has_custom_logo": has_custom_logo,
            "logo_url": "/portal-logo",
        }
    )


@api_bp.route("/settings/whitelabel/portal/app-name", methods=["PUT", "POST"])
@require_auth
@require_permission("appearance.write")
def update_portal_whitelabel_app_name() -> Response:
    """Update or reset the portal custom application name."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}),
            500,
        )

    actor = get_current_user()
    actor_id = actor.id if actor else None
    data = request.get_json(silent=True) or {}

    raw_name = data.get("custom_app_name")
    if raw_name is None:
        raw_name = data.get("app_name")

    should_reset = data.get("reset", False) or raw_name is None or not str(raw_name).strip()

    if should_reset:
        store.delete_setting("portal_custom_app_name", user_id=actor_id, ip=request.remote_addr)
        return jsonify(
            {
                "status": "ok",
                "message": _("api_msg_portal_app_name_restored"),
                "app_name": "EmberVault public portal",
                "custom_app_name": "",
            }
        )

    custom_name = str(raw_name).strip()
    if len(custom_name) > 64:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_app_name_too_long")}),
            400,
        )

    store.set_setting(
        "portal_custom_app_name", custom_name, user_id=actor_id, ip=request.remote_addr
    )
    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_portal_app_name_saved"),
            "app_name": custom_name,
            "custom_app_name": custom_name,
        }
    )


@api_bp.route("/settings/whitelabel/portal/logo", methods=["POST"])
@require_auth
@require_permission("appearance.write")
def upload_portal_whitelabel_logo() -> Response:
    """Upload or update custom portal logo (PNG, JPG, WebP, SVG, max 5MB)."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}),
            500,
        )

    actor = get_current_user()
    actor_id = actor.id if actor else None

    # Check for file upload first
    uploaded_file = (
        request.files.get("logo") or request.files.get("file") or request.files.get("image")
    )
    if uploaded_file and uploaded_file.filename:
        file_bytes = uploaded_file.read()
        if len(file_bytes) > 5 * 1024 * 1024:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_logo_max_5mb")}),
                400,
            )
        content_type = uploaded_file.content_type or "image/png"
        lower_name = uploaded_file.filename.lower()
        if not (
            content_type in ("image/png", "image/jpeg", "image/jpg", "image/webp", "image/svg+xml")
            or lower_name.endswith((".png", ".jpg", ".jpeg", ".webp", ".svg"))
        ):
            return make_response(
                jsonify({"status": "error", "message": _("api_err_logo_unsupported_format")}),
                400,
            )
        if lower_name.endswith(".svg") and not content_type.startswith("image/"):
            content_type = "image/svg+xml"
        b64_data = base64.b64encode(file_bytes).decode("ascii")
        data_uri = f"data:{content_type};base64,{b64_data}"
        store.set_setting("portal_custom_logo", data_uri, user_id=actor_id, ip=request.remote_addr)
        return jsonify(
            {
                "status": "ok",
                "message": _("api_msg_portal_logo_updated"),
                "logo_url": "/portal-logo",
                "has_custom_logo": True,
            }
        )

    payload = request.get_json(silent=True) or {}
    raw_image = payload.get("logo") or payload.get("image") or payload.get("data")
    if not raw_image or not str(raw_image).strip():
        return make_response(
            jsonify({"status": "error", "message": _("api_err_logo_no_payload")}),
            400,
        )

    raw_str = str(raw_image).strip()
    if len(raw_str) > 7 * 1024 * 1024:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_logo_max_5mb")}),
            400,
        )

    store.set_setting("portal_custom_logo", raw_str, user_id=actor_id, ip=request.remote_addr)
    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_portal_logo_updated"),
            "logo_url": "/portal-logo",
            "has_custom_logo": True,
        }
    )


@api_bp.route("/settings/whitelabel/portal/logo", methods=["DELETE"])
@require_auth
@require_permission("appearance.write")
def delete_portal_whitelabel_logo() -> Response:
    """Reset the portal logo to the default EmberVault logo."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}),
            500,
        )

    actor = get_current_user()
    actor_id = actor.id if actor else None
    store.delete_setting("portal_custom_logo", user_id=actor_id, ip=request.remote_addr)
    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_portal_logo_removed"),
            "logo_url": "/portal-logo",
            "has_custom_logo": False,
        }
    )


@api_bp.route("/settings/portal/status", methods=["GET"])
@require_auth
@require_permission("settings.read")
def get_portal_status() -> Response:
    """Retrieve global public portal status."""
    from embervault_app.whitelabel import is_public_portal_enabled

    return jsonify({"status": "ok", "enabled": is_public_portal_enabled()})


@api_bp.route("/settings/portal/status", methods=["PUT"])
@require_auth
@require_permission("settings.write")
def update_portal_status() -> Response:
    """Update global public portal status (enabled or disabled)."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}),
            500,
        )

    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled", True))

    actor = get_current_user()
    actor_id = getattr(actor, "id", None)
    store.set_setting("public_portal_enabled", enabled, user_id=actor_id, ip=request.remote_addr)

    msg = _("api_msg_portal_status_updated")
    return jsonify(
        {
            "status": "ok",
            "message": msg,
            "enabled": enabled,
        }
    )


@api_bp.route("/settings/portal/language", methods=["GET"])
@require_auth
@require_permission("settings.read")
def get_portal_language_setting() -> Response:
    """Retrieve configured portal language."""
    from embervault_app.whitelabel import get_portal_language

    return jsonify({"status": "ok", "language": get_portal_language()})


@api_bp.route("/settings/portal/language", methods=["PUT"])
@require_auth
@require_permission("settings.write")
def update_portal_language_setting() -> Response:
    """Update configured portal language."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}),
            500,
        )

    data = request.get_json(silent=True) or {}
    lang = str(data.get("language", "")).strip().lower()

    from embervault_app.i18n import SUPPORTED_LOCALES

    if lang not in SUPPORTED_LOCALES:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_portal_invalid_language")}),
            400,
        )

    actor = get_current_user()
    actor_id = getattr(actor, "id", None)
    store.set_setting("portal_language", lang, user_id=actor_id, ip=request.remote_addr)

    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_portal_language_saved"),
            "language": lang,
        }
    )


# ==============================================================================
# TRUSTED PROXIES SETTINGS API
# ==============================================================================


@api_bp.route("/settings/trusted-proxies", methods=["GET"])
@require_auth
@require_permission("network.manage")
def get_trusted_proxies_setting() -> Response:
    """Retrieve current trusted proxies configuration."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}), 500
        )

    val = str(store.get_setting("trusted_proxies") or "").strip()
    return jsonify({"status": "ok", "trusted_proxies": val})


@api_bp.route("/settings/trusted-proxies", methods=["PUT"])
@require_auth
@require_permission("network.manage")
def update_trusted_proxies_setting() -> Response:
    """Update trusted proxies configuration."""
    import ipaddress

    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}), 500
        )

    data = request.get_json(silent=True) or {}
    raw_val = str(data.get("trusted_proxies", "")).strip()

    if raw_val:
        items = [p.strip() for p in raw_val.split(",") if p.strip()]
        for item in items:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                return make_response(
                    jsonify(
                        {
                            "status": "error",
                            "message": _("api_err_invalid_trusted_proxy_ip", item=item),
                        }
                    ),
                    400,
                )
        cleaned_str = ",".join(items)
    else:
        cleaned_str = ""

    actor = get_current_user()
    actor_id = actor.id if actor else None
    store.set_setting("trusted_proxies", cleaned_str, user_id=actor_id, ip=request.remote_addr)

    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_trusted_proxies_updated"),
            "trusted_proxies": cleaned_str,
        }
    )


# ==============================================================================
# BASH HOOKS SETTINGS API (Milestone M8)
# ==============================================================================


@api_bp.route("/settings/hooks", methods=["GET"])
@require_auth
@require_permission("hooks.manage")
def get_hooks_settings() -> Response:
    """Retrieve current bash hooks execution configuration."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}), 500
        )

    hooks_enabled = bool(store.get_setting("hooks_enabled"))
    hooks_timeout_s = int(store.get_setting("hooks_timeout_s") or 60)

    return jsonify(
        {
            "status": "ok",
            "hooks_enabled": hooks_enabled,
            "hooks_timeout_s": hooks_timeout_s,
        }
    )


@api_bp.route("/settings/hooks", methods=["PUT"])
@require_auth
@require_permission("hooks.manage")
def update_hooks_settings() -> Response:
    """Update bash hooks configuration (admin only)."""
    current_user = get_current_user()
    is_admin = is_admin_user()
    if not is_admin:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _("api_err_hooks_admin_only"),
                }
            ),
            403,
        )

    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}), 500
        )

    data = request.get_json(silent=True) or {}
    hooks_enabled = bool(data.get("hooks_enabled", False))
    try:
        hooks_timeout_s = int(data.get("hooks_timeout_s", 60))
        if hooks_timeout_s < 1:
            raise ValueError()
    except (ValueError, TypeError):
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _("api_err_hooks_timeout_positive"),
                }
            ),
            400,
        )

    actor_id = current_user.id if current_user else None
    store.set_setting("hooks_enabled", hooks_enabled, user_id=actor_id, ip=request.remote_addr)
    store.set_setting("hooks_timeout_s", hooks_timeout_s, user_id=actor_id, ip=request.remote_addr)
    if "hook_runner_url" in data:
        store.set_setting(
            "hook_runner_url",
            str(data["hook_runner_url"]).strip(),
            user_id=actor_id,
            ip=request.remote_addr,
        )

    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_hooks_saved"),
            "hooks_enabled": hooks_enabled,
            "hooks_timeout_s": hooks_timeout_s,
            "hook_runner_url": str(store.get_setting("hook_runner_url") or "").strip(),
        }
    )


# ==============================================================================
# AI INTEGRATION SETTINGS API
# ==============================================================================


@api_bp.route("/settings/ai", methods=["GET"])
@require_auth
@require_permission("ai.read")
def get_ai_settings() -> Response:
    """Retrieve AI integration settings."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}), 500
        )

    ai_language = str(store.get_setting("ai_language") or "en").strip().lower()
    saved_sys = str(store.get_setting("ai_system_prompt") or "").strip()
    saved_rep = str(store.get_setting("ai_reporting_system_prompt") or "").strip()
    def_sys = get_default_error_system_prompt(ai_language)
    def_rep = get_default_reporting_system_prompt(ai_language)

    return jsonify(
        {
            "status": "ok",
            "ai_enabled": bool(store.get_setting("ai_enabled")),
            "ai_provider_type": str(
                store.get_setting("ai_provider_type") or "openai_compatible"
            ).strip(),
            "ai_endpoint_url": str(
                store.get_setting("ai_endpoint_url") or "http://localhost:11434"
            ).strip(),
            "ai_model": str(store.get_setting("ai_model") or "llama3.2").strip(),
            "ai_timeout_seconds": int(store.get_setting("ai_timeout_seconds") or 15),
            "ai_has_api_key": bool(store.get_setting("ai_api_key")),
            "ai_language": ai_language,
            "ai_system_prompt": saved_sys or def_sys,
            "ai_custom_system_prompt": saved_sys,
            "ai_default_system_prompt": def_sys,
            "ai_reporting_system_prompt": saved_rep or def_rep,
            "ai_custom_reporting_system_prompt": saved_rep,
            "ai_default_reporting_system_prompt": def_rep,
            "ai_error_handling_enabled": bool(store.get_setting("ai_error_handling_enabled")),
            "ai_error_handling_uncensored": bool(store.get_setting("ai_error_handling_uncensored")),
            "ai_reporting_analysis_enabled": bool(
                store.get_setting("ai_reporting_analysis_enabled")
            ),
        }
    )


@api_bp.route("/settings/ai", methods=["PUT"])
@require_auth
@require_permission("ai.write")
def update_ai_settings() -> Response:
    """Update AI integration settings and decision-making options."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}), 500
        )

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return make_response(
            jsonify({"status": "error", "message": _("api_err_invalid_json_payload")}), 400
        )

    current_user = get_current_user()
    actor_id = current_user.id if current_user else None
    ip_addr = request.remote_addr

    try:
        if "ai_enabled" in data:
            store.set_setting("ai_enabled", bool(data["ai_enabled"]), user_id=actor_id, ip=ip_addr)
        if "ai_provider_type" in data:
            provider = str(data["ai_provider_type"]).strip().lower()
            store.set_setting("ai_provider_type", provider, user_id=actor_id, ip=ip_addr)
        if "ai_endpoint_url" in data:
            endpoint = str(data["ai_endpoint_url"]).strip()
            store.set_setting("ai_endpoint_url", endpoint, user_id=actor_id, ip=ip_addr)
        if "ai_model" in data:
            model = str(data["ai_model"]).strip()
            store.set_setting("ai_model", model, user_id=actor_id, ip=ip_addr)
        if "ai_timeout_seconds" in data:
            timeout_s = int(data["ai_timeout_seconds"])
            store.set_setting("ai_timeout_seconds", timeout_s, user_id=actor_id, ip=ip_addr)
        if "ai_api_key" in data:
            api_key = str(data["ai_api_key"]).strip()
            if api_key != "":
                store.set_setting("ai_api_key", api_key, user_id=actor_id, ip=ip_addr)
            elif data.get("clear_api_key"):
                store.set_setting("ai_api_key", "", user_id=actor_id, ip=ip_addr)

        if "ai_error_handling_enabled" in data:
            store.set_setting(
                "ai_error_handling_enabled",
                bool(data["ai_error_handling_enabled"]),
                user_id=actor_id,
                ip=ip_addr,
            )
        if "ai_error_handling_uncensored" in data:
            store.set_setting(
                "ai_error_handling_uncensored",
                bool(data["ai_error_handling_uncensored"]),
                user_id=actor_id,
                ip=ip_addr,
            )
        if "ai_reporting_analysis_enabled" in data:
            store.set_setting(
                "ai_reporting_analysis_enabled",
                bool(data["ai_reporting_analysis_enabled"]),
                user_id=actor_id,
                ip=ip_addr,
            )
        if "ai_language" in data:
            ai_lang = str(data["ai_language"]).strip().lower() or "en"
            store.set_setting("ai_language", ai_lang, user_id=actor_id, ip=ip_addr)
        if "ai_system_prompt" in data:
            sys_prompt = str(data["ai_system_prompt"]).strip()
            store.set_setting("ai_system_prompt", sys_prompt, user_id=actor_id, ip=ip_addr)
        if "ai_reporting_system_prompt" in data:
            rep_sys_prompt = str(data["ai_reporting_system_prompt"]).strip()
            store.set_setting(
                "ai_reporting_system_prompt", rep_sys_prompt, user_id=actor_id, ip=ip_addr
            )

    except Exception as exc:
        logger.error("update_ai_settings_failed", error=str(exc))
        return make_response(
            jsonify({"status": "error", "message": _("api_err_ai_save_failed", error=str(exc))}),
            400,
        )

    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_ai_saved"),
        }
    )


@api_bp.route("/settings/ai/test", methods=["POST"])
@require_auth
@require_permission("ai.write")
def test_ai_connection() -> Response:
    """Test connection to the AI endpoint and model."""
    store = current_app.config.get("SETTINGS_STORE")
    data = request.get_json(silent=True) or {}

    endpoint_url = str(
        data.get("ai_endpoint_url")
        or (store.get_setting("ai_endpoint_url") if store else None)
        or "http://localhost:11434"
    ).strip()

    model = str(
        data.get("ai_model") or (store.get_setting("ai_model") if store else None) or "llama3.2"
    ).strip()

    provider_type = str(
        data.get("ai_provider_type")
        or (store.get_setting("ai_provider_type") if store else None)
        or "openai_compatible"
    ).strip()

    # If api_key not provided in request body, fall back to stored secret
    api_key = data.get("ai_api_key")
    if api_key is None or api_key == "":
        api_key = store.get_setting("ai_api_key") if store else None

    timeout_s = int(
        data.get("ai_timeout_seconds")
        or (store.get_setting("ai_timeout_seconds") if store else None)
        or 15
    )

    from embervault_common.ai.client import AIClient

    client = AIClient(
        endpoint_url=endpoint_url,
        model=model,
        provider_type=provider_type,
        api_key=api_key,
        timeout_seconds=timeout_s,
    )

    success, message = client.test_connection()
    status_str = "ok" if success else "error"
    code = 200 if success else 400

    return make_response(
        jsonify(
            {
                "status": status_str,
                "success": success,
                "message": message,
            }
        ),
        code,
    )


# ==============================================================================
# GENERAL SETTINGS API
# ==============================================================================


@api_bp.route("/settings/general", methods=["GET"])
@require_auth
@require_permission("settings.read")
def get_general_settings() -> Response:
    """Retrieve all GUI-overridable settings and their currently resolved values."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}), 500
        )

    from embervault_common.config.registry import CONFIG_REGISTRY

    resolved = store.get_all_resolved_settings()
    gui_settings = {
        k.name: resolved.get(k.name, k.default) for k in CONFIG_REGISTRY if k.overridable_from_gui
    }
    return jsonify({"status": "ok", "settings": gui_settings})


@api_bp.route("/settings/general", methods=["PUT"])
@require_auth
@require_permission("settings.write")
def update_general_settings() -> Response:
    """Update one or more GUI-overridable configuration settings.

    Settings that are not overridable from GUI (such as database credentials,
    master encryption keys, or listen ports) are strictly blocked from being modified.
    """
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}), 500
        )

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return make_response(
            jsonify({"status": "error", "message": _("api_err_invalid_or_missing_json")}), 400
        )

    from embervault_common.config.registry import CONFIG_REGISTRY

    registry_by_name = {k.name: k for k in CONFIG_REGISTRY}
    current_user = get_current_user()
    actor_id = current_user.id if current_user else None
    ip_addr = request.remote_addr

    updated: dict[str, Any] = {}
    try:
        for key, raw_val in data.items():
            if key not in registry_by_name:
                return make_response(
                    jsonify({"status": "error", "message": _("api_err_unknown_setting", key=key)}),
                    400,
                )
            key_def = registry_by_name[key]
            if not key_def.overridable_from_gui:
                return make_response(
                    jsonify(
                        {
                            "status": "error",
                            "message": _("api_err_setting_not_overridable", key=key),
                        }
                    ),
                    403,
                )

            # Convert type
            if key_def.type_name == "bool":
                val = bool(raw_val)
            elif key_def.type_name == "int":
                if raw_val is None or str(raw_val).strip() == "":
                    return make_response(
                        jsonify(
                            {
                                "status": "error",
                                "message": _("api_err_setting_requires_int", key=key),
                            }
                        ),
                        400,
                    )
                val = int(raw_val)
            else:
                val = str(raw_val).strip() if raw_val is not None else ""

            store.set_setting(key, val, user_id=actor_id, ip=ip_addr)
            updated[key] = val

    except ValueError as val_err:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_invalid_param", error=str(val_err))}),
            400,
        )
    except Exception as exc:
        logger.error("general_settings_update_failed", error=str(exc))
        return make_response(
            jsonify({"status": "error", "message": _("api_err_update_failed", error=str(exc))}),
            400,
        )

    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_settings_updated"),
            "settings": updated,
        }
    )


@api_bp.route("/settings/rclone", methods=["GET"])
@require_auth
@require_permission("settings.read")
def get_rclone_settings() -> Response:
    """Retrieve global RClone and task execution defaults from SettingsStore."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}), 500
        )

    from embervault_common.rclone.filters import parse_filter_rules

    task_retries = int(store.get_setting("task_retries") or 2)
    checkers = int(store.get_setting("rclone_checkers") or 8)
    transfers = int(store.get_setting("rclone_transfers") or 4)
    check_first = bool(store.get_setting("rclone_check_first"))
    recurse_val = store.get_setting("rclone_recurse")
    recurse = bool(recurse_val) if recurse_val is not None else True
    order_by = str(store.get_setting("rclone_order_by") or "")
    first_level_filters = parse_filter_rules(store.get_setting("rclone_first_level_filters") or "")
    second_level_filters = parse_filter_rules(
        store.get_setting("rclone_second_level_filters") or ""
    )

    return jsonify(
        {
            "status": "ok",
            "task_retries": task_retries,
            "rclone_checkers": checkers,
            "rclone_transfers": transfers,
            "rclone_check_first": check_first,
            "rclone_recurse": recurse,
            "rclone_order_by": order_by,
            "rclone_first_level_filters": first_level_filters,
            "rclone_second_level_filters": second_level_filters,
        }
    )


@api_bp.route("/settings/rclone", methods=["PUT"])
@require_auth
@require_permission("settings.write")
def update_rclone_settings() -> Response:
    """Update global RClone and task execution defaults."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}), 500
        )

    from embervault_common.rclone.filters import parse_filter_rules

    data = request.get_json(silent=True) or {}
    current_user = get_current_user()
    actor_id = current_user.id if current_user else None
    ip_addr = request.remote_addr

    try:
        if "task_retries" in data:
            retries = int(data["task_retries"])
            if retries < 0 or retries > 10:
                raise ValueError(_("api_err_rclone_retries_range"))
            store.set_setting("task_retries", retries, user_id=actor_id, ip=ip_addr)

        if "rclone_checkers" in data:
            checkers = int(data["rclone_checkers"])
            if checkers < 1 or checkers > 128:
                raise ValueError(_("api_err_rclone_checkers_range"))
            store.set_setting("rclone_checkers", checkers, user_id=actor_id, ip=ip_addr)

        if "rclone_transfers" in data:
            transfers = int(data["rclone_transfers"])
            if transfers < 1 or transfers > 64:
                raise ValueError(_("api_err_rclone_transfers_range"))
            store.set_setting("rclone_transfers", transfers, user_id=actor_id, ip=ip_addr)

        if "rclone_check_first" in data:
            check_first = bool(data["rclone_check_first"])
            store.set_setting("rclone_check_first", check_first, user_id=actor_id, ip=ip_addr)

        if "rclone_recurse" in data:
            recurse = bool(data["rclone_recurse"])
            store.set_setting("rclone_recurse", recurse, user_id=actor_id, ip=ip_addr)

        if "rclone_order_by" in data:
            order_by = str(data["rclone_order_by"]).strip()
            store.set_setting("rclone_order_by", order_by, user_id=actor_id, ip=ip_addr)

        if "rclone_first_level_filters" in data:
            f1 = parse_filter_rules(data["rclone_first_level_filters"])
            store.set_setting(
                "rclone_first_level_filters", "\n".join(f1), user_id=actor_id, ip=ip_addr
            )

        if "rclone_second_level_filters" in data:
            f2 = parse_filter_rules(data["rclone_second_level_filters"])
            store.set_setting(
                "rclone_second_level_filters", "\n".join(f2), user_id=actor_id, ip=ip_addr
            )

    except ValueError as val_err:
        return make_response(jsonify({"status": "error", "message": str(val_err)}), 400)

    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_rclone_saved"),
        }
    )


# ==============================================================================
# NOTIFICATION CHANNELS & SETTINGS API (Milestone M6)
# ==============================================================================


@api_bp.route("/notification-channels", methods=["GET"])
@api_bp.route("/settings/notifications/channels", methods=["GET"])
@require_auth
@require_permission("notification.read")
def list_notification_channels() -> Response:
    """List all configured notification channels with sensitive tokens masked."""
    session_factory = get_db()
    with session_factory() as session:
        channels = NotificationRepository.list_channels(session)
        data = [NotificationRepository.to_dict(c, mask_secrets=True) for c in channels]
    return jsonify({"status": "ok", "channels": data})


@api_bp.route("/notification-channels", methods=["POST"])
@api_bp.route("/settings/notifications/channels", methods=["POST"])
@require_auth
@require_permission("notification.write")
def create_notification_channel() -> Response:
    """Create a new notification channel (Email, Telegram, or Custom Apprise URL)."""
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    channel_type = str(payload.get("channel_type", "custom")).strip().lower()
    telegram_format = str(payload.get("telegram_format", "html")).strip().lower()
    rate_limit_interval_s = int(payload.get("rate_limit_interval_s") or 0)
    enabled = bool(payload.get("enabled", True))
    config_metadata: dict[str, Any] = payload.get("config_metadata") or {}

    raw_url = str(payload.get("url", "")).strip()

    # Friendly builders for Telegram and Email if explicit url not provided
    if channel_type == "telegram" and not raw_url:
        token = str(payload.get("telegram_bot_token", "")).strip()
        chat_id = str(payload.get("telegram_chat_id", "")).strip()
        if not token or not chat_id:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_telegram_required")}),
                400,
            )
        raw_url = build_telegram_url(token, chat_id, format_mode=telegram_format)
        config_metadata.setdefault("chat_id", chat_id)
        config_metadata.setdefault("format", telegram_format)

    elif channel_type == "email" and not raw_url:
        host = str(payload.get("smtp_host", "")).strip()
        port = int(payload.get("smtp_port") or 587)
        user = str(payload.get("smtp_user", "")).strip() or None
        password = str(payload.get("smtp_password", "")).strip() or None
        from_addr = str(payload.get("smtp_from", "")).strip() or None
        to_addrs = str(payload.get("smtp_to", "")).strip() or None
        secure = bool(payload.get("smtp_secure", False))
        if not host:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_smtp_host_required")}),
                400,
            )
        raw_url = build_email_url(
            host=host,
            port=port,
            user=user,
            password=password,
            from_addr=from_addr,
            to_addrs=to_addrs,
            secure=secure,
        )
        config_metadata.setdefault("host", host)
        config_metadata.setdefault("port", port)
        if user:
            config_metadata.setdefault("user", user)
        if from_addr:
            config_metadata.setdefault("from", from_addr)
        if to_addrs:
            config_metadata.setdefault("to", to_addrs)
        config_metadata.setdefault("secure", secure)

    if not raw_url:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _("api_err_channel_url_missing"),
                }
            ),
            400,
        )

    actor = get_current_user()
    actor_id = actor.id if actor else None
    session_factory = get_db()
    try:
        with session_factory() as session:
            channel = NotificationRepository.create_channel(
                session=session,
                name=name,
                url=raw_url,
                channel_type=channel_type,
                telegram_format=telegram_format,
                rate_limit_interval_s=rate_limit_interval_s,
                enabled=enabled,
                config_metadata=config_metadata,
            )
            audit = AuditLog(
                action="notification_channel.create",
                actor_user_id=actor_id,
                entity_type="notification_channel",
                entity_id=str(channel.id),
                details={"name": channel.name, "channel_type": channel.channel_type},
                ip=request.remote_addr,
            )
            session.add(audit)
            session.commit()
            return make_response(
                jsonify(
                    {
                        "status": "created",
                        "channel": NotificationRepository.to_dict(channel, mask_secrets=True),
                        "message": _("api_msg_channel_created", name=channel.name),
                    }
                ),
                201,
            )
    except ValueError as exc:
        return make_response(jsonify({"status": "error", "message": str(exc)}), 400)
    except Exception as exc:
        logger.error("notification_channel_create_failed", error=str(exc))
        return make_response(jsonify({"status": "error", "message": str(exc)}), 500)


@api_bp.route("/notification-channels/<uuid:channel_id>", methods=["GET"])
@api_bp.route("/settings/notifications/channels/<uuid:channel_id>", methods=["GET"])
@require_auth
@require_permission("notification.read")
def get_notification_channel(channel_id: uuid.UUID) -> Response:
    """Retrieve details of a single notification channel."""
    session_factory = get_db()
    with session_factory() as session:
        channel = NotificationRepository.get_channel_by_id(session, channel_id)
        if channel is None:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_channel_not_found")}), 404
            )
        return jsonify(
            {
                "status": "ok",
                "channel": NotificationRepository.to_dict(channel, mask_secrets=True),
            }
        )


@api_bp.route("/notification-channels/<uuid:channel_id>", methods=["PUT"])
@api_bp.route("/settings/notifications/channels/<uuid:channel_id>", methods=["PUT"])
@require_auth
@require_permission("notification.write")
def update_notification_channel(channel_id: uuid.UUID) -> Response:
    """Update an existing notification channel."""
    payload = request.get_json(silent=True) or {}
    session_factory = get_db()
    actor = get_current_user()
    actor_id = actor.id if actor else None

    with session_factory() as session:
        channel = NotificationRepository.get_channel_by_id(session, channel_id)
        if channel is None:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_channel_not_found")}), 404
            )

        name = payload.get("name")
        channel_type = payload.get("channel_type")
        telegram_format = payload.get("telegram_format")
        rate_limit_interval_s = payload.get("rate_limit_interval_s")
        enabled = payload.get("enabled")
        config_metadata = payload.get("config_metadata")
        raw_url = payload.get("url")

        # Handle updating Telegram or Email helpers without re-submitting secret password/token
        current_url = NotificationRepository.get_decrypted_url(channel)
        if channel_type == "telegram" and not raw_url:
            token = str(payload.get("telegram_bot_token", "")).strip()
            chat_id = str(payload.get("telegram_chat_id", "")).strip()
            # If token not re-entered or masked, preserve existing token
            if not token or "••" in token:
                # Extract existing bot token from current_url (tgram://TOKEN/CHAT...)
                match = re.search(r"tgram://([^/]+)/", current_url)
                token = match.group(1) if match else token
            if token and chat_id:
                raw_url = build_telegram_url(
                    token, chat_id, format_mode=telegram_format or channel.telegram_format
                )
                if config_metadata is None:
                    config_metadata = dict(channel.config_metadata or {})
                config_metadata["chat_id"] = chat_id
                config_metadata["format"] = telegram_format or channel.telegram_format

        elif channel_type == "email" and not raw_url:
            host = str(payload.get("smtp_host", "")).strip()
            port = int(payload.get("smtp_port") or 587)
            user = str(payload.get("smtp_user", "")).strip() or None
            password = str(payload.get("smtp_password", "")).strip() or None
            from_addr = str(payload.get("smtp_from", "")).strip() or None
            to_addrs = str(payload.get("smtp_to", "")).strip() or None
            secure = bool(payload.get("smtp_secure", False))

            if not password or "••" in password:
                # Extract password from current mailto URL if present
                parsed = urllib.parse.urlparse(current_url)
                if parsed.password:
                    password = parsed.password

            if host:
                raw_url = build_email_url(
                    host=host,
                    port=port,
                    user=user,
                    password=password,
                    from_addr=from_addr,
                    to_addrs=to_addrs,
                    secure=secure,
                )
                if config_metadata is None:
                    config_metadata = dict(channel.config_metadata or {})
                config_metadata["host"] = host
                config_metadata["port"] = port
                if user:
                    config_metadata["user"] = user
                if from_addr:
                    config_metadata["from"] = from_addr
                if to_addrs:
                    config_metadata["to"] = to_addrs
                config_metadata["secure"] = secure

        # If raw_url is masked, do not overwrite the encrypted secret!
        if raw_url and "••" in raw_url:
            raw_url = None

        try:
            updated = NotificationRepository.update_channel(
                session=session,
                channel_id=channel_id,
                name=name,
                url=raw_url,
                channel_type=channel_type,
                telegram_format=telegram_format,
                rate_limit_interval_s=rate_limit_interval_s,
                enabled=enabled,
                config_metadata=config_metadata,
            )
            audit = AuditLog(
                action="notification_channel.update",
                actor_user_id=actor_id,
                entity_type="notification_channel",
                entity_id=str(channel_id),
                details={"name": updated.name},
                ip=request.remote_addr,
            )
            session.add(audit)
            session.commit()
            return jsonify(
                {
                    "status": "updated",
                    "channel": NotificationRepository.to_dict(updated, mask_secrets=True),
                    "message": _("api_msg_channel_updated", name=updated.name),
                }
            )
        except ValueError as exc:
            return make_response(jsonify({"status": "error", "message": str(exc)}), 400)


@api_bp.route("/notification-channels/<uuid:channel_id>", methods=["DELETE"])
@api_bp.route("/settings/notifications/channels/<uuid:channel_id>", methods=["DELETE"])
@require_auth
@require_permission("notification.write")
def delete_notification_channel(channel_id: uuid.UUID) -> Response:
    """Delete a notification channel."""
    actor = get_current_user()
    actor_id = actor.id if actor else None
    session_factory = get_db()
    with session_factory() as session:
        channel = NotificationRepository.get_channel_by_id(session, channel_id)
        if channel is None:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_channel_not_found")}), 404
            )
        ch_name = channel.name
        NotificationRepository.delete_channel(session, channel_id)
        audit = AuditLog(
            action="notification_channel.delete",
            actor_user_id=actor_id,
            entity_type="notification_channel",
            entity_id=str(channel_id),
            details={"name": ch_name},
            ip=request.remote_addr,
        )
        session.add(audit)
        session.commit()
    return jsonify({"status": "ok", "message": _("api_msg_channel_deleted", name=ch_name)})


@api_bp.route("/notification-channels/test", methods=["POST"])
@api_bp.route("/settings/notifications/channels/test", methods=["POST"])
@require_auth
@require_permission("notification.write")
def test_unsaved_notification_channel() -> Response:
    """Test arbitrary or unsaved notification parameters before saving."""
    payload = request.get_json(silent=True) or {}
    channel_type = str(payload.get("channel_type", "custom")).strip().lower()
    telegram_format = str(payload.get("telegram_format", "html")).strip().lower()
    channel_name = str(payload.get("name", _("api_default_test_channel_name"))).strip() or _(
        "api_default_test_channel_name"
    )
    raw_url = str(payload.get("url", "")).strip()

    if channel_type == "telegram" and not raw_url:
        token = str(payload.get("telegram_bot_token", "")).strip()
        chat_id = str(payload.get("telegram_chat_id", "")).strip()
        if not token or not chat_id:
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": _("api_err_telegram_test_required"),
                    }
                ),
                400,
            )
        raw_url = build_telegram_url(token, chat_id, format_mode=telegram_format)

    elif channel_type == "email" and not raw_url:
        host = str(payload.get("smtp_host", "")).strip()
        port = int(payload.get("smtp_port") or 587)
        user = str(payload.get("smtp_user", "")).strip() or None
        password = str(payload.get("smtp_password", "")).strip() or None
        from_addr = str(payload.get("smtp_from", "")).strip() or None
        to_addrs = str(payload.get("smtp_to", "")).strip() or None
        secure = bool(payload.get("smtp_secure", False))
        if not host:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_smtp_test_required")}),
                400,
            )
        raw_url = build_email_url(
            host=host,
            port=port,
            user=user,
            password=password,
            from_addr=from_addr,
            to_addrs=to_addrs,
            secure=secure,
        )

    if not raw_url:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _("api_err_test_url_missing"),
                }
            ),
            400,
        )

    valid, err = validate_apprise_url(raw_url)
    if not valid:
        return make_response(
            jsonify(
                {"status": "error", "message": _("api_err_invalid_apprise_url", error=str(err))}
            ),
            400,
        )

    title, body, notify_fmt = NotificationFormatter.format(
        event_type=NotificationEventType.TEST,
        context={"channel_name": channel_name},
        telegram_format=telegram_format,
    )
    notifier = AppriseNotifier()
    success = notifier.send(raw_url, title, body, notify_fmt)
    if success:
        return jsonify(
            {
                "status": "ok",
                "message": _("api_msg_test_notification_sent"),
            }
        )
    else:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _("api_err_test_notification_failed"),
                }
            ),
            400,
        )


@api_bp.route("/notification-channels/<uuid:channel_id>/test", methods=["POST"])
@api_bp.route("/settings/notifications/channels/<uuid:channel_id>/test", methods=["POST"])
@require_auth
@require_permission("notification.write")
def test_saved_notification_channel(channel_id: uuid.UUID) -> Response:
    """Send a live test notification using an existing saved channel."""
    session_factory = get_db()
    with session_factory() as session:
        channel = NotificationRepository.get_channel_by_id(session, channel_id)
        if channel is None:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_channel_not_found")}), 404
            )
        raw_url = NotificationRepository.get_decrypted_url(channel)
        ch_name = channel.name
        tg_fmt = channel.telegram_format

    title, body, notify_fmt = NotificationFormatter.format(
        event_type=NotificationEventType.TEST,
        context={"channel_name": ch_name},
        telegram_format=tg_fmt,
    )
    notifier = AppriseNotifier()
    success = notifier.send(raw_url, title, body, notify_fmt)
    if success:
        return jsonify(
            {
                "status": "ok",
                "message": _("api_msg_saved_channel_test_sent", name=ch_name),
            }
        )
    else:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _("api_err_saved_channel_test_failed", name=ch_name),
                }
            ),
            400,
        )


@api_bp.route("/notifications/settings", methods=["GET"])
@api_bp.route("/settings/notifications/general", methods=["GET"])
@require_auth
@require_permission("notification.read")
def get_notification_settings() -> Response:
    """Retrieve global notification policy settings."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}), 500
        )

    return jsonify(
        {
            "status": "ok",
            "notifications_enabled": bool(store.get_setting("notifications_enabled")),
            "notification_job_policy": str(
                store.get_setting("notification_job_policy") or "only_errors"
            ),
            "notification_proxy_offline_enabled": bool(
                store.get_setting("notification_proxy_offline_enabled")
            ),
            "notification_rclone_update_enabled": (
                store.get_setting("notification_rclone_update_enabled") is not False
            ),
            "rclone_auto_update_check_enabled": (
                store.get_setting("rclone_auto_update_check_enabled") is not False
            ),
            "rclone_auto_update_check_interval_hours": int(
                store.get_setting("rclone_auto_update_check_interval_hours") or 24
            ),
        }
    )


@api_bp.route("/notifications/settings", methods=["PUT"])
@api_bp.route("/settings/notifications/general", methods=["PUT"])
@require_auth
@require_permission("notification.write")
def update_notification_settings() -> Response:
    """Update global notification policy settings."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_settings_store_unavailable")}), 500
        )

    data = request.get_json(silent=True) or {}
    actor = get_current_user()
    actor_id = actor.id if actor else None
    ip = request.remote_addr

    if "notifications_enabled" in data:
        store.set_setting(
            "notifications_enabled",
            bool(data["notifications_enabled"]),
            user_id=actor_id,
            ip=ip,
        )

    if "notification_job_policy" in data:
        policy = str(data["notification_job_policy"]).strip().lower()
        if policy not in ("only_errors", "always"):
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": _("api_err_invalid_job_notification_policy"),
                    }
                ),
                400,
            )
        store.set_setting(
            "notification_job_policy",
            policy,
            user_id=actor_id,
            ip=ip,
        )

    if "notification_proxy_offline_enabled" in data:
        store.set_setting(
            "notification_proxy_offline_enabled",
            bool(data["notification_proxy_offline_enabled"]),
            user_id=actor_id,
            ip=ip,
        )

    if "notification_rclone_update_enabled" in data:
        store.set_setting(
            "notification_rclone_update_enabled",
            bool(data["notification_rclone_update_enabled"]),
            user_id=actor_id,
            ip=ip,
        )

    if "rclone_auto_update_check_enabled" in data:
        store.set_setting(
            "rclone_auto_update_check_enabled",
            bool(data["rclone_auto_update_check_enabled"]),
            user_id=actor_id,
            ip=ip,
        )

    if "rclone_auto_update_check_interval_hours" in data:
        try:
            val_hours = int(data["rclone_auto_update_check_interval_hours"])
            if val_hours >= 1:
                store.set_setting(
                    "rclone_auto_update_check_interval_hours",
                    val_hours,
                    user_id=actor_id,
                    ip=ip,
                )
        except (ValueError, TypeError):
            pass

    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_notification_settings_saved"),
            "notifications_enabled": bool(store.get_setting("notifications_enabled")),
            "notification_job_policy": str(
                store.get_setting("notification_job_policy") or "only_errors"
            ),
            "notification_proxy_offline_enabled": bool(
                store.get_setting("notification_proxy_offline_enabled")
            ),
            "notification_rclone_update_enabled": (
                store.get_setting("notification_rclone_update_enabled") is not False
            ),
            "rclone_auto_update_check_enabled": (
                store.get_setting("rclone_auto_update_check_enabled") is not False
            ),
            "rclone_auto_update_check_interval_hours": int(
                store.get_setting("rclone_auto_update_check_interval_hours") or 24
            ),
        }
    )


# ==============================================================================
# MASTER KEY / CREDENTIAL ROTATION API (Milestone M9 Hardening)
# ==============================================================================


@api_bp.route("/settings/rotate-key", methods=["POST"])
@require_auth
@require_permission("crypto.rotate")
def rotate_master_key() -> Response:
    """Trigger re-encryption of all database credentials with target or primary master key."""
    current_user = get_current_user()
    user_perms: set[str] = getattr(g, "permissions", set())
    has_perm = is_admin_user() or "crypto.rotate" in user_perms
    if not has_perm:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _("api_err_rotate_key_admin_only"),
                }
            ),
            403,
        )

    data = request.get_json(silent=True) or {}
    target_key_id = data.get("target_key_id")
    if target_key_id is not None:
        target_key_id = str(target_key_id).strip() or None

    session_factory = get_db()
    store = current_app.config.get("SETTINGS_STORE")

    with session_factory() as session:
        result = rotate_all_credentials(session, settings_store=store, target_key_id=target_key_id)
        session.commit()

    logger.info(
        "master_key_rotation_executed",
        user=current_user.username if current_user else "unknown",
        target_key_id=target_key_id or "primary",
        result=result,
    )

    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_rotate_key_success", total=result["total"]),
            "details": result,
        }
    )


# ==============================================================================
# Backup & Restore APIs (Admin Exclusive)
# ==============================================================================


@api_bp.route("/backup/export", methods=["POST"])
@require_permission("backup.export")
def backup_export() -> Response:
    """Export encrypted configuration backup and return binary blob with decryption key."""
    import io

    from embervault_db.backup import create_backup_archive, generate_backup_key

    payload = request.get_json(silent=True) or {}
    include_audit = bool(payload.get("include_audit", False))
    include_history = bool(payload.get("include_history", False))
    custom_key = str(payload.get("key") or "").strip()
    key = custom_key or generate_backup_key()

    current_u = get_current_user()
    session_factory = get_db()
    with session_factory() as session:
        backup_bytes, stats = create_backup_archive(
            session=session,
            key=key,
            include_audit=include_audit,
            include_history=include_history,
        )
        # Log export in audit trail
        session.add(
            AuditLog(
                action="system.backup.exported",
                actor_user_id=current_u.id if current_u else None,
                entity_type="system",
                entity_id="backup",
                details={
                    "include_audit": include_audit,
                    "include_history": include_history,
                    "stats": stats,
                    "size_bytes": len(backup_bytes),
                },
                ts=datetime.now(UTC),
            )
        )
        session.commit()

    timestamp_str = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    filename = f"embervault_backup_{timestamp_str}.evb"

    # Support direct download or JSON envelope with base64 payload
    if request.args.get("download") == "1":
        resp = make_response(
            send_file(
                io.BytesIO(backup_bytes),
                mimetype="application/octet-stream",
                as_attachment=True,
                download_name=filename,
            )
        )
        resp.headers["X-Decryption-Key"] = key
        resp.headers["X-Backup-Stats"] = json.dumps(stats)
        return resp

    b64_data = base64.b64encode(backup_bytes).decode("ascii")
    return jsonify(
        {
            "status": "ok",
            "key": key,
            "filename": filename,
            "size_bytes": len(backup_bytes),
            "stats": stats,
            "data": b64_data,
        }
    )


@api_bp.route("/backup/inspect", methods=["POST"])
@require_permission("backup.restore")
def backup_inspect() -> Response:
    """Inspect an uploaded encrypted backup file and verify decryption key."""
    from embervault_db.backup import inspect_backup_archive

    uploaded_file = request.files.get("backup_file")
    if not uploaded_file:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_no_backup_file")}),
            400,
        )

    key = str(request.form.get("key") or "").strip()
    if not key:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_backup_key_missing")}),
            400,
        )

    file_bytes = uploaded_file.read()
    try:
        info = inspect_backup_archive(file_bytes, key)
        return jsonify({"status": "ok", "info": info})
    except Exception as exc:
        logger.warning("backup_inspect_failed", error=str(exc))
        return make_response(
            jsonify({"status": "error", "message": str(exc)}),
            400,
        )


@api_bp.route("/backup/import", methods=["POST"])
@require_permission("backup.restore")
def backup_import() -> Response:
    """Import and restore EmberVault configuration from an uploaded backup file."""
    from embervault_db.backup import restore_backup_archive

    uploaded_file = request.files.get("backup_file")
    if not uploaded_file:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_no_backup_selected")}),
            400,
        )

    key = str(request.form.get("key") or "").strip()
    if not key:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_backup_key_required")}),
            400,
        )

    restore_audit = str(request.form.get("restore_audit", "")).lower() in ("true", "1", "yes")
    restore_history = str(request.form.get("restore_history", "")).lower() in ("true", "1", "yes")

    current_u = get_current_user()
    admin_username = current_u.username if current_u else "admin"

    file_bytes = uploaded_file.read()
    session_factory = get_db()
    with session_factory() as session:
        try:
            stats = restore_backup_archive(
                session=session,
                backup_bytes=file_bytes,
                key=key,
                restore_audit=restore_audit,
                restore_history=restore_history,
                current_admin_username=admin_username,
            )
        except Exception as exc:
            logger.error("backup_import_failed", error=str(exc))
            return make_response(
                jsonify({"status": "error", "message": str(exc)}),
                400,
            )

    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_backup_restored"),
            "stats": stats,
        }
    )


@api_bp.route("/backup/config", methods=["GET"])
@require_permission("backup.read")
def get_backup_config() -> Response:
    """Retrieve auto-backup configuration and directory status."""
    import os

    from embervault_db.backup import list_automated_backups
    from embervault_db.models.auth import Setting

    session_factory = get_db()
    with session_factory() as session:
        auto_enabled = session.get(Setting, "auto_backup_enabled")
        auto_cron = session.get(Setting, "auto_backup_cron")
        auto_key = session.get(Setting, "auto_backup_key")
        auto_dir = session.get(Setting, "auto_backup_dir")
        auto_history = session.get(Setting, "auto_backup_include_history")
        auto_audit = session.get(Setting, "auto_backup_include_audit")
        auto_retention = session.get(Setting, "auto_backup_retention_days")
        last_run = session.get(Setting, "last_auto_backup_at")

        backup_dir = str(auto_dir.value or "/backups") if auto_dir else "/backups"
        files = list_automated_backups(backup_dir)

        return jsonify(
            {
                "status": "ok",
                "config": {
                    "enabled": bool(auto_enabled.value) if auto_enabled else False,
                    "cron": str(auto_cron.value or "0 3 * * *") if auto_cron else "0 3 * * *",
                    "key": str(auto_key.value or "") if auto_key else "",
                    "dir": backup_dir,
                    "include_history": bool(auto_history.value) if auto_history else False,
                    "include_audit": bool(auto_audit.value) if auto_audit else False,
                    "retention_days": int(auto_retention.value or 30) if auto_retention else 30,
                    "last_run": str(last_run.value) if last_run and last_run.value else None,
                },
                "dir_exists": os.path.isdir(backup_dir),
                "dir_writable": os.access(backup_dir, os.W_OK)
                if os.path.isdir(backup_dir)
                else False,
                "files": files,
            }
        )


def _validate_cron_expression(expr: str) -> None:
    """Validate 5-part crontab expression without external dependencies."""
    parts = expr.strip().split()
    if len(parts) != 5:
        raise ValueError(_("api_err_cron_5_fields"))
    import re

    pattern = re.compile(r"^(\*|[0-9]+(-[0-9]+)?)(/[0-9]+)?(,\s*(\*|[0-9]+(-[0-9]+)?)(/[0-9]+)?)*$")
    for idx, part in enumerate(parts):
        if not pattern.match(part):
            raise ValueError(_("api_err_cron_invalid_field", pos=idx + 1, part=part))


@api_bp.route("/backup/config", methods=["PUT"])
@require_permission("backup.manage")
def update_backup_config() -> Response:
    """Update auto-backup configuration parameters."""
    from embervault_db.models.auth import Setting

    payload = request.get_json(silent=True) or {}
    cron_expr = str(payload.get("cron", "0 3 * * *")).strip()

    # Validate cron expression
    try:
        cron_expr = validate_cron_expression(cron_expr)
    except Exception as exc:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_invalid_cron", error=str(exc))}),
            400,
        )

    enabled = bool(payload.get("enabled", False))
    key = str(payload.get("key") or "").strip()
    include_history = bool(payload.get("include_history", False))
    include_audit = bool(payload.get("include_audit", False))
    retention_days = int(payload.get("retention_days", 30))

    if retention_days < 1:
        retention_days = 30

    session_factory = get_db()
    current_u = get_current_user()

    with session_factory() as session:

        def upsert_setting(k: str, v: Any) -> None:
            s = session.get(Setting, k)
            if s:
                s.value = v
                s.updated_at = datetime.now(UTC)
                if current_u:
                    s.updated_by = current_u.id
            else:
                session.add(
                    Setting(
                        key=k,
                        value=v,
                        updated_by=current_u.id if current_u else None,
                        updated_at=datetime.now(UTC),
                    )
                )

        upsert_setting("auto_backup_enabled", enabled)
        upsert_setting("auto_backup_cron", cron_expr)
        if key:
            upsert_setting("auto_backup_key", key)
        upsert_setting("auto_backup_include_history", include_history)
        upsert_setting("auto_backup_include_audit", include_audit)
        upsert_setting("auto_backup_retention_days", retention_days)

        session.add(
            AuditLog(
                action="settings.backup.auto_config.updated",
                actor_user_id=current_u.id if current_u else None,
                entity_type="setting",
                entity_id="auto_backup",
                details={
                    "enabled": enabled,
                    "cron": cron_expr,
                    "include_history": include_history,
                    "include_audit": include_audit,
                    "retention_days": retention_days,
                },
                ts=datetime.now(UTC),
            )
        )
        session.commit()

    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_auto_backup_saved"),
        }
    )


@api_bp.route("/backup/run-now", methods=["POST"])
@require_permission("backup.export")
def run_backup_now() -> Response:
    """Manually execute an immediate automated backup to the backup directory."""
    import os
    from pathlib import Path

    from embervault_db.backup import create_backup_archive, generate_backup_key
    from embervault_db.models.auth import Setting

    session_factory = get_db()
    current_u = get_current_user()

    with session_factory() as session:
        dir_setting = session.get(Setting, "auto_backup_dir")
        backup_dir = str(dir_setting.value or "/backups").strip() if dir_setting else "/backups"

        key_setting = session.get(Setting, "auto_backup_key")
        encryption_key = str(key_setting.value or "").strip() if key_setting else ""
        if not encryption_key:
            encryption_key = generate_backup_key()
            if key_setting:
                key_setting.value = encryption_key
            else:
                session.add(Setting(key="auto_backup_key", value=encryption_key))
            session.commit()

        inc_hist_setting = session.get(Setting, "auto_backup_include_history")
        include_history = bool(inc_hist_setting.value) if inc_hist_setting else False

        inc_aud_setting = session.get(Setting, "auto_backup_include_audit")
        include_audit = bool(inc_aud_setting.value) if inc_aud_setting else False

        try:
            os.makedirs(backup_dir, exist_ok=True)
        except PermissionError as exc:
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": _(
                            "api_err_backup_mkdir_permission", backup_dir=backup_dir, error=str(exc)
                        ),
                    }
                ),
                403,
            )
        except Exception as exc:
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": _(
                            "api_err_backup_dir_inaccessible", backup_dir=backup_dir, error=str(exc)
                        ),
                    }
                ),
                500,
            )

        if not os.access(backup_dir, os.W_OK):
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": _("api_err_backup_dir_not_writable", backup_dir=backup_dir),
                    }
                ),
                403,
            )

        now = datetime.now(UTC)
        timestamp_str = now.strftime("%Y%m%d_%H%M%S")
        filename = f"embervault_backup_{timestamp_str}.evb"
        target_path = Path(backup_dir) / filename

        try:
            backup_bytes, stats = create_backup_archive(
                session=session,
                key=encryption_key,
                include_audit=include_audit,
                include_history=include_history,
            )
            target_path.write_bytes(backup_bytes)

            last_run_setting = session.get(Setting, "last_auto_backup_at")
            if last_run_setting:
                last_run_setting.value = now.isoformat()
            else:
                session.add(Setting(key="last_auto_backup_at", value=now.isoformat()))

            session.add(
                AuditLog(
                    action="system.backup.manual_trigger.created",
                    actor_user_id=current_u.id if current_u else None,
                    entity_type="system",
                    entity_id=filename,
                    details={
                        "path": str(target_path),
                        "size_bytes": len(backup_bytes),
                        "stats": stats,
                    },
                    ts=now,
                )
            )
            session.commit()
        except PermissionError as exc:
            session.rollback()
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": _(
                            "api_err_backup_write_permission",
                            filename=filename,
                            backup_dir=backup_dir,
                            error=str(exc),
                        ),
                    }
                ),
                403,
            )
        except Exception as exc:
            session.rollback()
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": _("api_err_backup_create_failed", error=str(exc)),
                    }
                ),
                500,
            )

    return jsonify(
        {
            "status": "ok",
            "message": _("api_msg_backup_created", filename=filename),
            "filename": filename,
            "path": str(target_path),
            "stats": stats,
        }
    )


@api_bp.route("/backup/download/<path:filename>", methods=["GET"])
@require_permission("backup.export")
def download_backup_file(filename: str) -> Response:
    """Download an automated backup file from the backups directory."""
    import os

    from embervault_db.models.auth import Setting

    # Sanitization
    clean_name = os.path.basename(filename)
    if clean_name != filename or not filename.endswith(".evb"):
        return make_response(
            jsonify({"status": "error", "message": _("api_err_invalid_filename")}), 400
        )

    session_factory = get_db()
    with session_factory() as session:
        dir_setting = session.get(Setting, "auto_backup_dir")
        backup_dir = str(dir_setting.value or "/backups").strip() if dir_setting else "/backups"

    target_file = Path(backup_dir) / clean_name
    if not target_file.is_file():
        return make_response(
            jsonify({"status": "error", "message": _("api_err_file_not_found")}), 404
        )

    return send_file(
        str(target_file.absolute()),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=clean_name,
    )


# =========================================================================
# Public Shares Management
# =========================================================================


def _format_portal_url_from_public_url(public_url: str, portal_env: str = "") -> str:
    """Format portal URL based on EMBERVAULT_PUBLIC_URL and portal_env port if available."""
    clean_pub = public_url.strip().rstrip("/")
    if not clean_pub:
        return clean_pub

    try:
        parsed = urllib.parse.urlsplit(clean_pub)
        # If public_url has an explicit non-standard port and portal_env specifies a distinct portal port,
        # adjust the port to match the portal service while keeping the configured host and scheme.
        if parsed.port and portal_env and ":" in portal_env.rsplit("/", 1)[-1]:
            portal_port_part = portal_env.rsplit(":", 1)[-1].split("/")[0]
            if portal_port_part.isdigit() and int(portal_port_part) != parsed.port:
                scheme = parsed.scheme or "http"
                hostname = parsed.hostname or ""
                return f"{scheme}://{hostname}:{portal_port_part}"
    except Exception:
        pass

    return clean_pub


def _get_public_base_url() -> str:
    """Return configured Public Portal base URL, or EMBERVAULT_PUBLIC_URL as fallback."""
    # 1. Direct environment variable EMBERVAULT_PORTAL_URL if explicitly provided
    portal_env = os.environ.get("EMBERVAULT_PORTAL_URL", "").strip()
    if portal_env and "localhost" not in portal_env and "127.0.0.1" not in portal_env:
        return portal_env.rstrip("/")

    # 2. Dynamic SettingsStore in database (if configured from Web UI)
    store = current_app.config.get("SETTINGS_STORE")
    if store:
        try:
            val = store.get_setting("portal_url")
            if val and str(val).strip():
                s_val = str(val).strip()
                if "localhost" not in s_val and "127.0.0.1" not in s_val:
                    return s_val.rstrip("/")
        except Exception:
            pass

    # 3. Direct environment variable EMBERVAULT_PUBLIC_URL if explicitly provided and not default localhost
    env_url = os.environ.get("EMBERVAULT_PUBLIC_URL", "").strip()
    if env_url and "localhost" not in env_url and "127.0.0.1" not in env_url:
        return _format_portal_url_from_public_url(env_url, portal_env)

    # 4. Dynamic SettingsStore for public_url
    if store:
        try:
            val = store.get_setting("public_url")
            if (
                val
                and str(val).strip()
                and "localhost" not in str(val)
                and "127.0.0.1" not in str(val)
            ):
                return _format_portal_url_from_public_url(str(val).strip(), portal_env)
        except Exception:
            pass

    # 5. If request is available, infer from HTTP request headers (reverse proxy or client host)
    try:
        from flask import has_request_context, request

        if has_request_context() and request:
            proto = request.headers.get("X-Forwarded-Proto", request.scheme)
            host = request.headers.get("X-Forwarded-Host", request.host)
            if portal_env and ":" in portal_env.rsplit("/", 1)[-1]:
                portal_port_part = portal_env.rsplit(":", 1)[-1].split("/")[0]
                host_no_port = host.split(":")[0]
                return f"{proto}://{host_no_port}:{portal_port_part}".rstrip("/")
            if host and "localhost" not in host and "127.0.0.1" not in host:
                return f"{proto}://{host}".rstrip("/")
    except Exception:
        pass

    if portal_env:
        return portal_env.rstrip("/")

    if env_url:
        return env_url.rstrip("/")

    # 6. AppSettings configuration object
    settings = current_app.config.get("SETTINGS")
    if settings:
        if getattr(settings, "portal_url", None):
            val = str(settings.portal_url).strip()
            if val:
                return val.rstrip("/")
        if getattr(settings, "public_url", None):
            val = str(settings.public_url).strip()
            if val:
                return _format_portal_url_from_public_url(val, portal_env)

    return "http://localhost:8083"


def _generate_share_credentials() -> tuple[str, str]:
    import secrets
    import string

    rand_user = "share_" + "".join(
        secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8)
    )
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    rand_pass = "".join(secrets.choice(chars) for _ in range(16))
    return rand_user, rand_pass


def _is_share_expired(expires_at: datetime | None) -> bool:
    if not expires_at:
        return False
    now = utc_now()
    exp = expires_at if expires_at.tzinfo is not None else expires_at.replace(tzinfo=UTC)
    nw = now if now.tzinfo is not None else now.replace(tzinfo=UTC)
    return exp <= nw


@api_bp.route("/public-shares", methods=["GET"])
@require_permission("share.read")
def list_public_shares() -> Response:
    """List all public shares."""
    from embervault_db.repositories.public_share_repository import PublicShareRepository

    session_factory = get_db()
    with session_factory() as session:
        shares = PublicShareRepository.list_shares(session)
        base_url = _get_public_base_url()
        data = []
        for s in shares:
            is_expired = _is_share_expired(s.expires_at)
            data.append(
                {
                    "id": str(s.id),
                    "token": s.token,
                    "url": f"{base_url}/share/{s.token}",
                    "remote_id": str(s.remote_id),
                    "remote_name": s.remote.name if s.remote else "Remote",
                    "base_path": s.base_path,
                    "username": s.username,
                    "note": s.note or "",
                    "expires_at": s.expires_at.isoformat() if s.expires_at else None,
                    "is_active": s.is_active,
                    "is_expired": is_expired,
                    "first_accessed_at": s.first_accessed_at.isoformat()
                    if s.first_accessed_at
                    else None,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                    "created_by": str(s.created_by) if s.created_by else None,
                }
            )
    return jsonify({"status": "ok", "shares": data})


@api_bp.route("/public-shares", methods=["POST"])
@require_permission("share.create")
def create_public_share() -> Response:
    """Create a new public share for a remote path."""
    from embervault_app.whitelabel import is_public_portal_enabled

    if not is_public_portal_enabled():
        return make_response(jsonify({"status": "error", "message": _("err_portal_disabled")}), 403)

    from embervault_db.repositories.public_share_repository import PublicShareRepository

    payload = request.get_json(silent=True) or {}
    remote_id_str = payload.get("remote_id")
    raw_base_path = str(payload.get("base_path", "")).strip().strip("/")
    raw_expires_at = payload.get("expires_at")
    expires_in_hours = payload.get("expires_in_hours")
    note = str(payload.get("note", "")).strip()

    if not remote_id_str:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_invalid_remote_id")}), 400
        )

    try:
        remote_id = uuid.UUID(str(remote_id_str))
    except ValueError:
        return make_response(
            jsonify({"status": "error", "message": _("api_err_invalid_remote_id")}), 400
        )

    # Sanitize base_path
    parts = [p for p in raw_base_path.replace("\\", "/").split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        return make_response(jsonify({"status": "error", "message": "Percorso non valido."}), 400)
    clean_base_path = "/".join(parts)

    now = utc_now()
    if raw_expires_at:
        try:
            expires_str = str(raw_expires_at).replace("Z", "+00:00")
            expires_at = datetime.fromisoformat(expires_str)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
        except Exception:
            expires_at = now + timedelta(hours=72)
    elif expires_in_hours is not None:
        try:
            hrs = float(expires_in_hours)
            if hrs <= 0:
                hrs = 72
            expires_at = now + timedelta(hours=hrs)
        except Exception:
            expires_at = now + timedelta(hours=72)
    else:
        expires_at = now + timedelta(hours=72)

    if expires_at <= now:
        return make_response(
            jsonify({"status": "error", "message": "La data di scadenza deve essere nel futuro."}),
            400,
        )

    session_factory = get_db()
    with session_factory() as session:
        remote = RemoteRepository.get_remote_by_id(session, remote_id)
        if not remote:
            return make_response(
                jsonify({"status": "error", "message": _("api_err_remote_not_found")}), 404
            )

        current_user = get_current_user()
        actor_id = current_user.id if current_user else None

        share, token, username, password = PublicShareRepository.create_share(
            session=session,
            remote_id=remote_id,
            base_path=clean_base_path,
            expires_at=expires_at,
            note=note,
            created_by=actor_id,
        )
        session.commit()

        base_url = _get_public_base_url()
        public_url = f"{base_url}/share/{share.token}"
        remote_name = remote.name

        return jsonify(
            {
                "status": "ok",
                "share": {
                    "id": str(share.id),
                    "token": share.token,
                    "url": public_url,
                    "remote_id": str(share.remote_id),
                    "remote_name": remote_name,
                    "base_path": share.base_path,
                    "username": share.username,
                    "password": password,
                    "note": share.note or "",
                    "expires_at": share.expires_at.isoformat(),
                    "is_active": share.is_active,
                    "first_accessed_at": None,
                    "created_at": share.created_at.isoformat(),
                },
            }
        ), 201


@api_bp.route("/public-shares/<uuid:share_id>", methods=["PATCH"])
@require_permission("share.update")
def update_public_share(share_id: uuid.UUID) -> Response:
    """Update public share expiration date only."""
    from embervault_db.repositories.public_share_repository import PublicShareRepository

    payload = request.get_json(silent=True) or {}
    raw_expires_at = payload.get("expires_at")
    if not raw_expires_at:
        return make_response(
            jsonify({"status": "error", "message": "Data di scadenza obbligatoria."}), 400
        )

    now = utc_now()
    try:
        expires_str = str(raw_expires_at).replace("Z", "+00:00")
        expires_at = datetime.fromisoformat(expires_str)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
    except Exception:
        return make_response(
            jsonify({"status": "error", "message": "Formato data non valido."}), 400
        )

    if expires_at <= now:
        return make_response(
            jsonify({"status": "error", "message": "La data di scadenza deve essere nel futuro."}),
            400,
        )

    session_factory = get_db()
    with session_factory() as session:
        existing = PublicShareRepository.get_share_by_id(session, share_id)
        if not existing:
            return make_response(
                jsonify({"status": "error", "message": "Link pubblico non trovato."}), 404
            )
        if not existing.is_active:
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": "Impossibile modificare la scadenza di un link disattivato.",
                    }
                ),
                400,
            )

        share = PublicShareRepository.update_share_expiration(session, share_id, expires_at)
        if not share:
            return make_response(
                jsonify(
                    {"status": "error", "message": "Link pubblico non trovato o non modificabile."}
                ),
                404,
            )
        session.commit()

        base_url = _get_public_base_url()
        return jsonify(
            {
                "status": "ok",
                "share": {
                    "id": str(share.id),
                    "token": share.token,
                    "url": f"{base_url}/share/{share.token}",
                    "expires_at": share.expires_at.isoformat(),
                    "is_active": share.is_active,
                    "is_expired": share.expires_at <= now,
                    "first_accessed_at": share.first_accessed_at.isoformat()
                    if share.first_accessed_at
                    else None,
                },
            }
        )


@api_bp.route("/public-shares/<uuid:share_id>/deactivate", methods=["POST"])
@require_permission("share.deactivate")
def deactivate_public_share(share_id: uuid.UUID) -> Response:
    """Permanently deactivate a public share link."""
    from embervault_db.repositories.public_share_repository import PublicShareRepository

    session_factory = get_db()
    with session_factory() as session:
        share = PublicShareRepository.deactivate_share(session, share_id)
        if not share:
            return make_response(
                jsonify({"status": "error", "message": "Link pubblico non trovato."}), 404
            )
        session.commit()

        base_url = _get_public_base_url()
        return jsonify(
            {
                "status": "ok",
                "share": {
                    "id": str(share.id),
                    "token": share.token,
                    "url": f"{base_url}/share/{share.token}",
                    "expires_at": share.expires_at.isoformat() if share.expires_at else None,
                    "is_active": share.is_active,
                    "is_expired": _is_share_expired(share.expires_at),
                    "first_accessed_at": share.first_accessed_at.isoformat()
                    if share.first_accessed_at
                    else None,
                },
            }
        )


@api_bp.route("/public-shares/<uuid:share_id>", methods=["DELETE"])
@require_permission("share.delete")
def delete_public_share(share_id: uuid.UUID) -> Response:
    """Delete a public share."""
    from embervault_db.repositories.public_share_repository import PublicShareRepository

    session_factory = get_db()
    with session_factory() as session:
        deleted = PublicShareRepository.delete_share(session, share_id)
        if not deleted:
            return make_response(
                jsonify({"status": "error", "message": "Link pubblico non trovato."}), 404
            )
        session.commit()

    return jsonify({"status": "ok"})
