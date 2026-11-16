"""Prometheus metrics helpers and common metric definitions for EmberVault."""

from __future__ import annotations

import time
from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# Common HTTP metrics
HTTP_REQUESTS_TOTAL = Counter(
    "embervault_http_requests_total",
    "Total HTTP requests handled by service",
    ["service", "route", "method", "status"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "embervault_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["service", "route", "method"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# Service metadata
SERVICE_INFO = Gauge(
    "embervault_service_info",
    "Metadata information about the running EmberVault service",
    ["service", "version", "milestone"],
)

# 1. Job statistics metrics
JOB_LAST_EXECUTION_TIMESTAMP_SECONDS = Gauge(
    "embervault_job_last_execution_timestamp_seconds",
    "Timestamp in epoch seconds of the last execution start of the job",
    ["job_id", "job_name"],
)

JOB_LAST_EXECUTION_DURATION_SECONDS = Gauge(
    "embervault_job_last_execution_duration_seconds",
    "Duration in seconds of the last execution of the job",
    ["job_id", "job_name"],
)

JOB_LAST_EXECUTION_STATUS = Gauge(
    "embervault_job_last_execution_status",
    "Last execution status of the job (0=never_run, 1=succeeded, 2=failed, 3=in_progress)",
    ["job_id", "job_name"],
)

JOB_LAST_EXECUTION_FILES_TOTAL = Gauge(
    "embervault_job_last_execution_files_total",
    "Total files analyzed (checked and transferred) in the last execution of the job",
    ["job_id", "job_name"],
)

JOB_LAST_EXECUTION_BYTES_TOTAL = Gauge(
    "embervault_job_last_execution_bytes_total",
    "Total bytes of all files analyzed in the last execution of the job",
    ["job_id", "job_name"],
)

# 2. Proxy metrics
PROXY_UP = Gauge(
    "embervault_proxy_up",
    "Proxy node availability status (1 for UP/online, 0 for DOWN/offline)",
    ["proxy_name", "proxy_address"],
)

PROXY_CURRENT_TASK = Gauge(
    "embervault_proxy_current_task",
    "Currently executing task for proxy node (1 for active task label, otherwise task_name='None')",
    ["proxy_name", "proxy_address", "task_name"],
)

PROXY_STATUS = Gauge(
    "embervault_proxy_status",
    "Proxy operational state (0=standby, 1=working)",
    ["proxy_name", "proxy_address"],
)

PROXY_CURRENT_THROUGHPUT_BYTES_PER_SEC = Gauge(
    "embervault_proxy_current_throughput_bytes_per_second",
    "Current real-time transfer throughput of the proxy in bytes per second",
    ["proxy_name", "proxy_address"],
)

# 3. Historical total metrics
TOTAL_FILES_CHECKED = Gauge(
    "embervault_total_files_checked",
    "Historical total number of files checked across all job runs",
)

TOTAL_FILES_TRANSFERRED = Gauge(
    "embervault_total_files_transferred",
    "Historical total number of files transferred across all job runs",
)

TOTAL_BYTES_TRANSFERRED = Gauge(
    "embervault_total_bytes_transferred",
    "Historical total volume of data transferred across all job runs in bytes",
)


def collect_system_prometheus_metrics(session: Any) -> None:
    """Collect dynamic Prometheus metrics from database for jobs, proxies, and historical totals."""
    try:
        from datetime import datetime, timezone
        from sqlalchemy import func, select

        from embervault_db.models.execution import JobRun, Task, TaskAssignment, TaskLog
        from embervault_db.models.proxy import Proxy
        from embervault_db.models.remotes import Job
    except ImportError:
        return

    # Self-healing backfill for existing task assignments where checks_count == 0 but logs have checks
    try:
        import re

        checks_logs = session.execute(
            select(TaskLog.assignment_id, TaskLog.message)
            .join(TaskAssignment, TaskLog.assignment_id == TaskAssignment.id)
            .where(
                TaskAssignment.checks_count == 0,
                TaskLog.message.like("%Checks:%"),
            )
            .order_by(TaskLog.assignment_id, TaskLog.seq.asc())
        ).all()
        if checks_logs:
            checks_re = re.compile(r"Checks:\s*(\d+)\s*/")
            asgn_max_checks: dict[Any, int] = {}
            for asgn_id, msg in checks_logs:
                m = checks_re.search(msg)
                if m:
                    c_val = int(m.group(1))
                    if c_val > asgn_max_checks.get(asgn_id, 0):
                        asgn_max_checks[asgn_id] = c_val
            if asgn_max_checks:
                for asgn_id, count in asgn_max_checks.items():
                    asgn = session.get(TaskAssignment, asgn_id)
                    if asgn and count > asgn.checks_count:
                        asgn.checks_count = count
                try:
                    session.commit()
                except Exception:
                    session.rollback()
    except Exception:
        pass

    def _to_utc(dt: Any) -> Any:
        if dt is None:
            return None
        if getattr(dt, "tzinfo", None) is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    now = datetime.now(timezone.utc)

    # ---------------------------------------------------------
    # 1. Job statistics
    # ---------------------------------------------------------
    JOB_LAST_EXECUTION_TIMESTAMP_SECONDS.clear()
    JOB_LAST_EXECUTION_DURATION_SECONDS.clear()
    JOB_LAST_EXECUTION_STATUS.clear()
    JOB_LAST_EXECUTION_FILES_TOTAL.clear()
    JOB_LAST_EXECUTION_BYTES_TOTAL.clear()

    jobs = session.scalars(select(Job)).all()
    for job in jobs:
        j_id = str(job.id)
        j_name = job.name

        last_run = session.scalars(
            select(JobRun)
            .where(JobRun.job_id == job.id)
            .order_by(JobRun.created_at.desc())
            .limit(1)
        ).first()

        if last_run is not None:
            # Timestamp ultima esecuzione
            st_time = _to_utc(last_run.started_at or last_run.created_at)
            ts_val = st_time.timestamp() if st_time else 0.0
            JOB_LAST_EXECUTION_TIMESTAMP_SECONDS.labels(job_id=j_id, job_name=j_name).set(ts_val)

            # Durata ultima esecuzione
            fin_time = _to_utc(last_run.finished_at)
            if fin_time and st_time:
                dur_val = max(0.0, (fin_time - st_time).total_seconds())
            elif st_time and last_run.status in (
                "running",
                "planning",
                "queued",
                "awaiting_confirmation",
            ):
                dur_val = max(0.0, (now - st_time).total_seconds())
            else:
                dur_val = 0.0
            JOB_LAST_EXECUTION_DURATION_SECONDS.labels(job_id=j_id, job_name=j_name).set(dur_val)

            # Ultimo stato numerico: 0=never_run, 1=succeeded, 2=failed, 3=in_progress
            if last_run.status == "succeeded":
                job_status_val = 1.0
            elif last_run.status in ("failed", "partially_failed", "cancelled"):
                job_status_val = 2.0
            elif last_run.status in ("running", "planning", "queued", "awaiting_confirmation"):
                job_status_val = 3.0
            else:
                job_status_val = 0.0

            JOB_LAST_EXECUTION_STATUS.labels(job_id=j_id, job_name=j_name).set(job_status_val)

            # File e byte totali analizzati
            assign_stats = session.execute(
                select(
                    func.coalesce(func.sum(TaskAssignment.checks_count), 0),
                    func.coalesce(func.sum(TaskAssignment.files_transferred), 0),
                    func.coalesce(func.sum(TaskAssignment.bytes_transferred), 0),
                )
                .join(Task, TaskAssignment.task_id == Task.id)
                .where(Task.run_id == last_run.id)
            ).one()
            checks_sum, files_sum, bytes_sum = assign_stats

            files_analyzed = max(
                int(checks_sum) + int(files_sum), int(last_run.files_transferred or 0)
            )
            bytes_analyzed = max(int(bytes_sum), int(last_run.bytes_transferred or 0))

            JOB_LAST_EXECUTION_FILES_TOTAL.labels(job_id=j_id, job_name=j_name).set(files_analyzed)
            JOB_LAST_EXECUTION_BYTES_TOTAL.labels(job_id=j_id, job_name=j_name).set(bytes_analyzed)
        else:
            JOB_LAST_EXECUTION_TIMESTAMP_SECONDS.labels(job_id=j_id, job_name=j_name).set(0.0)
            JOB_LAST_EXECUTION_DURATION_SECONDS.labels(job_id=j_id, job_name=j_name).set(0.0)
            JOB_LAST_EXECUTION_STATUS.labels(job_id=j_id, job_name=j_name).set(0.0)
            JOB_LAST_EXECUTION_FILES_TOTAL.labels(job_id=j_id, job_name=j_name).set(0)
            JOB_LAST_EXECUTION_BYTES_TOTAL.labels(job_id=j_id, job_name=j_name).set(0)

    # ---------------------------------------------------------
    # 2. Proxy metrics
    # ---------------------------------------------------------
    PROXY_UP.clear()
    PROXY_CURRENT_TASK.clear()
    PROXY_STATUS.clear()
    PROXY_CURRENT_THROUGHPUT_BYTES_PER_SEC.clear()

    proxies = session.scalars(select(Proxy)).all()

    active_assignments = session.scalars(
        select(TaskAssignment).where(
            TaskAssignment.status.in_(["assigned", "dispatched", "running"])
        )
    ).all()

    proxy_assignments: dict[Any, list[TaskAssignment]] = {}
    for a in active_assignments:
        proxy_assignments.setdefault(a.proxy_id, []).append(a)

    for p in proxies:
        p_name = p.name
        p_addr = f"{p.host}:{p.port}"

        # UP/DOWN
        is_up = bool(p.is_enabled and p.status and p.status.state == "online")
        PROXY_UP.labels(proxy_name=p_name, proxy_address=p_addr).set(1.0 if is_up else 0.0)

        # Task in corso e Stato (standby / working)
        p_active_tasks = proxy_assignments.get(p.id, [])
        if p_active_tasks:
            t_names = []
            for a in p_active_tasks:
                t = a.task
                t_label = (
                    t.spec.get("source_subpath")
                    if (t and t.spec and t.spec.get("source_subpath"))
                    else ((t.scope if t and t.scope != "whole" else t.kind) if t else "task")
                )
                t_names.append(str(t_label))
            current_task_str = ", ".join(t_names) if t_names else "task"
            proxy_state_str = "working"
            proxy_status_val = 1.0
        else:
            current_task_str = "None"
            proxy_state_str = "standby"
            proxy_status_val = 0.0

        PROXY_CURRENT_TASK.labels(
            proxy_name=p_name, proxy_address=p_addr, task_name=current_task_str
        ).set(1.0)

        # Stato numerico: 0=standby, 1=working
        PROXY_STATUS.labels(proxy_name=p_name, proxy_address=p_addr).set(proxy_status_val)

        # Throughput attuale in bytes/second
        p_throughput = 0.0
        if p_active_tasks:
            try:
                from embervault_db.repositories.execution_repository import ExecutionRepository

                run_ids = {a.task.run_id for a in p_active_tasks if a.task and a.task.run_id}
                for rid in run_ids:
                    r_obj = session.get(JobRun, rid)
                    if r_obj:
                        t_stats = ExecutionRepository.get_run_tasks_progress_stats(session, r_obj)
                        for a in p_active_tasks:
                            if a.task_id in t_stats:
                                p_throughput += t_stats[a.task_id].get("speed_bytes_per_sec", 0.0)
            except Exception:
                pass

        PROXY_CURRENT_THROUGHPUT_BYTES_PER_SEC.labels(proxy_name=p_name, proxy_address=p_addr).set(
            float(p_throughput)
        )

    # ---------------------------------------------------------
    # 3. Metriche totali storiche
    # ---------------------------------------------------------
    tot_checks = (
        session.scalar(select(func.coalesce(func.sum(TaskAssignment.checks_count), 0))) or 0
    )
    TOTAL_FILES_CHECKED.set(float(tot_checks))

    tot_files = session.scalar(select(func.coalesce(func.sum(JobRun.files_transferred), 0))) or 0
    TOTAL_FILES_TRANSFERRED.set(float(tot_files))

    tot_bytes = session.scalar(select(func.coalesce(func.sum(JobRun.bytes_transferred), 0))) or 0
    TOTAL_BYTES_TRANSFERRED.set(float(tot_bytes))


def init_service_metrics(
    service_name: str,
    version: str | None = None,
    milestone: str = "M7",
) -> None:
    """Initialize base service info metrics."""
    if version is None:
        try:
            from embervault_common import __version__

            version = __version__
        except Exception:
            version = "1.0.0"

    try:
        for metric in list(SERVICE_INFO.collect()):
            for s in metric.samples:
                if s.labels.get("service") == service_name:
                    SERVICE_INFO.remove(
                        s.labels["service"],
                        s.labels["version"],
                        s.labels.get("milestone", ""),
                    )
    except Exception:
        pass

    SERVICE_INFO.labels(service=service_name, version=version, milestone=milestone).set(1)


def generate_metrics_response(
    registry: CollectorRegistry = REGISTRY,
    session_factory: Any | None = None,
) -> tuple[bytes, str]:
    """Generate the Prometheus metrics payload and content-type header."""
    if session_factory is None:
        try:
            from flask import current_app

            if current_app:
                session_factory = current_app.config.get("SESSION_FACTORY")
        except Exception:
            pass

    if session_factory is not None:
        try:
            with session_factory() as session:
                collect_system_prometheus_metrics(session)
        except Exception as exc:
            try:
                import structlog

                structlog.get_logger("embervault_common.metrics").warning(
                    "failed_to_collect_system_prometheus_metrics", error=str(exc)
                )
            except Exception:
                pass

    return generate_latest(registry), CONTENT_TYPE_LATEST


def create_metrics_middleware(app: Any, service_name: str) -> None:
    """Attach request duration and count monitoring to a Flask WSGI application."""

    @app.before_request
    def before_request() -> None:
        from flask import g, request

        g._request_start_time = time.monotonic()
        g._request_endpoint = request.endpoint or request.path

    @app.after_request
    def after_request(response: Any) -> Any:
        from flask import g, request

        start_time = getattr(g, "_request_start_time", None)
        if start_time is not None:
            duration = time.monotonic() - start_time
            route = getattr(g, "_request_endpoint", request.path)
            method = request.method
            status = str(response.status_code)

            # Avoid scraping /metrics from skewing metrics
            if request.path != "/metrics":
                HTTP_REQUESTS_TOTAL.labels(
                    service=service_name, route=route, method=method, status=status
                ).inc()
                HTTP_REQUEST_DURATION_SECONDS.labels(
                    service=service_name, route=route, method=method
                ).observe(duration)

        return response
