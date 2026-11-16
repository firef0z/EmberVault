"""UI Blueprint for serving HTML views across all EmberVault pages."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

from flask import Blueprint, Response, current_app, g, redirect, render_template, request
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, joinedload, sessionmaker

from embervault_app.auth import (
    get_current_user,
    is_admin_user,
    require_auth,
    require_permission,
)
from embervault_app.i18n import translate as _
from embervault_app.timezones import format_user_datetime, parse_user_datetime_input
from embervault_common.config.registry import CONFIG_REGISTRY
from embervault_common.ai.prompts import (
    get_default_error_system_prompt,
    get_default_reporting_system_prompt,
)
from embervault_common.contracts import ErrorCode
from embervault_common.rclone.filters import parse_filter_rules
from embervault_common.version import (
    MIN_COMPATIBLE_PROXY_VERSION,
    is_proxy_version_compatible,
)
from embervault_db.models import AuditLog, JobRun, Proxy, ProxyStatus, TaskAssignment
from embervault_db.repositories.user_repository import UserRepository
from embervault_db.settings_store import SettingsStore

ui_bp = Blueprint("ui", __name__)


def get_db() -> sessionmaker[Session]:
    """Retrieve session factory from Flask current_app."""
    return cast(sessionmaker[Session], current_app.config["SESSION_FACTORY"])


@ui_bp.route("/", methods=["GET"])
@require_auth
def dashboard() -> str:
    """Dashboard view with live proxy metrics, recent runs, and error counter."""
    session_factory = get_db()
    with session_factory() as session:
        # Proxies count (disabled proxies are counted as offline)
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

        # Active & total runs
        active_runs = (
            session.scalar(
                select(func.count(JobRun.id)).where(JobRun.status.in_(["pending", "running"]))
            )
            or 0
        )
        total_runs = session.scalar(select(func.count(JobRun.id))) or 0

        # Recent error events (last 24h)
        cutoff_24h = datetime.now(UTC) - timedelta(hours=24)
        recent_errors = (
            session.scalar(
                select(func.count(AuditLog.id)).where(
                    AuditLog.action.like("%error%"),
                    AuditLog.ts >= cutoff_24h,
                )
            )
            or 0
        )

        # Live proxies list
        stmt = select(Proxy).where(Proxy.is_enabled.is_(True)).order_by(Proxy.name).limit(10)
        proxies = list(session.scalars(stmt).unique().all())

        # Recent runs list
        runs_stmt = select(JobRun).order_by(desc(JobRun.created_at)).limit(5)
        recent_runs_list = list(session.scalars(runs_stmt).all())

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        total_proxies=total_proxies,
        online_proxies=online_proxies,
        offline_proxies=offline_proxies,
        active_runs=active_runs,
        total_runs=total_runs,
        recent_errors=recent_errors,
        proxies=proxies,
        recent_runs=recent_runs_list,
    )


@ui_bp.route("/proxies", methods=["GET"])
@require_auth
@require_permission("proxy.read")
def proxies() -> str:
    """Proxy nodes list with status indicators and TOFU registration flow."""
    session_factory = get_db()
    with session_factory() as session:
        settings_store = SettingsStore(session_factory)
        min_ver = settings_store.get_setting("min_proxy_version") or MIN_COMPATIBLE_PROXY_VERSION
        stmt = select(Proxy).order_by(Proxy.name)
        proxy_list = list(session.scalars(stmt).unique().all())
        from embervault_db.repositories.remote_repository import RemoteRepository

        remotes_list = RemoteRepository.list_remotes(session)
        from embervault_db.repositories.job_repository import JobRepository

        jobs_list = JobRepository.list_jobs(session)
        remote_job_usage = {}
        for j in jobs_list:
            j_remotes = JobRepository.get_job_required_remote_ids(session, j)
            assigned_pids = [str(p.id) for p in j.assigned_proxies]
            for rid in j_remotes:
                rid_str = str(rid)
                if rid_str not in remote_job_usage:
                    remote_job_usage[rid_str] = []
                remote_job_usage[rid_str].append(
                    {
                        "job_id": str(j.id),
                        "job_name": j.name,
                        "assigned_proxy_ids": assigned_pids,
                    }
                )

    incompatible_proxies = []
    now_utc = datetime.now(UTC)
    for p in proxy_list:
        is_incompat = False
        if p.status and p.status.last_error_code == ErrorCode.PROXY_VERSION_INCOMPATIBLE:
            is_incompat = True
        elif p.proxy_version and not is_proxy_version_compatible(p.proxy_version, min_ver):
            is_incompat = True
        p.is_incompatible = is_incompat
        if is_incompat:
            incompatible_proxies.append(p)

        p.cert_expiring_soon = False
        p.cert_days_remaining = None
        if p.cert_expires_at:
            cert_exp = p.cert_expires_at
            if cert_exp.tzinfo is None:
                cert_exp = cert_exp.replace(tzinfo=UTC)
            diff = cert_exp - now_utc
            days = int(diff.total_seconds() // 86400)
            p.cert_days_remaining = days
            if days < 15:
                p.cert_expiring_soon = True

    settings = current_app.config["SETTINGS"]
    dev_noauth = getattr(settings, "dev_noauth", False)
    user = get_current_user()
    user_perms: set[str] = getattr(g, "permissions", set())
    can_register = bool(dev_noauth or (user and "proxy.manage" in user_perms))
    can_renew_cert = bool(
        dev_noauth or (user and ("proxy.manage" in user_perms or "proxy.renew_cert" in user_perms))
    )

    return render_template(
        "proxies.html",
        active_page="proxies",
        proxies=proxy_list,
        remotes=remotes_list,
        remote_job_usage=remote_job_usage,
        incompatible_proxies=incompatible_proxies,
        min_proxy_version=min_ver,
        dev_noauth=dev_noauth,
        can_register=can_register,
        can_renew_cert=can_renew_cert,
    )


@ui_bp.route("/remotes", methods=["GET"])
@require_auth
@require_permission("remote.read")
def remotes() -> str:
    """RClone remotes management list view."""
    session_factory = get_db()
    with session_factory() as session:
        from embervault_common.remotes.catalog import get_backend_spec
        from embervault_db.repositories.remote_repository import RemoteRepository

        user = get_current_user()
        is_admin = is_admin_user()
        remote_list = RemoteRepository.list_remotes_for_user(session, user, is_admin=is_admin)
        enriched = []
        for r in remote_list:
            spec = get_backend_spec(r.backend_type)
            enriched.append(
                {
                    "entity": r,
                    "spec": spec,
                    "masked_config": RemoteRepository.get_masked_config(r),
                }
            )

    return render_template(
        "remotes.html",
        active_page="remotes",
        remotes=enriched,
    )


def _get_localized_catalog() -> list[dict[str, Any]]:
    from embervault_common.remotes.catalog import get_backend_catalog
    from embervault_app.i18n import translate

    catalog = []
    for b in get_backend_catalog():
        b_dict = b.to_dict()
        b_dict["label"] = translate(b.label)
        b_dict["description"] = translate(b.description)
        b_dict["category"] = translate(b.category)
        localized_fields = []
        for f in b_dict["fields"]:
            f_copy = dict(f)
            f_copy["label"] = translate(f["label"])
            if f.get("help_text"):
                f_copy["help_text"] = translate(f["help_text"])
            if f.get("placeholder"):
                f_copy["placeholder"] = translate(f["placeholder"])
            if f.get("options"):
                f_copy["options"] = [[val, translate(lbl)] for val, lbl in f["options"]]
            localized_fields.append(f_copy)
        b_dict["fields"] = localized_fields
        catalog.append(b_dict)
    return catalog


@ui_bp.route("/remotes/new", methods=["GET"])
@require_auth
@require_permission("remote.write")
def new_remote() -> str:
    """Create new RClone remote form."""
    from embervault_db.models.auth import Role
    from embervault_db.repositories.remote_repository import RemoteRepository

    session_factory = get_db()
    with session_factory() as session:
        user = get_current_user()
        is_admin = is_admin_user()
        existing_remotes = [
            {"id": str(r.id), "name": r.name, "backend_type": r.backend_type}
            for r in RemoteRepository.list_remotes_for_user(session, user, is_admin=is_admin)
        ]
        from embervault_db.repositories.proxy_repository import ProxyRepository

        proxies_list = ProxyRepository.get_all_proxies(session)
        roles_list = list(session.scalars(select(Role).order_by(Role.name)).all())

    catalog = _get_localized_catalog()
    return render_template(
        "remote_edit.html",
        active_page="remotes",
        is_edit=False,
        remote=None,
        catalog=catalog,
        existing_remotes=existing_remotes,
        proxies=proxies_list,
        roles=roles_list,
    )


@ui_bp.route("/remotes/<uuid:remote_id>/edit", methods=["GET"])
@require_auth
@require_permission("remote.write")
def edit_remote(remote_id: UUID) -> Any:
    """Edit existing RClone remote form."""
    session_factory = get_db()
    with session_factory() as session:
        from embervault_common.remotes.catalog import get_backend_spec
        from embervault_db.models.auth import Role
        from embervault_db.repositories.remote_repository import RemoteRepository

        remote = RemoteRepository.get_remote_by_id(session, remote_id)
        if remote is None:
            return (
                render_template(
                    "error.html",
                    error_code=404,
                    error_title=_("error_remote_not_found_title"),
                    error_message=_("error_remote_not_found_msg_tpl").format(remote_id=remote_id),
                ),
                404,
            )

        user = get_current_user()
        is_admin = is_admin_user()
        if not RemoteRepository.can_user_view_remote(remote, user, is_admin=is_admin):
            return (
                render_template(
                    "error.html",
                    error_code=403,
                    error_title=_("auth_forbidden_title"),
                    error_message=_("err_remote_not_permitted"),
                ),
                403,
            )

        spec = get_backend_spec(remote.backend_type)
        masked_config = RemoteRepository.get_masked_config(remote)
        catalog = _get_localized_catalog()
        existing_remotes = [
            {"id": str(r.id), "name": r.name, "backend_type": r.backend_type}
            for r in RemoteRepository.list_remotes_for_user(session, user, is_admin=is_admin)
            if r.id != remote_id
        ]
        from embervault_db.repositories.proxy_repository import ProxyRepository

        proxies_list = ProxyRepository.get_all_proxies(session)
        roles_list = list(session.scalars(select(Role).order_by(Role.name)).all())

    return render_template(
        "remote_edit.html",
        active_page="remotes",
        is_edit=True,
        remote=remote,
        remote_spec=spec,
        masked_config=masked_config,
        catalog=catalog,
        existing_remotes=existing_remotes,
        proxies=proxies_list,
        roles=roles_list,
    )


@ui_bp.route("/public-shares", methods=["GET"])
@require_auth
@require_permission("share.read")
def public_shares() -> Any:
    """Public shares management view."""
    from embervault_app.whitelabel import is_public_portal_enabled

    if not is_public_portal_enabled():
        from flask import abort

        abort(403, description=_("err_portal_disabled"))
    return render_template(
        "public_shares.html",
        active_page="public_shares",
    )


@ui_bp.route("/share/<path:subpath>", methods=["GET", "POST"])
def redirect_to_public_portal(subpath: str) -> Response:
    """Redirect traffic landing on /share/<token> on Web App port directly to the Public Portal."""
    from embervault_app.blueprints.api import _get_public_base_url

    portal_base = _get_public_base_url()
    current_origin = request.host_url.rstrip("/")
    if portal_base.rstrip("/") == current_origin:
        return Response(
            "Public Portal is not hosted directly on the Web App console. Please check your EMBERVAULT_PORTAL_URL configuration.",
            status=502,
            mimetype="text/plain",
        )
    query_str = f"?{request.query_string.decode('utf-8')}" if request.query_string else ""
    return redirect(f"{portal_base}/share/{subpath}{query_str}", code=302)


@ui_bp.route("/jobs", methods=["GET"])
@require_auth
@require_permission("job.read")
def jobs() -> str:
    """Backup jobs list view."""
    session_factory = get_db()
    with session_factory() as session:
        from embervault_db.repositories.job_repository import JobRepository

        job_list = JobRepository.list_jobs(session)

    return render_template("jobs.html", active_page="jobs", jobs=job_list)


@ui_bp.route("/jobs/new", methods=["GET"])
@require_auth
@require_permission("job.write")
def new_job() -> str:
    """Create new backup job form."""
    settings_store = current_app.config.get("SETTINGS_STORE")
    hooks_enabled = bool(settings_store.get_setting("hooks_enabled")) if settings_store else False

    global_rclone_defaults = {
        "task_retries": int(settings_store.get_setting("task_retries") or 2)
        if settings_store
        else 2,
        "rclone_checkers": int(settings_store.get_setting("rclone_checkers") or 8)
        if settings_store
        else 8,
        "rclone_transfers": int(settings_store.get_setting("rclone_transfers") or 4)
        if settings_store
        else 4,
        "rclone_check_first": bool(settings_store.get_setting("rclone_check_first"))
        if settings_store
        else False,
        "rclone_recurse": bool(settings_store.get_setting("rclone_recurse"))
        if settings_store and settings_store.get_setting("rclone_recurse") is not None
        else True,
        "rclone_order_by": str(settings_store.get_setting("rclone_order_by") or "")
        if settings_store
        else "",
        "rclone_first_level_filters": parse_filter_rules(
            settings_store.get_setting("rclone_first_level_filters")
        )
        if settings_store
        else [],
        "rclone_second_level_filters": parse_filter_rules(
            settings_store.get_setting("rclone_second_level_filters")
        )
        if settings_store
        else [],
    }

    session_factory = get_db()
    with session_factory() as session:
        from embervault_db.repositories.proxy_repository import ProxyRepository
        from embervault_db.repositories.remote_repository import RemoteRepository

        user = get_current_user()
        is_admin = is_admin_user()
        remotes = RemoteRepository.list_remotes_for_user(session, user, is_admin=is_admin)
        proxies = ProxyRepository.get_all_proxies(session)

    default_missed_run_policy = (
        str(settings_store.get_setting("default_missed_run_policy") or "run_once")
        if settings_store
        else "run_once"
    )
    default_overlap_policy = (
        str(settings_store.get_setting("default_overlap_policy") or "skip")
        if settings_store
        else "skip"
    )
    default_pending_policy = (
        str(settings_store.get_setting("default_pending_policy") or "fail")
        if settings_store
        else "fail"
    )

    return render_template(
        "job_edit.html",
        active_page="jobs",
        is_edit=False,
        job=None,
        remotes=remotes,
        proxies=proxies,
        can_edit_source_remote=True,
        can_edit_dest_remote=True,
        hooks_enabled=hooks_enabled,
        global_rclone_defaults=global_rclone_defaults,
        default_missed_run_policy=default_missed_run_policy,
        default_overlap_policy=default_overlap_policy,
        default_pending_policy=default_pending_policy,
    )


@ui_bp.route("/jobs/<uuid:job_id>/edit", methods=["GET"])
@require_auth
@require_permission("job.write")
def edit_job(job_id: UUID) -> Any:
    """Edit existing backup job form."""
    settings_store = current_app.config.get("SETTINGS_STORE")
    hooks_enabled = bool(settings_store.get_setting("hooks_enabled")) if settings_store else False
    global_rclone_defaults = {
        "task_retries": int(settings_store.get_setting("task_retries") or 2)
        if settings_store
        else 2,
        "rclone_checkers": int(settings_store.get_setting("rclone_checkers") or 8)
        if settings_store
        else 8,
        "rclone_transfers": int(settings_store.get_setting("rclone_transfers") or 4)
        if settings_store
        else 4,
        "rclone_check_first": bool(settings_store.get_setting("rclone_check_first"))
        if settings_store
        else False,
        "rclone_recurse": bool(settings_store.get_setting("rclone_recurse"))
        if settings_store and settings_store.get_setting("rclone_recurse") is not None
        else True,
        "rclone_order_by": str(settings_store.get_setting("rclone_order_by") or "")
        if settings_store
        else "",
        "rclone_first_level_filters": parse_filter_rules(
            settings_store.get_setting("rclone_first_level_filters")
        )
        if settings_store
        else [],
        "rclone_second_level_filters": parse_filter_rules(
            settings_store.get_setting("rclone_second_level_filters")
        )
        if settings_store
        else [],
    }

    session_factory = get_db()
    with session_factory() as session:
        from embervault_db.repositories.job_repository import JobRepository
        from embervault_db.repositories.proxy_repository import ProxyRepository
        from embervault_db.repositories.remote_repository import RemoteRepository

        job = JobRepository.get_job_by_id(session, job_id)
        if job is None:
            return (
                render_template(
                    "error.html",
                    error_code=404,
                    error_title=_("error_job_not_found_title"),
                    error_message=_("error_job_not_found_msg_tpl").format(job_id=job_id),
                ),
                404,
            )
        user = get_current_user()
        is_admin = is_admin_user()
        remotes = RemoteRepository.list_remotes_for_user(session, user, is_admin=is_admin)
        proxies = ProxyRepository.get_all_proxies(session)

        can_edit_source_remote = (
            RemoteRepository.can_user_view_remote(job.source_remote, user, is_admin=is_admin)
            if job.source_remote
            else True
        )
        can_edit_dest_remote = (
            RemoteRepository.can_user_view_remote(job.destination_remote, user, is_admin=is_admin)
            if job.destination_remote
            else True
        )

    default_missed_run_policy = (
        str(settings_store.get_setting("default_missed_run_policy") or "run_once")
        if settings_store
        else "run_once"
    )
    default_overlap_policy = (
        str(settings_store.get_setting("default_overlap_policy") or "skip")
        if settings_store
        else "skip"
    )
    default_pending_policy = (
        str(settings_store.get_setting("default_pending_policy") or "fail")
        if settings_store
        else "fail"
    )

    return render_template(
        "job_edit.html",
        active_page="jobs",
        is_edit=True,
        job=job,
        remotes=remotes,
        proxies=proxies,
        can_edit_source_remote=can_edit_source_remote,
        can_edit_dest_remote=can_edit_dest_remote,
        hooks_enabled=hooks_enabled,
        global_rclone_defaults=global_rclone_defaults,
        default_missed_run_policy=default_missed_run_policy,
        default_overlap_policy=default_overlap_policy,
        default_pending_policy=default_pending_policy,
    )


@ui_bp.route("/runs", methods=["GET"])
@require_auth
@require_permission("job.read")
def runs() -> str:
    """Runs history."""
    session_factory = get_db()
    with session_factory() as session:
        from embervault_db.repositories.execution_repository import ExecutionRepository

        run_list = ExecutionRepository.list_runs(session, limit=50)

    return render_template("runs.html", active_page="runs", runs=run_list)


@ui_bp.route("/runs/<uuid:run_id>", methods=["GET"])
@require_auth
@require_permission("job.read")
def run_detail(run_id: UUID) -> str:
    """Detail view for a specific run."""
    session_factory = get_db()
    with session_factory() as session:
        from embervault_app.i18n import localize_proxies_activity
        from embervault_db.repositories.execution_repository import ExecutionRepository

        run = ExecutionRepository.get_run_by_id(session, run_id)
        proxies_activity = localize_proxies_activity(
            ExecutionRepository.get_run_proxies_activity(session, run) if run else []
        )
        tasks_stats = ExecutionRepository.get_run_tasks_progress_stats(session, run) if run else {}
        total_speed_bytes = sum(p.get("speed_bytes_per_sec", 0.0) for p in proxies_activity)
        total_throughput_str = ExecutionRepository.format_speed(total_speed_bytes)

        return render_template(
            "run_detail.html",
            active_page="runs",
            run=run,
            run_id=run_id,
            proxies_activity=proxies_activity,
            tasks_stats=tasks_stats,
            total_throughput_str=total_throughput_str,
        )


def _query_audit_logs(
    session: Session,
    limit: int | None = 100,
    start_date: str | None = None,
    end_date: str | None = None,
) -> list[AuditLog]:
    """Helper to query AuditLog records applying optional limit and date range."""
    stmt = select(AuditLog)
    if start_date:
        dt_from = parse_user_datetime_input(start_date, is_end_of_day=False)
        if dt_from:
            stmt = stmt.where(AuditLog.ts >= dt_from)
    if end_date:
        dt_to = parse_user_datetime_input(end_date, is_end_of_day=True)
        if dt_to:
            stmt = stmt.where(AuditLog.ts <= dt_to)

    stmt = stmt.order_by(desc(AuditLog.id))
    if limit is not None and limit > 0:
        stmt = stmt.limit(limit)
    return list(session.scalars(stmt).all())


@ui_bp.route("/logs", methods=["GET"])
@require_auth
@require_permission("audit.read")
def logs() -> str:
    """System and audit logs view with filtering support."""
    from flask import request

    limit_param = request.args.get("limit", "100")
    start_date = request.args.get("start_date", "").strip() or None
    end_date = request.args.get("end_date", "").strip() or None

    try:
        limit: int | None = int(limit_param)
        if limit <= 0:
            limit = None
    except (ValueError, TypeError):
        limit = 100

    session_factory = get_db()
    with session_factory() as session:
        audit_entries = _query_audit_logs(
            session=session,
            limit=limit,
            start_date=start_date,
            end_date=end_date,
        )

    return render_template(
        "logs.html",
        active_page="logs",
        logs=audit_entries,
        current_limit=str(limit or "all"),
        current_start_date=start_date or "",
        current_end_date=end_date or "",
    )


@ui_bp.route("/logs/export", methods=["GET"])
@require_auth
@require_permission("audit.export")
def export_logs() -> Any:
    """Export filtered audit logs to a downloadable .xlsx spreadsheet."""
    import json

    from flask import Response, request

    from embervault_app.excel_export import generate_xlsx

    limit_param = request.args.get("limit", "100")
    start_date = request.args.get("start_date", "").strip() or None
    end_date = request.args.get("end_date", "").strip() or None

    try:
        limit: int | None = int(limit_param)
        if limit <= 0:
            limit = None
    except (ValueError, TypeError):
        limit = 100

    session_factory = get_db()
    with session_factory() as session:
        audit_entries = _query_audit_logs(
            session=session,
            limit=limit,
            start_date=start_date,
            end_date=end_date,
        )

    headers = [
        "ID",
        _("export_col_timestamp_utc"),
        _("col_action"),
        _("logs_modal_entity_type"),
        "Entity ID",
        _("export_col_user_id"),
        _("logs_modal_source_ip"),
        _("export_col_details_json"),
    ]

    rows = []
    for log in audit_entries:
        ts_str = format_user_datetime(log.ts, "%Y-%m-%d %H:%M:%S") if log.ts else ""
        details_str = json.dumps(log.details, ensure_ascii=False) if log.details else ""
        rows.append(
            [
                log.id,
                ts_str,
                log.action,
                log.entity_type,
                log.entity_id or "",
                str(log.actor_user_id) if log.actor_user_id else "",
                log.ip or "",
                details_str,
            ]
        )

    xlsx_bytes = generate_xlsx(headers=headers, rows=rows, sheet_name="Audit Log")
    filename = f"embervault_audit_logs_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.xlsx"

    return Response(
        xlsx_bytes,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@ui_bp.route("/settings", methods=["GET"])
@require_auth
@require_permission("settings.read")
def settings_view() -> str:
    """View of all system configuration keys with hierarchical resolution."""
    settings_store: SettingsStore = current_app.config["SETTINGS_STORE"]
    resolved_settings = settings_store.get_all_resolved_settings()

    settings_list = []
    for key_def in CONFIG_REGISTRY:
        if key_def.overridable_from_gui:
            continue
        val = resolved_settings.get(key_def.name, key_def.default)
        if key_def.name == "login_custom_background" and val:
            val_display = _("settings_custom_image_configured_val")
        elif key_def.secret and val is not None:
            val_display = "••••••••••••"
        else:
            val_display = str(val) if val is not None else "None"

        settings_list.append(
            {
                "def": key_def,
                "resolved_value": val_display,
            }
        )

    session_factory = get_db()
    with session_factory() as session:
        from embervault_app.ldap_service import get_ldap_config
        from embervault_app.oidc_service import get_oidc_config
        from embervault_db.repositories.notification_repository import NotificationRepository

        ldap_enabled, ldap_config = get_ldap_config(session)
        oidc_enabled, oidc_config = get_oidc_config(session)
        channels = NotificationRepository.list_channels(session)
        notification_channels = [
            NotificationRepository.to_dict(c, mask_secrets=True) for c in channels
        ]

    has_custom_login_bg = bool(settings_store.get_setting("login_custom_background"))
    trusted_proxies = str(settings_store.get_setting("trusted_proxies") or "").strip()
    hooks_enabled = bool(settings_store.get_setting("hooks_enabled"))
    hooks_timeout_s = int(settings_store.get_setting("hooks_timeout_s") or 60)
    hook_runner_url = str(settings_store.get_setting("hook_runner_url") or "").strip()
    notifications_enabled = bool(settings_store.get_setting("notifications_enabled"))
    notification_job_policy = str(
        settings_store.get_setting("notification_job_policy") or "only_errors"
    )
    notification_proxy_offline_enabled = bool(
        settings_store.get_setting("notification_proxy_offline_enabled")
    )
    notification_rclone_update_enabled = (
        settings_store.get_setting("notification_rclone_update_enabled") is not False
    )
    rclone_auto_update_check_enabled = (
        settings_store.get_setting("rclone_auto_update_check_enabled") is not False
    )
    rclone_auto_update_check_interval_hours = int(
        settings_store.get_setting("rclone_auto_update_check_interval_hours") or 24
    )

    task_retries = int(settings_store.get_setting("task_retries") or 2)
    rclone_checkers = int(settings_store.get_setting("rclone_checkers") or 8)
    rclone_transfers = int(settings_store.get_setting("rclone_transfers") or 4)
    rclone_check_first = bool(settings_store.get_setting("rclone_check_first"))
    rclone_recurse_val = settings_store.get_setting("rclone_recurse")
    rclone_recurse = bool(rclone_recurse_val) if rclone_recurse_val is not None else True
    rclone_order_by = str(settings_store.get_setting("rclone_order_by") or "")
    rclone_first_level_filters = (
        parse_filter_rules(settings_store.get_setting("rclone_first_level_filters"))
        if settings_store
        else []
    )
    rclone_second_level_filters = (
        parse_filter_rules(settings_store.get_setting("rclone_second_level_filters"))
        if settings_store
        else []
    )

    ai_enabled = bool(settings_store.get_setting("ai_enabled"))
    ai_provider_type = str(
        settings_store.get_setting("ai_provider_type") or "openai_compatible"
    ).strip()
    ai_endpoint_url = str(
        settings_store.get_setting("ai_endpoint_url") or "http://localhost:11434"
    ).strip()
    ai_model = str(settings_store.get_setting("ai_model") or "llama3.2").strip()
    ai_timeout_seconds = int(settings_store.get_setting("ai_timeout_seconds") or 15)
    ai_has_api_key = bool(settings_store.get_setting("ai_api_key"))
    ai_error_handling_enabled = bool(settings_store.get_setting("ai_error_handling_enabled"))
    ai_error_handling_uncensored = bool(settings_store.get_setting("ai_error_handling_uncensored"))
    ai_reporting_analysis_enabled = bool(
        settings_store.get_setting("ai_reporting_analysis_enabled")
    )
    ai_language = str(settings_store.get_setting("ai_language") or "en").strip().lower()
    saved_ai_system_prompt = str(settings_store.get_setting("ai_system_prompt") or "").strip()
    saved_ai_reporting_system_prompt = str(
        settings_store.get_setting("ai_reporting_system_prompt") or ""
    ).strip()
    default_error_system_prompt = get_default_error_system_prompt(ai_language)
    default_reporting_system_prompt = get_default_reporting_system_prompt(ai_language)

    # Pre-populate textbox with default prompt if none saved yet
    ai_system_prompt = saved_ai_system_prompt or default_error_system_prompt
    ai_reporting_system_prompt = saved_ai_reporting_system_prompt or default_reporting_system_prompt

    return render_template(
        "settings.html",
        active_page="settings",
        settings=resolved_settings,
        settings_list=settings_list,
        ldap_enabled=ldap_enabled,
        ldap_config=ldap_config,
        oidc_enabled=oidc_enabled,
        oidc_config=oidc_config,
        has_custom_login_bg=has_custom_login_bg,
        trusted_proxies=trusted_proxies,
        hooks_enabled=hooks_enabled,
        hooks_timeout_s=hooks_timeout_s,
        hook_runner_url=hook_runner_url,
        notifications_enabled=notifications_enabled,
        notification_job_policy=notification_job_policy,
        notification_proxy_offline_enabled=notification_proxy_offline_enabled,
        notification_rclone_update_enabled=notification_rclone_update_enabled,
        rclone_auto_update_check_enabled=rclone_auto_update_check_enabled,
        rclone_auto_update_check_interval_hours=rclone_auto_update_check_interval_hours,
        notification_channels=notification_channels,
        task_retries=task_retries,
        rclone_checkers=rclone_checkers,
        rclone_transfers=rclone_transfers,
        rclone_check_first=rclone_check_first,
        rclone_recurse=rclone_recurse,
        rclone_order_by=rclone_order_by,
        rclone_first_level_filters=rclone_first_level_filters,
        rclone_second_level_filters=rclone_second_level_filters,
        ai_enabled=ai_enabled,
        ai_provider_type=ai_provider_type,
        ai_endpoint_url=ai_endpoint_url,
        ai_model=ai_model,
        ai_timeout_seconds=ai_timeout_seconds,
        ai_has_api_key=ai_has_api_key,
        ai_error_handling_enabled=ai_error_handling_enabled,
        ai_error_handling_uncensored=ai_error_handling_uncensored,
        ai_reporting_analysis_enabled=ai_reporting_analysis_enabled,
        ai_language=ai_language,
        ai_system_prompt=ai_system_prompt,
        ai_reporting_system_prompt=ai_reporting_system_prompt,
        default_error_system_prompt=default_error_system_prompt,
        default_reporting_system_prompt=default_reporting_system_prompt,
        custom_app_name=str(settings_store.get_setting("custom_app_name") or "").strip(),
        has_custom_logo=bool(settings_store.get_setting("custom_logo")),
    )


@ui_bp.route("/users", methods=["GET"])
@require_auth
@require_permission("user.read", "role.read")
def users_view() -> str:
    """Users list and roles permissions matrix view."""
    session_factory = get_db()
    with session_factory() as session:
        user_list = UserRepository.list_users(session)
        roles = UserRepository.list_roles(session)
        matrix_data = UserRepository.get_permissions_matrix(session)

    user_perms: set[str] = getattr(g, "permissions", set())
    can_manage = "user.manage" in user_perms or "role.manage" in user_perms

    return render_template(
        "users.html",
        active_page="users",
        users=user_list,
        roles=roles,
        matrix_data=matrix_data,
        can_manage=can_manage,
    )


@ui_bp.route("/users/new", methods=["GET"])
@require_auth
@require_permission("user.manage")
def new_user() -> str:
    """Create new user form."""
    session_factory = get_db()
    with session_factory() as session:
        roles = UserRepository.list_roles(session)

    return render_template(
        "user_edit.html",
        active_page="users",
        is_edit=False,
        user=None,
        roles=roles,
    )


@ui_bp.route("/users/<uuid:user_id>/edit", methods=["GET"])
@require_auth
def edit_user(user_id: UUID) -> Any:
    """Edit user form (administrators can edit any user; operators can edit their own profile)."""
    current_u = get_current_user()
    user_perms: set[str] = getattr(g, "permissions", set())
    is_admin_manage = "user.manage" in user_perms
    is_self = current_u is not None and current_u.id == user_id

    if not is_admin_manage and not is_self:
        return (
            render_template(
                "error.html",
                error_code=403,
                error_title=_("error_access_denied_title"),
                error_message=_("error_cannot_edit_user_msg"),
            ),
            403,
        )

    session_factory = get_db()
    with session_factory() as session:
        user = UserRepository.get_user_by_id(session, user_id)
        if user is None:
            return (
                render_template(
                    "error.html",
                    error_code=404,
                    error_title=_("error_user_not_found_title"),
                    error_message=_("error_user_not_found_msg_tpl").format(user_id=user_id),
                ),
                404,
            )
        roles = UserRepository.list_roles(session)

    return render_template(
        "user_edit.html",
        active_page="users",
        is_edit=True,
        user=user,
        roles=roles,
        can_manage_roles=is_admin_manage,
    )


@ui_bp.route("/about", methods=["GET"])
@require_auth
def about() -> str:
    from embervault_app import __version__

    return render_template(
        "about.html",
        active_page="about",
        version=__version__,
    )


@ui_bp.route("/backup-restore", methods=["GET"])
@require_auth
@require_permission("backup.read")
def backup_restore() -> str:
    """Backup & Restore dashboard for administrators."""
    import os

    from embervault_db.backup import generate_backup_key, list_automated_backups
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

        backup_dir = str(auto_dir.value or "/backups").strip() if auto_dir else "/backups"
        config = {
            "enabled": bool(auto_enabled.value) if auto_enabled else False,
            "cron": str(auto_cron.value or "0 3 * * *") if auto_cron else "0 3 * * *",
            "key": str(auto_key.value or "") if auto_key else "",
            "dir": backup_dir,
            "include_history": bool(auto_history.value) if auto_history else False,
            "include_audit": bool(auto_audit.value) if auto_audit else False,
            "retention_days": int(auto_retention.value or 30) if auto_retention else 30,
            "last_run": str(last_run.value) if last_run and last_run.value else None,
        }

        backup_files = list_automated_backups(backup_dir)
        dir_exists = os.path.isdir(backup_dir)
        dir_writable = os.access(backup_dir, os.W_OK) if dir_exists else False

    suggested_export_key = generate_backup_key()

    return render_template(
        "backup_restore.html",
        active_page="backup_restore",
        config=config,
        backup_files=backup_files,
        dir_exists=dir_exists,
        dir_writable=dir_writable,
        suggested_export_key=suggested_export_key,
    )


@ui_bp.route("/errors", methods=["GET"])
@require_auth
@require_permission("job.read", "ai.diagnostics")
def errors_view() -> str:
    """View recent errors with AI diagnostic decisions, execution links, and pagination."""
    try:
        page = int(request.args.get("page", 1))
        if page < 1:
            page = 1
    except (ValueError, TypeError):
        page = 1

    per_page = 100

    session_factory = get_db()
    with session_factory() as session:
        # Fetch audit log errors
        audit_stmt = (
            select(AuditLog)
            .where(AuditLog.action.like("%error%"))
            .order_by(desc(AuditLog.ts))
        )
        audit_errors = list(session.scalars(audit_stmt).all())

        # Fetch failed task assignments
        failed_assignments_stmt = (
            select(TaskAssignment)
            .options(joinedload(TaskAssignment.task))
            .where(TaskAssignment.status == "failed")
            .order_by(desc(TaskAssignment.assigned_at))
        )
        failed_assignments = list(session.scalars(failed_assignments_stmt).all())

        # Collect run_ids to prefetch job information
        seen_assignment_ids: set[str] = set()
        error_items: list[dict[str, Any]] = []

        for log in audit_errors:
            details = log.details or {}
            run_id_str: str | None = None
            rid = details.get("run_id")
            if rid:
                run_id_str = str(rid)
            elif log.entity_type in ("job_run", "run") and log.entity_id:
                run_id_str = str(log.entity_id)

            aid = details.get("assignment_id")
            if aid:
                seen_assignment_ids.add(str(aid))

            source = f"Entity: {log.entity_type}" if log.entity_type else "System"

            is_ai = log.action == "ai.error_decision"
            ai_data = None
            if is_ai or "decision" in details:
                decision = str(details.get("decision", "fail")).lower()
                confidence = details.get("confidence")
                conf_pct = f"{round(float(confidence) * 100)}%" if confidence is not None else None
                ai_data = {
                    "decision": decision,
                    "confidence": confidence,
                    "confidence_pct": conf_pct,
                    "reason": details.get("reason", ""),
                    "interpretation": details.get("interpretation", ""),
                    "action_taken": details.get("action_taken", ""),
                    "raw_response": details.get("raw_response", ""),
                    "suggested_backoff_seconds": details.get("suggested_backoff_seconds"),
                }
                msg = details.get("interpretation") or details.get("reason") or log.action
            else:
                msg = (
                    details.get("error")
                    or details.get("message")
                    or details.get("reason")
                    or log.action
                )

            error_items.append(
                {
                    "id": f"audit-{log.id}",
                    "ts": log.ts,
                    "source": source,
                    "message": msg,
                    "run_id": run_id_str,
                    "run": None,
                    "has_ai": bool(ai_data),
                    "ai": ai_data,
                    "raw_details": details,
                    "action": log.action,
                }
            )

        for fa in failed_assignments:
            if str(fa.id) in seen_assignment_ids:
                continue

            run_id_str = str(fa.task.run_id) if fa.task and fa.task.run_id else None
            source = "Task Runner"
            err_label = fa.error_code or fa.error_class or "FAILURE"
            msg = f"Task {fa.task.kind if fa.task else 'execution'} error ({err_label})"

            error_items.append(
                {
                    "id": f"assignment-{fa.id}",
                    "ts": fa.finished_at or fa.assigned_at,
                    "source": source,
                    "message": msg,
                    "run_id": run_id_str,
                    "run": None,
                    "has_ai": False,
                    "ai": None,
                    "raw_details": {
                        "error_code": fa.error_code,
                        "error_class": fa.error_class,
                        "exit_code": fa.exit_code,
                        "errors_count": fa.errors_count,
                        "duration_ms": fa.duration_ms,
                    },
                    "action": "task.failure",
                }
            )

        # Sort all combined errors by timestamp desc
        error_items.sort(
            key=lambda x: x["ts"] if x["ts"] is not None else datetime.min.replace(tzinfo=UTC),
            reverse=True,
        )

        total_errors = len(error_items)
        total_pages = max(1, (total_errors + per_page - 1) // per_page)
        if page > total_pages:
            page = total_pages

        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        page_errors = error_items[start_idx:end_idx]

        # Batch load runs and job names for current page items only
        run_ids_to_fetch: set[UUID] = set()
        for item in page_errors:
            rid = item.get("run_id")
            if rid:
                try:
                    run_ids_to_fetch.add(UUID(str(rid)))
                except (ValueError, TypeError):
                    pass

        run_lookup: dict[UUID, JobRun] = {}
        if run_ids_to_fetch:
            runs = session.scalars(select(JobRun).where(JobRun.id.in_(run_ids_to_fetch))).all()
            for r in runs:
                run_lookup[r.id] = r

        for item in page_errors:
            rid = item.get("run_id")
            if rid:
                try:
                    run_obj = run_lookup.get(UUID(str(rid)))
                    if run_obj:
                        item["run"] = run_obj
                        job_name = (
                            run_obj.job.name
                            if run_obj.job
                            else run_obj.job_snapshot.get("name", "Job")
                        )
                        if job_name:
                            item["source"] = job_name
                except (ValueError, TypeError):
                    pass

    return render_template(
        "errors.html",
        active_page="errors",
        errors=page_errors,
        page=page,
        total_pages=total_pages,
        total_errors=total_errors,
        per_page=per_page,
    )


@ui_bp.route("/offline", methods=["GET"])
def offline() -> str:
    """Offline shell fallback rendered when client loses internet connectivity."""
    return render_template("offline.html")
