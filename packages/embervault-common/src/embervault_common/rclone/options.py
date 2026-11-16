"""RClone option resolution and inheritance between Job-specific settings and Global settings."""

from __future__ import annotations

from typing import Any

from embervault_common.rclone.filters import parse_filter_rules
from embervault_common.rclone.validator import sanitize_rclone_parameters


def resolve_job_rclone_options(
    job: Any,
    settings_store: Any,
) -> tuple[dict[str, Any], int]:
    """Resolve active RClone and task execution parameters for a Job run.

    Per specification:
    For every parameter, if the Job specifies a value, it overrides the global EmberVault setting.
    Otherwise, the parameter falls back to the global configuration in SettingsStore (or default).

    Returns:
        tuple of (resolved_options_dict, resolved_max_attempts)
    """
    job_opts = getattr(job, "rclone_options", None) or {}

    # 1. Retry count / Max attempts
    # Job max_attempts column or rclone_options["retry_count"]
    resolved_max_attempts: int
    if getattr(job, "max_attempts", None) is not None and job.max_attempts > 0:
        resolved_max_attempts = int(job.max_attempts)
    elif job_opts.get("retry_count") is not None:
        resolved_max_attempts = int(job_opts["retry_count"]) + 1
    elif job_opts.get("max_attempts") is not None:
        resolved_max_attempts = int(job_opts["max_attempts"])
    else:
        # Fall back to global SettingsStore
        g_retries = None
        if settings_store is not None:
            try:
                g_retries = settings_store.get_setting("task_retries")
            except Exception:
                g_retries = None

        if g_retries is not None:
            resolved_max_attempts = int(g_retries) + 1
        else:
            g_max_att = None
            if settings_store is not None:
                try:
                    g_max_att = settings_store.get_setting("task_max_attempts")
                except Exception:
                    g_max_att = None
            resolved_max_attempts = int(g_max_att or 3)

    # 2. Checkers (--checkers)
    if job_opts.get("checkers") is not None:
        resolved_checkers = int(job_opts["checkers"])
    else:
        g_chk = None
        if settings_store is not None:
            try:
                g_chk = settings_store.get_setting("rclone_checkers")
            except Exception:
                g_chk = None
        resolved_checkers = int(g_chk or 8)

    # 3. Transfers (--transfers)
    if job_opts.get("transfers") is not None:
        resolved_transfers = int(job_opts["transfers"])
    else:
        g_tr = None
        if settings_store is not None:
            try:
                g_tr = settings_store.get_setting("rclone_transfers")
            except Exception:
                g_tr = None
        resolved_transfers = int(g_tr or 4)

    # 4. Check First (--check-first)
    if job_opts.get("check_first") is not None:
        resolved_check_first = bool(job_opts["check_first"])
    else:
        g_cf = None
        if settings_store is not None:
            try:
                g_cf = settings_store.get_setting("rclone_check_first")
            except Exception:
                g_cf = None
        resolved_check_first = bool(g_cf or False)

    # 5. Recurse (--recurse / --max-depth 1 when false)
    if job_opts.get("recurse") is not None:
        resolved_recurse = bool(job_opts["recurse"])
    else:
        g_rec = None
        if settings_store is not None:
            try:
                g_rec = settings_store.get_setting("rclone_recurse")
            except Exception:
                g_rec = None
        resolved_recurse = bool(g_rec) if g_rec is not None else True

    # 6. Order By (--order-by)
    if job_opts.get("order_by"):
        resolved_order_by = str(job_opts["order_by"]).strip()
    elif job_opts.get("order-by"):
        resolved_order_by = str(job_opts["order-by"]).strip()
    elif job_opts.get("OrderBy"):
        resolved_order_by = str(job_opts["OrderBy"]).strip()
    else:
        g_ob = None
        if settings_store is not None:
            try:
                g_ob = settings_store.get_setting("rclone_order_by")
            except Exception:
                g_ob = None
        resolved_order_by = str(g_ob or "").strip()

    # 7. First Level Filters
    if job_opts.get("first_level_filters") is not None:
        resolved_f1 = parse_filter_rules(job_opts["first_level_filters"])
    else:
        g_f1 = None
        if settings_store is not None:
            try:
                g_f1 = settings_store.get_setting("rclone_first_level_filters")
            except Exception:
                g_f1 = None
        resolved_f1 = parse_filter_rules(g_f1)

    # 8. Second Level Filters
    if job_opts.get("second_level_filters") is not None:
        resolved_f2 = parse_filter_rules(job_opts["second_level_filters"])
    else:
        g_f2 = None
        if settings_store is not None:
            try:
                g_f2 = settings_store.get_setting("rclone_second_level_filters")
            except Exception:
                g_f2 = None
        resolved_f2 = parse_filter_rules(g_f2)

    # 9. Additional Parameters
    raw_additional = (
        job_opts.get("additional_args")
        if job_opts.get("additional_args") is not None
        else job_opts.get("additional_params")
    )
    if raw_additional is None:
        raw_additional = job_opts.get("extra_args")
    resolved_additional_args = sanitize_rclone_parameters(raw_additional)

    resolved_options = {
        "retry_count": max(0, resolved_max_attempts - 1),
        "max_attempts": resolved_max_attempts,
        "checkers": resolved_checkers,
        "transfers": resolved_transfers,
        "check_first": resolved_check_first,
        "recurse": resolved_recurse,
        "order_by": resolved_order_by,
        "first_level_filters": resolved_f1,
        "second_level_filters": resolved_f2,
        "additional_args": resolved_additional_args,
    }

    return resolved_options, resolved_max_attempts
