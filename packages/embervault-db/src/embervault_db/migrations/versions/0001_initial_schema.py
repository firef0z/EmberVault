"""0001_initial_schema

Revision ID: 0001
Revises:
Create Date: 2026-10-16 18:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. roles
    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=50), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_system", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_roles")),
        sa.UniqueConstraint("name", name=op.f("uq_roles_name")),
    )

    # 2. permissions
    op.create_table(
        "permissions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("code", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_permissions")),
        sa.UniqueConstraint("code", name=op.f("uq_permissions_code")),
    )

    # 3. role_permissions
    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("permission_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permissions.id"],
            name=op.f("fk_role_permissions_permission_id_permissions"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name=op.f("fk_role_permissions_role_id_roles"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("role_id", "permission_id", name=op.f("pk_role_permissions")),
    )

    # 4. users
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=100), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("auth_source", sa.String(length=20), nullable=False),
        sa.Column("external_subject", sa.String(length=255), nullable=True),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("must_change_password", sa.Boolean(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "auth_source IN ('local', 'ldap', 'oidc')",
            name=op.f("ck_users_ck_users_auth_source"),
        ),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], name=op.f("fk_users_role_id_roles")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
        sa.UniqueConstraint(
            "auth_source",
            "external_subject",
            name=op.f("uq_users_uq_users_auth_source_external_subject"),
        ),
    )

    # 5. user_sessions
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("mfa_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_sessions")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_user_sessions_token_hash")),
    )

    # 6. user_mfa_factors
    op.create_table(
        "user_mfa_factors",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("type", sa.String(length=20), nullable=False),
        sa.Column("secret_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("label", sa.String(length=100), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "type IN ('totp', 'webauthn')",
            name=op.f("ck_user_mfa_factors_ck_user_mfa_factors_type"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_mfa_factors_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_mfa_factors")),
    )

    # 7. user_recovery_codes
    op.create_table(
        "user_recovery_codes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.String(length=128), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_user_recovery_codes_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_recovery_codes")),
    )

    # 8. audit_log
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_user_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("entity_type", sa.String(length=100), nullable=False),
        sa.Column("entity_id", sa.String(length=100), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name=op.f("fk_audit_log_actor_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log")),
    )
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"], unique=False)

    # 9. settings
    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=100), nullable=False),
        sa.Column("value", sa.JSON(), nullable=True),
        sa.Column("value_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["updated_by"],
            ["users.id"],
            name=op.f("fk_settings_updated_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("key", name=op.f("pk_settings")),
    )

    # 10. rclone_remotes
    op.create_table(
        "rclone_remotes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("backend_type", sa.String(length=50), nullable=False),
        sa.Column("config_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("public_params", sa.JSON(), nullable=False),
        sa.Column("secret_field_names", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_rclone_remotes_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_rclone_remotes")),
        sa.UniqueConstraint("name", name=op.f("uq_rclone_remotes_name")),
    )

    # 11. jobs
    op.create_table(
        "jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("source_remote_id", sa.Uuid(), nullable=False),
        sa.Column("source_path", sa.Text(), nullable=False),
        sa.Column("destination_remote_id", sa.Uuid(), nullable=False),
        sa.Column("destination_path", sa.Text(), nullable=False),
        sa.Column("source_kind", sa.String(length=20), nullable=False),
        sa.Column("operation", sa.String(length=20), nullable=False),
        sa.Column("parallelization", sa.String(length=20), nullable=False),
        sa.Column("discovery_status", sa.String(length=20), nullable=False),
        sa.Column("last_discovery_id", sa.Uuid(), nullable=True),
        sa.Column("max_parallel_tasks", sa.Integer(), nullable=True),
        sa.Column("files_per_task", sa.Integer(), nullable=True),
        sa.Column("schedule_cron", sa.String(length=100), nullable=True),
        sa.Column("timezone", sa.String(length=50), nullable=False),
        sa.Column("missed_run_policy", sa.String(length=20), nullable=False),
        sa.Column("overlap_policy", sa.String(length=20), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=True),
        sa.Column("task_timeout_s", sa.Integer(), nullable=True),
        sa.Column("parallel_ack_task_count", sa.Integer(), nullable=True),
        sa.Column("rclone_options", sa.JSON(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "discovery_status IN ('not_required', 'unverified', 'verified')",
            name=op.f("ck_jobs_ck_jobs_discovery_status"),
        ),
        sa.CheckConstraint(
            "missed_run_policy IN ('skip', 'run_once')",
            name=op.f("ck_jobs_ck_jobs_missed_run_policy"),
        ),
        sa.CheckConstraint(
            "operation IN ('copy', 'sync')",
            name=op.f("ck_jobs_ck_jobs_operation"),
        ),
        sa.CheckConstraint(
            "overlap_policy IN ('skip', 'queue', 'fail')",
            name=op.f("ck_jobs_ck_jobs_overlap_policy"),
        ),
        sa.CheckConstraint(
            "parallelization IN ('none', 'by_subfolder')",
            name=op.f("ck_jobs_ck_jobs_parallelization"),
        ),
        sa.CheckConstraint(
            "source_kind IN ('folder', 'files')",
            name=op.f("ck_jobs_ck_jobs_source_kind"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            name=op.f("fk_jobs_created_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["destination_remote_id"],
            ["rclone_remotes.id"],
            name=op.f("fk_jobs_destination_remote_id_rclone_remotes"),
        ),
        sa.ForeignKeyConstraint(
            ["source_remote_id"],
            ["rclone_remotes.id"],
            name=op.f("fk_jobs_source_remote_id_rclone_remotes"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_jobs")),
        sa.UniqueConstraint("name", name=op.f("uq_jobs_name")),
    )

    # 12. job_sources
    op.create_table(
        "job_sources",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=10), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "kind IN ('dir', 'file')", name=op.f("ck_job_sources_ck_job_sources_kind")
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["jobs.id"],
            name=op.f("fk_job_sources_job_id_jobs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_job_sources")),
    )

    # 13. job_discoveries
    op.create_table(
        "job_discoveries",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=True),
        sa.Column("source_remote_id", sa.Uuid(), nullable=False),
        sa.Column("source_remote_version", sa.Integer(), nullable=False),
        sa.Column("source_path", sa.Text(), nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=True),
        sa.Column("trigger", sa.String(length=20), nullable=False),
        sa.Column("proxy_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("folder_count", sa.Integer(), nullable=False),
        sa.Column("root_file_count", sa.Integer(), nullable=False),
        sa.Column("task_count_estimate", sa.Integer(), nullable=False),
        sa.Column("level", sa.String(length=10), nullable=False),
        sa.Column("entries", sa.JSON(), nullable=True),
        sa.Column("error_code", sa.String(length=50), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "level IN ('ok', 'warn', 'blocked')",
            name=op.f("ck_job_discoveries_ck_job_discoveries_level"),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'succeeded', 'failed')",
            name=op.f("ck_job_discoveries_ck_job_discoveries_status"),
        ),
        sa.CheckConstraint(
            "trigger IN ('job_form', 'run_start', 'manual')",
            name=op.f("ck_job_discoveries_ck_job_discoveries_trigger"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["jobs.id"],
            name=op.f("fk_job_discoveries_job_id_jobs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"],
            ["users.id"],
            name=op.f("fk_job_discoveries_requested_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["source_remote_id"],
            ["rclone_remotes.id"],
            name=op.f("fk_job_discoveries_source_remote_id_rclone_remotes"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_job_discoveries")),
    )

    # 14. proxies
    op.create_table(
        "proxies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("token_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("cert_fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("fingerprint_confirmed_by", sa.Uuid(), nullable=True),
        sa.Column("fingerprint_confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("max_concurrent_tasks", sa.Integer(), nullable=False),
        sa.Column("proxy_version", sa.String(length=50), nullable=True),
        sa.Column("rclone_version", sa.String(length=50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["fingerprint_confirmed_by"],
            ["users.id"],
            name=op.f("fk_proxies_fingerprint_confirmed_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_proxies")),
        sa.UniqueConstraint("host", "port", name=op.f("uq_proxies_host_port")),
        sa.UniqueConstraint("name", name=op.f("uq_proxies_name")),
    )

    # 15. proxy_status
    op.create_table(
        "proxy_status",
        sa.Column("proxy_id", sa.Uuid(), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("consecutive_successes", sa.Integer(), nullable=False),
        sa.Column("cooldown_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("running_tasks", sa.Integer(), nullable=False),
        sa.Column("capacity", sa.Integer(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("last_error_code", sa.String(length=50), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "state IN ('unknown', 'online', 'offline', 'unauthorized', 'untrusted', 'cooldown')",
            name=op.f("ck_proxy_status_ck_proxy_status_state"),
        ),
        sa.ForeignKeyConstraint(
            ["proxy_id"],
            ["proxies.id"],
            name=op.f("fk_proxy_status_proxy_id_proxies"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("proxy_id", name=op.f("pk_proxy_status")),
    )

    # 16. proxy_state_events
    op.create_table(
        "proxy_state_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("proxy_id", sa.Uuid(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("from_state", sa.String(length=20), nullable=False),
        sa.Column("to_state", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["proxy_id"],
            ["proxies.id"],
            name=op.f("fk_proxy_state_events_proxy_id_proxies"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_proxy_state_events")),
    )

    # 17. job_runs
    op.create_table(
        "job_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("trigger", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("requested_by", sa.Uuid(), nullable=True),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("job_snapshot", sa.JSON(), nullable=False),
        sa.Column("planned_task_count", sa.Integer(), nullable=False),
        sa.Column("warning_code", sa.String(length=50), nullable=True),
        sa.Column("ack_by", sa.Uuid(), nullable=True),
        sa.Column("ack_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=50), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("bytes_transferred", sa.BigInteger(), nullable=False),
        sa.Column("files_transferred", sa.BigInteger(), nullable=False),
        sa.Column("tasks_succeeded", sa.Integer(), nullable=False),
        sa.Column("tasks_failed", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('queued', 'planning', 'awaiting_confirmation', 'running', 'succeeded', 'partially_failed', 'failed', 'cancelled')",
            name=op.f("ck_job_runs_ck_job_runs_status"),
        ),
        sa.CheckConstraint(
            "trigger IN ('schedule', 'manual', 'api')",
            name=op.f("ck_job_runs_ck_job_runs_trigger"),
        ),
        sa.ForeignKeyConstraint(
            ["ack_by"],
            ["users.id"],
            name=op.f("fk_job_runs_ack_by_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["jobs.id"],
            name=op.f("fk_job_runs_job_id_jobs"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"],
            ["users.id"],
            name=op.f("fk_job_runs_requested_by_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_job_runs")),
    )
    op.create_index(
        "ix_job_runs_one_active_per_job",
        "job_runs",
        ["job_id"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('queued', 'planning', 'awaiting_confirmation', 'running')"
        ),
        sqlite_where=sa.text(
            "status IN ('queued', 'planning', 'awaiting_confirmation', 'running')"
        ),
    )

    # 18. tasks
    op.create_table(
        "tasks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("scope", sa.String(length=20), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("spec", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ready_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=50), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("kind IN ('discover', 'transfer')", name=op.f("ck_tasks_ck_tasks_kind")),
        sa.CheckConstraint(
            "scope IN ('whole', 'root_files', 'subfolder', 'files')",
            name=op.f("ck_tasks_ck_tasks_scope"),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'ready', 'assigned', 'running', 'retry_wait', 'succeeded', 'failed', 'cancelled')",
            name=op.f("ck_tasks_ck_tasks_status"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["job_runs.id"],
            name=op.f("fk_tasks_run_id_job_runs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tasks")),
    )
    op.create_index(
        "ix_tasks_status_next_attempt",
        "tasks",
        ["status", "next_attempt_at"],
        unique=False,
    )

    # 19. task_assignments
    op.create_table(
        "task_assignments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("attempt_no", sa.Integer(), nullable=False),
        sa.Column("proxy_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("error_class", sa.String(length=30), nullable=True),
        sa.Column("error_code", sa.String(length=50), nullable=True),
        sa.Column("bytes_transferred", sa.BigInteger(), nullable=False),
        sa.Column("files_transferred", sa.BigInteger(), nullable=False),
        sa.Column("errors_count", sa.Integer(), nullable=False),
        sa.Column("checks_count", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "error_class IS NULL OR error_class IN ('temporary', 'permanent', 'timeout', 'proxy_unreachable', 'lost')",
            name=op.f("ck_task_assignments_ck_task_assignments_error_class"),
        ),
        sa.CheckConstraint(
            "status IN ('assigned', 'dispatched', 'running', 'succeeded', 'failed', 'cancelled')",
            name=op.f("ck_task_assignments_ck_task_assignments_status"),
        ),
        sa.ForeignKeyConstraint(
            ["proxy_id"],
            ["proxies.id"],
            name=op.f("fk_task_assignments_proxy_id_proxies"),
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_task_assignments_task_id_tasks"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_assignments")),
        sa.UniqueConstraint("task_id", "attempt_no", name=op.f("uq_task_assignments_task_attempt")),
    )

    # 20. task_logs
    op.create_table(
        "task_logs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("assignment_id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("level", sa.String(length=20), nullable=False),
        sa.Column("stream", sa.String(length=10), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "stream IN ('stdout', 'stderr', 'system')",
            name=op.f("ck_task_logs_ck_task_logs_stream"),
        ),
        sa.ForeignKeyConstraint(
            ["assignment_id"],
            ["task_assignments.id"],
            name=op.f("fk_task_logs_assignment_id_task_assignments"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["job_runs.id"],
            name=op.f("fk_task_logs_run_id_job_runs"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_task_logs_task_id_tasks"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_logs")),
    )
    op.create_index(
        "ix_task_logs_assignment_seq", "task_logs", ["assignment_id", "seq"], unique=False
    )

    # 21. error_events
    op.create_table(
        "error_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("component", sa.String(length=20), nullable=False),
        sa.Column("error_code", sa.String(length=50), nullable=False),
        sa.Column("error_class", sa.String(length=50), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("task_id", sa.Uuid(), nullable=True),
        sa.Column("assignment_id", sa.Uuid(), nullable=True),
        sa.Column("proxy_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "component IN ('app', 'orchestrator', 'proxy')",
            name=op.f("ck_error_events_ck_error_events_component"),
        ),
        sa.ForeignKeyConstraint(
            ["assignment_id"],
            ["task_assignments.id"],
            name=op.f("fk_error_events_assignment_id_task_assignments"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["proxy_id"],
            ["proxies.id"],
            name=op.f("fk_error_events_proxy_id_proxies"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["job_runs.id"],
            name=op.f("fk_error_events_run_id_job_runs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
            name=op.f("fk_error_events_task_id_tasks"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_error_events")),
    )
    op.create_index("ix_error_events_ts", "error_events", ["ts"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_error_events_ts", table_name="error_events")
    op.drop_table("error_events")
    op.drop_index("ix_task_logs_assignment_seq", table_name="task_logs")
    op.drop_table("task_logs")
    op.drop_table("task_assignments")
    op.drop_index("ix_tasks_status_next_attempt", table_name="tasks")
    op.drop_table("tasks")
    op.drop_index("ix_job_runs_one_active_per_job", table_name="job_runs")
    op.drop_table("job_runs")
    op.drop_table("proxy_state_events")
    op.drop_table("proxy_status")
    op.drop_table("proxies")
    op.drop_table("job_discoveries")
    op.drop_table("job_sources")
    op.drop_table("jobs")
    op.drop_table("rclone_remotes")
    op.drop_table("settings")
    op.drop_index("ix_audit_log_ts", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_table("user_recovery_codes")
    op.drop_table("user_mfa_factors")
    op.drop_table("user_sessions")
    op.drop_table("users")
    op.drop_table("role_permissions")
    op.drop_table("permissions")
    op.drop_table("roles")
