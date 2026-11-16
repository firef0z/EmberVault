"""Backup and restore engine for EmberVault configuration and data.

Provides encrypted backup export and restore using AES-256-GCM with HKDF key derivation,
including proxies, remotes with decrypted passwords, jobs, settings, users, and optionally
audit logs and execution history.
"""

from __future__ import annotations

import contextlib
import gzip
import json
import os
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.observability import get_logger
from embervault_db.models.auth import AuditLog, Role, Setting, User
from embervault_db.models.execution import JobRun, JobRunHook, Task, TaskAssignment
from embervault_db.models.notifications import NotificationChannel
from embervault_db.models.proxy import Proxy
from embervault_db.models.remotes import Job, JobSource, RcloneRemote
from embervault_db.repositories.notification_repository import NotificationRepository
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.repositories.remote_repository import RemoteRepository

logger = get_logger("embervault_db.backup")

# Header constants for EmberVault encrypted backups
BACKUP_MAGIC = b"EVBK"
BACKUP_VERSION = 1
BACKUP_HEADER_AAD = b"EVBK\x01"
SALT_LENGTH = 16
NONCE_LENGTH = 12
TAG_LENGTH = 16
MIN_BACKUP_SIZE = len(BACKUP_MAGIC) + 1 + SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH


class BackupError(Exception):
    """Base exception for backup and restore operations."""


class BackupDecryptionError(BackupError):
    """Raised when backup file cannot be decrypted or authentication tag fails."""


class InvalidBackupFormatError(BackupError):
    """Raised when backup file is corrupted or not a valid EmberVault backup."""


def generate_backup_key() -> str:
    """Generate a cryptographically secure 256-bit hexadecimal encryption key."""
    return secrets.token_hex(32)


def _derive_backup_key(passphrase: str, salt: bytes) -> bytes:
    """Derive 32-byte AES key from user passphrase/key string using HKDF-SHA256."""
    clean = passphrase.strip().encode("utf-8")
    if not clean:
        raise BackupError("La chiave di crittografia non può essere vuota.")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"embervault-backup-v1",
    )
    return hkdf.derive(clean)


def encrypt_backup_payload(payload_bytes: bytes, key: str) -> bytes:
    """Compress and encrypt backup payload into a standalone EVBK binary blob."""
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    derived_key = _derive_backup_key(key, salt)

    compressed = gzip.compress(payload_bytes, compresslevel=6)
    aesgcm = AESGCM(derived_key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, compressed, associated_data=BACKUP_HEADER_AAD)

    return BACKUP_MAGIC + bytes([BACKUP_VERSION]) + salt + nonce + ciphertext_and_tag


def decrypt_backup_payload(encrypted_blob: bytes, key: str) -> bytes:
    """Validate, decrypt and decompress an EVBK binary blob back into payload bytes."""
    if len(encrypted_blob) < MIN_BACKUP_SIZE:
        raise InvalidBackupFormatError("Dimensione del file di backup non valida o file tronco.")

    if encrypted_blob[:4] != BACKUP_MAGIC:
        raise InvalidBackupFormatError("Formato non valido: intestazione EVBK mancante.")

    version = encrypted_blob[4]
    if version != BACKUP_VERSION:
        raise InvalidBackupFormatError(f"Versione di backup non supportata: {version}.")

    salt = encrypted_blob[5 : 5 + SALT_LENGTH]
    nonce = encrypted_blob[5 + SALT_LENGTH : 5 + SALT_LENGTH + NONCE_LENGTH]
    ciphertext_and_tag = encrypted_blob[5 + SALT_LENGTH + NONCE_LENGTH :]

    try:
        derived_key = _derive_backup_key(key, salt)
        aesgcm = AESGCM(derived_key)
        compressed = aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data=BACKUP_HEADER_AAD)
        return gzip.decompress(compressed)
    except InvalidTag as exc:
        raise BackupDecryptionError("Chiave di decrittografia errata o file danneggiato.") from exc
    except Exception as exc:
        if isinstance(exc, BackupDecryptionError):
            raise
        raise BackupError(f"Impossibile elaborare il file di backup: {exc}") from exc


def create_backup_archive(
    session: Session,
    key: str,
    include_audit: bool = False,
    include_history: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    """Export all configurations, remotes with credentials, proxies, jobs, and optional logs."""
    stats: dict[str, int] = {
        "proxies": 0,
        "remotes": 0,
        "jobs": 0,
        "settings": 0,
        "notification_channels": 0,
        "users": 0,
        "audit_logs": 0,
        "execution_history": 0,
    }

    # 1. Proxies
    proxies_list = []
    for p in session.scalars(select(Proxy).order_by(Proxy.name)).unique().all():
        token = ""
        try:
            token = ProxyRepository.decrypt_token(p.token_encrypted, p.id)
        except Exception as exc:
            logger.warning("proxy_token_decrypt_failed", proxy_id=str(p.id), error=str(exc))
        proxies_list.append(
            {
                "id": str(p.id),
                "name": p.name,
                "host": p.host,
                "port": p.port,
                "token": token,
                "cert_fingerprint_sha256": p.cert_fingerprint_sha256,
                "is_enabled": p.is_enabled,
                "max_concurrent_tasks": p.max_concurrent_tasks,
                "proxy_version": p.proxy_version,
                "rclone_version": p.rclone_version,
            }
        )
    stats["proxies"] = len(proxies_list)

    # 2. Remotes with full decrypted configs
    remotes_list = []
    for r in session.scalars(select(RcloneRemote).order_by(RcloneRemote.name)).unique().all():
        full_cfg = {}
        try:
            full_cfg = RemoteRepository.get_decrypted_config(r)
        except Exception as exc:
            logger.warning("remote_config_decrypt_failed", remote_id=str(r.id), error=str(exc))
        remotes_list.append(
            {
                "id": str(r.id),
                "name": r.name,
                "backend_type": r.backend_type,
                "is_enabled": r.is_enabled,
                "public_params": r.public_params,
                "full_config": full_cfg,
                "allowed_roles": [role.name for role in (r.roles or [])],
            }
        )
    stats["remotes"] = len(remotes_list)

    # 3. Jobs with sources, assigned proxies, and schedules
    jobs_list = []
    for j in session.scalars(select(Job).order_by(Job.name)).unique().all():
        assigned_names = [p.name for p in (j.assigned_proxies or [])]
        sources = [
            {"kind": s.kind, "path": s.path, "position": s.position} for s in (j.sources or [])
        ]
        jobs_list.append(
            {
                "id": str(j.id),
                "name": j.name,
                "enabled": j.enabled,
                "notifications_enabled": j.notifications_enabled,
                "notification_policy": j.notification_policy,
                "source_remote_name": j.source_remote.name if j.source_remote else None,
                "source_path": j.source_path,
                "destination_remote_name": (
                    j.destination_remote.name if j.destination_remote else None
                ),
                "destination_path": j.destination_path,
                "source_kind": j.source_kind,
                "operation": j.operation,
                "parallelization": j.parallelization,
                "discovery_status": j.discovery_status,
                "max_parallel_tasks": j.max_parallel_tasks,
                "files_per_task": j.files_per_task,
                "schedule_cron": j.schedule_cron,
                "timezone": j.timezone,
                "follow_dst": bool(getattr(j, "follow_dst", True)),
                "missed_run_policy": j.missed_run_policy,
                "overlap_policy": j.overlap_policy,
                "pending_policy": getattr(j, "pending_policy", "fail"),
                "max_runtime_minutes": getattr(j, "max_runtime_minutes", None),
                "missed_run_notify": bool(getattr(j, "missed_run_notify", False)),
                "overlap_notify": bool(getattr(j, "overlap_notify", False)),
                "pending_notify": bool(getattr(j, "pending_notify", False)),
                "max_runtime_notify": bool(getattr(j, "max_runtime_notify", False)),
                "max_attempts": j.max_attempts,
                "task_timeout_s": j.task_timeout_s,
                "parallel_ack_task_count": j.parallel_ack_task_count,
                "rclone_options": j.rclone_options,
                "pre_run_hook": j.pre_run_hook,
                "post_run_hook": j.post_run_hook,
                "assigned_proxy_names": assigned_names,
                "sources": sources,
            }
        )
    stats["jobs"] = len(jobs_list)

    # 4. Notification Channels
    channels_list = []
    for c in session.scalars(select(NotificationChannel).order_by(NotificationChannel.name)).all():
        url = ""
        try:
            url = NotificationRepository.decrypt_url(c.url_encrypted, c.id)
        except Exception as exc:
            logger.warning("channel_url_decrypt_failed", channel_id=str(c.id), error=str(exc))
        channels_list.append(
            {
                "id": str(c.id),
                "name": c.name,
                "enabled": c.enabled,
                "channel_type": c.channel_type,
                "url": url,
                "telegram_format": c.telegram_format,
                "rate_limit_interval_s": c.rate_limit_interval_s,
                "config_metadata": c.config_metadata,
            }
        )
    stats["notification_channels"] = len(channels_list)

    # 5. Settings
    settings_list = []
    for s in session.scalars(select(Setting).order_by(Setting.key)).all():
        if s.key in ("master_key", "secret_key"):
            continue
        settings_list.append(
            {
                "key": s.key,
                "value": s.value,
            }
        )
    stats["settings"] = len(settings_list)

    # 6. Users and Roles
    users_list = []
    for u in session.scalars(select(User).order_by(User.username)).all():
        users_list.append(
            {
                "id": str(u.id),
                "username": u.username,
                "email": u.email,
                "display_name": u.display_name,
                "password_hash": u.password_hash,
                "auth_source": u.auth_source,
                "is_active": u.is_active,
                "theme": u.theme,
                "role_name": u.role.name if u.role else "viewer",
            }
        )
    stats["users"] = len(users_list)

    # 7. Audit Logs (optional)
    audit_list = []
    if include_audit:
        for a in session.scalars(select(AuditLog).order_by(AuditLog.id.asc())).all():
            audit_list.append(
                {
                    "action": a.action,
                    "actor_user_id": str(a.actor_user_id) if a.actor_user_id else None,
                    "entity_type": a.entity_type,
                    "entity_id": a.entity_id,
                    "details": a.details,
                    "ip": a.ip,
                    "ts": a.ts.isoformat() if a.ts else None,
                }
            )
        stats["audit_logs"] = len(audit_list)

    # 8. Execution History (optional)
    runs_list = []
    if include_history:
        for r in session.scalars(select(JobRun).order_by(JobRun.id.asc())).unique().all():
            tasks_list = []
            for t in r.tasks or []:
                asg_list = []
                for asgn in t.assignments or []:
                    asg_list.append(
                        {
                            "id": str(asgn.id),
                            "attempt_no": asgn.attempt_no,
                            "proxy_name": asgn.proxy.name if asgn.proxy else None,
                            "status": asgn.status,
                            "assigned_at": asgn.assigned_at.isoformat()
                            if asgn.assigned_at
                            else None,
                            "started_at": asgn.started_at.isoformat() if asgn.started_at else None,
                            "finished_at": asgn.finished_at.isoformat()
                            if asgn.finished_at
                            else None,
                            "exit_code": asgn.exit_code,
                            "error_class": asgn.error_class,
                            "error_code": asgn.error_code,
                            "bytes_transferred": asgn.bytes_transferred,
                            "files_transferred": asgn.files_transferred,
                            "checks_count": asgn.checks_count,
                            "duration_ms": asgn.duration_ms,
                        }
                    )
                tasks_list.append(
                    {
                        "id": str(t.id),
                        "kind": t.kind,
                        "scope": t.scope,
                        "seq": t.seq,
                        "spec": t.spec,
                        "status": t.status,
                        "attempt_count": t.attempt_count,
                        "max_attempts": t.max_attempts,
                        "ready_at": t.ready_at.isoformat() if t.ready_at else None,
                        "finished_at": t.finished_at.isoformat() if t.finished_at else None,
                        "assignments": asg_list,
                    }
                )
            hooks_list = []
            for h in r.hooks or []:
                hooks_list.append(
                    {
                        "hook_type": h.hook_type,
                        "status": h.status,
                        "exit_code": h.exit_code,
                        "duration_ms": h.duration_ms,
                        "output": h.output,
                        "script_hash": h.script_hash,
                        "executed_at": h.executed_at.isoformat()
                        if getattr(h, "executed_at", None)
                        else None,
                    }
                )
            runs_list.append(
                {
                    "id": str(r.id),
                    "job_name": r.job.name if r.job else r.job_snapshot.get("name"),
                    "trigger": r.trigger,
                    "status": r.status,
                    "scheduled_for": r.scheduled_for.isoformat() if r.scheduled_for else None,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                    "job_snapshot": r.job_snapshot,
                    "planned_task_count": r.planned_task_count,
                    "warning_code": r.warning_code,
                    "bytes_transferred": r.bytes_transferred,
                    "files_transferred": r.files_transferred,
                    "tasks_succeeded": r.tasks_succeeded,
                    "tasks_failed": r.tasks_failed,
                    "error_code": r.error_code,
                    "error_message": r.error_message,
                    "tasks": tasks_list,
                    "hooks": hooks_list,
                }
            )
        stats["execution_history"] = len(runs_list)

    payload_data = {
        "version": 1,
        "format": "embervault_backup",
        "created_at": datetime.now(UTC).isoformat(),
        "embervault_version": "1.0.0",
        "includes": {
            "audit_logs": include_audit,
            "execution_history": include_history,
        },
        "stats": stats,
        "entities": {
            "proxies": proxies_list,
            "remotes": remotes_list,
            "jobs": jobs_list,
            "notification_channels": channels_list,
            "settings": settings_list,
            "users": users_list,
            "audit_logs": audit_list,
            "execution_history": runs_list,
        },
    }

    raw_json = json.dumps(payload_data, default=str, ensure_ascii=False)
    encrypted_blob = encrypt_backup_payload(raw_json.encode("utf-8"), key)
    return encrypted_blob, stats


def inspect_backup_archive(backup_bytes: bytes, key: str) -> dict[str, Any]:
    """Inspect and return metadata from an encrypted backup file without restoring."""
    decrypted_bytes = decrypt_backup_payload(backup_bytes, key)
    try:
        data = json.loads(decrypted_bytes.decode("utf-8"))
    except Exception as exc:
        raise InvalidBackupFormatError(f"Contenuto JSON non valido nel backup: {exc}") from exc

    if not isinstance(data, dict) or data.get("format") != "embervault_backup":
        raise InvalidBackupFormatError("Formato archivio non riconosciuto come backup EmberVault.")

    entities = data.get("entities", {})
    return {
        "version": data.get("version", 1),
        "created_at": data.get("created_at"),
        "embervault_version": data.get("embervault_version"),
        "includes": data.get("includes", {}),
        "stats": {
            "proxies": len(entities.get("proxies", [])),
            "remotes": len(entities.get("remotes", [])),
            "jobs": len(entities.get("jobs", [])),
            "notification_channels": len(entities.get("notification_channels", [])),
            "settings": len(entities.get("settings", [])),
            "users": len(entities.get("users", [])),
            "audit_logs": len(entities.get("audit_logs", [])),
            "execution_history": len(entities.get("execution_history", [])),
        },
    }


def restore_backup_archive(
    session: Session,
    backup_bytes: bytes,
    key: str,
    restore_audit: bool = False,
    restore_history: bool = False,
    current_admin_username: str | None = None,
) -> dict[str, int]:
    """Decrypt and restore EmberVault configuration and data idempotently."""
    decrypted_bytes = decrypt_backup_payload(backup_bytes, key)
    try:
        data = json.loads(decrypted_bytes.decode("utf-8"))
    except Exception as exc:
        raise InvalidBackupFormatError(f"Contenuto JSON non valido nel backup: {exc}") from exc

    entities = data.get("entities", {})
    restored_stats = {
        "proxies": 0,
        "remotes": 0,
        "jobs": 0,
        "notification_channels": 0,
        "settings": 0,
        "users": 0,
        "audit_logs": 0,
        "execution_history": 0,
    }

    # 1. Restore Settings
    settings_data = entities.get("settings", [])
    for s_item in settings_data:
        s_key = s_item.get("key")
        s_val = s_item.get("value")
        if not s_key or s_key in ("master_key", "secret_key"):
            continue
        existing_s = session.get(Setting, s_key)
        if existing_s:
            existing_s.value = s_val
            existing_s.updated_at = datetime.now(UTC)
        else:
            session.add(
                Setting(
                    key=s_key,
                    value=s_val,
                    updated_at=datetime.now(UTC),
                )
            )
        restored_stats["settings"] += 1

    # 2. Restore Notification Channels
    channels_data = entities.get("notification_channels", [])
    for c_item in channels_data:
        c_name = c_item.get("name")
        c_url = c_item.get("url", "")
        if not c_name:
            continue
        existing_c = session.scalar(
            select(NotificationChannel).where(NotificationChannel.name == c_name)
        )
        if existing_c:
            existing_c.enabled = bool(c_item.get("enabled", True))
            existing_c.channel_type = c_item.get("channel_type", "custom")
            existing_c.telegram_format = c_item.get("telegram_format", "html")
            existing_c.rate_limit_interval_s = int(c_item.get("rate_limit_interval_s", 0))
            existing_c.config_metadata = c_item.get("config_metadata", {})
            if c_url:
                existing_c.url_encrypted = NotificationRepository.encrypt_url(c_url, existing_c.id)
        else:
            new_id = uuid4()
            url_enc = NotificationRepository.encrypt_url(c_url, new_id) if c_url else b""
            session.add(
                NotificationChannel(
                    id=new_id,
                    name=c_name,
                    enabled=bool(c_item.get("enabled", True)),
                    channel_type=c_item.get("channel_type", "custom"),
                    url_encrypted=url_enc,
                    telegram_format=c_item.get("telegram_format", "html"),
                    rate_limit_interval_s=int(c_item.get("rate_limit_interval_s", 0)),
                    config_metadata=c_item.get("config_metadata", {}),
                )
            )
        restored_stats["notification_channels"] += 1

    # 3. Restore Users & Roles
    roles_cache = {r.name: r for r in session.scalars(select(Role)).all()}
    users_data = entities.get("users", [])
    for u_item in users_data:
        u_name = u_item.get("username")
        if not u_name:
            continue
        role_name = u_item.get("role_name", "viewer")
        target_role = roles_cache.get(role_name) or roles_cache.get("viewer")
        role_id = target_role.id if target_role else None

        existing_u = session.scalar(select(User).where(User.username == u_name))
        if existing_u:
            # If this is the current active admin, do not change password or deactivate
            if current_admin_username and existing_u.username == current_admin_username:
                existing_u.display_name = u_item.get("display_name") or existing_u.display_name
                existing_u.theme = u_item.get("theme") or existing_u.theme
            else:
                existing_u.email = u_item.get("email") or existing_u.email
                existing_u.display_name = u_item.get("display_name") or existing_u.display_name
                if u_item.get("password_hash"):
                    existing_u.password_hash = u_item["password_hash"]
                existing_u.auth_source = u_item.get("auth_source", "local")
                existing_u.is_active = bool(u_item.get("is_active", True))
                existing_u.theme = u_item.get("theme", "embervault")
                if role_id:
                    existing_u.role_id = role_id
        else:
            session.add(
                User(
                    username=u_name,
                    email=u_item.get("email", f"{u_name}@embervault.local"),
                    display_name=u_item.get("display_name", u_name),
                    password_hash=u_item.get("password_hash", ""),
                    auth_source=u_item.get("auth_source", "local"),
                    is_active=bool(u_item.get("is_active", True)),
                    theme=u_item.get("theme", "embervault"),
                    role_id=role_id,
                )
            )
        restored_stats["users"] += 1

    session.flush()

    # 4. Restore Proxies
    proxies_data = entities.get("proxies", [])
    proxies_by_name: dict[str, Proxy] = {}
    for p_item in proxies_data:
        p_name = p_item.get("name")
        p_host = p_item.get("host")
        p_port = int(p_item.get("port", 8443))
        p_token = p_item.get("token", "")
        if not p_name or not p_host:
            continue

        existing_p = session.scalar(
            select(Proxy).where(
                (Proxy.name == p_name) | ((Proxy.host == p_host) & (Proxy.port == p_port))
            )
        )
        if existing_p:
            existing_p.name = p_name
            existing_p.host = p_host
            existing_p.port = p_port
            existing_p.cert_fingerprint_sha256 = p_item.get("cert_fingerprint_sha256", "")
            existing_p.is_enabled = bool(p_item.get("is_enabled", True))
            existing_p.max_concurrent_tasks = int(p_item.get("max_concurrent_tasks", 1))
            existing_p.proxy_version = p_item.get("proxy_version")
            existing_p.rclone_version = p_item.get("rclone_version")
            if p_token:
                existing_p.token_encrypted = ProxyRepository.encrypt_token(p_token, existing_p.id)
            proxies_by_name[p_name] = existing_p
        else:
            new_id = uuid4()
            token_enc = ProxyRepository.encrypt_token(p_token, new_id) if p_token else b""
            new_p = Proxy(
                id=new_id,
                name=p_name,
                host=p_host,
                port=p_port,
                token_encrypted=token_enc,
                cert_fingerprint_sha256=p_item.get("cert_fingerprint_sha256", ""),
                is_enabled=bool(p_item.get("is_enabled", True)),
                max_concurrent_tasks=int(p_item.get("max_concurrent_tasks", 1)),
                proxy_version=p_item.get("proxy_version"),
                rclone_version=p_item.get("rclone_version"),
            )
            session.add(new_p)
            session.flush()
            ProxyRepository.get_or_create_status(session, new_id)
            proxies_by_name[p_name] = new_p
        restored_stats["proxies"] += 1

    session.flush()

    # 5. Restore Remotes with full credentials
    remotes_data = entities.get("remotes", [])
    remotes_by_name: dict[str, RcloneRemote] = {}
    for r_item in remotes_data:
        r_name = r_item.get("name")
        r_type = r_item.get("backend_type")
        r_cfg = r_item.get("full_config") or {}
        if not r_name or not r_type:
            continue

        role_names = r_item.get("allowed_roles")
        allowed_roles_objs = None
        if role_names is not None:
            allowed_roles_objs = list(
                session.scalars(select(Role).where(Role.name.in_(role_names))).all()
            )

        existing_r = RemoteRepository.get_remote_by_name(session, r_name)
        if existing_r:
            existing_r.backend_type = r_type
            existing_r.is_enabled = bool(r_item.get("is_enabled", True))
            existing_r.public_params = r_item.get("public_params", {})
            if r_cfg:
                existing_r.config_encrypted = RemoteRepository.encrypt_config(r_cfg, existing_r.id)
            if allowed_roles_objs is not None:
                existing_r.roles = allowed_roles_objs
            remotes_by_name[r_name] = existing_r
        else:
            try:
                new_r = RemoteRepository.create_remote(
                    session=session,
                    name=r_name,
                    backend_type=r_type,
                    raw_config=r_cfg,
                    is_enabled=bool(r_item.get("is_enabled", True)),
                    allowed_role_ids=[role.id for role in allowed_roles_objs]
                    if allowed_roles_objs is not None
                    else None,
                )
                remotes_by_name[r_name] = new_r
            except Exception as exc:
                logger.error("restore_remote_failed", remote=r_name, error=str(exc))
                continue
        restored_stats["remotes"] += 1

    session.flush()

    # 6. Restore Jobs
    jobs_data = entities.get("jobs", [])
    for j_item in jobs_data:
        j_name = j_item.get("name")
        src_remote_name = j_item.get("source_remote_name")
        dst_remote_name = j_item.get("destination_remote_name")
        if not j_name or not src_remote_name or not dst_remote_name:
            continue

        src_remote = remotes_by_name.get(src_remote_name) or RemoteRepository.get_remote_by_name(
            session, src_remote_name
        )
        dst_remote = remotes_by_name.get(dst_remote_name) or RemoteRepository.get_remote_by_name(
            session, dst_remote_name
        )
        if not src_remote or not dst_remote:
            logger.warning(
                "job_remotes_missing_skipping",
                job=j_name,
                source=src_remote_name,
                destination=dst_remote_name,
            )
            continue

        assigned_proxies = []
        for p_name in j_item.get("assigned_proxy_names", []):
            p = proxies_by_name.get(p_name) or session.scalar(
                select(Proxy).where(Proxy.name == p_name)
            )
            if p:
                assigned_proxies.append(p)

        existing_j = session.scalar(select(Job).where(Job.name == j_name))
        if existing_j:
            existing_j.enabled = bool(j_item.get("enabled", True))
            existing_j.notifications_enabled = bool(j_item.get("notifications_enabled", True))
            existing_j.notification_policy = j_item.get("notification_policy")
            existing_j.source_remote_id = src_remote.id
            existing_j.source_path = j_item.get("source_path", "")
            existing_j.destination_remote_id = dst_remote.id
            existing_j.destination_path = j_item.get("destination_path", "")
            existing_j.source_kind = j_item.get("source_kind", "folder")
            existing_j.operation = j_item.get("operation", "copy")
            existing_j.parallelization = j_item.get("parallelization", "none")
            existing_j.discovery_status = j_item.get("discovery_status", "not_required")
            existing_j.max_parallel_tasks = j_item.get("max_parallel_tasks")
            existing_j.files_per_task = j_item.get("files_per_task")
            existing_j.schedule_cron = j_item.get("schedule_cron")
            existing_j.timezone = j_item.get("timezone", "UTC")
            existing_j.follow_dst = bool(j_item.get("follow_dst", True))
            existing_j.missed_run_policy = j_item.get("missed_run_policy", "run_once")
            existing_j.overlap_policy = j_item.get("overlap_policy", "skip")
            existing_j.pending_policy = j_item.get("pending_policy", "fail")
            existing_j.max_runtime_minutes = j_item.get("max_runtime_minutes")
            existing_j.missed_run_notify = bool(j_item.get("missed_run_notify", False))
            existing_j.overlap_notify = bool(j_item.get("overlap_notify", False))
            existing_j.pending_notify = bool(j_item.get("pending_notify", False))
            existing_j.max_runtime_notify = bool(j_item.get("max_runtime_notify", False))
            existing_j.max_attempts = j_item.get("max_attempts")
            existing_j.task_timeout_s = j_item.get("task_timeout_s")
            existing_j.parallel_ack_task_count = j_item.get("parallel_ack_task_count")
            existing_j.rclone_options = j_item.get("rclone_options", {})
            existing_j.pre_run_hook = j_item.get("pre_run_hook")
            existing_j.post_run_hook = j_item.get("post_run_hook")
            existing_j.assigned_proxies = assigned_proxies

            # Sources
            session.execute(delete(JobSource).where(JobSource.job_id == existing_j.id))
            for s_entry in j_item.get("sources", []):
                session.add(
                    JobSource(
                        id=uuid4(),
                        job_id=existing_j.id,
                        kind=s_entry.get("kind", "dir"),
                        path=s_entry.get("path", ""),
                        position=int(s_entry.get("position", 0)),
                    )
                )
        else:
            new_job_id = uuid4()
            new_j = Job(
                id=new_job_id,
                name=j_name,
                enabled=bool(j_item.get("enabled", True)),
                notifications_enabled=bool(j_item.get("notifications_enabled", True)),
                notification_policy=j_item.get("notification_policy"),
                source_remote_id=src_remote.id,
                source_path=j_item.get("source_path", ""),
                destination_remote_id=dst_remote.id,
                destination_path=j_item.get("destination_path", ""),
                source_kind=j_item.get("source_kind", "folder"),
                operation=j_item.get("operation", "copy"),
                parallelization=j_item.get("parallelization", "none"),
                discovery_status=j_item.get("discovery_status", "not_required"),
                max_parallel_tasks=j_item.get("max_parallel_tasks"),
                files_per_task=j_item.get("files_per_task"),
                schedule_cron=j_item.get("schedule_cron"),
                timezone=j_item.get("timezone", "UTC"),
                follow_dst=bool(j_item.get("follow_dst", True)),
                missed_run_policy=j_item.get("missed_run_policy", "run_once"),
                overlap_policy=j_item.get("overlap_policy", "skip"),
                pending_policy=j_item.get("pending_policy", "fail"),
                max_runtime_minutes=j_item.get("max_runtime_minutes"),
                missed_run_notify=bool(j_item.get("missed_run_notify", False)),
                overlap_notify=bool(j_item.get("overlap_notify", False)),
                pending_notify=bool(j_item.get("pending_notify", False)),
                max_runtime_notify=bool(j_item.get("max_runtime_notify", False)),
                max_attempts=j_item.get("max_attempts"),
                task_timeout_s=j_item.get("task_timeout_s"),
                parallel_ack_task_count=j_item.get("parallel_ack_task_count"),
                rclone_options=j_item.get("rclone_options", {}),
                pre_run_hook=j_item.get("pre_run_hook"),
                post_run_hook=j_item.get("post_run_hook"),
            )
            new_j.assigned_proxies = assigned_proxies
            session.add(new_j)
            session.flush()

            for s_entry in j_item.get("sources", []):
                session.add(
                    JobSource(
                        id=uuid4(),
                        job_id=new_job_id,
                        kind=s_entry.get("kind", "dir"),
                        path=s_entry.get("path", ""),
                        position=int(s_entry.get("position", 0)),
                    )
                )
        restored_stats["jobs"] += 1

    session.flush()

    # 7. Restore Audit Logs (if requested)
    if restore_audit and "audit_logs" in entities:
        audit_logs = entities.get("audit_logs", [])
        for a_item in audit_logs:
            ts_val = None
            if a_item.get("ts"):
                try:
                    ts_val = datetime.fromisoformat(a_item["ts"])
                except Exception:
                    ts_val = None
            actor_uuid = None
            if a_item.get("actor_user_id"):
                try:
                    actor_uuid = UUID(a_item["actor_user_id"])
                except Exception:
                    actor_uuid = None

            action_name = a_item.get("action", "system.unknown")
            entity_type_val = a_item.get("entity_type", "system")
            entity_id_val = a_item.get("entity_id")

            # Deduplicate audit log if already present
            if ts_val:
                existing_log = session.scalar(
                    select(AuditLog).where(
                        AuditLog.ts == ts_val,
                        AuditLog.action == action_name,
                        AuditLog.entity_id == entity_id_val,
                    )
                )
                if existing_log:
                    restored_stats["audit_logs"] += 1
                    continue

            session.add(
                AuditLog(
                    action=action_name,
                    actor_user_id=actor_uuid,
                    entity_type=entity_type_val,
                    entity_id=entity_id_val,
                    details=a_item.get("details"),
                    ip=a_item.get("ip"),
                    ts=ts_val or datetime.now(UTC),
                )
            )
            restored_stats["audit_logs"] += 1

    # 8. Restore Execution History (if requested)
    if restore_history and "execution_history" in entities:
        runs_data = entities.get("execution_history", [])
        for r_item in runs_data:
            j_name = r_item.get("job_name")
            target_job = session.scalar(select(Job).where(Job.name == j_name)) if j_name else None
            if not target_job:
                continue

            run_id = uuid4()
            if r_item.get("id"):
                with contextlib.suppress(Exception):
                    run_id = UUID(r_item["id"])

            # Parse datetimes
            def parse_dt(v: str | None) -> datetime | None:
                if not v:
                    return None
                try:
                    return datetime.fromisoformat(v)
                except Exception:
                    return None

            raw_status = r_item.get("status", "succeeded")
            # Sanitize active statuses: a restored historic run cannot be currently active
            if raw_status in ("running", "queued", "planning", "awaiting_confirmation"):
                # If tasks had errors, mark partially_failed/failed, otherwise cancelled
                run_status = "cancelled"
                finished_at_val = (
                    parse_dt(r_item.get("finished_at"))
                    or parse_dt(r_item.get("started_at"))
                    or datetime.now(UTC)
                )
                error_msg = (
                    r_item.get("error_message")
                    or "Interrotta al momento del backup (stato attivo originario: %s)" % raw_status
                )
            else:
                run_status = raw_status
                finished_at_val = parse_dt(r_item.get("finished_at"))
                error_msg = r_item.get("error_message")

            existing_run = session.get(JobRun, run_id)
            if existing_run:
                existing_run.job_id = target_job.id
                existing_run.trigger = r_item.get("trigger", existing_run.trigger)
                existing_run.status = run_status
                existing_run.scheduled_for = (
                    parse_dt(r_item.get("scheduled_for")) or existing_run.scheduled_for
                )
                existing_run.started_at = (
                    parse_dt(r_item.get("started_at")) or existing_run.started_at
                )
                existing_run.finished_at = finished_at_val or existing_run.finished_at
                existing_run.job_snapshot = r_item.get("job_snapshot") or existing_run.job_snapshot
                existing_run.planned_task_count = int(
                    r_item.get("planned_task_count", existing_run.planned_task_count)
                )
                existing_run.warning_code = r_item.get("warning_code") or existing_run.warning_code
                existing_run.bytes_transferred = int(
                    r_item.get("bytes_transferred", existing_run.bytes_transferred)
                )
                existing_run.files_transferred = int(
                    r_item.get("files_transferred", existing_run.files_transferred)
                )
                existing_run.tasks_succeeded = int(
                    r_item.get("tasks_succeeded", existing_run.tasks_succeeded)
                )
                existing_run.tasks_failed = int(
                    r_item.get("tasks_failed", existing_run.tasks_failed)
                )
                existing_run.error_code = r_item.get("error_code") or existing_run.error_code
                existing_run.error_message = error_msg or existing_run.error_message
                run_entity = existing_run
            else:
                new_run = JobRun(
                    id=run_id,
                    job_id=target_job.id,
                    trigger=r_item.get("trigger", "manual"),
                    status=run_status,
                    scheduled_for=parse_dt(r_item.get("scheduled_for")),
                    started_at=parse_dt(r_item.get("started_at")),
                    finished_at=finished_at_val,
                    job_snapshot=r_item.get("job_snapshot") or {},
                    planned_task_count=int(r_item.get("planned_task_count", 0)),
                    warning_code=r_item.get("warning_code"),
                    bytes_transferred=int(r_item.get("bytes_transferred", 0)),
                    files_transferred=int(r_item.get("files_transferred", 0)),
                    tasks_succeeded=int(r_item.get("tasks_succeeded", 0)),
                    tasks_failed=int(r_item.get("tasks_failed", 0)),
                    error_code=r_item.get("error_code"),
                    error_message=error_msg,
                )
                session.add(new_run)
                run_entity = new_run
            session.flush()

            # Tasks and assignments
            for t_item in r_item.get("tasks", []):
                t_id = uuid4()
                if t_item.get("id"):
                    with contextlib.suppress(Exception):
                        t_id = UUID(t_item["id"])

                t_raw_status = t_item.get("status", "succeeded")
                t_status = (
                    "cancelled"
                    if t_raw_status in ("pending", "ready", "assigned", "running", "retry_wait")
                    else t_raw_status
                )
                t_finished = parse_dt(t_item.get("finished_at")) or (
                    datetime.now(UTC) if t_status == "cancelled" else None
                )

                existing_t = session.get(Task, t_id)
                if existing_t:
                    existing_t.status = t_status
                    existing_t.attempt_count = int(
                        t_item.get("attempt_count", existing_t.attempt_count)
                    )
                    existing_t.max_attempts = int(
                        t_item.get("max_attempts", existing_t.max_attempts)
                    )
                    existing_t.ready_at = parse_dt(t_item.get("ready_at")) or existing_t.ready_at
                    existing_t.finished_at = t_finished or existing_t.finished_at
                else:
                    new_t = Task(
                        id=t_id,
                        run_id=run_id,
                        kind=t_item.get("kind", "transfer"),
                        scope=t_item.get("scope", "whole"),
                        seq=int(t_item.get("seq", 0)),
                        spec=t_item.get("spec") or {},
                        status=t_status,
                        attempt_count=int(t_item.get("attempt_count", 1)),
                        max_attempts=int(t_item.get("max_attempts", 3)),
                        ready_at=parse_dt(t_item.get("ready_at")),
                        finished_at=t_finished,
                    )
                    session.add(new_t)
                    session.flush()

                for asgn_item in t_item.get("assignments", []):
                    proxy_name = asgn_item.get("proxy_name")
                    prx = proxies_by_name.get(proxy_name) if proxy_name else None
                    if not prx:
                        prx = session.scalar(select(Proxy))
                    if not prx:
                        continue

                    asgn_attempt = int(asgn_item.get("attempt_no", 1))
                    asgn_raw_status = asgn_item.get("status", "succeeded")
                    asgn_status = (
                        "cancelled"
                        if asgn_raw_status in ("assigned", "dispatched", "running")
                        else asgn_raw_status
                    )
                    asgn_finished = parse_dt(asgn_item.get("finished_at")) or (
                        datetime.now(UTC) if asgn_status == "cancelled" else None
                    )

                    existing_asgn = session.scalar(
                        select(TaskAssignment).where(
                            TaskAssignment.task_id == t_id,
                            TaskAssignment.attempt_no == asgn_attempt,
                        )
                    )
                    if existing_asgn:
                        existing_asgn.status = asgn_status
                        existing_asgn.finished_at = asgn_finished or existing_asgn.finished_at
                        existing_asgn.bytes_transferred = int(
                            asgn_item.get("bytes_transferred", existing_asgn.bytes_transferred)
                        )
                        existing_asgn.files_transferred = int(
                            asgn_item.get("files_transferred", existing_asgn.files_transferred)
                        )
                        existing_asgn.checks_count = int(
                            asgn_item.get("checks_count", existing_asgn.checks_count)
                        )
                        existing_asgn.duration_ms = int(
                            asgn_item.get("duration_ms", existing_asgn.duration_ms)
                        )
                    else:
                        new_asgn = TaskAssignment(
                            id=uuid4(),
                            task_id=t_id,
                            attempt_no=asgn_attempt,
                            proxy_id=prx.id,
                            status=asgn_status,
                            assigned_at=parse_dt(asgn_item.get("assigned_at")) or datetime.now(UTC),
                            started_at=parse_dt(asgn_item.get("started_at")),
                            finished_at=asgn_finished,
                            exit_code=asgn_item.get("exit_code", 0),
                            error_class=asgn_item.get("error_class"),
                            error_code=asgn_item.get("error_code"),
                            bytes_transferred=int(asgn_item.get("bytes_transferred", 0)),
                            files_transferred=int(asgn_item.get("files_transferred", 0)),
                            checks_count=int(asgn_item.get("checks_count", 0)),
                            duration_ms=int(asgn_item.get("duration_ms", 0)),
                        )
                        session.add(new_asgn)

            for h_item in r_item.get("hooks", []):
                h_type = h_item.get("hook_type", "post_run")
                existing_h = session.scalar(
                    select(JobRunHook).where(
                        JobRunHook.run_id == run_id,
                        JobRunHook.hook_type == h_type,
                    )
                )
                if existing_h:
                    existing_h.status = h_item.get("status", existing_h.status)
                    existing_h.duration_ms = float(
                        h_item.get("duration_ms", existing_h.duration_ms)
                    )
                    existing_h.output = h_item.get("output", existing_h.output)
                    if h_item.get("exit_code") is not None:
                        existing_h.exit_code = int(h_item["exit_code"])
                else:
                    session.add(
                        JobRunHook(
                            id=uuid4(),
                            run_id=run_id,
                            hook_type=h_type,
                            script_hash=h_item.get("script_hash", ""),
                            status=h_item.get("status", "succeeded"),
                            exit_code=int(h_item["exit_code"])
                            if h_item.get("exit_code") is not None
                            else None,
                            duration_ms=float(h_item.get("duration_ms", 0.0)),
                            output=h_item.get("output", ""),
                            executed_at=parse_dt(
                                h_item.get("executed_at") or h_item.get("created_at")
                            )
                            or datetime.now(UTC),
                        )
                    )

            # Reconcile final run status based on restored tasks to ensure accuracy and terminal state
            if run_entity.tasks:
                all_tasks = run_entity.tasks
                tot_t = len(all_tasks)
                succ_t = sum(1 for t in all_tasks if t.status == "succeeded")
                fail_t = sum(1 for t in all_tasks if t.status == "failed")
                canc_t = sum(1 for t in all_tasks if t.status == "cancelled")
                run_entity.tasks_succeeded = succ_t
                run_entity.tasks_failed = fail_t
                if tot_t > 0:
                    if fail_t == tot_t:
                        run_entity.status = "failed"
                    elif canc_t == tot_t:
                        run_entity.status = "cancelled"
                    elif fail_t > 0 or canc_t > 0:
                        run_entity.status = "partially_failed"
                    elif succ_t == tot_t:
                        run_entity.status = "succeeded"
                    if not run_entity.finished_at:
                        run_entity.finished_at = datetime.now(UTC)

            session.flush()
            restored_stats["execution_history"] += 1

    # Record restoration audit log
    session.add(
        AuditLog(
            action="system.backup.restore.succeeded",
            actor_user_id=None,
            entity_type="system",
            entity_id="backup",
            details={
                "restored_stats": restored_stats,
                "restore_audit": restore_audit,
                "restore_history": restore_history,
            },
            ts=datetime.now(UTC),
        )
    )

    session.commit()
    return restored_stats


def list_automated_backups(backup_dir: str = "/backups") -> list[dict[str, Any]]:
    """List all available backup files in the backup directory."""
    path = Path(backup_dir)
    if not path.is_dir():
        return []

    files: list[dict[str, Any]] = []
    for f in path.glob("*.evb"):
        if not f.is_file():
            continue
        stat = f.stat()
        size_bytes = stat.st_size
        mtime = datetime.fromtimestamp(stat.st_mtime, tz=UTC)

        # Human readable size
        if size_bytes < 1024:
            human_size = f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            human_size = f"{size_bytes / 1024:.1f} KB"
        else:
            human_size = f"{size_bytes / (1024 * 1024):.2f} MB"

        files.append(
            {
                "filename": f.name,
                "path": str(f.absolute()),
                "size_bytes": size_bytes,
                "human_size": human_size,
                "modified_at": mtime.isoformat(),
                "created_at": datetime.fromtimestamp(stat.st_ctime, tz=UTC).isoformat(),
            }
        )

    files.sort(key=lambda x: x["modified_at"], reverse=True)
    return files


def run_automated_backup_if_due(
    session_factory: sessionmaker[Session],
    default_backup_dir: str = "/backups",
) -> str | None:
    """Check auto backup configuration, evaluate CRON schedule, and execute backup if due."""
    try:
        from apscheduler.triggers.cron import CronTrigger
    except ImportError:
        logger.warning("apscheduler_not_available_skipping_auto_backup")
        return None

    with session_factory() as session:
        # Load settings
        enabled_setting = session.get(Setting, "auto_backup_enabled")
        is_enabled = bool(enabled_setting.value) if enabled_setting else False
        if not is_enabled:
            return None

        cron_setting = session.get(Setting, "auto_backup_cron")
        cron_expr = str(cron_setting.value or "0 3 * * *").strip() if cron_setting else "0 3 * * *"

        key_setting = session.get(Setting, "auto_backup_key")
        encryption_key = str(key_setting.value or "").strip() if key_setting else ""
        if not encryption_key:
            # Generate a key and save it in settings
            encryption_key = generate_backup_key()
            if key_setting:
                key_setting.value = encryption_key
                key_setting.updated_at = datetime.now(UTC)
            else:
                session.add(
                    Setting(
                        key="auto_backup_key",
                        value=encryption_key,
                        updated_at=datetime.now(UTC),
                    )
                )
            session.commit()

        dir_setting = session.get(Setting, "auto_backup_dir")
        backup_dir = (
            str(dir_setting.value or default_backup_dir).strip()
            if dir_setting
            else default_backup_dir
        )

        inc_hist_setting = session.get(Setting, "auto_backup_include_history")
        include_history = bool(inc_hist_setting.value) if inc_hist_setting else False

        inc_aud_setting = session.get(Setting, "auto_backup_include_audit")
        include_audit = bool(inc_aud_setting.value) if inc_aud_setting else False

        last_run_setting = session.get(Setting, "last_auto_backup_at")
        last_run_iso = str(last_run_setting.value or "") if last_run_setting else ""
        last_run_dt = None
        if last_run_iso:
            try:
                last_run_dt = datetime.fromisoformat(last_run_iso)
            except Exception:
                last_run_dt = None

        now = datetime.now(UTC)

        # Check CRON
        try:
            trigger = CronTrigger.from_crontab(cron_expr, timezone=UTC)
        except Exception as exc:
            logger.error("invalid_auto_backup_cron", cron=cron_expr, error=str(exc))
            return None

        # Determine if due
        is_due = False
        if last_run_dt is None:
            is_due = True
        else:
            # Check next fire time after last_run_dt
            next_fire = trigger.get_next_fire_time(last_run_dt, now)
            if next_fire is not None and next_fire <= now:
                is_due = True

        if not is_due:
            return None

        # Ensure directory exists and is writable
        try:
            os.makedirs(backup_dir, exist_ok=True)
        except PermissionError as exc:
            logger.error(
                "auto_backup_mkdir_permission_denied",
                path=backup_dir,
                error=str(exc),
                hint="Directory non creabile dall'utente non-root UID 10001 (eseguire chown -R 10001:10001)",
            )
            return None
        except Exception as exc:
            logger.error("auto_backup_mkdir_failed", path=backup_dir, error=str(exc))
            return None

        if not os.access(backup_dir, os.W_OK):
            logger.error(
                "auto_backup_dir_not_writable",
                path=backup_dir,
                hint="Directory non scrivibile dall'utente non-root UID 10001 (eseguire chown -R 10001:10001 o chmod 777)",
            )
            return None

        # Execute backup
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
            logger.info("auto_backup_created", path=str(target_path), stats=stats)

            # Record in Setting
            if last_run_setting:
                last_run_setting.value = now.isoformat()
                last_run_setting.updated_at = now
            else:
                session.add(
                    Setting(
                        key="last_auto_backup_at",
                        value=now.isoformat(),
                        updated_at=now,
                    )
                )

            # Audit log
            session.add(
                AuditLog(
                    action="system.backup.auto.created",
                    actor_user_id=None,
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

            # Retention cleanup
            retention_setting = session.get(Setting, "auto_backup_retention_days")
            retention_days = int(retention_setting.value or 30) if retention_setting else 30
            _cleanup_expired_backups(backup_dir, retention_days)

            session.commit()
            return str(target_path)
        except Exception as exc:
            session.rollback()
            logger.error("auto_backup_execution_failed", error=str(exc))
            return None


def _cleanup_expired_backups(backup_dir: str, retention_days: int) -> int:
    """Delete backup files older than retention_days."""
    deleted = 0
    now_ts = datetime.now(UTC).timestamp()
    cutoff_ts = now_ts - (retention_days * 86400)
    path = Path(backup_dir)
    if not path.is_dir():
        return 0

    for f in path.glob("*.evb"):
        try:
            stat = f.stat()
            if stat.st_mtime < cutoff_ts:
                f.unlink(missing_ok=True)
                deleted += 1
        except Exception:
            pass
    return deleted
