"""Data access repository for proxies, proxy status, and proxy state transition events."""

from __future__ import annotations

import datetime
from uuid import UUID

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from embervault_common.security.crypto import decrypt_blob_to_str, encrypt_blob
from embervault_db.models.proxy import Proxy, ProxyStateEvent, ProxyStatus


class ProxyRepository:
    """Repository handling all database queries and updates for proxies and their health status."""

    @staticmethod
    def encrypt_token(token: str, proxy_id: UUID) -> bytes:
        """Encrypt a proxy Bearer token using AES-256-GCM bound to proxy_id AAD."""
        aad = f"proxy:{proxy_id}".encode()
        return encrypt_blob(token, aad=aad)

    @staticmethod
    def decrypt_token(encrypted_token: bytes, proxy_id: UUID) -> str:
        """Decrypt a proxy Bearer token using AES-256-GCM and proxy_id AAD."""
        aad = f"proxy:{proxy_id}".encode()
        return decrypt_blob_to_str(encrypted_token, aad=aad)

    @staticmethod
    def get_all_proxies(session: Session) -> list[Proxy]:
        """Retrieve all registered proxies with their status eagerly loaded."""
        stmt = select(Proxy).order_by(Proxy.name)
        return list(session.scalars(stmt).unique().all())

    @staticmethod
    def get_all_enabled_proxies(session: Session) -> list[Proxy]:
        """Retrieve all enabled proxies with their status eagerly loaded."""
        stmt = select(Proxy).where(Proxy.is_enabled.is_(True)).order_by(Proxy.name)
        return list(session.scalars(stmt).unique().all())

    @staticmethod
    def get_proxy_by_id(session: Session, proxy_id: UUID) -> Proxy | None:
        """Retrieve a proxy by its unique UUID."""
        return session.get(Proxy, proxy_id)

    @staticmethod
    def get_or_create_status(session: Session, proxy_id: UUID) -> ProxyStatus:
        """Get existing ProxyStatus or initialize a default 'unknown' status row."""
        status = session.get(ProxyStatus, proxy_id)
        if status is None:
            status = ProxyStatus(
                proxy_id=proxy_id,
                state="unknown",
                consecutive_failures=0,
                consecutive_successes=0,
                running_tasks=0,
                capacity=1,
                latency_ms=0,
            )
            session.add(status)
            session.flush()
        return status

    @staticmethod
    def record_state_transition(
        session: Session,
        proxy_id: UUID,
        from_state: str,
        to_state: str,
        reason: str | None = None,
    ) -> ProxyStateEvent:
        """Log a state transition in proxy_state_events audit table."""
        event = ProxyStateEvent(
            proxy_id=proxy_id,
            ts=datetime.datetime.now(datetime.UTC),
            from_state=from_state,
            to_state=to_state,
            reason=reason,
        )
        session.add(event)
        return event

    @classmethod
    def apply_probe_result(
        cls,
        session: Session,
        proxy: Proxy,
        new_state: str,
        is_success: bool = True,
        latency_ms: int = 0,
        running_tasks: int = 0,
        capacity: int | None = None,
        proxy_version: str | None = None,
        rclone_version: str | None = None,
        cert_expires_at: datetime.datetime | None = None,
        error_code: str | None = None,
        reason: str | None = None,
    ) -> tuple[ProxyStatus, ProxyStateEvent | None]:
        """Apply health probe outcome, update counters/status, and record event if state changed."""
        status = cls.get_or_create_status(session, proxy.id)
        now = datetime.datetime.now(datetime.UTC)
        status.last_check_at = now
        status.latency_ms = latency_ms

        if capacity is not None and capacity > 0:
            status.capacity = capacity

        if proxy_version:
            proxy.proxy_version = proxy_version
        if rclone_version:
            proxy.rclone_version = rclone_version
        if cert_expires_at is not None:
            proxy.cert_expires_at = cert_expires_at

        previous_state = status.state
        event: ProxyStateEvent | None = None

        if new_state != previous_state:
            status.state = new_state
            event = cls.record_state_transition(
                session,
                proxy_id=proxy.id,
                from_state=previous_state,
                to_state=new_state,
                reason=reason,
            )

        if is_success:
            status.last_seen_at = now
            status.consecutive_successes += 1
            status.consecutive_failures = 0
            status.running_tasks = running_tasks
            status.last_error_code = None
        else:
            status.consecutive_failures += 1
            status.consecutive_successes = 0
            status.last_error_code = error_code

        session.flush()
        return status, event

    @classmethod
    def set_reachable_remotes(
        cls,
        session: Session,
        proxy: Proxy,
        reachable_remote_ids: list[UUID] | None = None,
    ) -> None:
        """Assign reachable remotes to a proxy, validating for inconsistencies with active jobs."""
        from embervault_db.models.remotes import Job, RcloneRemote

        if reachable_remote_ids is None:
            remotes = list(session.scalars(select(RcloneRemote)).all())
        else:
            proxy._explicitly_set_reachable_remotes = True
            if reachable_remote_ids:
                remotes = list(
                    session.scalars(
                        select(RcloneRemote).where(RcloneRemote.id.in_(reachable_remote_ids))
                    ).all()
                )
            else:
                remotes = []

        new_remote_ids = {r.id for r in remotes}
        current_remote_ids = {r.id for r in proxy.reachable_remotes}
        removed_remote_ids = current_remote_ids - new_remote_ids

        if removed_remote_ids:
            from embervault_db.repositories.job_repository import JobRepository

            active_jobs = list(
                session.scalars(
                    select(Job).where(
                        or_(
                            Job.assigned_proxies.any(Proxy.id == proxy.id),
                            ~Job.assigned_proxies.any(),
                        )
                    )
                ).all()
            )
            for job in active_jobs:
                required_remotes = JobRepository.get_job_required_remote_ids(session, job)
                conflicts = removed_remote_ids.intersection(required_remotes)
                if conflicts:
                    conf_id = list(conflicts)[0]
                    removed_rem = next(
                        (r for r in proxy.reachable_remotes if r.id == conf_id), None
                    )
                    if not removed_rem:
                        removed_rem = session.get(RcloneRemote, conf_id)
                    rem_name = removed_rem.name if removed_rem else str(conf_id)
                    if not job.assigned_proxies:
                        raise ValueError(
                            f"Impossibile rimuovere il remote '{rem_name}': il job '{job.name}' utilizza tutti i proxy del cluster e richiede questo remote."
                        )
                    else:
                        raise ValueError(
                            f"Impossibile rimuovere il remote '{rem_name}': il proxy '{proxy.name}' è attivato per il job '{job.name}' che richiede questo remote."
                        )

        if proxy not in session:
            session.add(proxy)
        proxy.reachable_remotes = remotes
        session.flush()

    @classmethod
    def update_proxy(
        cls,
        session: Session,
        proxy_id: UUID,
        name: str,
        host: str,
        port: int,
        max_concurrent_tasks: int = 1,
        is_enabled: bool = True,
        token: str | None = None,
        cert_fingerprint_sha256: str | None = None,
        reachable_remote_ids: list[UUID] | None = None,
    ) -> Proxy:
        """Update proxy attributes, optionally re-encrypting a new token or updating fingerprint."""
        proxy = session.get(Proxy, proxy_id)
        if proxy is None:
            raise ValueError(f"Proxy con ID {proxy_id} non trovato.")
        proxy.name = name
        proxy.host = host
        proxy.port = port
        proxy.max_concurrent_tasks = max_concurrent_tasks
        proxy.is_enabled = is_enabled
        if token:
            proxy.token_encrypted = cls.encrypt_token(token, proxy_id)
        if cert_fingerprint_sha256:
            proxy.cert_fingerprint_sha256 = cert_fingerprint_sha256
            proxy.fingerprint_confirmed_at = datetime.datetime.now(datetime.UTC)
        if reachable_remote_ids is not None:
            cls.set_reachable_remotes(session, proxy, reachable_remote_ids)
        session.flush()
        return proxy

    @classmethod
    def delete_proxy(cls, session: Session, proxy_id: UUID) -> bool:
        """Delete a proxy by UUID, cascading to status and events, and unlinking historical assignments."""
        proxy = session.get(Proxy, proxy_id)
        if proxy is None:
            return False

        # Nullify any historical task assignments referencing this proxy
        from embervault_db.models.execution import TaskAssignment

        session.execute(
            update(TaskAssignment).where(TaskAssignment.proxy_id == proxy_id).values(proxy_id=None)
        )

        session.delete(proxy)
        session.flush()
        return True

    @classmethod
    def reencrypt_proxy_token(
        cls,
        session: Session,
        proxy_id: UUID,
        new_key_id: str | None = None,
    ) -> bool:
        """Re-encrypt proxy auth token using a newly designated primary or target key.

        Returns True if the token was re-encrypted, False if it was already current or not found.
        """
        from embervault_common.security.crypto import reencrypt_blob

        proxy = session.get(Proxy, proxy_id)
        if proxy is None:
            return False

        aad = f"proxy:{proxy.id}".encode()
        reencrypted = reencrypt_blob(proxy.token_encrypted, new_key_id=new_key_id, aad=aad)
        if reencrypted != proxy.token_encrypted:
            proxy.token_encrypted = reencrypted
            session.flush()
            return True
        return False
