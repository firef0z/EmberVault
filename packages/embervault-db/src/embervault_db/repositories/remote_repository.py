"""Data access repository for RClone remotes with envelope encryption."""

from __future__ import annotations

import json
from typing import Any, cast
from uuid import UUID, uuid4

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from embervault_common.remotes.catalog import validate_and_split_remote_config
from embervault_common.security.crypto import decrypt_blob_to_str, encrypt_blob
from embervault_db.models.remotes import Job, JobDiscovery, RcloneRemote


class RemoteRepository:
    """Repository handling CRUD and cryptographic operations for RClone remotes."""

    @staticmethod
    def encrypt_config(config_dict: dict[str, Any], remote_id: UUID) -> bytes:
        """Encrypt full remote configuration dictionary bound to remote_id AAD."""
        aad = f"remote:{remote_id}".encode()
        payload = json.dumps(config_dict, sort_keys=True)
        return encrypt_blob(payload, aad=aad)

    @staticmethod
    def decrypt_config(encrypted_config: bytes, remote_id: UUID) -> dict[str, Any]:
        """Decrypt remote configuration dictionary bound to remote_id AAD."""
        aad = f"remote:{remote_id}".encode()
        raw_json = decrypt_blob_to_str(encrypted_config, aad=aad)
        return cast(dict[str, Any], json.loads(raw_json))

    @classmethod
    def get_decrypted_config(cls, remote: RcloneRemote) -> dict[str, Any]:
        """Decrypt full configuration for a remote entity."""
        return cls.decrypt_config(remote.config_encrypted, remote.id)

    @classmethod
    def get_masked_config(cls, remote: RcloneRemote) -> dict[str, Any]:
        """Return configuration dictionary with sensitive secrets replaced by asterisks."""
        masked = dict(remote.public_params)
        for secret_name in remote.secret_field_names:
            masked[secret_name] = "***"
        return masked

    @classmethod
    def create_remote(
        cls,
        session: Session,
        name: str,
        backend_type: str,
        raw_config: dict[str, Any],
        created_by: UUID | None = None,
        is_enabled: bool = True,
        reachable_proxy_ids: list[UUID] | None = None,
        allowed_role_ids: list[UUID] | None = None,
    ) -> RcloneRemote:
        """Validate, encrypt, and persist a new RClone remote."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Il nome del remote non può essere vuoto.")

        # Check unique name
        existing = cls.get_remote_by_name(session, clean_name)
        if existing is not None:
            raise ValueError(f"Un remote con il nome '{clean_name}' esiste già.")

        public_params, secret_params, secret_field_names = validate_and_split_remote_config(
            backend_type=backend_type,
            raw_config=raw_config,
        )

        remote_id = uuid4()
        full_config = {**public_params, **secret_params}
        config_encrypted = cls.encrypt_config(full_config, remote_id)

        from embervault_db.models.auth import Role
        from embervault_db.models.proxy import Proxy

        if reachable_proxy_ids is None:
            proxies = list(session.scalars(select(Proxy)).all())
        elif reachable_proxy_ids:
            proxies = list(
                session.scalars(select(Proxy).where(Proxy.id.in_(reachable_proxy_ids))).all()
            )
        else:
            proxies = []

        if allowed_role_ids is None:
            roles = list(session.scalars(select(Role)).all())
        elif allowed_role_ids:
            roles = list(
                session.scalars(select(Role).where(Role.id.in_(allowed_role_ids))).all()
            )
        else:
            roles = []

        remote = RcloneRemote(
            id=remote_id,
            name=clean_name,
            backend_type=backend_type,
            config_encrypted=config_encrypted,
            public_params=public_params,
            secret_field_names=secret_field_names,
            version=1,
            is_enabled=is_enabled,
            created_by=created_by,
            proxies=proxies,
            roles=roles,
        )

        session.add(remote)
        session.flush()
        return remote

    @staticmethod
    def get_remote_by_id(session: Session, remote_id: UUID) -> RcloneRemote | None:
        """Retrieve remote by primary key UUID."""
        return session.get(RcloneRemote, remote_id)

    @staticmethod
    def get_remote_by_name(session: Session, name: str) -> RcloneRemote | None:
        """Retrieve remote by unique alphanumeric name."""
        return session.scalar(select(RcloneRemote).where(RcloneRemote.name == name.strip()))

    @staticmethod
    def list_remotes(session: Session, include_disabled: bool = True) -> list[RcloneRemote]:
        """List all remotes ordered by name."""
        stmt = select(RcloneRemote)
        if not include_disabled:
            stmt = stmt.where(RcloneRemote.is_enabled.is_(True))
        stmt = stmt.order_by(RcloneRemote.name)
        return list(session.scalars(stmt).all())

    @classmethod
    def update_remote(
        cls,
        session: Session,
        remote_id: UUID,
        name: str | None = None,
        raw_config: dict[str, Any] | None = None,
        is_enabled: bool | None = None,
        reachable_proxy_ids: list[UUID] | None = None,
        allowed_role_ids: list[UUID] | None = None,
    ) -> RcloneRemote:
        """Update an existing remote, merging secrets if masked values ('***') were submitted."""
        remote = cls.get_remote_by_id(session, remote_id)
        if remote is None:
            raise ValueError(f"Remote con ID '{remote_id}' non trovato.")

        if name is not None:
            clean_name = name.strip()
            if not clean_name:
                raise ValueError("Il nome del remote non può essere vuoto.")
            existing = cls.get_remote_by_name(session, clean_name)
            if existing is not None and existing.id != remote_id:
                raise ValueError(f"Un remote con il nome '{clean_name}' esiste già.")
            remote.name = clean_name

        if is_enabled is not None:
            remote.is_enabled = is_enabled

        if raw_config is not None:
            # Check if secret fields were passed as "***", if so keep previous secret value
            prev_config = cls.get_decrypted_config(remote)
            merged_raw = dict(raw_config)
            for secret_key in remote.secret_field_names:
                if merged_raw.get(secret_key) in (None, "", "***") and secret_key in prev_config:
                    merged_raw[secret_key] = prev_config[secret_key]

            public_params, secret_params, secret_field_names = validate_and_split_remote_config(
                backend_type=remote.backend_type,
                raw_config=merged_raw,
            )
            full_config = {**public_params, **secret_params}
            remote.config_encrypted = cls.encrypt_config(full_config, remote.id)
            remote.public_params = public_params
            remote.secret_field_names = secret_field_names
            remote.version += 1

        if reachable_proxy_ids is not None:
            from embervault_db.models.proxy import Proxy

            if reachable_proxy_ids:
                new_proxies = list(
                    session.scalars(select(Proxy).where(Proxy.id.in_(reachable_proxy_ids))).all()
                )
            else:
                new_proxies = []

            new_proxy_ids = {p.id for p in new_proxies}
            current_proxy_ids = {p.id for p in remote.proxies}
            removed_proxy_ids = current_proxy_ids - new_proxy_ids

            if removed_proxy_ids:
                from embervault_db.repositories.job_repository import JobRepository

                all_jobs = list(session.scalars(select(Job)).all())
                for job in all_jobs:
                    job_remotes = JobRepository.get_job_required_remote_ids(session, job)
                    if remote.id in job_remotes:
                        assigned_ids = {p.id for p in job.assigned_proxies}
                        if not assigned_ids:
                            # Job uses all cluster proxies
                            conflict_ids = removed_proxy_ids
                            if conflict_ids:
                                conflict_proxy = next(
                                    (p for p in remote.proxies if p.id in conflict_ids), None
                                )
                                p_name = (
                                    conflict_proxy.name
                                    if conflict_proxy
                                    else str(list(conflict_ids)[0])
                                )
                                raise ValueError(
                                    f"Impossibile rimuovere il proxy '{p_name}': il job '{job.name}' utilizza tutti i proxy del cluster e richiede questo remote."
                                )
                        else:
                            conflict_ids = removed_proxy_ids.intersection(assigned_ids)
                            if conflict_ids:
                                conflict_proxy = next(
                                    (p for p in remote.proxies if p.id in conflict_ids), None
                                )
                                p_name = (
                                    conflict_proxy.name
                                    if conflict_proxy
                                    else str(list(conflict_ids)[0])
                                )
                                raise ValueError(
                                    f"Impossibile rimuovere il proxy '{p_name}': è attivato per il job '{job.name}' che richiede questo remote."
                                )

            remote.proxies = new_proxies

        if allowed_role_ids is not None:
            from embervault_db.models.auth import Role

            if allowed_role_ids:
                new_roles = list(
                    session.scalars(select(Role).where(Role.id.in_(allowed_role_ids))).all()
                )
            else:
                new_roles = []
            remote.roles = new_roles

        session.flush()
        return remote

    @staticmethod
    def can_user_view_remote(
        remote: RcloneRemote,
        user: Any | None,
        is_admin: bool = False,
    ) -> bool:
        """Check if a user has permission to view and use a remote endpoint."""
        if is_admin:
            return True
        if user is None:
            return False
        user_role = getattr(user, "role", None)
        if user_role is not None and getattr(user_role, "name", "").strip().lower() in (
            "admin",
            "administrator",
        ):
            return True
        user_role_id = getattr(user, "role_id", None)
        if user_role_id and remote.roles:
            if any(r.id == user_role_id for r in remote.roles):
                return True
        if user_role is not None and remote.roles:
            if any(r.name == getattr(user_role, "name", "") for r in remote.roles):
                return True
        return False

    @classmethod
    def list_remotes_for_user(
        cls,
        session: Session,
        user: Any | None,
        is_admin: bool = False,
        include_disabled: bool = True,
    ) -> list[RcloneRemote]:
        """List remotes viewable by a specific user based on assigned roles."""
        all_remotes = cls.list_remotes(session, include_disabled=include_disabled)
        if is_admin:
            return all_remotes
        if user is None:
            return []
        user_role = getattr(user, "role", None)
        if user_role is not None and getattr(user_role, "name", "").strip().lower() in (
            "admin",
            "administrator",
        ):
            return all_remotes
        return [r for r in all_remotes if cls.can_user_view_remote(r, user, is_admin=False)]

    @classmethod
    def delete_remote(cls, session: Session, remote_id: UUID) -> tuple[bool, str | None]:
        """Delete remote if not referenced by any jobs."""
        remote = cls.get_remote_by_id(session, remote_id)
        if remote is None:
            return False, "Remote non trovato."

        # Check referencing jobs
        ref_job = session.scalar(
            select(Job)
            .where(or_(Job.source_remote_id == remote_id, Job.destination_remote_id == remote_id))
            .limit(1)
        )
        if ref_job is not None:
            return (
                False,
                f"Impossibile eliminare il remote '{remote.name}': è attualmente utilizzato dal job '{ref_job.name}'.",
            )

        # Remove any cached job discoveries referencing this remote
        session.execute(delete(JobDiscovery).where(JobDiscovery.source_remote_id == remote_id))

        session.delete(remote)
        session.flush()
        return True, None

    @classmethod
    def reencrypt_remote(
        cls,
        session: Session,
        remote_id: UUID,
        new_key_id: str | None = None,
    ) -> bool:
        """Re-encrypt remote credentials using a newly designated primary or target key.

        Returns True if the remote was re-encrypted, False if it was already current or not found.
        """
        from datetime import UTC, datetime
        from embervault_common.security.crypto import extract_envelope_key_id, reencrypt_blob

        remote = cls.get_remote_by_id(session, remote_id)
        if remote is None:
            return False

        aad = f"remote:{remote.id}".encode()
        current_k_id = extract_envelope_key_id(remote.config_encrypted)
        reencrypted = reencrypt_blob(remote.config_encrypted, new_key_id=new_key_id, aad=aad)
        if reencrypted != remote.config_encrypted:
            remote.config_encrypted = reencrypted
            remote.rotated_at = datetime.now(UTC)
            session.flush()
            return True
        return False

    @staticmethod
    def extract_referenced_remote_names(backend_type: str, config: dict[str, Any]) -> list[str]:
        """Extract remote names referenced by special backends (alias, crypt, compress, chunker, union)."""
        btype = str(backend_type).lower().strip()
        names: list[str] = []

        if btype in ("alias", "crypt", "compress", "chunker"):
            target = str(config.get("remote", "")).strip()
            if target:
                # Target can be "remote_name:path", "remote_name:", or "remote_name"
                name_part = target.split(":")[0].strip()
                # Ignore local filesystem paths or drives (e.g. C:, /, /mnt, ./, .\)
                if (
                    name_part
                    and not (len(name_part) == 1 and name_part.isalpha())
                    and not name_part.startswith(("/", "\\", "."))
                ):
                    names.append(name_part)
        elif btype == "union":
            upstreams = str(config.get("upstreams", "")).strip()
            if upstreams:
                # Space-separated entries like "remote1:path remote2:path"
                for entry in upstreams.split():
                    name_part = entry.split(":")[0].strip()
                    if (
                        name_part
                        and not (len(name_part) == 1 and name_part.isalpha())
                        and not name_part.startswith(("/", "\\", "."))
                    ):
                        if name_part not in names:
                            names.append(name_part)

        return names

    @classmethod
    def resolve_referenced_remotes(
        cls,
        session: Session,
        backend_type: str,
        config: dict[str, Any],
        visited: set[str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Recursively resolve all remotes referenced by a backend configuration.

        Returns a dictionary mapping remote_name -> {"backend_type": ..., "config": ...}.
        """
        if visited is None:
            visited = set()

        resolved: dict[str, dict[str, Any]] = {}
        ref_names = cls.extract_referenced_remote_names(backend_type, config)

        for ref_name in ref_names:
            if ref_name in visited:
                continue
            visited.add(ref_name)

            remote_entity = cls.get_remote_by_name(session, ref_name)
            if remote_entity is not None:
                dec_cfg = cls.get_decrypted_config(remote_entity)
                resolved[remote_entity.name] = {
                    "backend_type": remote_entity.backend_type,
                    "config": dec_cfg,
                }
                # Recursively resolve nested referenced remotes (e.g. Alias -> Crypt -> SMB)
                nested = cls.resolve_referenced_remotes(
                    session=session,
                    backend_type=remote_entity.backend_type,
                    config=dec_cfg,
                    visited=visited,
                )
                resolved.update(nested)

        return resolved
