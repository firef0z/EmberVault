"""Data access repository for users, roles, and permissions management (Milestone M2)."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import delete, desc, func, select
from sqlalchemy.orm import Session

from embervault_common.security.passwords import (
    hash_password,
    validate_password_complexity,
)
from embervault_db.models.auth import (
    AuditLog,
    Permission,
    Role,
    User,
    UserMfaFactor,
    UserRecoveryCode,
    UserSession,
)


class UserRepository:
    """Repository handling User lifecycle, Role assignments, and Audit logging."""

    @staticmethod
    def list_users(session: Session) -> list[User]:
        """List all users ordered by username."""
        stmt = select(User).order_by(User.username)
        return list(session.scalars(stmt).all())

    @staticmethod
    def get_user_by_id(session: Session, user_id: UUID) -> User | None:
        """Find user by UUID."""
        return session.get(User, user_id)

    @staticmethod
    def get_user_by_username(session: Session, username: str) -> User | None:
        """Find user by unique username (case-insensitive search)."""
        clean = username.strip().lower()
        stmt = select(User).where(func.lower(User.username) == clean)
        return session.scalar(stmt)

    @staticmethod
    def list_roles(session: Session) -> list[Role]:
        """List all system and custom roles with permissions."""
        # Custom roles ordered: system roles first (Administrator, Operator, Viewer), then custom by name
        stmt = select(Role).order_by(desc(Role.is_system), Role.name)
        return list(session.scalars(stmt).all())

    @staticmethod
    def get_role_by_id(session: Session, role_id: UUID) -> Role | None:
        """Find role by UUID."""
        return session.get(Role, role_id)

    @staticmethod
    def get_role_by_name(session: Session, name: str) -> Role | None:
        """Find role by name (case-insensitive and alias-aware)."""
        clean = name.strip()
        lower_name = clean.lower()
        alias_map = {
            "admin": "administrator",
            "administrator": "admin",
            "operator": "operator",
            "viewer": "viewer",
        }
        candidates = [lower_name]
        if lower_name in alias_map:
            candidates.append(alias_map[lower_name])

        stmt = select(Role).where(func.lower(Role.name).in_(candidates))
        return session.scalar(stmt)

    @staticmethod
    def create_role(
        session: Session,
        name: str,
        description: str | None = None,
        copy_from_role_id: UUID | None = None,
        permission_codes: list[str] | None = None,
        actor_user_id: UUID | None = None,
        ip: str | None = None,
    ) -> Role:
        """Create a new custom role with optional initial permissions."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Il nome del ruolo non può essere vuoto.")

        existing = UserRepository.get_role_by_name(session, clean_name)
        if existing is not None:
            raise ValueError(f"Un ruolo con il nome '{clean_name}' esiste già.")

        role = Role(
            name=clean_name,
            description=description.strip() if description else None,
            is_system=False,
            enforce_2fa=False,
        )
        session.add(role)
        session.flush()

        initial_perms: set[str] = set()
        if copy_from_role_id is not None:
            source_role = session.get(Role, copy_from_role_id)
            if source_role:
                initial_perms.update(p.code for p in source_role.permissions)

        if permission_codes is not None:
            initial_perms.update(permission_codes)

        if initial_perms:
            db_perms = list(
                session.scalars(select(Permission).where(Permission.code.in_(initial_perms))).all()
            )
            role.permissions = db_perms
            if "auth.enforce_2fa" in initial_perms:
                role.enforce_2fa = True

        audit = AuditLog(
            action="role.create",
            actor_user_id=actor_user_id,
            entity_type="role",
            entity_id=str(role.id),
            ip=ip,
            details={
                "role_name": role.name,
                "description": role.description,
                "permissions_count": len(role.permissions),
                "enforce_2fa": role.enforce_2fa,
            },
        )
        session.add(audit)
        session.flush()
        return role

    @staticmethod
    def update_role(
        session: Session,
        role_id: UUID,
        name: str | None = None,
        enforce_2fa: bool | None = None,
        description: str | None = None,
        actor_user_id: UUID | None = None,
        ip: str | None = None,
    ) -> Role:
        """Update role configuration such as name, description, and 2FA enforcement."""
        role = session.get(Role, role_id)
        if role is None:
            raise ValueError(f"Ruolo non trovato (ID '{role_id}').")

        changes: dict[str, Any] = {}

        if name is not None:
            clean_name = name.strip()
            if not clean_name:
                raise ValueError("Il nome del ruolo non può essere vuoto.")
            if clean_name != role.name:
                if role.is_system:
                    raise ValueError("Non è consentito rinominare i ruoli built-in di sistema.")
                existing = UserRepository.get_role_by_name(session, clean_name)
                if existing is not None and existing.id != role.id:
                    raise ValueError(f"Un ruolo con il nome '{clean_name}' esiste già.")
                changes["name"] = {"from": role.name, "to": clean_name}
                role.name = clean_name

        if enforce_2fa is not None and role.enforce_2fa != enforce_2fa:
            changes["enforce_2fa"] = {"from": role.enforce_2fa, "to": enforce_2fa}
            role.enforce_2fa = enforce_2fa

            # Sync auth.enforce_2fa permission
            perm_2fa = session.scalar(
                select(Permission).where(Permission.code == "auth.enforce_2fa")
            )
            if perm_2fa:
                has_perm = any(p.code == "auth.enforce_2fa" for p in role.permissions)
                if enforce_2fa and not has_perm:
                    role.permissions.append(perm_2fa)
                elif not enforce_2fa and has_perm:
                    role.permissions = [p for p in role.permissions if p.code != "auth.enforce_2fa"]

        if description is not None and role.description != description:
            changes["description"] = {"from": role.description, "to": description}
            role.description = description

        if changes:
            audit = AuditLog(
                action="role.update",
                actor_user_id=actor_user_id,
                entity_type="role",
                entity_id=str(role.id),
                ip=ip,
                details={"role_name": role.name, **changes},
            )
            session.add(audit)

        session.flush()
        return role

    @staticmethod
    def delete_role(
        session: Session,
        role_id: UUID,
        actor_user_id: UUID | None = None,
        ip: str | None = None,
    ) -> None:
        """Delete a custom role if not a system role and not assigned to any users."""
        role = session.get(Role, role_id)
        if role is None:
            raise ValueError(f"Ruolo non trovato (ID '{role_id}').")

        if role.is_system:
            raise ValueError("I ruoli built-in di sistema non possono essere eliminati.")

        users_count = (
            session.scalar(select(func.count(User.id)).where(User.role_id == role.id)) or 0
        )
        if users_count > 0:
            raise ValueError(
                f"Impossibile eliminare il ruolo '{role.name}': è attualmente assegnato a {users_count} "
                f"utent{'e' if users_count == 1 else 'i'}. Riassegna gli utenti a un altro ruolo prima di procedere."
            )

        role_name = role.name
        audit = AuditLog(
            action="role.delete",
            actor_user_id=actor_user_id,
            entity_type="role",
            entity_id=str(role_id),
            ip=ip,
            details={"role_name": role_name},
        )
        session.add(audit)
        session.delete(role)
        session.flush()

    @staticmethod
    def toggle_role_permission(
        session: Session,
        role_id: UUID,
        permission_code: str,
        enabled: bool | None = None,
        actor_user_id: UUID | None = None,
        ip: str | None = None,
    ) -> tuple[Role, bool]:
        """Toggle or explicitly set a single permission on a role."""
        role = session.get(Role, role_id)
        if role is None:
            raise ValueError(f"Ruolo non trovato (ID '{role_id}').")

        perm = session.scalar(select(Permission).where(Permission.code == permission_code))
        if perm is None:
            raise ValueError(f"Permesso '{permission_code}' non trovato.")

        current_has_perm = any(p.code == permission_code for p in role.permissions)
        new_state = (not current_has_perm) if enabled is None else enabled

        if new_state and not current_has_perm:
            role.permissions.append(perm)
        elif not new_state and current_has_perm:
            role.permissions = [p for p in role.permissions if p.code != permission_code]

        # If toggling 2FA enforcement permission, sync role.enforce_2fa flag
        if permission_code == "auth.enforce_2fa":
            role.enforce_2fa = new_state

        audit = AuditLog(
            action="role.permission.toggle",
            actor_user_id=actor_user_id,
            entity_type="role",
            entity_id=str(role.id),
            ip=ip,
            details={
                "role_name": role.name,
                "permission_code": permission_code,
                "enabled": new_state,
            },
        )
        session.add(audit)
        session.flush()
        return role, new_state

    @staticmethod
    def set_role_permissions(
        session: Session,
        role_id: UUID,
        permission_codes: list[str],
        actor_user_id: UUID | None = None,
        ip: str | None = None,
    ) -> Role:
        """Replace all permissions of a role with the specified list of codes."""
        role = session.get(Role, role_id)
        if role is None:
            raise ValueError(f"Ruolo non trovato (ID '{role_id}').")

        db_perms = list(
            session.scalars(select(Permission).where(Permission.code.in_(permission_codes))).all()
        )
        role.permissions = db_perms

        # Sync 2FA enforcement
        role.enforce_2fa = "auth.enforce_2fa" in permission_codes

        audit = AuditLog(
            action="role.permissions.set",
            actor_user_id=actor_user_id,
            entity_type="role",
            entity_id=str(role.id),
            ip=ip,
            details={
                "role_name": role.name,
                "permissions_count": len(role.permissions),
                "enforce_2fa": role.enforce_2fa,
            },
        )
        session.add(audit)
        session.flush()
        return role

    @staticmethod
    def list_permissions(session: Session) -> list[Permission]:
        """List all available permission codes ordered by category and code."""
        stmt = select(Permission).order_by(Permission.category, Permission.code)
        return list(session.scalars(stmt).all())

    @staticmethod
    def get_permissions_matrix(session: Session) -> dict[str, Any]:
        """Build matrix of roles vs permissions categorized for UI and management API."""
        # 1. Roles with user counts
        roles = UserRepository.list_roles(session)
        user_counts: dict[UUID, int] = dict(
            session.execute(select(User.role_id, func.count(User.id)).group_by(User.role_id)).all()
        )

        role_list: list[dict[str, Any]] = []
        for r in roles:
            role_list.append(
                {
                    "id": str(r.id),
                    "name": r.name,
                    "description": r.description or "",
                    "is_system": r.is_system,
                    "enforce_2fa": r.enforce_2fa,
                    "users_count": user_counts.get(r.id, 0),
                    "permissions": [p.code for p in r.permissions],
                }
            )

        # 2. Permissions grouped by category
        perms = UserRepository.list_permissions(session)
        categories_dict: dict[str, list[dict[str, Any]]] = {}
        category_order = [
            "Job",
            "Remote Storage",
            "Nodi Proxy",
            "Portale Pubblico",
            "Notifiche",
            "Identità & Directory",
            "Intelligenza Artificiale",
            "Personalizzazione & Branding",
            "Utenti & Ruoli",
            "Autenticazione",
            "Backup & Restore Sistema",
            "Impostazioni & Sistema",
            "Audit & Monitoraggio",
        ]

        for p in perms:
            cat = p.category or "Generale"
            if cat not in categories_dict:
                categories_dict[cat] = []
            categories_dict[cat].append(
                {
                    "id": str(p.id),
                    "code": p.code,
                    "name": p.name or p.code,
                    "category": cat,
                    "description": p.description or "",
                }
            )

        # Sort categories according to canonical category_order
        sorted_categories: list[dict[str, Any]] = []
        for cat in category_order:
            if cat in categories_dict:
                sorted_categories.append(
                    {
                        "name": cat,
                        "permissions": categories_dict.pop(cat),
                    }
                )
        # Any remaining categories
        for cat, plist in sorted(categories_dict.items()):
            sorted_categories.append({"name": cat, "permissions": plist})

        # 3. Direct lookup mapping role_id -> set of permission codes
        matrix_lookup: dict[str, list[str]] = {
            str(r.id): [p.code for p in r.permissions] for r in roles
        }

        return {
            "roles": role_list,
            "categories": sorted_categories,
            "matrix": matrix_lookup,
        }

    @staticmethod
    def create_user(
        session: Session,
        username: str,
        password: str,
        role_id: UUID,
        email: str | None = None,
        display_name: str | None = None,
        is_active: bool = True,
        must_change_password: bool = False,
        theme: str = "embervault",
        actor_user_id: UUID | None = None,
        ip: str | None = None,
    ) -> User:
        """Create a new user with password complexity validation and audit logging."""
        clean_user = username.strip()
        if not clean_user:
            raise ValueError("Il nome utente non può essere vuoto.")

        existing = UserRepository.get_user_by_username(session, clean_user)
        if existing is not None:
            raise ValueError(f"Nome utente '{clean_user}' già esistente.")

        valid, err = validate_password_complexity(password)
        if not valid:
            raise ValueError(err or "Password non valida.")

        role = UserRepository.get_role_by_id(session, role_id)
        if role is None:
            raise ValueError(f"Ruolo non valido (ID '{role_id}').")

        hashed = hash_password(password)
        user_id = uuid4()
        valid_theme = "embervault"
        if theme:
            clean_theme = theme.strip().lower()
            valid_themes = ("embervault", "theeame", "acrovault", "emberxp", "iembervault")
            if clean_theme not in valid_themes:
                raise ValueError(
                    f"Tema '{theme}' non valido. Temi disponibili: {', '.join(valid_themes)}"
                )
            valid_theme = clean_theme

        user = User(
            id=user_id,
            username=clean_user,
            email=email.strip() if email else None,
            display_name=display_name.strip() if display_name else None,
            password_hash=hashed,
            auth_source="local",
            role_id=role_id,
            is_active=is_active,
            must_change_password=must_change_password,
            theme=valid_theme,
        )
        session.add(user)

        # Audit log
        audit = AuditLog(
            action="user.create",
            actor_user_id=actor_user_id,
            entity_type="user",
            entity_id=str(user_id),
            ip=ip,
            details={
                "username": clean_user,
                "role": role.name,
                "email": user.email,
                "is_active": is_active,
                "theme": user.theme,
            },
        )
        session.add(audit)
        session.flush()
        return user

    @staticmethod
    def update_user(
        session: Session,
        user_id: UUID,
        role_id: UUID | None = None,
        email: str | None = None,
        display_name: str | None = None,
        is_active: bool | None = None,
        must_change_password: bool | None = None,
        new_password: str | None = None,
        theme: str | None = None,
        actor_user_id: UUID | None = None,
        ip: str | None = None,
    ) -> User:
        """Update user properties, role, or password with audit logging."""
        user = session.get(User, user_id)
        if user is None:
            raise ValueError(f"Utente con ID '{user_id}' non trovato.")

        changes: dict[str, Any] = {}

        if role_id is not None and role_id != user.role_id:
            role = session.get(Role, role_id)
            if role is None:
                raise ValueError("Ruolo specificato non valido.")
            changes["role"] = {"old": user.role.name if user.role else None, "new": role.name}
            user.role_id = role_id

        if email is not None and email != user.email:
            changes["email"] = {"old": user.email, "new": email}
            user.email = email.strip() if email else None

        if display_name is not None and display_name != user.display_name:
            changes["display_name"] = {"old": user.display_name, "new": display_name}
            user.display_name = display_name.strip() if display_name else None

        if is_active is not None and is_active != user.is_active:
            # Prevent deactivating the last active admin
            if not is_active and user.role and user.role.name.lower() in ("admin", "administrator"):
                active_admins = (
                    session.scalar(
                        select(func.count(User.id))
                        .join(Role, User.role_id == Role.id)
                        .where(func.lower(Role.name).in_(["admin", "administrator"]))
                        .where(User.is_active.is_(True))
                    )
                    or 0
                )
                if active_admins <= 1:
                    raise ValueError(
                        "Impossibile disattivare l'unico amministratore attivo del sistema."
                    )

            changes["is_active"] = {"old": user.is_active, "new": is_active}
            user.is_active = is_active

            # If user deactivated, revoke active sessions
            if not is_active:
                session.execute(delete(UserSession).where(UserSession.user_id == user.id))

        if must_change_password is not None:
            user.must_change_password = must_change_password

        if new_password:
            valid, err = validate_password_complexity(new_password)
            if not valid:
                raise ValueError(err or "Password non valida.")
            user.password_hash = hash_password(new_password)
            changes["password_reset"] = True
            # Invalidate existing sessions on password change
            session.execute(delete(UserSession).where(UserSession.user_id == user.id))

        if theme is not None and theme != user.theme:
            valid_themes = ("embervault", "theeame", "acrovault", "emberxp", "iembervault")
            clean_theme = theme.strip().lower()
            if clean_theme not in valid_themes:
                raise ValueError(
                    f"Tema '{theme}' non valido. Temi disponibili: {', '.join(valid_themes)}"
                )
            changes["theme"] = {"old": user.theme, "new": clean_theme}
            user.theme = clean_theme

        if changes:
            audit = AuditLog(
                action="user.update",
                actor_user_id=actor_user_id,
                entity_type="user",
                entity_id=str(user.id),
                ip=ip,
                details=changes,
            )
            session.add(audit)

        session.flush()
        return user

    @staticmethod
    def delete_user(
        session: Session,
        user_id: UUID,
        actor_user_id: UUID | None = None,
        ip: str | None = None,
    ) -> bool:
        """Delete user account after validating safety constraints."""
        user = session.get(User, user_id)
        if user is None:
            return False

        # Protect against self-deletion
        if actor_user_id is not None and user.id == actor_user_id:
            raise ValueError("Impossibile eliminare il proprio account corrente.")

        # Protect against deleting the last admin
        if user.role and user.role.name.lower() in ("admin", "administrator"):
            admin_count = (
                session.scalar(
                    select(func.count(User.id))
                    .join(Role, User.role_id == Role.id)
                    .where(func.lower(Role.name).in_(["admin", "administrator"]))
                )
                or 0
            )
            if admin_count <= 1:
                raise ValueError("Impossibile eliminare l'unico utente con ruolo Amministratore.")

        username_deleted = user.username
        # Delete user child relations explicitly (sessions, MFA factors, recovery codes)
        session.execute(delete(UserSession).where(UserSession.user_id == user.id))
        session.execute(delete(UserMfaFactor).where(UserMfaFactor.user_id == user.id))
        session.execute(delete(UserRecoveryCode).where(UserRecoveryCode.user_id == user.id))
        session.delete(user)

        audit = AuditLog(
            action="user.delete",
            actor_user_id=actor_user_id,
            entity_type="user",
            entity_id=str(user_id),
            ip=ip,
            details={"username": username_deleted},
        )
        session.add(audit)
        session.flush()
        return True

    @staticmethod
    def record_audit(
        session: Session,
        action: str,
        entity_type: str,
        actor_user_id: UUID | None = None,
        entity_id: str | None = None,
        details: dict[str, Any] | None = None,
        ip: str | None = None,
    ) -> AuditLog:
        """Append an entry to the immutable audit log."""
        audit = AuditLog(
            action=action,
            actor_user_id=actor_user_id,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
            ip=ip,
        )
        session.add(audit)
        session.flush()
        return audit

    @staticmethod
    def list_audit_logs(
        session: Session,
        limit: int = 100,
        action_prefix: str | None = None,
    ) -> list[AuditLog]:
        """Fetch audit log records descending."""
        stmt = select(AuditLog)
        if action_prefix:
            stmt = stmt.where(AuditLog.action.startswith(action_prefix))
        stmt = stmt.order_by(desc(AuditLog.id)).limit(limit)
        return list(session.scalars(stmt).all())

    @staticmethod
    def get_user_mfa_factor(
        session: Session, user_id: UUID, factor_type: str = "totp"
    ) -> Any | None:
        """Retrieve confirmed or pending MFA factor for user."""
        from embervault_db.models.auth import UserMfaFactor

        stmt = select(UserMfaFactor).where(
            UserMfaFactor.user_id == user_id,
            UserMfaFactor.type == factor_type,
        )
        return session.scalar(stmt)

    @staticmethod
    def set_user_totp_factor(
        session: Session,
        user_id: UUID,
        secret_encrypted: bytes,
        label: str = "Authenticator App",
        confirmed: bool = False,
        actor_user_id: UUID | None = None,
        ip: str | None = None,
    ) -> Any:
        """Create or replace TOTP factor for user."""
        from embervault_db.models.auth import UserMfaFactor
        from embervault_db.models.base import utc_now

        factor = UserRepository.get_user_mfa_factor(session, user_id, "totp")
        if factor is None:
            factor = UserMfaFactor(
                user_id=user_id,
                type="totp",
                secret_encrypted=secret_encrypted,
                label=label,
                confirmed_at=utc_now() if confirmed else None,
            )
            session.add(factor)
        else:
            factor.secret_encrypted = secret_encrypted
            factor.label = label
            factor.confirmed_at = utc_now() if confirmed else None

        if confirmed:
            audit = AuditLog(
                action="auth.2fa.totp_enabled",
                actor_user_id=actor_user_id or user_id,
                entity_type="user",
                entity_id=str(user_id),
                ip=ip,
                details={"factor": "totp"},
            )
            session.add(audit)

        session.flush()
        return factor

    @staticmethod
    def confirm_user_totp_factor(
        session: Session,
        user_id: UUID,
        actor_user_id: UUID | None = None,
        ip: str | None = None,
    ) -> bool:
        """Mark user's TOTP factor as confirmed."""
        from embervault_db.models.base import utc_now

        factor = UserRepository.get_user_mfa_factor(session, user_id, "totp")
        if factor is None:
            return False
        factor.confirmed_at = utc_now()

        audit = AuditLog(
            action="auth.2fa.totp_enabled",
            actor_user_id=actor_user_id or user_id,
            entity_type="user",
            entity_id=str(user_id),
            ip=ip,
            details={"factor": "totp"},
        )
        session.add(audit)
        session.flush()
        return True

    @staticmethod
    def disable_user_2fa(
        session: Session,
        user_id: UUID,
        actor_user_id: UUID | None = None,
        ip: str | None = None,
    ) -> bool:
        """Remove all MFA factors and recovery codes for user."""
        from embervault_db.models.auth import UserMfaFactor, UserRecoveryCode

        session.execute(delete(UserMfaFactor).where(UserMfaFactor.user_id == user_id))
        session.execute(delete(UserRecoveryCode).where(UserRecoveryCode.user_id == user_id))

        audit = AuditLog(
            action="auth.2fa.disabled",
            actor_user_id=actor_user_id or user_id,
            entity_type="user",
            entity_id=str(user_id),
            ip=ip,
            details={"action": "2fa_disabled"},
        )
        session.add(audit)
        session.flush()
        return True

    @staticmethod
    def set_user_recovery_codes(
        session: Session,
        user_id: UUID,
        hashed_codes: list[str],
        actor_user_id: UUID | None = None,
        ip: str | None = None,
    ) -> None:
        """Replace all existing recovery codes for user with new ones."""
        from embervault_db.models.auth import UserRecoveryCode

        session.execute(delete(UserRecoveryCode).where(UserRecoveryCode.user_id == user_id))
        for h in hashed_codes:
            code_entry = UserRecoveryCode(
                user_id=user_id,
                code_hash=h,
            )
            session.add(code_entry)

        audit = AuditLog(
            action="auth.2fa.recovery_codes_generated",
            actor_user_id=actor_user_id or user_id,
            entity_type="user",
            entity_id=str(user_id),
            ip=ip,
            details={"count": len(hashed_codes)},
        )
        session.add(audit)
        session.flush()

    @staticmethod
    def verify_and_consume_recovery_code(
        session: Session,
        user_id: UUID,
        normalized_code_hash: str,
        ip: str | None = None,
    ) -> bool:
        """Check if recovery code hash exists and is unused; mark used if valid."""
        from embervault_db.models.auth import UserRecoveryCode
        from embervault_db.models.base import utc_now

        stmt = select(UserRecoveryCode).where(
            UserRecoveryCode.user_id == user_id,
            UserRecoveryCode.code_hash == normalized_code_hash,
            UserRecoveryCode.used_at.is_(None),
        )
        record = session.scalar(stmt)
        if record is None:
            return False

        record.used_at = utc_now()
        audit = AuditLog(
            action="auth.2fa.recovery_code_used",
            actor_user_id=user_id,
            entity_type="user",
            entity_id=str(user_id),
            ip=ip,
            details={"code_id": str(record.id)},
        )
        session.add(audit)
        session.flush()
        return True

    @staticmethod
    def get_remaining_recovery_codes_count(session: Session, user_id: UUID) -> int:
        """Count how many unused recovery codes remain for user."""
        from embervault_db.models.auth import UserRecoveryCode

        stmt = select(func.count(UserRecoveryCode.id)).where(
            UserRecoveryCode.user_id == user_id,
            UserRecoveryCode.used_at.is_(None),
        )
        return session.scalar(stmt) or 0

    @staticmethod
    def reencrypt_user_mfa_factors(
        session: Session,
        new_key_id: str | None = None,
    ) -> int:
        """Re-encrypt all user MFA factor secrets using target or primary key.

        Returns the number of re-encrypted MFA factors.
        """
        from embervault_common.security.crypto import reencrypt_blob
        from embervault_db.models.auth import UserMfaFactor

        stmt = select(UserMfaFactor)
        factors = list(session.scalars(stmt).all())
        reencrypted_count = 0
        for f in factors:
            aad = f"user_mfa:{f.user_id}".encode()
            reencrypted = reencrypt_blob(f.secret_encrypted, new_key_id=new_key_id, aad=aad)
            if reencrypted != f.secret_encrypted:
                f.secret_encrypted = reencrypted
                reencrypted_count += 1
        if reencrypted_count > 0:
            session.flush()
        return reencrypted_count
