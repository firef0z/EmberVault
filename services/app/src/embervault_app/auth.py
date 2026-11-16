"""Authentication, session management, rate limiting, and RBAC decorators for EmberVault."""

from __future__ import annotations

import threading
import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, TypeVar, cast

from flask import (
    Flask,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.i18n import translate as _
from embervault_common.security.passwords import (
    needs_rehash,
    verify_password,
)
from embervault_common.security.tokens import generate_secure_token, hash_token
from embervault_db.models.auth import AuditLog, Role, User, UserSession

F = TypeVar("F", bound=Callable[..., Any])

# Default session duration: 12 hours
DEFAULT_SESSION_DURATION = timedelta(hours=12)


class LoginRateLimiter:
    """Thread-safe sliding-window rate limiter for login attempts."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _clean_old(self, key: str, now: float) -> list[float]:
        threshold = now - self.window_seconds
        filtered = [t for t in self._attempts[key] if t > threshold]
        self._attempts[key] = filtered
        return filtered

    def is_locked(self, key: str) -> tuple[bool, int]:
        """Check if key is locked out.

        Returns (is_locked, remaining_seconds).
        """
        now = time.time()
        with self._lock:
            recent = self._clean_old(key, now)
            if len(recent) >= self.max_attempts:
                oldest_in_window = recent[0]
                remaining = int(self.window_seconds - (now - oldest_in_window))
                return True, max(1, remaining)
            return False, 0

    def record_failure(self, key: str) -> None:
        """Record a failed authentication attempt."""
        now = time.time()
        with self._lock:
            self._attempts[key].append(now)

    def record_success(self, key: str) -> None:
        """Clear failures upon successful authentication."""
        with self._lock:
            self._attempts.pop(key, None)


login_rate_limiter = LoginRateLimiter(max_attempts=5, window_seconds=300)


def get_db_session() -> sessionmaker[Session]:
    """Retrieve session factory from current Flask application."""
    return cast(sessionmaker[Session], current_app.config["SESSION_FACTORY"])


def authenticate_user(
    db: Session,
    username: str,
    password: str,
    ip: str | None = None,
    user_agent: str | None = None,
    auth_source: str = "local",
    custom_ldap_server: Any = None,
    ldap_client_strategy: Any = None,
    ldap_config_override: Any = None,
) -> tuple[User | None, str | None]:
    """Authenticate a user with username and password against local DB or LDAP directory.

    Args:
        db: Active SQLAlchemy database session.
        username: Provided username.
        password: Provided password.
        ip: Client IP address for rate limiting and audit logging.
        user_agent: Client User-Agent header.
        auth_source: 'local' for local DB authentication, 'ldap' for Active Directory/LDAP.
        custom_ldap_server: Optional custom/mock Server instance (for unit testing).
        ldap_client_strategy: Optional custom client strategy (for unit testing).
        ldap_config_override: Optional LdapConfig override (for unit testing).

    Returns:
        (user, error_message).
    """
    clean_username = username.strip()
    rate_key = f"{ip or 'unknown'}:{auth_source}:{clean_username}"

    # Check rate limit
    is_locked, remaining = login_rate_limiter.is_locked(rate_key)
    if is_locked:
        return (
            None,
            _("auth_rate_limited_tpl").format(remaining=remaining),
        )

    # 1. Local Authentication Flow
    if auth_source == "local":
        user = db.scalar(select(User).where(User.username == clean_username))

        if user is None or not user.is_active:
            login_rate_limiter.record_failure(rate_key)
            return None, _("auth_invalid_credentials")

        if not user.password_hash:
            login_rate_limiter.record_failure(rate_key)
            return (
                None,
                _("auth_no_local_password"),
            )

        if not verify_password(user.password_hash, password):
            login_rate_limiter.record_failure(rate_key)
            audit = AuditLog(
                action="auth.login.failed",
                actor_user_id=user.id,
                entity_type="user",
                entity_id=str(user.id),
                ip=ip,
                details={
                    "username": clean_username,
                    "auth_source": "local",
                    "reason": "invalid_password",
                    "user_agent": user_agent,
                },
            )
            db.add(audit)
            db.commit()
            return None, _("auth_invalid_credentials")

        # Login successful
        login_rate_limiter.record_success(rate_key)
        if needs_rehash(user.password_hash):
            from embervault_common.security.passwords import hash_password

            user.password_hash = hash_password(password)

        user.last_login_at = datetime.now(UTC)
        db.commit()
        return user, None

    # 2. LDAP / Active Directory Flow
    if auth_source == "ldap":
        existing_user = db.scalar(select(User).where(User.username == clean_username))

        if existing_user is not None and not existing_user.is_active:
            return None, _("auth_account_disabled")

        if ldap_config_override is not None:
            ldap_config = ldap_config_override
        else:
            from embervault_app.ldap_service import get_ldap_config

            enabled, ldap_config = get_ldap_config(db)
            if not enabled:
                return (
                    None,
                    _("auth_ldap_not_enabled"),
                )

        from embervault_common.security.ldap import authenticate_ldap_user

        ok, err_msg, ldap_info = authenticate_ldap_user(
            config=ldap_config,
            username=clean_username,
            password=password,
            custom_server=custom_ldap_server,
            client_strategy=ldap_client_strategy,
        )

        if not ok or ldap_info is None:
            login_rate_limiter.record_failure(rate_key)
            if existing_user is not None:
                audit = AuditLog(
                    action="auth.login.failed",
                    actor_user_id=existing_user.id,
                    entity_type="user",
                    entity_id=str(existing_user.id),
                    ip=ip,
                    details={
                        "username": clean_username,
                        "auth_source": "ldap",
                        "reason": err_msg or "ldap_auth_failed",
                        "user_agent": user_agent,
                    },
                )
                db.add(audit)
                db.commit()
            return None, (_(err_msg) if err_msg else _("auth_invalid_ldap_credentials"))

        # Successful LDAP authentication
        login_rate_limiter.record_success(rate_key)

        from embervault_db.repositories.user_repository import UserRepository

        role = UserRepository.get_role_by_name(db, ldap_info.role_name)
        if role is None:
            role = UserRepository.get_role_by_name(db, "viewer")
        assert role is not None

        if existing_user is None:
            # Just-In-Time (JIT) user provisioning
            user = User(
                username=clean_username,
                email=ldap_info.email,
                display_name=ldap_info.display_name or clean_username,
                auth_source="ldap",
                external_subject=ldap_info.dn,
                password_hash=None,
                role_id=role.id,
                is_active=True,
                must_change_password=False,
                last_login_at=datetime.now(UTC),
            )
            db.add(user)
            db.flush()
        else:
            user = existing_user
            user.external_subject = ldap_info.dn
            if ldap_info.display_name:
                user.display_name = ldap_info.display_name
            if ldap_info.email:
                user.email = ldap_info.email
            user.role_id = role.id
            user.last_login_at = datetime.now(UTC)

        audit = AuditLog(
            action="auth.login.success",
            actor_user_id=user.id,
            entity_type="user",
            entity_id=str(user.id),
            ip=ip,
            details={
                "username": clean_username,
                "auth_source": "ldap",
                "ldap_dn": ldap_info.dn,
                "role": role.name,
                "groups": ldap_info.groups,
                "user_agent": user_agent,
            },
        )
        db.add(audit)
        db.commit()
        return user, None

    return None, _("auth_unknown_source_tpl").format(auth_source=auth_source)


def create_user_session(
    db: Session,
    user: User,
    ip: str | None = None,
    user_agent: str | None = None,
    duration: timedelta = DEFAULT_SESSION_DURATION,
    mfa_verified: bool = False,
) -> str:
    """Create a new database user session and return raw bearer session token."""
    raw_token = generate_secure_token(32, encoding="urlsafe")
    hashed_token = hash_token(raw_token)
    expires_at = datetime.now(UTC) + duration

    db_session = UserSession(
        user_id=user.id,
        token_hash=hashed_token,
        ip=ip,
        user_agent=user_agent,
        mfa_verified_at=datetime.now(UTC) if mfa_verified else None,
        expires_at=expires_at,
    )
    db.add(db_session)

    # Audit log successful login
    audit = AuditLog(
        action="auth.login.success",
        actor_user_id=user.id,
        entity_type="user",
        entity_id=str(user.id),
        ip=ip,
        details={"username": user.username, "role": user.role.name, "user_agent": user_agent},
    )
    db.add(audit)
    db.commit()

    return raw_token


def expand_permissions(perms: set[str]) -> set[str]:
    """Expand granular and cumulative permissions bi-directionally for backward compatibility."""
    expanded = set(perms)

    # Job write cumulative expansion
    if "job.write" in perms:
        expanded.update({"job.read", "job.create", "job.update", "job.delete", "job.run"})
    if {"job.create", "job.update", "job.delete"}.issubset(perms):
        expanded.add("job.write")

    # Remote write cumulative expansion
    if "remote.write" in perms:
        expanded.update(
            {
                "remote.read",
                "remote.create",
                "remote.update",
                "remote.delete",
                "remote.browse",
                "remote.download",
                "remote.test",
            }
        )
    if {"remote.create", "remote.update", "remote.delete"}.issubset(perms):
        expanded.add("remote.write")

    # Proxy manage cumulative expansion
    if "proxy.manage" in perms:
        expanded.update(
            {
                "proxy.read",
                "proxy.create",
                "proxy.update",
                "proxy.delete",
                "proxy.upgrade",
                "proxy.retrust",
                "proxy.renew_cert",
            }
        )
    if {"proxy.create", "proxy.update", "proxy.delete"}.issubset(perms):
        expanded.add("proxy.manage")

    # User manage cumulative expansion
    if "user.manage" in perms:
        expanded.update(
            {"user.read", "user.create", "user.update", "user.delete", "role.read", "role.manage"}
        )
    if {"user.create", "user.update", "user.delete", "role.manage"}.issubset(perms):
        expanded.add("user.manage")

    # Role manage implies role.read
    if "role.manage" in perms:
        expanded.add("role.read")

    # Portale Pubblico (share) cumulative expansion
    if "share.write" in perms:
        expanded.update(
            {"share.read", "share.create", "share.update", "share.deactivate", "share.delete"}
        )
    if {"share.create", "share.deactivate", "share.delete"}.issubset(perms):
        expanded.add("share.write")

    # Backup manage cumulative expansion
    if "backup.manage" in perms:
        expanded.update({"backup.read", "backup.export", "backup.restore"})
    if {"backup.export", "backup.restore"}.issubset(perms):
        expanded.add("backup.manage")

    # Notification write expansion
    if "notification.write" in perms:
        expanded.add("notification.read")

    # Identity write expansion
    if "identity.write" in perms:
        expanded.add("identity.read")

    # AI write expansion
    if "ai.write" in perms:
        expanded.add("ai.read")

    # Appearance write expansion
    if "appearance.write" in perms:
        expanded.add("appearance.read")

    # Audit export implies audit.read
    if "audit.export" in perms:
        expanded.add("audit.read")

    # Backward compatibility: settings.write expands to all sub-settings scopes
    if "settings.write" in perms:
        expanded.update(
            {
                "settings.read",
                "notification.write",
                "notification.read",
                "identity.write",
                "identity.read",
                "ai.write",
                "ai.read",
                "appearance.write",
                "appearance.read",
                "network.manage",
                "hooks.manage",
                "crypto.rotate",
            }
        )
    if "settings.read" in perms:
        expanded.update(
            {
                "notification.read",
                "identity.read",
                "ai.read",
                "appearance.read",
            }
        )

    return expanded


def get_current_user() -> User | None:
    """Resolve and return currently authenticated user from Flask session or context."""
    if hasattr(g, "current_user"):
        return cast(User | None, g.current_user)

    raw_token = session.get("auth_token")
    user_id_str = session.get("user_id")

    if not raw_token or not user_id_str:
        # If user explicitly logged out, do not auto-login via dev_noauth
        if session.get("logged_out"):
            g.current_user = None
            g.permissions = set()
            return None

        # Check dev mode noauth fallback
        settings = current_app.config.get("SETTINGS")
        if settings and getattr(settings, "dev_noauth", False):
            try:
                session_factory = get_db_session()
                with session_factory() as db:
                    dev_admin = db.scalar(
                        select(User).where(User.username == "admin").where(User.is_active.is_(True))
                    )
                    if dev_admin is None:
                        # Try to find another active admin user
                        dev_admin = db.scalar(
                            select(User)
                            .join(User.role)
                            .where(func.lower(Role.name).in_(["admin", "administrator"]))
                            .where(User.is_active.is_(True))
                        )
                    if dev_admin:
                        g.current_user = dev_admin
                        raw_perms = {p.code for p in dev_admin.role.permissions}
                        from embervault_db.seed import ALL_PERMISSION_CODES

                        raw_perms.update(ALL_PERMISSION_CODES)
                        g.permissions = expand_permissions(raw_perms)
                        return dev_admin
            except Exception:
                pass

            # Transient fallback user if DB tables not seeded
            from embervault_db.seed import ALL_PERMISSION_CODES

            dummy_role = Role(name="Administrator", description="Dev Admin", is_system=True)
            dummy_user = User(
                id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
                username="admin",
                email="admin@embervault.local",
                display_name="Dev Administrator",
                role=dummy_role,
                is_active=True,
                must_change_password=False,
            )
            g.current_user = dummy_user
            g.permissions = expand_permissions(set(ALL_PERMISSION_CODES))
            return dummy_user

        g.current_user = None
        g.permissions = set()
        return None

    hashed = hash_token(raw_token)
    session_factory = get_db_session()
    now = datetime.now(UTC)

    with session_factory() as db:
        user_session = db.scalar(
            select(UserSession)
            .where(UserSession.token_hash == hashed)
            .where(UserSession.expires_at > now)
        )
        if user_session is None:
            # Session expired or revoked
            session.pop("auth_token", None)
            session.pop("user_id", None)
            g.current_user = None
            g.permissions = set()
            return None

        user = db.scalar(
            select(User).where(User.id == user_session.user_id).where(User.is_active.is_(True))
        )
        if user is None:
            g.current_user = None
            g.permissions = set()
            return None

        # Cache on g for this request
        g.current_user = user
        g.current_user_session = user_session
        role = user.role
        raw_perms = {p.code for p in role.permissions} if role else set()
        if role and getattr(role, "name", "").strip().lower() in ("admin", "administrator"):
            from embervault_db.seed import ALL_PERMISSION_CODES

            raw_perms.update(c for c in ALL_PERMISSION_CODES if c != "auth.enforce_2fa")
            if role.enforce_2fa:
                raw_perms.add("auth.enforce_2fa")
        g.permissions = expand_permissions(raw_perms)
        return user


def logout_current_user() -> None:
    """Invalidate current session in DB and clear Flask session cookie."""
    raw_token = session.get("auth_token")
    if raw_token:
        hashed = hash_token(raw_token)
        session_factory = get_db_session()
        with session_factory() as db:
            current_user = getattr(g, "current_user", None)
            if current_user:
                audit = AuditLog(
                    action="auth.logout",
                    actor_user_id=current_user.id,
                    entity_type="user",
                    entity_id=str(current_user.id),
                    ip=request.remote_addr,
                    details={
                        "username": current_user.username,
                        "user_agent": request.headers.get("User-Agent"),
                    },
                )
                db.add(audit)
            db.execute(delete(UserSession).where(UserSession.token_hash == hashed))
            db.commit()

    session.clear()
    session["logged_out"] = True
    g.current_user = None
    g.permissions = set()


def require_auth[F: Callable[..., Any]](f: F) -> F:
    """Decorator requiring an active authenticated user session."""

    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        current_user = get_current_user()
        if current_user is None:
            if request.path.startswith("/api/") or request.is_json:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "error": "unauthorized",
                            "message": _("auth_required_msg"),
                        }
                    ),
                    401,
                )
            return redirect(url_for("auth.login", next=request.path))

        # Enforce password change if flagged (except on change-password/logout or if dev_noauth is enabled)
        settings = current_app.config.get("SETTINGS")
        is_dev_noauth = bool(settings and getattr(settings, "dev_noauth", False))
        if (
            not is_dev_noauth
            and current_user.must_change_password
            and request.endpoint not in ("auth.change_password", "auth.logout", "static")
        ):
            if request.path.startswith("/api/") or request.is_json:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "error": "password_change_required",
                            "message": _("auth_must_change_default_password"),
                        }
                    ),
                    403,
                )
            flash(
                _("auth_must_change_temp_password"),
                "warning",
            )
            return redirect(url_for("auth.change_password"))

        # Enforce role 2FA requirement if enabled (via role flag or auth.enforce_2fa permission on role)
        role = getattr(current_user, "role", None)
        is_2fa_enforced = False
        if role:
            if getattr(role, "enforce_2fa", False):
                is_2fa_enforced = True
            elif hasattr(role, "permissions"):
                is_2fa_enforced = any(p.code == "auth.enforce_2fa" for p in role.permissions)

        if not is_dev_noauth and is_2fa_enforced:
            # Check if user has confirmed 2FA factor
            has_confirmed_2fa = any(f.confirmed_at is not None for f in current_user.mfa_factors)
            if not has_confirmed_2fa:
                allowed_endpoints = (
                    "auth.change_password",
                    "auth.logout",
                    "auth.two_factor_setup",
                    "api.setup_2fa_totp",
                    "api.confirm_2fa_totp",
                    "api.get_2fa_status",
                    "static",
                )
                if request.endpoint not in allowed_endpoints:
                    if request.path.startswith("/api/") or request.is_json:
                        return (
                            jsonify(
                                {
                                    "status": "error",
                                    "error": "2fa_setup_required",
                                    "message": _("auth_2fa_mandatory_for_role"),
                                }
                            ),
                            403,
                        )
                    flash(
                        _("auth_2fa_mandatory_flash"),
                        "warning",
                    )
                    return redirect(url_for("auth.two_factor_setup"))

        return f(*args, **kwargs)

    return cast(F, decorated)


def require_permission(*permission_codes: str) -> Callable[[F], F]:
    """Decorator requiring at least one of the specified permission codes on authenticated user role."""

    def decorator(f: F) -> F:
        @wraps(f)
        @require_auth
        def decorated(*args: Any, **kwargs: Any) -> Any:
            if is_admin_user():
                return f(*args, **kwargs)

            user_perms: set[str] = getattr(g, "permissions", set())
            if not any(code in user_perms for code in permission_codes):
                code_display = ", ".join(permission_codes)
                if request.path.startswith("/api/") or request.is_json:
                    return (
                        jsonify(
                            {
                                "status": "error",
                                "error": "forbidden",
                                "message": _("auth_permission_not_granted_tpl").format(
                                    code=code_display
                                ),
                            }
                        ),
                        403,
                    )
                return (
                    render_template(
                        "error.html",
                        error_code=403,
                        error_title=_("error_access_denied_title"),
                        error_message=_("auth_insufficient_privileges_tpl").format(
                            code=code_display
                        ),
                    ),
                    403,
                )
            return f(*args, **kwargs)

        return cast(F, decorated)

    return decorator


def is_admin_user() -> bool:
    """Return True if the current user has full administrator role."""
    settings = current_app.config.get("SETTINGS")
    if settings and getattr(settings, "dev_noauth", False):
        return True
    current_u = getattr(g, "current_user", None)
    if current_u is not None:
        role = getattr(current_u, "role", None)
        if role is not None and getattr(role, "name", "").strip().lower() in (
            "admin",
            "administrator",
        ):
            return True
        user_p = getattr(g, "permissions", set())
        if "user.manage" in user_p and "settings.write" in user_p:
            return True
    return False


def require_admin(f: F) -> F:
    """Decorator requiring administrator role on authenticated user."""

    @wraps(f)
    @require_auth
    def decorated(*args: Any, **kwargs: Any) -> Any:
        if not is_admin_user():
            if request.path.startswith("/api/") or request.is_json:
                return (
                    jsonify(
                        {
                            "status": "error",
                            "error": "forbidden",
                            "message": _("auth_admin_only_api"),
                        }
                    ),
                    403,
                )
            return (
                render_template(
                    "error.html",
                    error_code=403,
                    error_title=_("error_access_denied_title"),
                    error_message=_("auth_admin_only_page"),
                ),
                403,
            )
        return f(*args, **kwargs)

    return cast(F, decorated)


def init_auth(app: Flask) -> None:
    """Initialize authentication hooks on Flask application."""

    @app.before_request
    def load_authenticated_user() -> None:
        """Pre-populate g.current_user and g.permissions on every incoming request."""
        get_current_user()

    @app.context_processor
    def inject_auth_context() -> dict[str, Any]:
        """Inject current user and permission helpers into Jinja templates."""
        current_u = getattr(g, "current_user", None)
        user_p: set[str] = getattr(g, "permissions", set())

        # Check security banner condition: single active admin or dev_noauth active
        settings = current_app.config.get("SETTINGS")
        is_dev_noauth = bool(settings and getattr(settings, "dev_noauth", False))
        single_admin_warning = False

        if current_u is not None:
            if is_dev_noauth:
                single_admin_warning = True
            else:
                try:
                    session_factory = get_db_session()
                    with session_factory() as db:
                        from sqlalchemy import func

                        total_users = db.scalar(select(func.count(User.id)))
                        if (
                            total_users is not None
                            and total_users <= 1
                            and current_u.username == "admin"
                        ):
                            single_admin_warning = True
                except Exception:
                    pass

        current_theme = (
            getattr(current_u, "theme", None) or session.get("user_theme") or "embervault"
        )
        valid_themes = ["embervault", "theeame", "acrovault", "emberxp", "iembervault"]
        if current_theme not in valid_themes:
            current_theme = "embervault"

        current_mode = (
            request.cookies.get("embervault_mode") or session.get("user_theme_mode") or "dark"
        )
        if current_mode not in ("light", "dark"):
            current_mode = "dark"

        from embervault_common.config import is_demo_mode
        demo_mode_active = is_demo_mode(settings)

        return {
            "current_user": current_u,
            "user_permissions": user_p,
            "has_permission": lambda code: code in user_p,
            "is_admin": is_admin_user(),
            "is_dev_noauth": is_dev_noauth,
            "demo_mode": demo_mode_active,
            "single_admin_warning": single_admin_warning,
            "current_theme": current_theme,
            "current_mode": current_mode,
            "available_themes": [
                {"id": "embervault", "name": "EmberVault Theme"},
                {"id": "theeame", "name": "Theeame"},
                {"id": "acrovault", "name": "AcroVault"},
                {"id": "emberxp", "name": "EmberXP"},
                {"id": "iembervault", "name": "iEmberVault"},
            ],
        }
