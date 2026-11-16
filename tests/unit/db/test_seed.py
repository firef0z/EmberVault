"""Unit tests for idempotent database seeding."""

from sqlalchemy import select

from embervault_common.security.passwords import verify_password
from embervault_db.models import Base, Permission, Role, User
from embervault_db.seed import DEFAULT_PERMISSIONS, DEFAULT_ROLES, seed_initial_data
from embervault_db.session import create_engine_from_url, create_session_factory, get_session


def test_seed_initial_data_idempotency() -> None:
    """Verify that seed_initial_data populates default roles/permissions and is strictly idempotent."""
    engine = create_engine_from_url("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)

    # First seed run
    with get_session(session_factory) as session:
        seed_initial_data(session)

    with get_session(session_factory) as session:
        roles = session.scalars(select(Role)).all()
        assert len(roles) == len(DEFAULT_ROLES)
        role_names = {r.name for r in roles}
        assert role_names == set(DEFAULT_ROLES.keys())

        perms = session.scalars(select(Permission)).all()
        assert len(perms) == len(DEFAULT_PERMISSIONS)

        admin = session.scalar(select(Role).where(Role.name.in_(["Administrator", "admin"])))
        assert admin is not None
        assert admin.is_system is True
        # Administrator has all operational permissions by default (excluding auth.enforce_2fa)
        assert len(admin.permissions) >= len(DEFAULT_PERMISSIONS) - 1

        # Verify default admin user was created
        admin_user = session.scalar(select(User).where(User.username == "admin"))
        assert admin_user is not None
        assert admin_user.role.name in ("Administrator", "admin")
        assert admin_user.is_active is True
        assert admin_user.must_change_password is True
        assert verify_password(admin_user.password_hash or "", "admin") is True

    # Second seed run (must be completely idempotent)
    with get_session(session_factory) as session:
        seed_initial_data(session)

    with get_session(session_factory) as session:
        roles_after = session.scalars(select(Role)).all()
        perms_after = session.scalars(select(Permission)).all()
        assert len(roles_after) == len(DEFAULT_ROLES)
        assert len(perms_after) == len(DEFAULT_PERMISSIONS)
        users_after = session.scalars(select(User)).all()
        assert len(users_after) == 1
