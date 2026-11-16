"""Unit tests for granular permissions, categories, custom roles, and permissions matrix."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.auth import Base, Permission, Role, User
from embervault_db.repositories.user_repository import UserRepository
from embervault_db.seed import DEFAULT_PERMISSIONS, DEFAULT_ROLES, seed_initial_data


@pytest.fixture
def db_session() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "test_encryption_key_32_characters_"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    with session_factory() as session:
        seed_initial_data(session)
    return session_factory


def test_builtin_roles_and_categories_created(db_session: sessionmaker[Session]) -> None:
    """Verify built-in Administrator, Operator, Viewer roles and categorized permissions."""
    with db_session() as session:
        roles = UserRepository.list_roles(session)
        role_names = {r.name for r in roles}

        # Check required built-in roles
        assert "Administrator" in role_names
        assert "Operator" in role_names
        assert "Viewer" in role_names

        admin = UserRepository.get_role_by_name(session, "Administrator")
        op = UserRepository.get_role_by_name(session, "Operator")
        vw = UserRepository.get_role_by_name(session, "Viewer")

        assert admin is not None and admin.is_system is True
        assert op is not None and op.is_system is True
        assert vw is not None and vw.is_system is True

        # Check permission categories
        perms = UserRepository.list_permissions(session)
        categories = {p.category for p in perms}
        expected_cats = {
            "Job",
            "Remote Storage",
            "Nodi Proxy",
            "Utenti & Ruoli",
            "Autenticazione",
            "Impostazioni & Sistema",
            "Audit & Monitoraggio",
        }
        assert expected_cats.issubset(categories)

        # Check that 2FA mandatory permission exists under Autenticazione category
        p_2fa = next((p for p in perms if p.code == "auth.enforce_2fa"), None)
        assert p_2fa is not None
        assert p_2fa.category == "Autenticazione"
        assert p_2fa.name == "2FA Obbligatoria"


def test_create_custom_roles_and_copy_permissions(db_session: sessionmaker[Session]) -> None:
    """Verify users can create infinite custom roles, optionally copying from existing roles."""
    with db_session() as session:
        # Create empty role
        role1 = UserRepository.create_role(
            session=session,
            name="Auditor",
            description="Ispezione e consultazione log",
        )
        assert role1.name == "Auditor"
        assert role1.is_system is False
        assert len(role1.permissions) == 0

        # Duplicate name rejected
        with pytest.raises(ValueError, match="esiste già"):
            UserRepository.create_role(session=session, name="auditor")

        # Create role copying from Operator
        op_role = UserRepository.get_role_by_name(session, "Operator")
        assert op_role is not None

        role2 = UserRepository.create_role(
            session=session,
            name="Junior Operator",
            description="Operatore limitato",
            copy_from_role_id=op_role.id,
        )
        assert role2.name == "Junior Operator"
        assert len(role2.permissions) == len(op_role.permissions)


def test_update_and_delete_custom_roles(db_session: sessionmaker[Session]) -> None:
    """Verify editing and deleting custom roles, preventing deletion of system roles or assigned roles."""
    with db_session() as session:
        admin_role = UserRepository.get_role_by_name(session, "Administrator")
        assert admin_role is not None

        # System roles cannot be renamed or deleted
        with pytest.raises(ValueError, match="non possono essere eliminati"):
            UserRepository.delete_role(session, admin_role.id)

        with pytest.raises(ValueError, match="Non è consentito rinominare"):
            UserRepository.update_role(session, admin_role.id, name="SuperAdmin")

        # Create custom role
        custom = UserRepository.create_role(session, name="Temp Role", description="Temporary")
        role_id = custom.id

        # Update description and name
        updated = UserRepository.update_role(
            session, role_id, name="Security Inspector", description="New Desc"
        )
        assert updated.name == "Security Inspector"
        assert updated.description == "New Desc"

        # Assign user to role
        user = UserRepository.create_user(
            session=session,
            username="inspector_1",
            password="StrongPass123!",
            role_id=role_id,
        )
        session.flush()

        # Cannot delete while user is assigned
        with pytest.raises(ValueError, match="è attualmente assegnato a 1 utente"):
            UserRepository.delete_role(session, role_id)

        # Reassign user to Viewer
        viewer = UserRepository.get_role_by_name(session, "Viewer")
        assert viewer is not None
        user.role_id = viewer.id
        session.flush()

        # Now deletion succeeds
        UserRepository.delete_role(session, role_id)
        assert session.get(Role, role_id) is None


def test_permissions_matrix_and_2fa_enforcement_toggle(db_session: sessionmaker[Session]) -> None:
    """Verify permissions matrix structure and moving 2FA mandatory enforcement to the matrix."""
    with db_session() as session:
        matrix = UserRepository.get_permissions_matrix(session)

        assert "roles" in matrix
        assert "categories" in matrix
        assert "matrix" in matrix

        role_names = [r["name"] for r in matrix["roles"]]
        assert "Administrator" in role_names
        assert "Operator" in role_names
        assert "Viewer" in role_names

        auth_cat = next((c for c in matrix["categories"] if c["name"] == "Autenticazione"), None)
        assert auth_cat is not None
        p_codes = [p["code"] for p in auth_cat["permissions"]]
        assert "auth.enforce_2fa" in p_codes

        # Test toggle permission on Viewer
        viewer = UserRepository.get_role_by_name(session, "Viewer")
        assert viewer is not None
        assert viewer.enforce_2fa is False
        assert "auth.enforce_2fa" not in [p.code for p in viewer.permissions]

        # Toggle 2FA mandatory ON
        role, state = UserRepository.toggle_role_permission(
            session, viewer.id, "auth.enforce_2fa", enabled=True
        )
        assert state is True
        assert role.enforce_2fa is True
        assert "auth.enforce_2fa" in [p.code for p in role.permissions]

        # Toggle 2FA mandatory OFF
        role, state = UserRepository.toggle_role_permission(
            session, viewer.id, "auth.enforce_2fa", enabled=False
        )
        assert state is False
        assert role.enforce_2fa is False
        assert "auth.enforce_2fa" not in [p.code for p in role.permissions]
