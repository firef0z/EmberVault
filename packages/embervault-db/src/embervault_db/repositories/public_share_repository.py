"""Repository for PublicShare CRUD and authentication operations."""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import desc, select

from embervault_common.observability import get_logger
from embervault_common.security.passwords import hash_password, verify_password
from embervault_db.models.base import utc_now
from embervault_db.models.public_share import PublicShare

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = get_logger("embervault_db.repositories.public_share")


class PublicShareRepository:
    """Operations on public shares."""

    @staticmethod
    def create_share(
        session: Session,
        remote_id: uuid.UUID,
        base_path: str,
        expires_at: datetime,
        username: str | None = None,
        raw_password: str | None = None,
        note: str | None = None,
        created_by: uuid.UUID | None = None,
    ) -> tuple[PublicShare, str, str, str]:
        """Create a new public share with random token, username and password if not provided.

        Returns:
            Tuple of (PublicShare entity, token, username, raw_password).
        """
        token = secrets.token_urlsafe(16)
        if not username:
            # Generate random human-friendly username
            username = f"guest_{secrets.token_hex(3)}"
        if not raw_password:
            # Generate random password (12 chars urlsafe)
            raw_password = secrets.token_urlsafe(9)

        hashed = hash_password(raw_password)
        clean_path = base_path.strip().strip("/")

        share = PublicShare(
            token=token,
            remote_id=remote_id,
            base_path=clean_path,
            username=username,
            password_hash=hashed,
            note=note.strip() if note else None,
            expires_at=expires_at,
            is_active=True,
            created_by=created_by,
        )
        session.add(share)
        session.flush()

        logger.info(
            "public_share_created",
            share_id=str(share.id),
            token=token,
            remote_id=str(remote_id),
            base_path=clean_path,
        )
        return share, token, username, raw_password

    @staticmethod
    def list_shares(session: Session) -> list[PublicShare]:
        """List all public shares ordered by creation date descending."""
        stmt = select(PublicShare).order_by(desc(PublicShare.created_at))
        return list(session.scalars(stmt).unique().all())

    @staticmethod
    def get_share_by_id(session: Session, share_id: uuid.UUID) -> PublicShare | None:
        """Fetch a public share by ID."""
        stmt = select(PublicShare).where(PublicShare.id == share_id)
        return session.scalars(stmt).first()

    @staticmethod
    def get_share_by_token(session: Session, token: str) -> PublicShare | None:
        """Fetch a public share by URL token."""
        stmt = select(PublicShare).where(PublicShare.token == token)
        return session.scalars(stmt).first()

    @staticmethod
    def update_share_expiration(
        session: Session,
        share_id: uuid.UUID,
        expires_at: datetime,
    ) -> PublicShare | None:
        """Update only the expiration datetime of an active public share."""
        share = PublicShareRepository.get_share_by_id(session, share_id)
        if not share or not share.is_active:
            return None
        share.expires_at = expires_at
        session.flush()
        logger.info(
            "public_share_expiration_updated",
            share_id=str(share_id),
            expires_at=expires_at.isoformat(),
        )
        return share

    @staticmethod
    def deactivate_share(session: Session, share_id: uuid.UUID) -> PublicShare | None:
        """Permanently deactivate a public share link."""
        share = PublicShareRepository.get_share_by_id(session, share_id)
        if not share:
            return None
        share.is_active = False
        session.flush()
        logger.info("public_share_deactivated", share_id=str(share_id))
        return share

    @staticmethod
    def record_first_access(session: Session, share: PublicShare) -> None:
        """Record the first client access timestamp if not already set."""
        if share.first_accessed_at is None:
            share.first_accessed_at = utc_now()
            session.flush()
            logger.info(
                "public_share_first_access_recorded",
                share_id=str(share.id),
                accessed_at=share.first_accessed_at.isoformat(),
            )

    @staticmethod
    def delete_share(session: Session, share_id: uuid.UUID) -> bool:
        """Delete a public share."""
        share = PublicShareRepository.get_share_by_id(session, share_id)
        if not share:
            return False
        session.delete(share)
        session.flush()
        logger.info("public_share_deleted", share_id=str(share_id))
        return True

    @staticmethod
    def verify_credentials(share: PublicShare, username: str, raw_password: str) -> bool:
        """Verify username and password against the share's stored credentials."""
        from datetime import UTC

        if not share.is_active:
            return False
        exp = share.expires_at
        if exp:
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            now = utc_now()
            if now.tzinfo is None:
                now = now.replace(tzinfo=UTC)
            if exp <= now:
                return False
        if share.username.strip().lower() != username.strip().lower():
            return False
        return verify_password(share.password_hash, raw_password)

    @staticmethod
    def is_valid(share: PublicShare) -> bool:
        """Check if share is currently active and unexpired."""
        from datetime import UTC

        if not share.is_active:
            return False
        exp = share.expires_at
        if exp:
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            now = utc_now()
            if now.tzinfo is None:
                now = now.replace(tzinfo=UTC)
            return exp > now
        return True
