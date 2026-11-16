"""SQLAlchemy models for EmberVault."""

from embervault_db.models.auth import (
    AuditLog,
    Permission,
    Role,
    RolePermission,
    Setting,
    User,
    UserMfaFactor,
    UserRecoveryCode,
    UserSession,
)
from embervault_db.models.base import (
    NAMING_CONVENTION,
    Base,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    metadata,
    utc_now,
)
from embervault_db.models.execution import (
    ErrorEvent,
    JobRun,
    JobRunHook,
    Task,
    TaskAssignment,
    TaskLog,
    ThroughputSample,
)
from embervault_db.models.notifications import (
    NotificationChannel,
)
from embervault_db.models.proxy import (
    Proxy,
    ProxyStateEvent,
    ProxyStatus,
)
from embervault_db.models.public_share import PublicShare
from embervault_db.models.remotes import (
    Job,
    JobDiscovery,
    JobProxy,
    JobSource,
    ProxyRemote,
    RcloneRemote,
    RemoteRole,
)

__all__ = [
    "NAMING_CONVENTION",
    "AuditLog",
    "Base",
    "ErrorEvent",
    "Job",
    "JobDiscovery",
    "JobProxy",
    "JobRun",
    "JobRunHook",
    "JobSource",
    "NotificationChannel",
    "Permission",
    "Proxy",
    "ProxyRemote",
    "ProxyStateEvent",
    "ProxyStatus",
    "PublicShare",
    "RcloneRemote",
    "RemoteRole",
    "Role",
    "RolePermission",
    "Setting",
    "Task",
    "TaskAssignment",
    "TaskLog",
    "ThroughputSample",
    "TimestampMixin",
    "UUIDPrimaryKeyMixin",
    "User",
    "UserMfaFactor",
    "UserRecoveryCode",
    "UserSession",
    "metadata",
    "utc_now",
]
