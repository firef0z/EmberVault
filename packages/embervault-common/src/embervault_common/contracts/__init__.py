"""Pydantic contracts and schemas for EmberVault protocol."""

from embervault_common.contracts.enums import (
    DiscoveryStatus,
    DiscoveryStatusLevel,
    ErrorClass,
    ErrorCode,
    ProxyState,
    RunState,
    TaskKind,
    TaskOperation,
    TaskScope,
    TaskState,
)
from embervault_common.contracts.internal import (
    CreateDiscoveryRequest,
    DiscoveryResponse,
    ProxyProbeRequest,
    ProxyProbeResponse,
    RemoteTestRequest,
    RemoteTestResponse,
)
from embervault_common.contracts.proxy import (
    EMBERVAULT_PROTOCOL_VERSION,
    PROTOCOL_HEADER,
    REQUEST_ID_HEADER,
    BaseContract,
    DiscoverTaskResultPayload,
    ProxyHealthResponse,
    RemoteConfigPayload,
    TaskCancelResponse,
    TaskDispatchPayload,
    TaskDispatchResponse,
    TaskListResponse,
    TaskLogLine,
    TaskLogsResponse,
    TaskProgress,
    TaskStatusResponse,
)

__all__ = [
    # Protocol Constants
    "EMBERVAULT_PROTOCOL_VERSION",
    "PROTOCOL_HEADER",
    "REQUEST_ID_HEADER",
    # Enums
    "DiscoveryStatus",
    "DiscoveryStatusLevel",
    "ErrorClass",
    "ErrorCode",
    "ProxyState",
    "RunState",
    "TaskKind",
    "TaskOperation",
    "TaskScope",
    "TaskState",
    # Base
    "BaseContract",
    # Proxy API contracts
    "DiscoverTaskResultPayload",
    "ProxyHealthResponse",
    "RemoteConfigPayload",
    "TaskCancelResponse",
    "TaskDispatchPayload",
    "TaskDispatchResponse",
    "TaskListResponse",
    "TaskLogLine",
    "TaskLogsResponse",
    "TaskProgress",
    "TaskStatusResponse",
    # Internal API contracts
    "CreateDiscoveryRequest",
    "DiscoveryResponse",
    "ProxyProbeRequest",
    "ProxyProbeResponse",
    "RemoteTestRequest",
    "RemoteTestResponse",
]
