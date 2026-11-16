"""EmberVault Web UI Application service."""

__version__ = "1.0.0"

from embervault_app.factory import create_app
from embervault_app.orchestrator_client import (
    OrchestratorAuthError,
    OrchestratorClient,
    OrchestratorClientError,
    OrchestratorUnreachableError,
)

__all__ = [
    "OrchestratorAuthError",
    "OrchestratorClient",
    "OrchestratorClientError",
    "OrchestratorUnreachableError",
    "create_app",
    "__version__",
]
