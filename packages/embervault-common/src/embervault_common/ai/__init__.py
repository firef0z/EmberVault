"""AI Integration package for EmberVault."""

from embervault_common.ai.anonymizer import DataAnonymizer
from embervault_common.ai.client import (
    AIClient,
    AIClientError,
    AIConnectionError,
    AIResponse,
    AIResponseError,
)
from embervault_common.ai.prompts import (
    SUPPORTED_AI_LANGUAGES,
    get_default_error_system_prompt,
    get_default_reporting_system_prompt,
)

__all__ = [
    "DataAnonymizer",
    "AIClient",
    "AIResponse",
    "AIClientError",
    "AIConnectionError",
    "AIResponseError",
    "SUPPORTED_AI_LANGUAGES",
    "get_default_error_system_prompt",
    "get_default_reporting_system_prompt",
]
