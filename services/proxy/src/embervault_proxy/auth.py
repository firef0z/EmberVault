"""Authentication and protocol middleware for EmberVault Proxy."""

from __future__ import annotations

import functools
import uuid
from collections.abc import Callable
from typing import Any

from flask import current_app, jsonify, make_response, request

from embervault_common.contracts import (
    EMBERVAULT_PROTOCOL_VERSION,
    PROTOCOL_HEADER,
    REQUEST_ID_HEADER,
)
from embervault_common.observability import get_logger
from embervault_common.security import compare_tokens

logger = get_logger("embervault_proxy.auth")


def require_proxy_auth(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator to enforce Bearer token authentication on proxy endpoints.

    Compares the incoming Bearer token against configured settings.token in constant time.
    Returns HTTP 401 Unauthorized upon missing or invalid credentials without leaking tokens.
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        auth_header = request.headers.get("Authorization", "").strip()
        if not auth_header:
            logger.warning("auth_failed_missing_header", path=request.path)
            response = make_response(
                jsonify(
                    {
                        "error": "unauthorized",
                        "message": "Missing Authorization header. Expected Bearer token.",
                    }
                ),
                401,
            )
            return response

        parts = auth_header.split(maxsplit=1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            logger.warning("auth_failed_malformed_header", path=request.path)
            response = make_response(
                jsonify(
                    {
                        "error": "unauthorized",
                        "message": "Malformed Authorization header. Format: Bearer <token>",
                    }
                ),
                401,
            )
            return response

        provided_token = parts[1].strip()
        settings = current_app.config.get("SETTINGS")
        if settings is None:
            logger.error("proxy_settings_missing_in_app_config")
            return make_response(jsonify({"error": "server_error"}), 500)

        expected_token = settings.token.get_secret_value()

        authenticated = compare_tokens(expected_token, provided_token)
        if not authenticated and getattr(settings, "previous_token", None):
            prev_token = settings.previous_token.get_secret_value()
            if prev_token:
                authenticated = compare_tokens(prev_token, provided_token)

        if not authenticated:
            logger.warning("auth_failed_invalid_token", path=request.path)
            response = make_response(
                jsonify(
                    {
                        "error": "unauthorized",
                        "message": "Invalid authentication token.",
                    }
                ),
                401,
            )
            return response

        return fn(*args, **kwargs)

    return wrapper


def inject_protocol_headers(response: Any) -> Any:
    """Ensure X-EmberVault-Protocol and X-Request-ID headers are present on all responses."""
    req_id = request.headers.get(REQUEST_ID_HEADER) or str(uuid.uuid4())
    response.headers[PROTOCOL_HEADER] = str(EMBERVAULT_PROTOCOL_VERSION)
    response.headers[REQUEST_ID_HEADER] = req_id
    return response
