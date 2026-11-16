"""Dedicated Hook Runner service for isolated pre/post hook execution (Milestone M8/M9).

Runs as an independent unprivileged sidecar container without DB credentials,
master keys, or access to the backend/proxy networks.
"""

from __future__ import annotations

import hmac
import os
import subprocess
import sys

from flask import Flask, Response, jsonify, request

from embervault_common.hooks.executor import (
    HookExecutor,
)
from embervault_common.observability import configure_logging, get_logger

logger = get_logger("embervault_hook_runner")


def create_hook_runner_app(
    auth_token: str | None = None,
    default_timeout_s: int = 60,
) -> Flask:
    """Create Flask application for hook runner sidecar."""
    app = Flask(__name__)
    expected_token = (auth_token or os.environ.get("EMBERVAULT_INTERNAL_API_TOKEN") or "").strip()

    @app.before_request
    def authenticate() -> Response | None:
        # Health check does not require authorization
        if request.path in ("/healthz", "/readyz"):
            return None

        if not expected_token:
            # If no token is configured, allow internal requests
            return None

        auth_header = request.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

        if not token or not hmac.compare_digest(token, expected_token):
            return Response(
                response='{"error": "Unauthorized"}\n',
                status=401,
                mimetype="application/json",
            )
        return None

    @app.route("/healthz", methods=["GET"])
    @app.route("/readyz", methods=["GET"])
    def healthz() -> Response:
        return Response('{"status": "ok"}\n', status=200, mimetype="application/json")

    @app.route("/execute", methods=["POST"])
    def execute_hook() -> Response:
        data = request.get_json(silent=True) or {}
        script = str(data.get("script") or "")
        context = data.get("context") or {}
        timeout_s = data.get("timeout_s")

        executor = HookExecutor(default_timeout_s=default_timeout_s)
        # Execute locally inside this isolated container
        result = executor.execute_local(
            script_content=script,
            context=context,
            timeout_s=timeout_s,
        )

        return jsonify(
            {
                "status": result.status,
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "script_hash": result.script_hash,
                "output": result.output,
            }
        )

    return app


def main() -> None:
    """CLI entrypoint for hook-runner daemon."""
    port = int(os.environ.get("EMBERVAULT_HOOK_RUNNER_PORT", "8082"))
    bind = os.environ.get("EMBERVAULT_HOOK_RUNNER_BIND", "0.0.0.0")
    log_level = os.environ.get("EMBERVAULT_LOG_LEVEL", "INFO")
    log_format = os.environ.get("EMBERVAULT_LOG_FORMAT", "console")

    configure_logging(
        service="hook-runner",
        log_level=log_level,
        log_format=log_format,
    )
    logger.info("starting_hook_runner", bind=bind, port=port)

    # In production, this runs via gunicorn
    cmd = [
        "gunicorn",
        "--bind",
        f"{bind}:{port}",
        "--workers",
        "1",
        "--threads",
        "4",
        "embervault_common.hooks.runner_service:create_hook_runner_app()",
    ]
    sys.exit(subprocess.call(cmd))


if __name__ == "__main__":
    main()
