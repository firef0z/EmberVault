"""Application factory for EmberVault Orchestrator service."""

from __future__ import annotations

from typing import Any

from flask import Flask, Response, jsonify

from embervault_common.config import OrchestratorSettings
from embervault_common.observability import (
    configure_logging,
    create_metrics_middleware,
    generate_metrics_response,
    get_logger,
    init_service_metrics,
)
from embervault_orchestrator.internal_api import internal_api


def create_orchestrator_app(
    settings: OrchestratorSettings | None = None,
    session_factory: Any | None = None,
    settings_store: Any | None = None,
    enable_background_services: bool | None = None,
) -> Flask:
    """Create and configure an instance of the Orchestrator Flask application."""
    if settings is None:
        settings = OrchestratorSettings.load()

    configure_logging(
        service="orchestrator",
        log_level=settings.log_level,
        log_format=settings.log_format,
    )
    logger = get_logger("embervault_orchestrator")
    logger.info("initializing_orchestrator", env=settings.env, port=settings.orch_port)

    from embervault_orchestrator import __version__

    init_service_metrics("orchestrator", version=__version__, milestone="M9")

    app = Flask(__name__)
    app.config["SETTINGS"] = settings

    is_custom_session = session_factory is not None
    if session_factory is None:
        import os

        from sqlalchemy import create_engine

        from embervault_common.config import DatabaseSettings
        from embervault_db.models.base import Base
        from embervault_db.session import create_session_factory

        if os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_HOST") == "postgres":
            db_settings = DatabaseSettings.load()
            engine = create_engine(db_settings.resolved_database_url, pool_pre_ping=True)
            session_factory = create_session_factory(engine)
        else:
            engine = create_engine("sqlite:///:memory:")
            Base.metadata.create_all(engine)
            session_factory = create_session_factory(engine)

    app.config["SESSION_FACTORY"] = session_factory
    if settings_store is not None:
        app.config["SETTINGS_STORE"] = settings_store

    should_start_bg = (
        enable_background_services
        if enable_background_services is not None
        else (
            not is_custom_session
            and not app.config.get("TESTING")
            and not app.config.get("DISABLE_BACKGROUND_SERVICES")
        )
    )

    if should_start_bg:
        from embervault_orchestrator.advisory_lock import PostgresAdvisoryLock
        from embervault_orchestrator.health_monitor import HealthMonitor
        from embervault_orchestrator.reconciler import ExecutionReconciler

        advisory_lock = PostgresAdvisoryLock(session_factory)
        if advisory_lock.acquire():
            logger.info("orchestrator_leader_active")
            health_monitor = HealthMonitor(
                session_factory=session_factory,
                settings=settings,
            )
            health_monitor.start()
            app.config["HEALTH_MONITOR"] = health_monitor

            execution_reconciler = ExecutionReconciler(
                session_factory=session_factory,
            )
            execution_reconciler.start()
            app.config["EXECUTION_RECONCILER"] = execution_reconciler
            app.config["ADVISORY_LOCK"] = advisory_lock
        else:
            logger.warning(
                "orchestrator_standby",
                message="Another orchestrator instance holds the leader lock. Running in standby mode.",
            )

    create_metrics_middleware(app, "orchestrator")

    # Register internal API blueprint
    app.register_blueprint(internal_api)

    @app.route("/healthz", methods=["GET"])
    def healthz() -> Response:
        """Liveness health check endpoint."""
        return jsonify({"status": "ok", "service": "orchestrator"})

    @app.route("/readyz", methods=["GET"])
    def readyz() -> Response:
        """Readiness health check endpoint."""
        return jsonify({"status": "ready", "service": "orchestrator"})

    @app.route("/metrics", methods=["GET"])
    def metrics() -> Response:
        """Prometheus metrics scrape endpoint."""
        data, content_type = generate_metrics_response(
            session_factory=app.config.get("SESSION_FACTORY")
        )
        return Response(data, mimetype=content_type)

    return app
