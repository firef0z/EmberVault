"""Application factory for EmberVault Portal."""

from __future__ import annotations

import os
from typing import Any
from flask import Flask

from embervault_portal.orchestrator_client import OrchestratorPortalClient
from embervault_portal.blueprints.portal import portal_bp


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure EmberVault Portal Flask application."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    app.config["SECRET_KEY"] = os.environ.get(
        "PORTAL_SECRET_KEY", "embervault-portal-secret-key-change-in-prod"
    )
    app.config["SESSION_COOKIE_NAME"] = "embervault_portal_session"
    app.config["SESSION_COOKIE_PATH"] = "/"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    from datetime import timedelta

    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=72)

    orch_url = os.environ.get("EMBERVAULT_ORCHESTRATOR_URL", "http://orchestrator:8081")
    timeout_s = int(os.environ.get("PORTAL_ORCHESTRATOR_TIMEOUT", "15"))
    connect_timeout_s = float(os.environ.get("PORTAL_ORCHESTRATOR_CONNECT_TIMEOUT", "4.0"))

    if test_config:
        app.config.update(test_config)
        if "EMBERVAULT_ORCHESTRATOR_URL" in test_config:
            orch_url = test_config["EMBERVAULT_ORCHESTRATOR_URL"]
        if "PORTAL_ORCHESTRATOR_TIMEOUT" in test_config:
            timeout_s = int(test_config["PORTAL_ORCHESTRATOR_TIMEOUT"])
        if "PORTAL_ORCHESTRATOR_CONNECT_TIMEOUT" in test_config:
            connect_timeout_s = float(test_config["PORTAL_ORCHESTRATOR_CONNECT_TIMEOUT"])

    app.extensions["orchestrator_client"] = OrchestratorPortalClient(
        base_url=orch_url,
        timeout_seconds=timeout_s,
        connect_timeout=connect_timeout_s,
    )

    _branding_cache: dict[str, Any] = {"data": None, "ts": 0.0}

    @app.context_processor
    def inject_portal_branding() -> dict[str, Any]:
        import time

        now = time.time()
        client = app.extensions.get("orchestrator_client")
        branding = None
        if _branding_cache["data"] and (now - _branding_cache["ts"] < 30.0):
            branding = _branding_cache["data"]
        elif client:
            try:
                branding = client.get_portal_branding()
                _branding_cache["data"] = branding
                _branding_cache["ts"] = now
            except Exception:
                _branding_cache["ts"] = now
                _branding_cache["data"] = {
                    "status": "ok",
                    "app_name": "EmberVault public portal",
                    "custom_app_name": "",
                    "has_custom_logo": False,
                    "logo_data": None,
                }

        branding = branding or {}
        app_name = branding.get("app_name") or "EmberVault public portal"
        language = str(branding.get("language") or "en").strip().lower()
        from embervault_portal.i18n import get_portal_translator, get_portal_i18n_dict
        import base64
        import hashlib
        import json
        import os

        logo_data = str(branding.get("logo_data") or "").strip()
        if logo_data.startswith("data:"):
            portal_logo_url = logo_data
        elif logo_data:
            v = hashlib.sha256(logo_data.encode("utf-8")).hexdigest()[:10]
            portal_logo_url = f"/share-logo?v={v}"
        else:
            try:
                img_path = os.path.join(app.root_path, "static", "img", "logo.svg")
                with open(img_path, "rb") as f:
                    portal_logo_url = (
                        f"data:image/svg+xml;base64,{base64.b64encode(f.read()).decode('ascii')}"
                    )
            except Exception:
                portal_logo_url = "/share-logo"

        return {
            "portal_app_name": app_name,
            "portal_logo_url": portal_logo_url,
            "has_portal_custom_logo": bool(branding.get("has_custom_logo")),
            "portal_language": language,
            "_": get_portal_translator(language),
            "I18N_JSON": json.dumps(get_portal_i18n_dict(language)),
        }

    app.register_blueprint(portal_bp)

    return app
