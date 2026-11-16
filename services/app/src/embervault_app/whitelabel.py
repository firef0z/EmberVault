"""Whitelabel and Branding management module for EmberVault."""

from __future__ import annotations

import base64
import os
from typing import Any, cast

from flask import Flask, Response, current_app, make_response, redirect, send_from_directory
from embervault_common.observability import get_logger

logger = get_logger("embervault_app.whitelabel")


def get_whitelabel_config() -> tuple[str, str, bool]:
    """Retrieve (app_name, custom_app_name, has_custom_logo) from the settings store."""
    store = current_app.config.get("SETTINGS_STORE")
    custom_name = ""
    has_custom = False
    if store:
        try:
            custom_name = str(store.get_setting("custom_app_name") or "").strip()
            has_custom = bool(store.get_setting("custom_logo"))
        except Exception as exc:
            logger.debug("whitelabel_settings_read_error", error=str(exc))

    app_name = custom_name if custom_name else "EmberVault"
    return app_name, custom_name, has_custom


def get_portal_whitelabel_config() -> tuple[str, str, bool]:
    """Retrieve (portal_app_name, portal_custom_app_name, has_portal_custom_logo) from the settings store."""
    store = current_app.config.get("SETTINGS_STORE")
    custom_name = ""
    has_custom = False
    if store:
        try:
            custom_name = str(store.get_setting("portal_custom_app_name") or "").strip()
            has_custom = bool(store.get_setting("portal_custom_logo"))
        except Exception as exc:
            logger.debug("portal_whitelabel_settings_read_error", error=str(exc))

    app_name = custom_name if custom_name else "EmberVault public portal"
    return app_name, custom_name, has_custom


_DEFAULT_LOGO_DATA_URI: str | None = None


def get_default_logo_data_uri() -> str:
    """Return the default logo encoded as a data URI for instantaneous zero-latency rendering."""
    global _DEFAULT_LOGO_DATA_URI
    if _DEFAULT_LOGO_DATA_URI is not None:
        return _DEFAULT_LOGO_DATA_URI

    img_path = os.path.join(current_app.root_path, "static", "img", "logo.svg")
    try:
        with open(img_path, "rb") as f:
            svg_bytes = f.read()
        b64 = base64.b64encode(svg_bytes).decode("ascii")
        _DEFAULT_LOGO_DATA_URI = f"data:image/svg+xml;base64,{b64}"
    except Exception as exc:
        logger.warning("failed_to_load_default_logo_data_uri", error=str(exc))
        _DEFAULT_LOGO_DATA_URI = "/app-logo"

    return _DEFAULT_LOGO_DATA_URI


def get_logo_version(raw_val: Any) -> str:
    """Return a short deterministic hash for cache busting."""
    if not raw_val or not str(raw_val).strip():
        try:
            logo_path = os.path.join(current_app.root_path, "static", "img", "logo.svg")
            return f"def_{int(os.path.getmtime(logo_path))}"
        except Exception:
            return "default"
    import hashlib

    return hashlib.sha256(str(raw_val).encode("utf-8")).hexdigest()[:12]


def serve_app_logo() -> Response:
    """Serve the active logo (custom if set, otherwise default logo)."""
    import hashlib
    from flask import request

    store = current_app.config.get("SETTINGS_STORE")
    raw_val = store.get_setting("custom_logo") if store else ""
    if not raw_val or not str(raw_val).strip():
        img_dir = os.path.join(current_app.root_path, "static", "img")
        resp = send_from_directory(img_dir, "logo.svg", mimetype="image/svg+xml", max_age=31536000)
        resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return resp

    val_str = str(raw_val).strip()
    if val_str.startswith("data:"):
        try:
            header, payload = val_str.split(",", 1)
            mimetype = header.split(";")[0].replace("data:", "").strip() or "image/png"
            img_bytes = base64.b64decode(payload)
            etag = hashlib.sha256(img_bytes).hexdigest()[:16]
            if_none_match = request.headers.get("If-None-Match", "")
            if if_none_match in (f'"{etag}"', etag):
                resp = make_response("", 304)
                resp.headers["ETag"] = f'"{etag}"'
                resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
                return resp
            resp = make_response(img_bytes)
            resp.headers["Content-Type"] = mimetype
            resp.headers["ETag"] = f'"{etag}"'
            resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            return resp
        except Exception as exc:
            logger.warning("whitelabel_logo_decode_failed", error=str(exc))
            img_dir = os.path.join(current_app.root_path, "static", "img")
            resp = send_from_directory(
                img_dir, "logo.svg", mimetype="image/svg+xml", max_age=31536000
            )
            resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            return resp

    return cast(Response, redirect(val_str))


def serve_portal_logo() -> Response:
    """Serve the active portal logo (custom if set, otherwise default logo)."""
    import hashlib
    from flask import request

    store = current_app.config.get("SETTINGS_STORE")
    raw_val = store.get_setting("portal_custom_logo") if store else ""
    if not raw_val or not str(raw_val).strip():
        img_dir = os.path.join(current_app.root_path, "static", "img")
        resp = send_from_directory(img_dir, "logo.svg", mimetype="image/svg+xml", max_age=31536000)
        resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return resp

    val_str = str(raw_val).strip()
    if val_str.startswith("data:"):
        try:
            header, payload = val_str.split(",", 1)
            mimetype = header.split(";")[0].replace("data:", "").strip() or "image/png"
            img_bytes = base64.b64decode(payload)
            etag = hashlib.sha256(img_bytes).hexdigest()[:16]
            if_none_match = request.headers.get("If-None-Match", "")
            if if_none_match in (f'"{etag}"', etag):
                resp = make_response("", 304)
                resp.headers["ETag"] = f'"{etag}"'
                resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
                return resp
            resp = make_response(img_bytes)
            resp.headers["Content-Type"] = mimetype
            resp.headers["ETag"] = f'"{etag}"'
            resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            return resp
        except Exception as exc:
            logger.warning("portal_whitelabel_logo_decode_failed", error=str(exc))
            img_dir = os.path.join(current_app.root_path, "static", "img")
            resp = send_from_directory(
                img_dir, "logo.svg", mimetype="image/svg+xml", max_age=31536000
            )
            resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            return resp

    return cast(Response, redirect(val_str))


def is_public_portal_enabled() -> bool:
    """Check if the public portal is globally enabled."""
    store = current_app.config.get("SETTINGS_STORE")
    if not store:
        return True
    try:
        val = store.get_setting("public_portal_enabled")
        if val is None:
            return True
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            return val.lower() in ("true", "1", "yes", "on")
        return bool(val)
    except Exception as exc:
        logger.debug("portal_enabled_read_error", error=str(exc))
        return True


def get_portal_language() -> str:
    """Retrieve portal language from settings store, default 'en'."""
    store = current_app.config.get("SETTINGS_STORE")
    if store:
        try:
            val = str(store.get_setting("portal_language") or "").strip().lower()
            if val in ("it", "en", "de", "es", "fr", "zh", "ja", "ko", "ar"):
                return val
        except Exception:
            pass
    return "en"


def init_whitelabel(app: Flask) -> None:
    """Initialize Whitelabel context processor and public logo route."""

    @app.context_processor
    def inject_whitelabel_context() -> dict[str, Any]:
        store = current_app.config.get("SETTINGS_STORE")
        custom_logo_raw = store.get_setting("custom_logo") if store else ""
        portal_custom_logo_raw = store.get_setting("portal_custom_logo") if store else ""

        raw_val_str = str(custom_logo_raw or "").strip()
        portal_val_str = str(portal_custom_logo_raw or "").strip()

        # Inlined data URI guarantees instantaneous synchronous frame-0 rendering with ZERO network requests
        if raw_val_str.startswith("data:"):
            app_logo_url = raw_val_str
        elif raw_val_str:
            app_logo_url = f"/app-logo?v={get_logo_version(raw_val_str)}"
        else:
            app_logo_url = get_default_logo_data_uri()

        if portal_val_str.startswith("data:"):
            portal_logo_url = portal_val_str
        elif portal_val_str:
            portal_logo_url = f"/portal-logo?v={get_logo_version(portal_val_str)}"
        else:
            portal_logo_url = get_default_logo_data_uri()

        app_name, custom_name, has_custom = get_whitelabel_config()
        p_app_name, p_custom_name, p_has_custom = get_portal_whitelabel_config()
        return {
            "app_name": app_name,
            "custom_app_name": custom_name,
            "app_logo_url": app_logo_url,
            "has_custom_logo": has_custom,
            "portal_app_name": p_app_name,
            "portal_custom_app_name": p_custom_name,
            "portal_logo_url": portal_logo_url,
            "has_portal_custom_logo": p_has_custom,
            "public_portal_enabled": is_public_portal_enabled(),
            "portal_language": get_portal_language(),
        }

    @app.route("/app-logo", methods=["GET"])
    def app_logo_route() -> Response:
        return serve_app_logo()

    @app.route("/portal-logo", methods=["GET"])
    def portal_logo_route() -> Response:
        return serve_portal_logo()
