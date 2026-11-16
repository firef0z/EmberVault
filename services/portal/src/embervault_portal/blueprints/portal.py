"""Blueprint for EmberVault Public Share Portal."""

from __future__ import annotations

import json
from typing import Any

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    stream_with_context,
)

portal_bp = Blueprint("portal", __name__)


def get_orchestrator_client():
    return current_app.extensions["orchestrator_client"]


@portal_bp.before_request
def check_portal_enabled() -> Any:
    # Always permit healthcheck and logo
    if request.path in ("/healthz", "/share-logo", "/share/logo"):
        return None
    client = get_orchestrator_client()
    try:
        branding = client.get_portal_branding()
        if branding.get("enabled") is False:
            if request.is_json:
                return make_response(
                    jsonify(
                        {
                            "status": "error",
                            "message": "Il portale pubblico è disattivato dall'amministratore.",
                        }
                    ),
                    403,
                )
            return (
                render_template(
                    "portal_disabled.html",
                    portal_app_name=branding.get("app_name", "EmberVault public portal"),
                ),
                403,
            )
    except Exception:
        pass
    return None


@portal_bp.route("/healthz", methods=["GET"])
def healthcheck() -> Response:
    return jsonify({"status": "ok", "service": "portal"})


@portal_bp.route("/share-logo", methods=["GET"])
@portal_bp.route("/share/logo", methods=["GET"])
def share_logo() -> Response:
    """Serve the active public portal logo (custom if set, otherwise default logo)."""
    import base64
    import hashlib
    import os
    from flask import request, send_from_directory

    client = get_orchestrator_client()
    try:
        branding = client.get_portal_branding()
        logo_data = branding.get("logo_data")
        if logo_data and str(logo_data).strip():
            val_str = str(logo_data).strip()
            if val_str.startswith("data:"):
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
            return redirect(val_str)
    except Exception:
        pass

    img_dir = os.path.join(current_app.root_path, "static", "img")
    resp = send_from_directory(img_dir, "logo.svg", mimetype="image/svg+xml", max_age=31536000)
    resp.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return resp


@portal_bp.route("/", methods=["GET"])
@portal_bp.route("/share", methods=["GET"])
@portal_bp.route("/share/", methods=["GET"])
def index() -> str:
    return render_template("layout.html", title="EmberVault Portal")


@portal_bp.route("/share/<token>", methods=["GET"])
def view_share(token: str) -> Any:
    auth_data = session.get(f"auth_{token}")
    if auth_data and isinstance(auth_data, dict):
        return render_template(
            "browse.html",
            token=token,
            remote_name=auth_data.get("remote_name", "Remote"),
            expires_at=auth_data.get("expires_at"),
            username=auth_data.get("username", ""),
        )
    return render_template("login.html", token=token, error=None)


@portal_bp.route("/share/<token>/login", methods=["POST"])
def login_share(token: str) -> Any:
    client = get_orchestrator_client()
    branding = {}
    try:
        branding = client.get_portal_branding()
    except Exception:
        pass
    lang = branding.get("language") or "en"
    from embervault_portal.i18n import get_portal_translator

    _tr = get_portal_translator(lang)

    if request.is_json:
        payload = request.get_json(silent=True) or {}
    else:
        payload = request.form.to_dict()

    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", "")).strip()

    if not username or not password:
        err = _tr("portal_missing_creds", "Username e password obbligatori.")
        if request.is_json:
            return make_response(jsonify({"status": "error", "message": err}), 400)
        return render_template("login.html", token=token, error=err), 400

    try:
        res = client.validate_share(token, username, password)
    except Exception:
        res = {"status_code": 503, "data": {"status": "error"}}

    status_code = res.get("status_code", 500)
    data = res.get("data", {})

    if status_code != 200 or data.get("status") != "ok":
        if status_code == 503 or status_code >= 500:
            err = _tr(
                "portal_service_unavailable",
                "Servizio momentaneamente non disponibile. Riprova più tardi.",
            )
        else:
            err = data.get(
                "message",
                _tr("portal_invalid_creds", "Credenziali non valide o link non disponibile."),
            )
        if request.is_json:
            return make_response(
                jsonify({"status": "error", "message": err}),
                status_code if status_code >= 400 else 401,
            )
        return render_template("login.html", token=token, error=err), (
            status_code if status_code >= 400 else 401
        )

    session.permanent = True
    session[f"auth_{token}"] = {
        "token": token,
        "username": username,
        "remote_name": data.get("remote_name", "Remote"),
        "expires_at": data.get("expires_at"),
    }

    if request.is_json:
        return jsonify({"status": "ok", "redirect_url": f"/share/{token}"})
    return redirect(f"/share/{token}")


@portal_bp.route("/share/<token>/logout", methods=["POST", "GET"])
def logout_share(token: str) -> Response:
    session.pop(f"auth_{token}", None)
    return redirect(f"/share/{token}")


@portal_bp.route("/share/<token>/browse", methods=["GET"])
def browse_share(token: str) -> Response:
    client = get_orchestrator_client()
    branding = {}
    try:
        branding = client.get_portal_branding()
    except Exception:
        pass
    lang = branding.get("language") or "en"
    from embervault_portal.i18n import get_portal_translator

    _tr = get_portal_translator(lang)

    auth_data = session.get(f"auth_{token}")
    if not auth_data:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _tr("portal_unauthenticated", "Sessione non autenticata."),
                }
            ),
            401,
        )

    subpath = str(request.args.get("subpath", "")).strip()
    try:
        res = client.browse_share(token, subpath)
    except Exception:
        res = {"status_code": 503, "data": {"status": "error"}}

    status_code = res.get("status_code", 500)
    data = res.get("data", {})
    if status_code == 503 or status_code >= 500:
        data = {
            "status": "error",
            "message": _tr(
                "portal_service_unavailable",
                "Servizio momentaneamente non disponibile. Riprova più tardi.",
            ),
        }
    return make_response(jsonify(data), status_code)


@portal_bp.route("/share/<token>/download", methods=["POST"])
def download_share(token: str) -> Response:
    client = get_orchestrator_client()
    branding = {}
    try:
        branding = client.get_portal_branding()
    except Exception:
        pass
    lang = branding.get("language") or "en"
    from embervault_portal.i18n import get_portal_translator

    _tr = get_portal_translator(lang)

    auth_data = session.get(f"auth_{token}")
    if not auth_data:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _tr("portal_unauthenticated", "Sessione non autenticata."),
                }
            ),
            401,
        )

    if request.is_json:
        payload = request.get_json(silent=True) or {}
    else:
        payload = request.form.to_dict()

    subpath = str(payload.get("subpath", "")).strip()
    raw_items = payload.get("items")
    items: list[dict[str, Any]] = []
    if isinstance(raw_items, str):
        try:
            items = json.loads(raw_items)
        except Exception:
            items = []
    elif isinstance(raw_items, list):
        items = raw_items

    if not items:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _tr("portal_no_selection", "Nessun elemento selezionato."),
                }
            ),
            400,
        )

    client = get_orchestrator_client()
    try:
        orch_resp = client.download_share(token=token, subpath=subpath, items=items)
        if orch_resp.status_code != 200:
            err_msg = orch_resp.text
            try:
                err_json = orch_resp.json()
                if isinstance(err_json, dict) and "message" in err_json:
                    err_msg = err_json["message"]
            except Exception:
                pass
            return make_response(
                jsonify({"status": "error", "message": err_msg}), orch_resp.status_code
            )

        headers: dict[str, str] = {}
        if "Content-Disposition" in orch_resp.headers:
            headers["Content-Disposition"] = orch_resp.headers["Content-Disposition"]
        content_type = orch_resp.headers.get("Content-Type", "application/octet-stream")

        def forward_stream():
            for chunk in orch_resp.iter_content(chunk_size=65536):
                if chunk:
                    yield chunk

        return Response(
            stream_with_context(forward_stream()),
            status=200,
            mimetype=content_type,
            headers=headers,
        )
    except Exception:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": _tr(
                        "portal_service_unavailable",
                        "Servizio momentaneamente non disponibile. Riprova più tardi.",
                    ),
                }
            ),
            503,
        )
