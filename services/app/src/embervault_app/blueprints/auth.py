"""Authentication Blueprint for handling login, logout, and password change."""

from __future__ import annotations

import urllib.parse
from datetime import UTC, datetime
from typing import Any

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import select

from embervault_app.auth import (
    authenticate_user,
    create_user_session,
    get_current_user,
    get_db_session,
    logout_current_user,
    require_auth,
)
from embervault_app.i18n import translate as _
from embervault_common.security.passwords import (
    hash_password,
    validate_password_complexity,
    verify_password,
)
from embervault_db.models.auth import AuditLog, User

auth_bp = Blueprint("auth", __name__)


def is_safe_redirect_url(target: str) -> bool:
    """Validate that redirect URL is local to prevent open-redirect vulnerabilities."""
    if not target:
        return False
    ref_url = urllib.parse.urlparse(request.host_url)
    test_url = urllib.parse.urlparse(urllib.parse.urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def _has_custom_login_bg() -> bool:
    """Check if a custom login background image is configured."""
    store = current_app.config.get("SETTINGS_STORE")
    return bool(store.get_setting("login_custom_background")) if store else False


@auth_bp.route("/login", methods=["GET", "POST"])
def login() -> Any:
    """Handle user login form and authentication."""
    if request.method == "GET":
        if get_current_user() is not None:
            return redirect(url_for("ui.dashboard"))
        if "_flashes" in session:
            session["_flashes"] = [
                (cat, msg)
                for cat, msg in session["_flashes"]
                if not str(msg).startswith(("Benvenuto,", "Welcome,"))
            ]
        session_factory = get_db_session()
        with session_factory() as db:
            from embervault_app.ldap_service import get_ldap_config
            from embervault_app.oidc_service import get_oidc_config

            ldap_enabled, _ldap_cfg = get_ldap_config(db)
            oidc_enabled, oidc_config = get_oidc_config(db)
        return render_template(
            "login.html",
            next=request.args.get("next", ""),
            ldap_enabled=ldap_enabled,
            oidc_enabled=oidc_enabled,
            oidc_provider_name=oidc_config.provider_name,
            selected_auth_source="local",
            has_custom_bg=_has_custom_login_bg(),
        )

    # POST request
    data = request.form if request.form else (request.get_json(silent=True) or {})
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    auth_source = str(data.get("auth_source", "local")).strip().lower()
    if auth_source not in ("local", "ldap"):
        auth_source = "local"
    next_url = str(data.get("next", "") or request.args.get("next", ""))

    session_factory = get_db_session()
    with session_factory() as db:
        from embervault_app.ldap_service import get_ldap_config
        from embervault_app.oidc_service import get_oidc_config

        ldap_enabled, _ldap_cfg = get_ldap_config(db)
        oidc_enabled, oidc_config = get_oidc_config(db)

        if not username or not password:
            err_msg = _("auth_specify_username_password")
            if request.is_json:
                return jsonify({"status": "error", "error": "validation", "message": err_msg}), 400
            flash(err_msg, "danger")
            return (
                render_template(
                    "login.html",
                    next=next_url,
                    ldap_enabled=ldap_enabled,
                    oidc_enabled=oidc_enabled,
                    oidc_provider_name=oidc_config.provider_name,
                    selected_auth_source=auth_source,
                    has_custom_bg=_has_custom_login_bg(),
                ),
                400,
            )

        user, err = authenticate_user(
            db=db,
            username=username,
            password=password,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            auth_source=auth_source,
        )
        if err or user is None:
            if request.is_json:
                return jsonify({"status": "error", "error": "auth_failed", "message": err}), 401
            flash(err or _("auth_invalid_credentials_short"), "danger")
            return (
                render_template(
                    "login.html",
                    next=next_url,
                    ldap_enabled=ldap_enabled,
                    oidc_enabled=oidc_enabled,
                    oidc_provider_name=oidc_config.provider_name,
                    selected_auth_source=auth_source,
                    has_custom_bg=_has_custom_login_bg(),
                ),
                401,
            )

        # Check if user has active 2FA enabled
        from embervault_db.repositories.user_repository import UserRepository

        factor = UserRepository.get_user_mfa_factor(db, user.id, "totp")
        has_2fa = factor is not None and factor.confirmed_at is not None

        if has_2fa:
            # 2FA challenge required: store intermediate pending auth state in session
            session.pop("auth_token", None)
            session["2fa_pending_user_id"] = str(user.id)
            session["2fa_next_url"] = next_url

            if request.is_json:
                return jsonify(
                    {
                        "status": "2fa_required",
                        "message": _("auth_2fa_required_msg"),
                        "user_id": str(user.id),
                    }
                )
            return redirect(url_for("auth.two_factor_login"))

        # Create session directly if no 2FA configured
        raw_token = create_user_session(
            db=db,
            user=user,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            mfa_verified=False,
        )
        session.pop("logged_out", None)
        session["auth_token"] = raw_token
        session["user_id"] = str(user.id)
        session["user_theme"] = getattr(user, "theme", "embervault")
        session["language"] = getattr(user, "language", "it") or "it"
        g.current_user = user
        session.permanent = True

        if request.is_json:
            return jsonify(
                {
                    "status": "success",
                    "user": {
                        "id": str(user.id),
                        "username": user.username,
                        "role": user.role.name,
                        "must_change_password": user.must_change_password,
                        "theme": getattr(user, "theme", "embervault"),
                    },
                    "token": raw_token,
                }
            )

        if user.must_change_password:
            flash(
                _("auth_login_ok_must_change_pwd"),
                "warning",
            )
            return redirect(url_for("auth.change_password"))

        session.pop("_flashes", None)
        if next_url and is_safe_redirect_url(next_url):
            return redirect(next_url)
        return redirect(url_for("ui.dashboard"))


@auth_bp.route("/login/2fa", methods=["GET", "POST"])
def two_factor_login() -> Any:
    """Challenge user for TOTP code or recovery code during two-factor login."""
    from uuid import UUID

    from embervault_common.security import (
        decrypt_blob,
        hash_recovery_code,
        verify_totp_code,
    )
    from embervault_db.repositories.user_repository import UserRepository

    pending_user_id_str = session.get("2fa_pending_user_id")
    next_url = session.get("2fa_next_url", "")

    if not pending_user_id_str:
        return redirect(url_for("auth.login"))

    try:
        user_uuid = UUID(pending_user_id_str)
    except ValueError:
        session.pop("2fa_pending_user_id", None)
        return redirect(url_for("auth.login"))

    if request.method == "GET":
        return render_template(
            "login_2fa.html", next=next_url, has_custom_bg=_has_custom_login_bg()
        )

    # POST request
    data = request.form if request.form else (request.get_json(silent=True) or {})
    code = str(data.get("code", "")).strip()

    if not code:
        err = _("auth_enter_6digit_or_recovery")
        if request.is_json:
            return jsonify({"status": "error", "message": err}), 400
        flash(err, "danger")
        return render_template(
            "login_2fa.html", next=next_url, has_custom_bg=_has_custom_login_bg()
        ), 400

    session_factory = get_db_session()
    with session_factory() as db:
        user = UserRepository.get_user_by_id(db, user_uuid)
        if user is None or not user.is_active:
            session.pop("2fa_pending_user_id", None)
            return redirect(url_for("auth.login"))

        factor = UserRepository.get_user_mfa_factor(db, user.id, "totp")
        if factor is None or factor.confirmed_at is None:
            session.pop("2fa_pending_user_id", None)
            return redirect(url_for("auth.login"))

        # 1. Attempt TOTP verification if 6 digits
        is_verified = False
        clean_code = code.replace(" ", "").replace("-", "")
        if clean_code.isdigit() and len(clean_code) == 6:
            try:
                raw_secret = decrypt_blob(
                    factor.secret_encrypted, aad=f"user-totp:{user.id}"
                ).decode("utf-8")
                is_verified = verify_totp_code(raw_secret, clean_code)
            except Exception:
                is_verified = False

        # 2. If not verified via TOTP, check if valid one-time recovery code
        if not is_verified:
            hashed_recovery = hash_recovery_code(code)
            if UserRepository.verify_and_consume_recovery_code(
                db, user.id, hashed_recovery, ip=request.remote_addr
            ):
                is_verified = True
                flash(_("auth_login_via_recovery_code_flash"), "warning")

        if not is_verified:
            err = _("auth_invalid_2fa_or_recovery_code")
            if request.is_json:
                return jsonify({"status": "error", "message": err}), 401
            flash(err, "danger")
            return render_template(
                "login_2fa.html", next=next_url, has_custom_bg=_has_custom_login_bg()
            ), 401

        # Clear pending 2FA state
        session.pop("2fa_pending_user_id", None)
        session.pop("2fa_next_url", None)

        # Create session with mfa_verified=True
        raw_token = create_user_session(
            db=db,
            user=user,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            mfa_verified=True,
        )
        session.pop("logged_out", None)
        session["auth_token"] = raw_token
        session["user_id"] = str(user.id)
        session["user_theme"] = getattr(user, "theme", "embervault")
        session["language"] = getattr(user, "language", "it") or "it"
        g.current_user = user
        session.permanent = True

        if request.is_json:
            return jsonify(
                {
                    "status": "success",
                    "user": {
                        "id": str(user.id),
                        "username": user.username,
                        "role": user.role.name,
                        "must_change_password": user.must_change_password,
                        "theme": getattr(user, "theme", "embervault"),
                    },
                    "token": raw_token,
                }
            )

        if user.must_change_password:
            flash(
                _("auth_login_ok_must_change_pwd"),
                "warning",
            )
            return redirect(url_for("auth.change_password"))

        session.pop("_flashes", None)
        if next_url and is_safe_redirect_url(next_url):
            return redirect(next_url)
        return redirect(url_for("ui.dashboard"))


@auth_bp.route("/2fa/setup", methods=["GET"])
@require_auth
def two_factor_setup() -> Any:
    """Render 2FA setup and configuration page."""
    current_u = get_current_user()
    assert current_u is not None

    from embervault_db.repositories.user_repository import UserRepository

    session_factory = get_db_session()
    with session_factory() as db:
        factor = UserRepository.get_user_mfa_factor(db, current_u.id, "totp")
        totp_enabled = factor is not None and factor.confirmed_at is not None
        recovery_count = UserRepository.get_remaining_recovery_codes_count(db, current_u.id)

    return render_template(
        "two_factor_setup.html",
        active_page="users",
        totp_enabled=totp_enabled,
        recovery_count=recovery_count,
        enforce_2fa=bool(current_u.role and current_u.role.enforce_2fa),
    )


@auth_bp.route("/logout", methods=["GET", "POST"])
def logout() -> Any:
    """Log out currently authenticated user."""
    logout_current_user()
    if request.is_json:
        return jsonify({"status": "success", "message": _("auth_logged_out_msg")})
    flash(_("auth_session_ended_flash"), "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
@require_auth
def change_password() -> Any:
    """Allow user to change password or force change on first login."""
    current_user = get_current_user()
    assert current_user is not None

    if request.method == "GET":
        if not current_user.must_change_password:
            session.pop("_flashes", None)
        elif "_flashes" in session:
            session["_flashes"] = [
                (cat, msg)
                for cat, msg in session["_flashes"]
                if not str(msg).startswith(("Benvenuto,", "Welcome,"))
            ]
        return render_template(
            "change_password.html",
            must_change=current_user.must_change_password,
        )

    # POST request
    data = request.form if request.form else (request.get_json(silent=True) or {})
    current_pw = str(data.get("current_password", ""))
    new_pw = str(data.get("new_password", ""))
    confirm_pw = str(data.get("confirm_password", ""))

    # Verify current password if user is not in forced change mode or if supplied
    session_factory = get_db_session()
    with session_factory() as db:
        db_user = db.scalar(select(User).where(User.id == current_user.id))
        assert db_user is not None

        if (not current_user.must_change_password or current_pw) and (
            not current_pw or not verify_password(db_user.password_hash or "", current_pw)
        ):
            err = _("auth_current_password_incorrect")
            if request.is_json:
                return jsonify({"status": "error", "error": "invalid_current", "message": err}), 400
            flash(err, "danger")
            return render_template(
                "change_password.html", must_change=db_user.must_change_password
            ), 400

        if new_pw != confirm_pw:
            err = _("auth_new_passwords_mismatch")
            if request.is_json:
                return jsonify({"status": "error", "error": "mismatch", "message": err}), 400
            flash(err, "danger")
            return render_template(
                "change_password.html", must_change=db_user.must_change_password
            ), 400

        # Validate complexity
        ok, complexity_err = validate_password_complexity(new_pw)
        if not ok:
            err = _(complexity_err) if complexity_err else _("auth_password_complexity_failed")
            if request.is_json:
                return jsonify({"status": "error", "error": "complexity", "message": err}), 400
            flash(err, "danger")
            return render_template(
                "change_password.html", must_change=db_user.must_change_password
            ), 400

        # Update password
        db_user.password_hash = hash_password(new_pw)
        db_user.must_change_password = False

        audit = AuditLog(
            action="auth.password.changed",
            actor_user_id=db_user.id,
            entity_type="user",
            entity_id=str(db_user.id),
            ip=request.remote_addr,
            details={"username": db_user.username, "user_agent": request.headers.get("User-Agent")},
        )
        db.add(audit)
        db.commit()

        # Update cached user
        g.current_user = db_user

    if request.is_json:
        return jsonify({"status": "success", "message": _("auth_password_updated_msg")})

    flash(_("auth_password_updated_flash"), "success")
    return redirect(url_for("ui.dashboard"))


@auth_bp.route("/auth/oidc/login", methods=["GET"])
def oidc_login() -> Any:
    """Initiate OpenID Connect Authorization Code Flow with PKCE."""
    session_factory = get_db_session()
    with session_factory() as db:
        from embervault_app.oidc_service import get_oidc_config

        enabled, oidc_config = get_oidc_config(db)

    if not enabled or not oidc_config.issuer_url or not oidc_config.client_id:
        flash(_("auth_oidc_not_configured_or_disabled"), "danger")
        return redirect(url_for("auth.login"))

    from embervault_common.security.oidc import (
        build_authorization_url,
        fetch_oidc_discovery,
        generate_pkce_pair,
        generate_state,
    )

    ok, err, disc = fetch_oidc_discovery(
        issuer_url=oidc_config.issuer_url,
        ca_cert_pem=oidc_config.ca_cert_pem,
        validate_cert=oidc_config.validate_cert,
    )
    if not ok or not disc.get("authorization_endpoint"):
        flash(_("auth_oidc_provider_unreachable_tpl").format(err=err), "danger")
        return redirect(url_for("auth.login"))

    code_verifier, code_challenge = generate_pkce_pair()
    state = generate_state()

    redirect_uri = url_for("auth.oidc_callback", _external=True)

    session["oidc_state"] = state
    session["oidc_verifier"] = code_verifier
    session["oidc_next"] = request.args.get("next", "")

    auth_url = build_authorization_url(
        config=oidc_config,
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
        authorization_endpoint=disc["authorization_endpoint"],
    )
    return redirect(auth_url)


@auth_bp.route("/auth/oidc/callback", methods=["GET"])
def oidc_callback() -> Any:
    """Handle redirect callback from OIDC provider, exchange code and authenticate user."""
    error = request.args.get("error")
    if error:
        error_desc = request.args.get("error_description", error)
        flash(_("auth_oidc_cancelled_or_failed_tpl").format(error_desc=error_desc), "danger")
        return redirect(url_for("auth.login"))

    code = request.args.get("code")
    state = request.args.get("state")
    saved_state = session.pop("oidc_state", None)
    code_verifier = session.pop("oidc_verifier", None)
    next_url = session.pop("oidc_next", "")

    if not code or not state or not saved_state or state != saved_state:
        flash(_("auth_oidc_invalid_state"), "danger")
        return redirect(url_for("auth.login"))

    if not code_verifier:
        flash(_("auth_oidc_pkce_missing"), "danger")
        return redirect(url_for("auth.login"))

    session_factory = get_db_session()
    with session_factory() as db:
        from embervault_app.oidc_service import get_oidc_config

        enabled, oidc_config = get_oidc_config(db)

        if not enabled:
            flash(_("auth_oidc_disabled"), "danger")
            return redirect(url_for("auth.login"))

        from embervault_common.security.oidc import (
            exchange_code_for_tokens,
            extract_user_info_from_claims,
            fetch_oidc_discovery,
            fetch_userinfo,
            parse_jwt_payload_unverified,
        )

        ok, err, disc = fetch_oidc_discovery(
            issuer_url=oidc_config.issuer_url,
            ca_cert_pem=oidc_config.ca_cert_pem,
            validate_cert=oidc_config.validate_cert,
        )
        if not ok:
            flash(_("auth_oidc_discovery_error_tpl").format(err=err), "danger")
            return redirect(url_for("auth.login"))

        redirect_uri = url_for("auth.oidc_callback", _external=True)

        ok, err, tokens = exchange_code_for_tokens(
            config=oidc_config,
            code=code,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            token_endpoint=disc["token_endpoint"],
        )
        if not ok:
            flash(_("auth_oidc_token_exchange_error_tpl").format(err=err), "danger")
            return redirect(url_for("auth.login"))

        claims: dict[str, Any] = {}
        if "id_token" in tokens:
            claims.update(parse_jwt_payload_unverified(tokens["id_token"]))

        access_token = tokens.get("access_token")
        userinfo_ep = disc.get("userinfo_endpoint")
        if access_token and userinfo_ep:
            ok_u, _u_err, userinfo_claims = fetch_userinfo(
                config=oidc_config,
                access_token=access_token,
                userinfo_endpoint=userinfo_ep,
            )
            if ok_u and userinfo_claims:
                claims.update(userinfo_claims)

        ok, err, user_info = extract_user_info_from_claims(claims, oidc_config)
        if not ok or user_info is None:
            flash((_(err) if err else _("auth_oidc_userinfo_failed")), "danger")
            return redirect(url_for("auth.login"))

        from embervault_db.repositories.user_repository import UserRepository

        role = UserRepository.get_role_by_name(db, user_info.role_name)
        if role is None:
            role = UserRepository.get_role_by_name(db, "viewer")
        assert role is not None

        # Account resolution and linking
        # 1. Match by external_subject (already linked to OIDC)
        user = db.scalar(select(User).where(User.external_subject == user_info.sub))

        if user is None:
            # 2. Check if username matches an existing account (e.g. local user)
            existing_by_username = db.scalar(
                select(User).where(User.username == user_info.username)
            )
            if existing_by_username is not None:
                # Link existing account to OIDC provider
                user = existing_by_username
                user.external_subject = user_info.sub
                user.role_id = role.id  # Permissions overwrite local ones
                if user_info.display_name:
                    user.display_name = user_info.display_name
                if user_info.email:
                    user.email = user_info.email
                user.last_login_at = datetime.now(UTC)
            else:
                # 3. JIT provision new user
                user = User(
                    username=user_info.username,
                    email=user_info.email,
                    display_name=user_info.display_name,
                    auth_source="oidc",
                    external_subject=user_info.sub,
                    password_hash=None,
                    role_id=role.id,
                    is_active=True,
                    must_change_password=False,
                    last_login_at=datetime.now(UTC),
                )
                db.add(user)
                db.flush()
        else:
            # Existing linked user: update profile and overwrite role
            user.role_id = role.id
            if user_info.display_name:
                user.display_name = user_info.display_name
            if user_info.email:
                user.email = user_info.email
            user.last_login_at = datetime.now(UTC)

        if not user.is_active:
            flash(_("auth_account_disabled"), "danger")
            return redirect(url_for("auth.login"))

        # Check if 2FA is active on EmberVault and enforced by OIDC config
        factor = UserRepository.get_user_mfa_factor(db, user.id, "totp")
        has_2fa = factor is not None and factor.confirmed_at is not None
        if has_2fa and oidc_config.enforce_mfa:
            session.pop("auth_token", None)
            session["2fa_pending_user_id"] = str(user.id)
            session["2fa_next_url"] = next_url
            return redirect(url_for("auth.two_factor_login"))

        # Create session
        raw_token = create_user_session(
            db=db,
            user=user,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            mfa_verified=has_2fa and not oidc_config.enforce_mfa,
        )
        session.pop("logged_out", None)
        session.pop("2fa_pending_user_id", None)
        session.pop("2fa_next_url", None)
        session["auth_token"] = raw_token
        session["user_id"] = str(user.id)
        session["user_theme"] = getattr(user, "theme", "embervault")
        session["language"] = getattr(user, "language", "it") or "it"
        g.current_user = user
        session.permanent = True

        audit = AuditLog(
            action="auth.login.success",
            actor_user_id=user.id,
            entity_type="user",
            entity_id=str(user.id),
            ip=request.remote_addr,
            details={
                "username": user.username,
                "auth_source": "oidc",
                "oidc_sub": user_info.sub,
                "role": role.name,
                "groups": user_info.groups,
                "user_agent": request.headers.get("User-Agent"),
            },
        )
        db.add(audit)
        db.commit()

        session.pop("_flashes", None)
        if next_url and is_safe_redirect_url(next_url):
            return redirect(next_url)
        return redirect(url_for("ui.dashboard"))
