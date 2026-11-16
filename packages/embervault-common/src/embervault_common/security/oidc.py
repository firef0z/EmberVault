"""OpenID Connect (OIDC) client and security helpers for EmberVault (Milestone M5).

Provides:
- Configuration model `OidcConfig`.
- PKCE (RFC 7636) code_verifier and code_challenge generation.
- Discovery document fetching (.well-known/openid-configuration).
- Authorization URL construction.
- Authorization code token exchange.
- UserInfo fetching and claim extraction.
- Role resolution mapping groups claims to RBAC roles (admin > operator > viewer).
- Diagnostic testing for OIDC connectivity.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import secrets
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger("embervault_common.security.oidc")


def _get_requests() -> Any:
    """Lazily import requests to avoid introducing an unneeded runtime dependency into worker proxies."""
    try:
        import requests

        return requests
    except ImportError as exc:
        raise RuntimeError(
            "Il pacchetto 'requests' non è installato in questo ambiente di esecuzione."
        ) from exc


@dataclass
class OidcConfig:
    """OIDC integration configuration."""

    enabled: bool = False
    provider_name: str = "PocketID"
    issuer_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scopes: str = "openid profile email groups"
    username_claim: str = "preferred_username"
    groups_claim: str = "groups"
    admin_group: str = ""
    operator_group: str = ""
    viewer_group: str = ""
    validate_cert: bool = True
    ca_cert_pem: str = ""
    enforce_mfa: bool = True


@dataclass
class OidcUserInfo:
    """Normalized user information extracted from OIDC claims."""

    sub: str
    username: str
    email: str | None = None
    display_name: str | None = None
    groups: list[str] = field(default_factory=list)
    role_name: str = "viewer"
    raw_claims: dict[str, Any] = field(default_factory=dict)


def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier and S256 code_challenge per RFC 7636.

    Returns:
        (code_verifier, code_challenge)
    """
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return code_verifier, code_challenge


def generate_state() -> str:
    """Generate cryptographically secure state token to prevent CSRF."""
    return secrets.token_urlsafe(32)


def _prepare_tls_verify(ca_cert_pem: str, validate_cert: bool) -> tuple[bool | str, str | None]:
    """Prepare requests `verify` argument and optional temp file path for cleanup."""
    if not validate_cert:
        return False, None

    if ca_cert_pem and ca_cert_pem.strip():
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".pem", encoding="utf-8"
        ) as tmp:
            tmp.write(ca_cert_pem.strip())
            tmp.write("\n")
            tmp.flush()
            temp_path = tmp.name
        return temp_path, temp_path

    return True, None


def fetch_oidc_discovery(
    issuer_url: str,
    ca_cert_pem: str = "",
    validate_cert: bool = True,
    timeout: int = 8,
) -> tuple[bool, str, dict[str, Any]]:
    """Fetch and parse OIDC discovery document from issuer URL.

    Returns:
        (ok, error_message, discovery_dict)
    """
    if not issuer_url or not issuer_url.strip():
        return False, "URL Issuer OIDC non specificato.", {}

    clean_issuer = issuer_url.strip().rstrip("/")
    discovery_url = f"{clean_issuer}/.well-known/openid-configuration"

    verify_arg, tmp_pem = _prepare_tls_verify(ca_cert_pem, validate_cert)
    try:
        req = _get_requests()
        resp = req.get(
            discovery_url,
            verify=verify_arg,
            timeout=timeout,
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            return (
                False,
                f"Errore discovery OIDC (HTTP {resp.status_code}): {resp.text[:200]}",
                {},
            )
        data = resp.json()
        if not isinstance(data, dict):
            return False, "Il documento OIDC discovery non è un oggetto JSON valido.", {}

        # Validate required endpoints
        if not data.get("authorization_endpoint"):
            return False, "Endpoint 'authorization_endpoint' mancante nel discovery OIDC.", {}
        if not data.get("token_endpoint"):
            return False, "Endpoint 'token_endpoint' mancante nel discovery OIDC.", {}

        return True, "", data
    except Exception as exc:
        err_type = exc.__class__.__name__
        if "SSL" in err_type:
            logger.warning("oidc_discovery_ssl_error", error=str(exc))
            return False, f"Errore certificato TLS/SSL durante la connessione OIDC: {exc}", {}
        logger.warning("oidc_discovery_connection_error", error=str(exc))
        return False, f"Errore di rete/connessione verso il provider OIDC: {exc}", {}
    except ValueError as exc:
        return False, f"Risposta discovery OIDC non in formato JSON valido: {exc}", {}
    finally:
        if tmp_pem and os.path.exists(tmp_pem):
            with contextlib.suppress(OSError):
                os.remove(tmp_pem)


def build_authorization_url(
    config: OidcConfig,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    authorization_endpoint: str,
) -> str:
    """Construct authorization URL for OIDC code flow with PKCE."""
    params = {
        "client_id": config.client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": config.scopes or "openid profile email groups",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    encoded = urllib.parse.urlencode(params)
    separator = "&" if "?" in authorization_endpoint else "?"
    return f"{authorization_endpoint}{separator}{encoded}"


def exchange_code_for_tokens(
    config: OidcConfig,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    token_endpoint: str,
    timeout: int = 10,
) -> tuple[bool, str, dict[str, Any]]:
    """Exchange authorization code and PKCE verifier for OIDC tokens at token endpoint."""
    payload: dict[str, Any] = {
        "grant_type": "authorization_code",
        "client_id": config.client_id,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
    }
    if config.client_secret:
        payload["client_secret"] = config.client_secret

    verify_arg, tmp_pem = _prepare_tls_verify(config.ca_cert_pem, config.validate_cert)
    try:
        req = _get_requests()
        resp = req.post(
            token_endpoint,
            data=payload,
            verify=verify_arg,
            timeout=timeout,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        if resp.status_code != 200:
            err_details = resp.text[:300]
            try:
                err_json = resp.json()
                err_desc = err_json.get("error_description") or err_json.get("error")
                if err_desc:
                    err_details = str(err_desc)
            except Exception:
                pass
            return False, f"Scambio token OIDC fallito (HTTP {resp.status_code}): {err_details}", {}

        data = resp.json()
        if not isinstance(data, dict):
            return False, "Risposta endpoint token OIDC non valida.", {}

        if not data.get("access_token") and not data.get("id_token"):
            return False, "Nessun access_token o id_token ricevuto dall'endpoint token.", {}

        return True, "", data
    except Exception as exc:
        logger.error("oidc_token_exchange_error", error=str(exc))
        return False, f"Errore durante lo scambio del codice OIDC: {exc}", {}
    finally:
        if tmp_pem and os.path.exists(tmp_pem):
            with contextlib.suppress(OSError):
                os.remove(tmp_pem)


def parse_jwt_payload_unverified(token: str) -> dict[str, Any]:
    """Extract and parse payload segment of a JWT without signature verification.

    Used to inspect claims from an ID token received over a secure TLS backchannel.
    """
    if not token or "." not in token:
        return {}
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload_b64 = parts[1]
    # Add base64 padding
    rem = len(payload_b64) % 4
    if rem > 0:
        payload_b64 += "=" * (4 - rem)
    try:
        decoded = base64.urlsafe_b64decode(payload_b64.encode("ascii")).decode("utf-8")
        parsed = json.loads(decoded)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def fetch_userinfo(
    config: OidcConfig,
    access_token: str,
    userinfo_endpoint: str,
    timeout: int = 10,
) -> tuple[bool, str, dict[str, Any]]:
    """Fetch userinfo claims from the OIDC userinfo endpoint."""
    if not access_token or not userinfo_endpoint:
        return False, "Token di accesso o userinfo_endpoint mancante.", {}

    verify_arg, tmp_pem = _prepare_tls_verify(config.ca_cert_pem, config.validate_cert)
    try:
        req = _get_requests()
        resp = req.get(
            userinfo_endpoint,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
            verify=verify_arg,
            timeout=timeout,
        )
        if resp.status_code != 200:
            return (
                False,
                f"Errore recupero UserInfo OIDC (HTTP {resp.status_code}): {resp.text[:200]}",
                {},
            )
        data = resp.json()
        if not isinstance(data, dict):
            return False, "Risposta UserInfo OIDC non è un dizionario JSON valido.", {}
        return True, "", data
    except Exception as exc:
        logger.warning("oidc_userinfo_fetch_error", error=str(exc))
        return False, f"Errore di connessione a UserInfo OIDC: {exc}", {}
    finally:
        if tmp_pem and os.path.exists(tmp_pem):
            with contextlib.suppress(OSError):
                os.remove(tmp_pem)


def resolve_oidc_role(
    user_groups: list[str],
    admin_group: str,
    operator_group: str,
    viewer_group: str,
) -> tuple[str | None, str | None]:
    """Resolve RBAC role from OIDC groups claim per hierarchy (admin > operator > viewer).

    Returns:
        (role_name, error_message)
    """
    admin_target = admin_group.strip().lower() if admin_group else ""
    operator_target = operator_group.strip().lower() if operator_group else ""
    viewer_target = viewer_group.strip().lower() if viewer_group else ""

    # If no groups are configured at all, fallback to default role 'viewer'
    if not admin_target and not operator_target and not viewer_target:
        return "viewer", None

    norm_groups = {g.strip().lower() for g in user_groups if isinstance(g, str)}

    # Highest hierarchy: Administrator
    if admin_target and admin_target in norm_groups:
        return "admin", None

    # Next: Operator
    if operator_target and operator_target in norm_groups:
        return "operator", None

    # Next: Viewer
    if viewer_target and viewer_target in norm_groups:
        return "viewer", None

    # User does not belong to any configured group
    return (
        None,
        "Non hai i diritti per accedere ad EmberVault, contatta il tuo amministratore OIDC.",
    )


def extract_user_info_from_claims(
    claims: dict[str, Any],
    config: OidcConfig,
) -> tuple[bool, str, OidcUserInfo | None]:
    """Extract and validate normalized user identity and role from combined claims.

    Returns:
        (ok, error_message, OidcUserInfo | None)
    """
    sub = str(claims.get("sub", "")).strip()
    if not sub:
        return False, "Claim obbligatorio 'sub' mancante nei dati OIDC.", None

    # Username extraction
    claim_key = (config.username_claim or "preferred_username").strip()
    raw_username = claims.get(claim_key)

    if not raw_username:
        # Fallbacks: preferred_username, username, nickname, email, sub
        raw_username = (
            claims.get("preferred_username")
            or claims.get("username")
            or claims.get("nickname")
            or claims.get("email")
            or sub
        )

    username = str(raw_username).strip()
    if not username:
        return False, f"Impossibile determinare il nome utente dal claim '{claim_key}'.", None

    # Email extraction
    email_val = claims.get("email")
    email = str(email_val).strip() if email_val else None

    # Display name extraction
    name_val = claims.get("name") or claims.get("display_name") or claims.get("given_name")
    display_name = str(name_val).strip() if name_val else username

    # Groups extraction
    groups_key = (config.groups_claim or "groups").strip()
    raw_groups = claims.get(groups_key, [])
    user_groups: list[str] = []
    if isinstance(raw_groups, list):
        user_groups = [str(g).strip() for g in raw_groups if g]
    elif isinstance(raw_groups, str):
        # Handle comma or space separated string
        if "," in raw_groups:
            user_groups = [g.strip() for g in raw_groups.split(",") if g.strip()]
        else:
            user_groups = [g.strip() for g in raw_groups.split() if g.strip()]

    # Role resolution
    role_name, role_err = resolve_oidc_role(
        user_groups=user_groups,
        admin_group=config.admin_group,
        operator_group=config.operator_group,
        viewer_group=config.viewer_group,
    )
    if role_err or not role_name:
        return False, role_err or "Accesso negato: gruppo non mappato.", None

    return (
        True,
        "",
        OidcUserInfo(
            sub=sub,
            username=username,
            email=email,
            display_name=display_name,
            groups=user_groups,
            role_name=role_name,
            raw_claims=claims,
        ),
    )


def check_oidc_connectivity(config: OidcConfig) -> tuple[bool, str, dict[str, Any]]:
    """Perform diagnostic test on OIDC configuration against provider discovery endpoint.

    Returns:
        (ok, message, details_dict)
    """
    if not config.issuer_url or not config.issuer_url.strip():
        return False, "URL Issuer OIDC non configurato.", {}

    ok, err, disc = fetch_oidc_discovery(
        issuer_url=config.issuer_url,
        ca_cert_pem=config.ca_cert_pem,
        validate_cert=config.validate_cert,
        timeout=6,
    )
    if not ok:
        return False, err, {"issuer_url": config.issuer_url}

    details = {
        "issuer": disc.get("issuer"),
        "authorization_endpoint": disc.get("authorization_endpoint"),
        "token_endpoint": disc.get("token_endpoint"),
        "userinfo_endpoint": disc.get("userinfo_endpoint"),
        "scopes_supported": disc.get("scopes_supported", []),
        "response_types_supported": disc.get("response_types_supported", []),
        "code_challenge_methods_supported": disc.get("code_challenge_methods_supported", []),
        "client_id_configured": bool(config.client_id),
        "client_secret_configured": bool(config.client_secret),
    }

    # Verify S256 PKCE support if listed
    cc_methods = disc.get("code_challenge_methods_supported")
    if cc_methods and "S256" not in cc_methods:
        logger.warning("oidc_s256_pkce_not_listed", methods=cc_methods)

    return (
        True,
        f"Connessione OIDC al provider '{config.provider_name}' stabilita con successo.",
        details,
    )
