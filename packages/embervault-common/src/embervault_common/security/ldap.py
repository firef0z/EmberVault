"""LDAP / Active Directory authentication and group-to-role mapping (Milestone M4).

Features:
- Pure Python ldap3 implementation (cross-platform, container-friendly).
- TLS enforcement (LDAPS or StartTLS).
- Safe LDAP filter escaping to prevent LDAP injection.
- Bind & Search with service account (or anonymous).
- Direct user bind for credential verification.
- Group extraction and RBAC role resolution.
- Connection testing and diagnostics.
"""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import structlog
from ldap3 import ALL, ANONYMOUS, SIMPLE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPCommunicationError, LDAPException, LDAPSocketOpenError
from ldap3.utils.conv import escape_filter_chars

logger = structlog.get_logger("embervault.security.ldap")


@dataclass(frozen=True)
class LdapConfig:
    """Configuration settings for LDAP / Active Directory connection."""

    server_url: str = "ldaps://127.0.0.1:636"
    require_tls: bool = True
    bind_dn: str = ""
    bind_password: str = ""
    base_dn: str = ""
    user_filter: str = "(&(objectClass=person)(|(sAMAccountName={username})(uid={username})))"
    group_attribute: str = "memberOf"
    admin_group: str = ""
    operator_group: str = ""
    viewer_group: str = ""
    connect_timeout_s: int = 5
    ca_cert_file: str | None = None
    ca_cert_pem: str = ""
    validate_cert: bool = True


@dataclass
class LdapUserInfo:
    """Authenticated LDAP user details and resolved RBAC role."""

    username: str
    dn: str
    display_name: str | None = None
    email: str | None = None
    groups: list[str] = field(default_factory=list)
    role_name: str = "viewer"


def _normalize_group_name(g: str) -> str:
    """Normalize group string (strip, lowercase, and extract CN if DN)."""
    g = g.strip()
    # If DN format (e.g. CN=EmberAdmins,OU=Groups,DC=example,DC=com), extract CN
    match = re.match(r"^CN=([^,]+)", g, re.IGNORECASE)
    if match:
        return match.group(1).strip().lower()
    return g.lower()


AD_ERROR_CODES: dict[str, str] = {
    "525": "Utente non trovato nel dominio (il Bind DN o UPN specificato non esiste in AD).",
    "52e": "Credenziali non valide (password errata o nome utente/Bind DN non corrispondente).",
    "530": "Accesso non consentito in questa fascia oraria (workstation logon hours limit).",
    "531": "Accesso non consentito da questa postazione (workstation restriction).",
    "532": "Password scaduta (è necessario aggiornare la password in Active Directory).",
    "533": "Account utente disabilitato in Active Directory.",
    "701": "Account utente scaduto.",
    "773": "L'utente deve obbligatoriamente reimpostare la password (User must change password at next logon).",
    "775": "Account utente bloccato per troppi tentativi falliti (Account locked out).",
    "1385": "Tipo di accesso non consentito per questo account (Logon type not granted).",
}


def parse_ad_diagnostic(message: str | None) -> str | None:
    """Extract and decode Active Directory Win32 / NTSTATUS error subcodes from server message."""
    if not message:
        return None
    match = re.search(r"data\s+([0-9a-fA-F]+)", str(message), re.IGNORECASE)
    if match:
        code = match.group(1).lower()
        explanation = AD_ERROR_CODES.get(code)
        if explanation:
            return f"Active Directory subcode data {code}: {explanation}"
        return f"Active Directory subcode data {code}"
    return None


def resolve_ldap_role(groups: list[str], config: LdapConfig) -> str | None:
    """Map user's LDAP groups to an EmberVault RBAC role.

    Priority hierarchy:
    1. Administrator (if user matches admin_group)
    2. Operator (elif user matches operator_group)
    3. Viewer (elif user matches viewer_group)
    4. None (if user belongs to none of the configured groups)
    """
    normalized_groups = [_normalize_group_name(g) for g in groups]
    raw_groups_lower = [g.strip().lower() for g in groups]

    # 1. Administrator (highest priority)
    if config.admin_group:
        target_admin = config.admin_group.strip().lower()
        target_norm = _normalize_group_name(config.admin_group)
        if any(
            target_admin == r or target_norm == n
            for r, n in zip(raw_groups_lower, normalized_groups, strict=False)
        ):
            return "admin"

    # 2. Operator (second priority)
    if config.operator_group:
        target_op = config.operator_group.strip().lower()
        target_norm = _normalize_group_name(config.operator_group)
        if any(
            target_op == r or target_norm == n
            for r, n in zip(raw_groups_lower, normalized_groups, strict=False)
        ):
            return "operator"

    # 3. Viewer (third priority)
    if config.viewer_group:
        target_viewer = config.viewer_group.strip().lower()
        target_norm = _normalize_group_name(config.viewer_group)
        if any(
            target_viewer == r or target_norm == n
            for r, n in zip(raw_groups_lower, normalized_groups, strict=False)
        ):
            return "viewer"

    # No matching group found
    return None


def _build_server(config: LdapConfig) -> tuple[Server, bool, bool]:
    """Parse server URL and configure Server instance with TLS if requested."""
    parsed = urlparse(config.server_url)
    scheme = parsed.scheme.lower()
    if scheme not in ("ldap", "ldaps"):
        raise ValueError(
            f"Schema URL non valido: '{scheme}'. Sono supportati solo 'ldap://' e 'ldaps://'."
        )

    is_ldaps = scheme == "ldaps"
    is_ldap = scheme == "ldap"

    tls_obj: Tls | None = None
    if is_ldaps or config.require_tls:
        validate_level = ssl.CERT_REQUIRED if config.validate_cert else ssl.CERT_NONE
        ca_data = config.ca_cert_pem.strip() if config.ca_cert_pem else None
        tls_obj = Tls(
            validate=validate_level,
            ca_certs_file=config.ca_cert_file,
            ca_certs_data=ca_data,
        )

    server = Server(
        config.server_url,
        connect_timeout=config.connect_timeout_s,
        get_info=ALL,
        tls=tls_obj if (is_ldaps or config.require_tls) else None,
    )
    return server, is_ldap, is_ldaps


def check_ldap_connectivity(
    config: LdapConfig,
    custom_server: Server | None = None,
    client_strategy: Any = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Test connectivity, TLS negotiation, and service account bind to LDAP server.

    Returns:
        (success: bool, message: str, details: dict)
    """
    password_len = len(config.bind_password) if config.bind_password else 0
    clean_bind_dn = config.bind_dn.strip() if config.bind_dn else ""
    details: dict[str, Any] = {
        "server_url": config.server_url,
        "bind_dn": clean_bind_dn or "(anonimo)",
        "bind_auth_method": "SIMPLE" if clean_bind_dn else "ANONYMOUS",
        "bind_password_set": bool(config.bind_password),
        "bind_password_length": password_len,
        "base_dn": config.base_dn or "(non specificato)",
        "require_tls": config.require_tls,
        "validate_cert": config.validate_cert,
        "ca_cert_custom": bool(config.ca_cert_pem and config.ca_cert_pem.strip()),
    }

    try:
        server, is_ldap, is_ldaps = (
            _build_server(config) if custom_server is None else (custom_server, False, False)
        )
        conn_kwargs: dict[str, Any] = {
            "server": server,
            "auto_bind": False,
            "authentication": SIMPLE if clean_bind_dn else ANONYMOUS,
        }
        if client_strategy:
            conn_kwargs["client_strategy"] = client_strategy

        if clean_bind_dn:
            conn_kwargs["user"] = clean_bind_dn
            conn_kwargs["password"] = config.bind_password

        conn = Connection(**conn_kwargs)
        conn.open()
        if conn.closed:
            return False, "Impossibile aprire la socket verso il server LDAP.", details

        if is_ldap and config.require_tls and not client_strategy:
            conn.start_tls()
            details["start_tls"] = True

        if clean_bind_dn:
            logger.info(
                "ldap_service_account_bind_attempt",
                server_url=config.server_url,
                bind_dn=clean_bind_dn,
                bind_auth_method="SIMPLE",
                password_len=password_len,
                require_tls=config.require_tls,
                validate_cert=config.validate_cert,
            )
            if not conn.bind():
                res_desc = str(conn.result.get("description") or "Credenziali non valide")
                res_msg = str(conn.result.get("message") or "")
                last_err = str(conn.last_error or "")
                ad_diag = parse_ad_diagnostic(res_msg)

                logger.warning(
                    "ldap_service_account_bind_failed",
                    server_url=config.server_url,
                    bind_dn=clean_bind_dn,
                    bind_auth_method="SIMPLE",
                    password_len=password_len,
                    description=res_desc,
                    server_message=res_msg,
                    last_error=last_err,
                    ad_diagnostic=ad_diag,
                )

                details["bind_status"] = "failed"
                details["result"] = str(conn.result)
                details["description"] = res_desc
                if res_msg:
                    details["server_message"] = res_msg
                if ad_diag:
                    details["ad_diagnostic"] = ad_diag
                if last_err:
                    details["last_error"] = last_err

                msg_parts = [f"Bind account di servizio fallito: {res_desc}"]
                if ad_diag:
                    msg_parts.append(ad_diag)
                elif res_msg:
                    msg_parts.append(f"Dettaglio server: {res_msg}")

                return (
                    False,
                    " — ".join(msg_parts),
                    details,
                )
            details["bind_status"] = "ok"
        else:
            details["bind_status"] = "anonymous"

        # Test base_dn search if provided
        if config.base_dn:
            search_ok = conn.search(
                search_base=config.base_dn,
                search_filter="(objectClass=*)",
                search_scope=SUBTREE,
                size_limit=1,
            )
            details["base_dn_search"] = search_ok
            if not search_ok:
                return (
                    True,
                    "Connessione stabilita con successo, ma la ricerca sul Base DN non ha restituito risultati.",
                    details,
                )

        conn.unbind()
        return True, "Connessione LDAP e verifica credenziali eseguite con successo.", details

    except (LDAPSocketOpenError, LDAPCommunicationError) as exc:
        details["error"] = str(exc)
        return False, f"Errore di comunicazione/timeout con il server LDAP: {exc}", details
    except LDAPException as exc:
        details["error"] = str(exc)
        return False, f"Errore LDAP: {exc}", details
    except Exception as exc:
        details["error"] = str(exc)
        return False, f"Errore di configurazione o TLS: {exc}", details


def authenticate_ldap_user(
    config: LdapConfig,
    username: str,
    password: str,
    custom_server: Server | None = None,
    client_strategy: Any = None,
) -> tuple[bool, str | None, LdapUserInfo | None]:
    """Authenticate user credentials against LDAP / Active Directory.

    Steps:
    1. Open TLS connection to LDAP server.
    2. Bind with service account (or anonymously).
    3. Search for user by safe escaped username filter.
    4. Bind directly with user DN and supplied password.
    5. Extract attributes (display_name, mail, memberOf) and compute RBAC role.

    Returns:
        (success: bool, error_message: str | None, user_info: LdapUserInfo | None)
    """
    clean_username = username.strip()
    if not clean_username or not password:
        return False, "Nome utente e password sono obbligatori.", None

    try:
        server, is_ldap, is_ldaps = (
            _build_server(config) if custom_server is None else (custom_server, False, False)
        )

        # 1. Search connection
        clean_bind_dn = config.bind_dn.strip() if config.bind_dn else ""
        search_conn_kwargs: dict[str, Any] = {
            "server": server,
            "auto_bind": False,
            "authentication": SIMPLE if clean_bind_dn else ANONYMOUS,
        }
        if client_strategy:
            search_conn_kwargs["client_strategy"] = client_strategy

        if clean_bind_dn:
            search_conn_kwargs["user"] = clean_bind_dn
            search_conn_kwargs["password"] = config.bind_password

        search_conn = Connection(**search_conn_kwargs)
        search_conn.open()
        if search_conn.closed:
            return False, "Server LDAP non raggiungibile.", None

        if is_ldap and config.require_tls and not client_strategy:
            search_conn.start_tls()

        if config.bind_dn and not search_conn.bind():
            res_desc = str(search_conn.result.get("description") or "")
            res_msg = str(search_conn.result.get("message") or "")
            last_err = str(search_conn.last_error or "")
            ad_diag = parse_ad_diagnostic(res_msg)
            logger.warning(
                "ldap_service_account_bind_failed",
                bind_dn=config.bind_dn,
                description=res_desc,
                server_message=res_msg,
                last_error=last_err,
                ad_diagnostic=ad_diag,
            )
            diag_str = f" ({ad_diag})" if ad_diag else (f" ({res_desc})" if res_desc else "")
            return False, f"Errore di autenticazione dell'account di servizio LDAP{diag_str}.", None

        # 2. Search for user DN
        safe_user = escape_filter_chars(clean_username)
        search_filter = config.user_filter.replace("{username}", safe_user)

        attributes_to_fetch = ["mail", "displayName", "cn"]
        if config.group_attribute:
            attributes_to_fetch.append(config.group_attribute)

        search_ok = search_conn.search(
            search_base=config.base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes_to_fetch,
        )

        if not search_ok or len(search_conn.entries) == 0:
            logger.info("ldap_user_not_found", username=clean_username)
            search_conn.unbind()
            return (
                False,
                "Credenziali non valide o utente non trovato in Active Directory/LDAP.",
                None,
            )

        if len(search_conn.entries) > 1:
            logger.warning(
                "ldap_ambiguous_user", username=clean_username, count=len(search_conn.entries)
            )
            search_conn.unbind()
            return False, "Filtro LDAP ambiguo: identificati utenti multipli.", None

        user_entry = search_conn.entries[0]
        user_dn = user_entry.entry_dn
        search_conn.unbind()

        # 3. User direct bind to verify password
        user_conn_kwargs: dict[str, Any] = {
            "server": server,
            "user": user_dn,
            "password": password,
            "auto_bind": False,
            "authentication": SIMPLE,
        }
        if client_strategy:
            user_conn_kwargs["client_strategy"] = client_strategy

        user_conn = Connection(**user_conn_kwargs)
        user_conn.open()
        if user_conn.closed:
            return False, "Impossibile connettersi a LDAP per la verifica delle credenziali.", None

        if is_ldap and config.require_tls and not client_strategy:
            user_conn.start_tls()

        if not user_conn.bind():
            res_desc = str(user_conn.result.get("description") or "")
            res_msg = str(user_conn.result.get("message") or "")
            last_err = str(user_conn.last_error or "")
            ad_diag = parse_ad_diagnostic(res_msg)
            logger.info(
                "ldap_invalid_credentials",
                username=clean_username,
                dn=user_dn,
                description=res_desc,
                server_message=res_msg,
                last_error=last_err,
                ad_diagnostic=ad_diag,
            )
            diag_str = f" ({ad_diag})" if ad_diag else ""
            return False, f"Password LDAP non valida{diag_str}.", None

        user_conn.unbind()

        # 4. Extract user attributes
        display_name: str | None = None
        if hasattr(user_entry, "displayName") and user_entry.displayName.value:
            display_name = str(user_entry.displayName.value)
        elif hasattr(user_entry, "cn") and user_entry.cn.value:
            display_name = str(user_entry.cn.value)

        email: str | None = None
        if hasattr(user_entry, "mail") and user_entry.mail.value:
            email = str(user_entry.mail.value)

        groups: list[str] = []
        if config.group_attribute and hasattr(user_entry, config.group_attribute):
            raw_groups = user_entry[config.group_attribute].values
            if isinstance(raw_groups, list):
                groups = [str(g) for g in raw_groups]
            elif raw_groups:
                groups = [str(raw_groups)]

        role_name = resolve_ldap_role(groups, config)
        if not role_name:
            logger.warning(
                "ldap_user_access_denied_no_group",
                username=clean_username,
                dn=user_dn,
                groups=groups,
            )
            return (
                False,
                "Non hai i diritti per accedere ad EmberVault, contatta il tuo amministratore di dominio LDAP.",
                None,
            )

        info = LdapUserInfo(
            username=clean_username,
            dn=user_dn,
            display_name=display_name,
            email=email,
            groups=groups,
            role_name=role_name,
        )
        return True, None, info

    except (LDAPSocketOpenError, LDAPCommunicationError) as exc:
        logger.error("ldap_communication_error", error=str(exc))
        return False, f"Timeout o errore di comunicazione con il server LDAP: {exc}", None
    except LDAPException as exc:
        logger.error("ldap_error", error=str(exc))
        return False, f"Errore server LDAP: {exc}", None
    except Exception as exc:
        logger.error("ldap_unexpected_error", error=str(exc))
        return False, f"Errore interno LDAP: {exc}", None


check_ldap_connectivity.__test__ = False
test_ldap_connection = check_ldap_connectivity
