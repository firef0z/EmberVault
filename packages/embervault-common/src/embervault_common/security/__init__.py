"""Security utilities for EmberVault.

Provides cryptographic envelope encryption, key ring management, constant-time
token operations, TLS certificate fingerprint pinning, and secret redaction.
"""

from embervault_common.security.crypto import (
    CURRENT_ENVELOPE_VERSION,
    CryptoError,
    DecryptionError,
    InvalidEnvelopeError,
    InvalidKeyError,
    KeyNotFoundError,
    KeyRing,
    decrypt_blob,
    decrypt_blob_to_str,
    derive_or_normalize_key,
    encrypt_blob,
    extract_envelope_key_id,
    get_default_key_ring,
    reencrypt_blob,
    set_default_key_ring,
)
from embervault_common.security.ldap import (
    LdapConfig,
    LdapUserInfo,
    authenticate_ldap_user,
    resolve_ldap_role,
    test_ldap_connection,
)
from embervault_common.security.oidc import (
    OidcConfig,
    OidcUserInfo,
    build_authorization_url,
    check_oidc_connectivity,
    exchange_code_for_tokens,
    extract_user_info_from_claims,
    fetch_oidc_discovery,
    fetch_userinfo,
    generate_pkce_pair,
    generate_state,
    parse_jwt_payload_unverified,
    resolve_oidc_role,
)
from embervault_common.security.passwords import (
    hash_password,
    needs_rehash,
    validate_password_complexity,
    verify_password,
)
from embervault_common.security.redaction import (
    REDACTED_PLACEHOLDER,
    RedactionProcessor,
    mask_secret,
    redact_data,
)
from embervault_common.security.tls_pin import (
    TLSCertificateParseError,
    TLSFingerprintError,
    TLSFingerprintMismatchError,
    compute_cert_fingerprint,
    extract_cert_expiration,
    extract_peer_cert_fingerprint,
    format_fingerprint,
    normalize_fingerprint,
    verify_cert_fingerprint,
)
from embervault_common.security.tokens import (
    compare_tokens,
    generate_secure_token,
    hash_token,
)
from embervault_common.security.totp import (
    DEFAULT_ISSUER_NAME,
    DEFAULT_TOTP_DIGITS,
    DEFAULT_TOTP_INTERVAL,
    NUM_RECOVERY_CODES,
    generate_recovery_codes,
    generate_totp_qr_png_data_uri,
    generate_totp_qr_svg,
    generate_totp_secret,
    get_totp_provisioning_uri,
    hash_recovery_code,
    normalize_recovery_code,
    verify_totp_code,
)

__all__ = [
    # Passwords
    "hash_password",
    "verify_password",
    "needs_rehash",
    "validate_password_complexity",
    # Redaction
    "REDACTED_PLACEHOLDER",
    "RedactionProcessor",
    "mask_secret",
    "redact_data",
    # Crypto
    "CURRENT_ENVELOPE_VERSION",
    "CryptoError",
    "DecryptionError",
    "InvalidEnvelopeError",
    "InvalidKeyError",
    "KeyNotFoundError",
    "KeyRing",
    "decrypt_blob",
    "decrypt_blob_to_str",
    "derive_or_normalize_key",
    "encrypt_blob",
    "extract_envelope_key_id",
    "get_default_key_ring",
    "reencrypt_blob",
    "set_default_key_ring",
    # Tokens
    "compare_tokens",
    "generate_secure_token",
    "hash_token",
    # TLS Pinning
    "TLSCertificateParseError",
    "TLSFingerprintError",
    "TLSFingerprintMismatchError",
    "compute_cert_fingerprint",
    "extract_cert_expiration",
    "extract_peer_cert_fingerprint",
    "format_fingerprint",
    "normalize_fingerprint",
    "verify_cert_fingerprint",
    # TOTP & 2FA
    "DEFAULT_ISSUER_NAME",
    "DEFAULT_TOTP_DIGITS",
    "DEFAULT_TOTP_INTERVAL",
    "NUM_RECOVERY_CODES",
    "generate_recovery_codes",
    "generate_totp_qr_png_data_uri",
    "generate_totp_qr_svg",
    "generate_totp_secret",
    "get_totp_provisioning_uri",
    "hash_recovery_code",
    "normalize_recovery_code",
    "verify_totp_code",
    # LDAP / Active Directory
    "LdapConfig",
    "LdapUserInfo",
    "authenticate_ldap_user",
    "resolve_ldap_role",
    "test_ldap_connection",
    # OIDC / PocketID
    "OidcConfig",
    "OidcUserInfo",
    "build_authorization_url",
    "check_oidc_connectivity",
    "exchange_code_for_tokens",
    "extract_user_info_from_claims",
    "fetch_oidc_discovery",
    "fetch_userinfo",
    "generate_pkce_pair",
    "generate_state",
    "parse_jwt_payload_unverified",
    "resolve_oidc_role",
]
