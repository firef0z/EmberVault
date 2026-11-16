"""TLS certificate pinning and SHA-256 fingerprint verification for EmberVault.

Supports Trust On First Use (TOFU) certificate pinning between the orchestrator
and proxy instances, validating peer certificates against stored fingerprints.
"""

from __future__ import annotations

import datetime
import hashlib
import re
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from embervault_common.security.crypto import CryptoError
from embervault_common.security.tokens import compare_tokens

_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class TLSFingerprintError(CryptoError):
    """Base exception for TLS fingerprinting and certificate validation errors."""


class TLSCertificateParseError(TLSFingerprintError):
    """Raised when certificate bytes or PEM data cannot be parsed."""


class TLSFingerprintMismatchError(TLSFingerprintError):
    """Raised when a remote TLS certificate fingerprint does not match the pinned expectation."""


def normalize_fingerprint(fingerprint: str) -> str:
    """Normalize a SHA-256 certificate fingerprint into a canonical 64-character lowercase hex string.

    Strips optional algorithm prefixes (e.g. 'SHA256:'), colons, hyphens, and whitespace.

    Args:
        fingerprint: Raw fingerprint string (e.g. 'AA:BB:CC:...' or 'sha256:aabbcc...').

    Returns:
        Canonical 64-character lowercase hexadecimal string.

    Raises:
        TLSFingerprintError: If the normalized string is not a valid 64-character hexadecimal SHA-256 digest.
    """
    clean = fingerprint.strip()
    if clean.lower().startswith("sha256:"):
        clean = clean[7:].strip()
    elif clean.lower().startswith("sha-256:"):
        clean = clean[8:].strip()

    normalized = clean.replace(":", "").replace("-", "").replace(" ", "").lower()

    if not _HEX_64_PATTERN.match(normalized):
        raise TLSFingerprintError(
            f"Invalid SHA-256 fingerprint format '{fingerprint}'. Expected 64 hexadecimal characters."
        )

    return normalized


def format_fingerprint(fingerprint: str, delimiter: str = ":", uppercase: bool = True) -> str:
    """Format a 64-character SHA-256 fingerprint into human-readable grouped pairs.

    Example: 'AA:BB:CC:DD:...'

    Args:
        fingerprint: Raw or normalized fingerprint.
        delimiter: Separator between byte hex pairs (default ':').
        uppercase: Whether to uppercase hex characters (default True).

    Returns:
        Formatted fingerprint string.
    """
    canonical = normalize_fingerprint(fingerprint)
    if uppercase:
        canonical = canonical.upper()
    return delimiter.join(canonical[i : i + 2] for i in range(0, len(canonical), 2))


def cert_to_der_bytes(cert_data: bytes | str) -> bytes:
    """Parse certificate data (PEM or DER) and return raw DER bytes.

    Args:
        cert_data: Certificate content as PEM string, PEM bytes, or raw DER bytes.

    Returns:
        Raw DER-encoded certificate bytes.

    Raises:
        TLSCertificateParseError: If the certificate data is invalid or cannot be parsed.
    """
    if isinstance(cert_data, str):
        pem_bytes = cert_data.strip().encode("utf-8")
        try:
            cert = x509.load_pem_x509_certificate(pem_bytes)
            return cert.public_bytes(serialization.Encoding.DER)
        except Exception as exc:
            raise TLSCertificateParseError(
                f"Failed to parse PEM certificate string: {exc}"
            ) from exc

    if not isinstance(cert_data, bytes):
        raise TLSCertificateParseError(
            f"Expected bytes or str for cert_data, got {type(cert_data).__name__}"
        )

    # Check if PEM formatted bytes
    if b"-----BEGIN CERTIFICATE-----" in cert_data:
        try:
            cert = x509.load_pem_x509_certificate(cert_data)
            return cert.public_bytes(serialization.Encoding.DER)
        except Exception as exc:
            raise TLSCertificateParseError(f"Failed to parse PEM certificate bytes: {exc}") from exc

    # Otherwise validate DER bytes
    try:
        cert = x509.load_der_x509_certificate(cert_data)
        return cert.public_bytes(serialization.Encoding.DER)
    except Exception as exc:
        raise TLSCertificateParseError(f"Failed to parse DER certificate bytes: {exc}") from exc


def compute_cert_fingerprint(cert_data: bytes | str) -> str:
    """Compute canonical SHA-256 fingerprint of a certificate.

    Args:
        cert_data: Certificate in PEM (str or bytes) or DER (bytes) format.

    Returns:
        64-character lowercase hexadecimal SHA-256 fingerprint.

    Raises:
        TLSCertificateParseError: If the certificate cannot be parsed.
    """
    der_bytes = cert_to_der_bytes(cert_data)
    return hashlib.sha256(der_bytes).hexdigest().lower()


def verify_cert_fingerprint(cert_data: bytes | str, expected_fingerprint: str) -> bool:
    """Verify that a certificate matches the expected SHA-256 fingerprint.

    Comparison is done in constant time using compare_tokens.

    Args:
        cert_data: Certificate in PEM or DER format.
        expected_fingerprint: Expected SHA-256 fingerprint (in any accepted format).

    Returns:
        True if the fingerprints match, False otherwise.

    Raises:
        TLSCertificateParseError: If the certificate cannot be parsed.
        TLSFingerprintError: If expected_fingerprint is invalid.
    """
    actual_fingerprint = compute_cert_fingerprint(cert_data)
    normalized_expected = normalize_fingerprint(expected_fingerprint)
    return compare_tokens(actual_fingerprint, normalized_expected)


def extract_cert_expiration(cert_data: bytes | str) -> datetime.datetime:
    """Extract not_valid_after date from a certificate in UTC.

    Args:
        cert_data: Certificate in PEM (str or bytes) or DER (bytes) format.

    Returns:
        Timezone-aware datetime in UTC.

    Raises:
        TLSCertificateParseError: If the certificate cannot be parsed.
    """
    if isinstance(cert_data, str):
        pem_bytes = cert_data.strip().encode("utf-8")
        try:
            cert = x509.load_pem_x509_certificate(pem_bytes)
            if hasattr(cert, "not_valid_after_utc"):
                return cert.not_valid_after_utc
            return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        except Exception as exc:
            raise TLSCertificateParseError(
                f"Failed to parse PEM certificate string: {exc}"
            ) from exc

    if not isinstance(cert_data, bytes):
        raise TLSCertificateParseError(
            f"Expected bytes or str for cert_data, got {type(cert_data).__name__}"
        )

    if b"-----BEGIN CERTIFICATE-----" in cert_data:
        try:
            cert = x509.load_pem_x509_certificate(cert_data)
            if hasattr(cert, "not_valid_after_utc"):
                return cert.not_valid_after_utc
            return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        except Exception as exc:
            raise TLSCertificateParseError(f"Failed to parse PEM certificate bytes: {exc}") from exc

    try:
        cert = x509.load_der_x509_certificate(cert_data)
        if hasattr(cert, "not_valid_after_utc"):
            return cert.not_valid_after_utc
        return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    except Exception as exc:
        raise TLSCertificateParseError(f"Failed to parse DER certificate bytes: {exc}") from exc


def extract_peer_cert_fingerprint(sock_or_sslobj: Any) -> str:
    """Extract peer certificate from an active SSLSocket or SSLObject and compute its fingerprint.

    Args:
        sock_or_sslobj: ssl.SSLSocket or ssl.SSLObject instance.

    Returns:
        64-character lowercase hexadecimal SHA-256 fingerprint of the peer certificate.

    Raises:
        TLSFingerprintError: If the socket has no peer certificate or does not support getpeercert.
    """
    if not hasattr(sock_or_sslobj, "getpeercert"):
        raise TLSFingerprintError(
            f"Object {type(sock_or_sslobj).__name__} does not have getpeercert method."
        )

    try:
        der_bytes = sock_or_sslobj.getpeercert(binary_form=True)
    except Exception as exc:
        raise TLSFingerprintError(f"Error retrieving peer certificate from socket: {exc}") from exc

    if not der_bytes:
        raise TLSFingerprintError("No peer certificate presented by the remote host.")

    return compute_cert_fingerprint(der_bytes)
