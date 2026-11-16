"""TLS certificate management and self-signed certificate generation for EmberVault Proxy."""

from __future__ import annotations

import contextlib
import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from embervault_common.config import ProxySettings
from embervault_common.observability import get_logger
from embervault_common.security import (
    compute_cert_fingerprint,
    extract_cert_expiration,
    format_fingerprint,
)

logger = get_logger("embervault_proxy.tls")


def generate_self_signed_cert(
    cert_path: Path,
    key_path: Path,
    valid_days: int = 90,
) -> str:
    """Generate a self-signed X.509 certificate and private key, writing them to disk.

    Args:
        cert_path: Path where the PEM certificate will be written.
        key_path: Path where the PEM private key will be written.
        valid_days: Certificate validity period in days (default 90 days).

    Returns:
        Canonical 64-character lowercase SHA-256 fingerprint of the certificate.
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate 2048-bit RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EmberVault"),
            x509.NameAttribute(NameOID.COMMON_NAME, "embervault-proxy"),
        ]
    )

    now = datetime.datetime.now(datetime.UTC)
    san_list: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.DNSName("embervault-proxy"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write private key
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_bytes)
    with contextlib.suppress(OSError):
        key_path.chmod(0o600)

    # Write certificate
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(cert_bytes)

    fingerprint = compute_cert_fingerprint(cert_bytes)
    logger.info(
        "tls_certificate_generated",
        cert_path=str(cert_path),
        key_path=str(key_path),
        fingerprint=fingerprint,
        fingerprint_formatted=format_fingerprint(fingerprint),
    )
    return fingerprint


def get_cert_expiration_date(cert_path: Path) -> datetime.datetime:
    """Extract expiration timestamp (UTC) from a certificate on disk."""
    cert_bytes = cert_path.read_bytes()
    return extract_cert_expiration(cert_bytes)


def renew_self_signed_cert(
    cert_path: Path,
    key_path: Path,
    valid_days: int = 90,
) -> tuple[str, datetime.datetime]:
    """Force renewal of self-signed TLS certificate and private key.

    Returns:
        Tuple of (new_canonical_fingerprint, new_expiration_datetime_utc).
    """
    logger.info("tls_certificate_renewing", cert_path=str(cert_path))
    fingerprint = generate_self_signed_cert(cert_path, key_path, valid_days=valid_days)
    expires_at = get_cert_expiration_date(cert_path)
    return fingerprint, expires_at


def ensure_tls_credentials(settings: ProxySettings) -> tuple[Path, Path, str]:
    """Ensure TLS certificate and private key exist, generating self-signed ones if configured.

    If an existing certificate has expired, it is automatically regenerated.

    Args:
        settings: Current ProxySettings.

    Returns:
        Tuple of (cert_path, key_path, canonical_sha256_fingerprint).

    Raises:
        FileNotFoundError: If configured cert/key paths do not exist and auto-generation is disabled.
    """
    tls_dir = settings.proxy_state_dir / "tls"
    cert_path = settings.proxy_tls_cert_file or (tls_dir / "cert.pem")
    key_path = settings.proxy_tls_key_file or (tls_dir / "key.pem")

    if cert_path.exists() and key_path.exists():
        cert_bytes = cert_path.read_bytes()
        try:
            expires_at = extract_cert_expiration(cert_bytes)
            now = datetime.datetime.now(datetime.UTC)
            if now >= expires_at:
                logger.warning(
                    "tls_certificate_expired_auto_renewing",
                    cert_path=str(cert_path),
                    expires_at=expires_at.isoformat(),
                )
                fingerprint = generate_self_signed_cert(cert_path, key_path, valid_days=90)
                return cert_path, key_path, fingerprint
        except Exception as exc:
            logger.warning("tls_certificate_expiration_check_failed", error=str(exc))

        fingerprint = compute_cert_fingerprint(cert_bytes)
        logger.info(
            "tls_certificate_loaded",
            cert_path=str(cert_path),
            fingerprint=fingerprint,
            fingerprint_formatted=format_fingerprint(fingerprint),
        )
        return cert_path, key_path, fingerprint

    if not settings.proxy_tls_auto_self_signed:
        raise FileNotFoundError(
            f"TLS certificate files not found at {cert_path} and auto-generation is disabled."
        )

    fingerprint = generate_self_signed_cert(cert_path, key_path, valid_days=90)
    return cert_path, key_path, fingerprint
