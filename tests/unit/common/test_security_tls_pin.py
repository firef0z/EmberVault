"""Unit tests for TLS certificate pinning and SHA-256 fingerprint verification."""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from embervault_common.security.tls_pin import (
    TLSCertificateParseError,
    TLSFingerprintError,
    compute_cert_fingerprint,
    extract_peer_cert_fingerprint,
    format_fingerprint,
    normalize_fingerprint,
    verify_cert_fingerprint,
)


@pytest.fixture(scope="module")
def sample_self_signed_cert() -> tuple[bytes, bytes, str]:
    """Generate a self-signed X.509 certificate for testing.

    Returns tuple of: (der_bytes, pem_bytes, pem_str)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EmberVault Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "embervault-proxy-test"),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
    pem_str = pem_bytes.decode("utf-8")
    return der_bytes, pem_bytes, pem_str


class TestFingerprintNormalizationAndFormatting:
    """Tests for fingerprint normalization and formatting."""

    def test_normalize_raw_hex(self) -> None:
        raw_hex = "0123456789abcdef" * 4
        assert normalize_fingerprint(raw_hex) == raw_hex.lower()

    def test_normalize_with_colons_and_uppercase(self) -> None:
        raw = "01:23:45:67:89:AB:CD:EF:" * 4
        clean = raw.rstrip(":")
        expected = ("0123456789abcdef" * 4).lower()
        assert normalize_fingerprint(clean) == expected

    def test_normalize_with_sha256_prefix(self) -> None:
        raw_hex = "abcdef0123456789" * 4
        assert normalize_fingerprint(f"SHA256: {raw_hex}") == raw_hex
        assert normalize_fingerprint(f"sha-256:{raw_hex}") == raw_hex

    def test_invalid_fingerprint_length_raises(self) -> None:
        with pytest.raises(TLSFingerprintError, match="Invalid SHA-256 fingerprint format"):
            normalize_fingerprint("too-short")

    def test_invalid_fingerprint_chars_raises(self) -> None:
        invalid_hex = "0123456789abcdeg" * 4  # 'g' is not hex
        with pytest.raises(TLSFingerprintError, match="Invalid SHA-256 fingerprint format"):
            normalize_fingerprint(invalid_hex)

    def test_format_fingerprint(self) -> None:
        raw_hex = "0123456789abcdef" * 4
        formatted = format_fingerprint(raw_hex, delimiter=":", uppercase=True)
        assert formatted.startswith("01:23:45:67:89:AB:CD:EF")
        assert len(formatted.split(":")) == 32


class TestCertificateFingerprintComputation:
    """Tests for certificate fingerprint computation."""

    def test_compute_fingerprint_from_der_pem_matches(
        self, sample_self_signed_cert: tuple[bytes, bytes, str]
    ) -> None:
        der_bytes, pem_bytes, pem_str = sample_self_signed_cert

        fp_der = compute_cert_fingerprint(der_bytes)
        fp_pem_bytes = compute_cert_fingerprint(pem_bytes)
        fp_pem_str = compute_cert_fingerprint(pem_str)

        assert len(fp_der) == 64
        assert fp_der == fp_pem_bytes
        assert fp_der == fp_pem_str

    def test_invalid_cert_raises(self) -> None:
        with pytest.raises(TLSCertificateParseError):
            compute_cert_fingerprint(b"not-a-valid-der-or-pem-cert")

        with pytest.raises(TLSCertificateParseError):
            compute_cert_fingerprint(
                "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"
            )


class TestCertificateFingerprintVerification:
    """Tests for verifying certificates against expected fingerprints."""

    def test_verify_success_with_various_formats(
        self, sample_self_signed_cert: tuple[bytes, bytes, str]
    ) -> None:
        der_bytes, pem_bytes, pem_str = sample_self_signed_cert
        raw_fp = compute_cert_fingerprint(der_bytes)

        # Verification with plain hex
        assert verify_cert_fingerprint(der_bytes, raw_fp) is True
        assert verify_cert_fingerprint(pem_str, raw_fp) is True

        # Verification with formatted uppercase colon separated
        formatted_fp = format_fingerprint(raw_fp, uppercase=True)
        assert verify_cert_fingerprint(der_bytes, formatted_fp) is True

        # Verification with prefix
        prefixed_fp = f"SHA256:{formatted_fp}"
        assert verify_cert_fingerprint(der_bytes, prefixed_fp) is True

    def test_verify_mismatch_returns_false(
        self, sample_self_signed_cert: tuple[bytes, bytes, str]
    ) -> None:
        der_bytes, _, _ = sample_self_signed_cert
        wrong_fp = "00" * 32
        assert verify_cert_fingerprint(der_bytes, wrong_fp) is False


class TestSocketExtraction:
    """Tests for extracting peer certificate fingerprints from SSL objects."""

    def test_extract_peer_cert_fingerprint(
        self, sample_self_signed_cert: tuple[bytes, bytes, str]
    ) -> None:
        der_bytes, _, _ = sample_self_signed_cert
        expected_fp = compute_cert_fingerprint(der_bytes)

        mock_socket = MagicMock()
        mock_socket.getpeercert.return_value = der_bytes

        extracted_fp = extract_peer_cert_fingerprint(mock_socket)
        assert extracted_fp == expected_fp
        mock_socket.getpeercert.assert_called_once_with(binary_form=True)

    def test_extract_missing_getpeercert_raises(self) -> None:
        mock_obj = object()
        with pytest.raises(TLSFingerprintError, match="does not have getpeercert method"):
            extract_peer_cert_fingerprint(mock_obj)

    def test_extract_no_cert_returned_raises(self) -> None:
        mock_socket = MagicMock()
        mock_socket.getpeercert.return_value = None
        with pytest.raises(TLSFingerprintError, match="No peer certificate presented"):
            extract_peer_cert_fingerprint(mock_socket)
