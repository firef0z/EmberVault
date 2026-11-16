"""Unit tests for TLS certificate extraction and expiration calculation."""

from __future__ import annotations

import datetime
from pathlib import Path

from embervault_common.security import compute_cert_fingerprint, extract_cert_expiration
from embervault_proxy.tls import generate_self_signed_cert


def test_extract_cert_expiration(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    generate_self_signed_cert(cert_path, key_path, valid_days=90)

    cert_bytes = cert_path.read_bytes()
    expires_at = extract_cert_expiration(cert_bytes)
    assert expires_at is not None
    assert expires_at.tzinfo == datetime.timezone.utc

    now = datetime.datetime.now(datetime.timezone.utc)
    diff = (expires_at - now).total_seconds()
    assert 89 * 86400 <= diff <= 91 * 86400

    # Fingerprint check
    fp = compute_cert_fingerprint(cert_bytes)
    assert len(fp) == 64
