"""Unit tests for proxy TLS certificate generation, loading, and persistence."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from embervault_common.config import ProxySettings
from embervault_common.security import compute_cert_fingerprint
from embervault_proxy.tls import ensure_tls_credentials, generate_self_signed_cert


class TestProxyTLS:
    """Tests for TLS certificate generation and lifecycle."""

    def test_generate_self_signed_cert(self, tmp_path: Path) -> None:
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"

        fingerprint = generate_self_signed_cert(cert_path, key_path, valid_days=365)
        assert cert_path.exists()
        assert key_path.exists()
        assert len(fingerprint) == 64

        # Verify fingerprint calculation matches
        expected_fp = compute_cert_fingerprint(cert_path.read_bytes())
        assert fingerprint == expected_fp

    def test_ensure_tls_credentials_generates_and_persists(self, tmp_path: Path) -> None:
        state_dir = tmp_path / "state"
        settings = ProxySettings(
            token=SecretStr("a_very_secret_proxy_token_with_more_than_32_characters"),
            proxy_state_dir=state_dir,
            proxy_tls_auto_self_signed=True,
        )

        cert_path, key_path, fp1 = ensure_tls_credentials(settings)
        assert cert_path.exists()
        assert key_path.exists()
        assert cert_path == state_dir / "tls" / "cert.pem"

        # Subsequent call must reuse existing cert and not change fingerprint
        _, _, fp2 = ensure_tls_credentials(settings)
        assert fp1 == fp2

    def test_missing_cert_without_auto_generate_raises(self, tmp_path: Path) -> None:
        state_dir = tmp_path / "empty_state"
        settings = ProxySettings(
            token=SecretStr("a_very_secret_proxy_token_with_more_than_32_characters"),
            proxy_state_dir=state_dir,
            proxy_tls_auto_self_signed=False,
        )

        with pytest.raises(FileNotFoundError, match="TLS certificate files not found"):
            ensure_tls_credentials(settings)

    def test_get_cert_expiration_date_and_renew(self, tmp_path: Path) -> None:
        from datetime import datetime, timezone
        from embervault_proxy.tls import get_cert_expiration_date, renew_self_signed_cert

        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        fp1 = generate_self_signed_cert(cert_path, key_path, valid_days=90)

        exp1 = get_cert_expiration_date(cert_path)
        assert exp1 is not None
        now = datetime.now(timezone.utc)
        diff = (exp1 - now).total_seconds()
        # Should be roughly 90 days (between 89 and 91 days)
        assert 89 * 86400 <= diff <= 91 * 86400

        # Renew
        fp2, exp2 = renew_self_signed_cert(cert_path, key_path, valid_days=90)
        assert fp2 != fp1
        assert exp2 is not None
        assert len(fp2) == 64

    def test_ensure_tls_credentials_regenerates_when_expired(self, tmp_path: Path) -> None:
        state_dir = tmp_path / "expired_state"
        settings = ProxySettings(
            token=SecretStr("a_very_secret_proxy_token_with_more_than_32_characters"),
            proxy_state_dir=state_dir,
            proxy_tls_auto_self_signed=True,
        )

        cert_path, key_path, fp1 = ensure_tls_credentials(settings)
        # Generate an already expired cert (-1 day)
        generate_self_signed_cert(cert_path, key_path, valid_days=-1)

        # Calling ensure_tls_credentials must detect expiration and regenerate
        cert_path2, key_path2, fp2 = ensure_tls_credentials(settings)
        assert fp2 != fp1
