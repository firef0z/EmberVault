"""Unit tests for RClone backend catalog and remote configuration validation."""

from __future__ import annotations

import pytest

from embervault_common.remotes.catalog import (
    get_backend_catalog,
    get_backend_spec,
    validate_and_split_remote_config,
)


def test_catalog_retrieval() -> None:
    catalog = get_backend_catalog()
    assert len(catalog) >= 7
    backend_types = {b.backend_type for b in catalog}
    assert {"s3", "b2", "sftp", "webdav", "smb", "local", "drive", "azureblob"}.issubset(
        backend_types
    )


def test_get_backend_spec() -> None:
    spec = get_backend_spec("s3")
    assert spec is not None
    assert spec.label == "Amazon S3 / S3-Compatible"
    assert any(f.name == "access_key_id" and f.is_secret for f in spec.fields)
    assert any(f.name == "secret_access_key" and f.is_secret for f in spec.fields)

    assert get_backend_spec("non_existent_backend") is None


def test_validate_and_split_s3_success() -> None:
    raw = {
        "provider": "AWS",
        "region": "eu-central-1",
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "acl": "private",
    }
    public_params, secret_params, secret_names = validate_and_split_remote_config("s3", raw)

    assert public_params["provider"] == "AWS"
    assert public_params["region"] == "eu-central-1"
    assert "access_key_id" not in public_params
    assert "secret_access_key" not in public_params

    assert secret_params["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
    assert secret_params["secret_access_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert set(secret_names) == {"access_key_id", "secret_access_key"}


def test_validate_and_split_missing_required() -> None:
    # Missing required secret_access_key
    raw = {
        "provider": "AWS",
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    }
    with pytest.raises(ValueError, match="Secret Access Key"):
        validate_and_split_remote_config("s3", raw)


def test_validate_and_split_type_casting() -> None:
    # SFTP with port as string number
    raw = {
        "host": "sftp.example.com",
        "port": "2222",
        "user": "backup",
        "pass": "secret123",
    }
    public_params, secret_params, secret_names = validate_and_split_remote_config("sftp", raw)
    assert public_params["port"] == 2222
    assert isinstance(public_params["port"], int)
    assert secret_params["pass"] == "secret123"
    assert "pass" in secret_names
