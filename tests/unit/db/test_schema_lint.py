"""Schema lint tests verifying that no plaintext secret columns exist."""

from sqlalchemy import Boolean, LargeBinary, Text

from embervault_db.models import metadata

# Whitelist of permissible column names and their expected safe types
PERMISSIBLE_SENSITIVE_COLUMNS: dict[str, type] = {
    "password_hash": Text,  # One-way salted hash
    "code_hash": str,  # One-way recovery code hash
    "secret_encrypted": LargeBinary,  # AES-256-GCM ciphertext blob
    "token_encrypted": LargeBinary,  # AES-256-GCM ciphertext blob
    "config_encrypted": LargeBinary,  # AES-256-GCM ciphertext blob
    "value_encrypted": LargeBinary,  # AES-256-GCM ciphertext blob
    "secret_field_names": object,  # Metadata array storing field names only (e.g. ["password"])
}


def test_schema_lint_no_unencrypted_secret_or_password_columns() -> None:
    """Verify that no database table has plaintext columns named password, secret, or token."""
    violations: list[str] = []

    for table_name, table in metadata.tables.items():
        for column in table.columns:
            col_name = column.name.lower()

            # Public share URL slug/token is a public link identifier, not a secret credential
            if table_name == "public_shares" and col_name == "token":
                continue

            # Boolean flags like must_change_password cannot contain secret values
            if isinstance(column.type, Boolean):
                continue

            # Check if column name contains sensitive terms
            has_sensitive_term = any(term in col_name for term in ("password", "secret", "token"))
            if not has_sensitive_term:
                continue

            # Check if column is a known permissible safe pattern
            if col_name in PERMISSIBLE_SENSITIVE_COLUMNS:
                expected_type = PERMISSIBLE_SENSITIVE_COLUMNS[col_name]
                if expected_type is LargeBinary and not isinstance(column.type, LargeBinary):
                    violations.append(
                        f"Table '{table_name}', column '{column.name}': expected encrypted LargeBinary type but got {column.type}"
                    )
                continue

            # If it's a foreign key (e.g. token_id), it's safe
            if column.foreign_keys:
                continue

            # If token_hash (session token hash)
            if col_name == "token_hash":
                continue

            violations.append(
                f"Table '{table_name}' has unapproved sensitive column: '{column.name}' ({column.type})"
            )

    assert not violations, "Found unapproved sensitive plaintext columns:\n" + "\n".join(violations)
