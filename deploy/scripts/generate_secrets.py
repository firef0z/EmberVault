#!/usr/bin/env python3
"""Generate cryptographically secure secrets for EmberVault production deployment.

Usage:
    python deploy/scripts/generate_secrets.py [--output-dir deploy/secrets]
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import os
import secrets
from pathlib import Path


def generate_secrets(output_dir: Path, force: bool = False) -> None:
    """Generate production secret files if they do not exist."""
    output_dir.mkdir(parents=True, exist_ok=True)

    secrets_to_create = {
        "postgres_password.txt": secrets.token_urlsafe(32),
        "master_key.txt": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "secret_key.txt": secrets.token_hex(32),
        "internal_api_token.txt": secrets.token_urlsafe(48),
        "proxy_1_token.txt": secrets.token_urlsafe(48),
        "proxy_2_token.txt": secrets.token_urlsafe(48),
    }

    for filename, secret_val in secrets_to_create.items():
        file_path = output_dir / filename
        if file_path.exists() and not force:
            print(f"[EXISTS] {file_path} (use --force to overwrite)")
            continue

        file_path.write_text(secret_val + "\n", encoding="utf-8")
        # Set restrictive permissions where supported
        with contextlib.suppress(OSError):
            os.chmod(file_path, 0o600)
        print(f"[GENERATED] {file_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate EmberVault production secrets.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("deploy/secrets"),
        help="Target directory for secret files (default: deploy/secrets)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing secret files",
    )
    args = parser.parse_args()
    generate_secrets(args.output_dir, force=args.force)


if __name__ == "__main__":
    main()
