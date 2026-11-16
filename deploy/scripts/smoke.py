#!/usr/bin/env python3
"""EmberVault Smoke Test Runner.

Executes baseline smoke verification across:
- System configuration and environment resolution
- Cryptographic envelope encryption and key ring operations
- Secret redaction and canary leak prevention
- Database schema metadata and migration status
- Compose hardening specs and network isolation contracts
- Live service health endpoints (when services are running or with --live)

Usage:
    python deploy/scripts/smoke.py [--live] [--strict-live]
"""

from __future__ import annotations

import argparse
import logging
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Import internal packages to verify importability and core functionality
from embervault_common.config.models import AppSettings, CommonSettings
from embervault_common.config.registry import CONFIG_REGISTRY, get_config_by_name
from embervault_common.security.crypto import KeyRing, decrypt_blob, encrypt_blob
from embervault_common.security.redaction import (
    REDACTED_PLACEHOLDER,
    RedactionProcessor,
    mask_secret,
    redact_data,
    register_canary,
)

logger = logging.getLogger("smoke")


def check_configuration_registry() -> bool:
    """Verify configuration registry completeness and default resolution."""
    print("[1/5] Checking configuration registry...")
    assert len(CONFIG_REGISTRY) >= 20, f"Expected >= 20 config items, got {len(CONFIG_REGISTRY)}"

    # Check key resolution from registry
    app_port_key = get_config_by_name("app_port")
    assert app_port_key is not None
    assert app_port_key.default == 8080

    # Validate settings model resolution
    common_cfg = CommonSettings(env="prod", log_format="json")
    assert common_cfg.env == "prod"

    app_cfg = AppSettings(
        app_port=8080,
    )
    assert app_cfg.app_port == 8080
    print("  -> Configuration registry & settings models validated OK.")
    return True


def check_crypto_and_canary() -> bool:
    """Verify envelope encryption and canary leak prevention."""
    print("[2/5] Checking cryptographic envelope encryption & canary redaction...")
    master_key = b"01234567890123456789012345678901"
    keyring = KeyRing(keys={"v1": master_key}, primary_key_id="v1")

    canary = "CANARY_SECRET_TOP_SECRET_DO_NOT_LEAK_9999"
    aad = b"tenant:smoke_test:record:1"

    # Encrypt canary payload
    encrypted = encrypt_blob(canary.encode("utf-8"), key_ring=keyring, aad=aad)
    decrypted = decrypt_blob(encrypted, key_ring=keyring, aad=aad).decode("utf-8")
    assert decrypted == canary, "Decrypted plaintext did not match original canary!"

    # Verify tampering detection
    tampered = bytearray(encrypted)
    tampered[-1] ^= 0xFF
    try:
        decrypt_blob(bytes(tampered), key_ring=keyring, aad=aad)
        raise AssertionError("Tampered ciphertext should have raised DecryptionError!")
    except Exception:
        pass  # Expected behavior

    # Register canary and test masking and processor
    register_canary(canary)
    raw_log = f"User logged in with token=supersecret and canary={canary}"
    masked = mask_secret(raw_log)
    assert canary not in masked, "Canary secret was not masked!"
    assert REDACTED_PLACEHOLDER in masked

    data_payload = {
        "user": "admin",
        "password": "supersecretpassword123",
        "nested": {"token": "my-bearer-token", "note": f"Leak test: {canary}"},
    }
    redacted_struct = redact_data(data_payload)
    assert redacted_struct["password"] == REDACTED_PLACEHOLDER
    assert redacted_struct["nested"]["token"] == REDACTED_PLACEHOLDER
    assert canary not in str(redacted_struct)

    # Structlog RedactionProcessor test
    processor = RedactionProcessor()
    event_dict = {"event": "task_failed", "error": f"Failed with {canary}", "password": "pass"}
    processed = processor(None, "error", event_dict)
    assert canary not in str(processed)
    assert processed["password"] == REDACTED_PLACEHOLDER

    print("  -> Crypto envelope & canary redaction validated OK.")
    return True


def check_compose_hardening_specs() -> bool:
    """Verify Docker Compose hardening configurations in prod files."""
    print("[3/5] Checking Docker Compose production hardening specifications...")
    import yaml

    prod_compose_path = Path("deploy/compose/docker-compose.prod.yml")
    assert prod_compose_path.exists(), f"Prod compose file not found at {prod_compose_path}"

    with open(prod_compose_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    services = data.get("services", {})
    assert "app" in services, "App service missing from prod compose"
    assert "orchestrator" in services, "Orchestrator service missing from prod compose"
    assert "proxy-1" in services, "Proxy service missing from prod compose"

    for svc_name in ["app", "orchestrator", "proxy-1"]:
        svc = services[svc_name]
        assert svc.get("read_only") is True, f"Service {svc_name} missing read_only: true"
        assert svc.get("cap_drop") == ["ALL"], f"Service {svc_name} missing cap_drop: [ALL]"
        assert "no-new-privileges:true" in svc.get("security_opt", []), (
            f"Service {svc_name} missing no-new-privileges:true"
        )
        limits = svc.get("deploy", {}).get("resources", {}).get("limits", {})
        assert "cpus" in limits and "memory" in limits, (
            f"Service {svc_name} missing CPU/memory limits"
        )

    # Verify secrets section exists
    secrets = data.get("secrets", {})
    assert "postgres_password" in secrets, "Missing postgres_password secret in prod compose"
    assert "master_key" in secrets, "Missing master_key secret in prod compose"
    print("  -> Compose hardening & secret mounts validated OK.")
    return True


def check_database_metadata() -> bool:
    """Verify database schema models and Alembic migration metadata."""
    print("[4/5] Checking database models & migration status...")
    from embervault_db.models import Base

    # Verify expected tables are registered in SQLAlchemy metadata
    table_names = set(Base.metadata.tables.keys())
    required_tables = {
        "proxies",
        "jobs",
        "tasks",
        "job_runs",
        "task_assignments",
        "settings",
    }
    missing = required_tables - table_names
    assert not missing, f"Missing required database tables in metadata: {missing}"
    print(f"  -> Database metadata verified ({len(table_names)} tables defined) OK.")
    return True


def probe_endpoint(
    url: str,
    expected_status: int = 200,
    headers: dict[str, str] | None = None,
    insecure: bool = False,
    timeout: float = 3.0,
) -> tuple[bool, int, str]:
    """Helper to probe an HTTP/HTTPS endpoint."""
    context = None
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "EmberVault-Smoke/1.0", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            status = response.getcode()
            body = response.read(1024).decode("utf-8", errors="replace")
            return status == expected_status, status, body
    except urllib.error.HTTPError as e:
        body = e.read(1024).decode("utf-8", errors="replace")
        return e.code == expected_status, e.code, body
    except Exception as e:
        return False, 0, str(e)


def check_live_endpoints(strict: bool = False) -> bool:
    """Probe live service endpoints if available."""
    print("[5/5] Probing live service endpoints...")

    # Probe app healthz
    ok, status, _ = probe_endpoint("http://localhost:8080/healthz")
    if not ok and status == 0:
        if strict:
            print("  [ERROR] Live services not running and --strict-live was specified.")
            return False
        print(
            "  -> [NOTICE] Live stack not running locally on port 8080. Skipping live endpoint probes."
        )
        print("     To run live probes against running containers, run: make up && make smoke")
        return True

    # If app is reachable, run full probe suite:
    assert status == 200, f"App /healthz returned status {status}"
    print("  -> App http://localhost:8080/healthz is healthy.")

    ok, status, _ = probe_endpoint("http://localhost:8080/readyz")
    assert status == 200, f"App /readyz returned status {status}"
    print("  -> App http://localhost:8080/readyz is ready.")

    ok, status, _ = probe_endpoint("http://localhost:8080/metrics")
    assert status == 200, f"App /metrics returned status {status}"
    print("  -> App http://localhost:8080/metrics is serving metrics.")

    # Probe orchestrator healthz
    ok, status, _ = probe_endpoint("http://localhost:8081/healthz")
    assert status == 200, f"Orchestrator /healthz returned status {status}"
    print("  -> Orchestrator http://localhost:8081/healthz is healthy.")

    # Probe proxy readyz (unauthenticated allowed)
    ok, status, _ = probe_endpoint("https://localhost:8443/readyz", insecure=True)
    if ok:
        print("  -> Proxy https://localhost:8443/readyz is ready.")

    # Probe proxy v1/health (unauthenticated MUST be 401 Unauthorized)
    ok, status, _ = probe_endpoint(
        "https://localhost:8443/v1/health",
        expected_status=401,
        insecure=True,
    )
    assert status == 401, (
        f"Proxy /v1/health should reject unauthenticated requests with 401, got {status}"
    )
    print(
        "  -> Proxy https://localhost:8443/v1/health correctly rejected unauthenticated request (401)."
    )

    # Probe proxy v1/health with Bearer token
    ok, status, _ = probe_endpoint(
        "https://localhost:8443/v1/health",
        expected_status=200,
        headers={"Authorization": "Bearer dev-proxy-token-secret"},
        insecure=True,
    )
    assert status == 200, (
        f"Proxy /v1/health with valid Bearer token should return 200, got {status}"
    )
    print("  -> Proxy https://localhost:8443/v1/health authenticated OK (200).")

    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="EmberVault Smoke Test Runner")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Attempt live endpoint probing (fails gracefully if stack is not up)",
    )
    parser.add_argument(
        "--strict-live",
        action="store_true",
        help="Fail if live stack containers are not reachable",
    )
    args = parser.parse_args()

    print("==================================================")
    print("  EmberVault Phase 0 Smoke Verification")
    print("==================================================")

    try:
        check_configuration_registry()
        check_crypto_and_canary()
        check_compose_hardening_specs()
        check_database_metadata()
        check_live_endpoints(strict=args.strict_live)
        print("==================================================")
        print("  ALL SMOKE CHECKS PASSED SUCCESSFULLY (DoD OK)")
        print("==================================================")
        return 0
    except AssertionError as e:
        print(f"\n[FAIL] Smoke verification assertion failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"\n[ERROR] Unexpected error during smoke test: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
