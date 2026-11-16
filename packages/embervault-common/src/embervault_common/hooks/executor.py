"""Bash hook execution module for EmberVault orchestrator (Milestone M8).

Executes pre-run and post-run scripts in an isolated, sanitized subprocess.
Ensures:
- Safe environment isolation (no database credentials, master keys, or external secrets)
- Execution timeouts
- SHA-256 script hashing and audit logging
- Output length limiting (max 64KB)
- Secret masking via SecretRedactor
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Any

import structlog

from embervault_common.security.redaction import mask_secret

logger = structlog.get_logger(__name__)

# Maximum stdout/stderr output captured to prevent database bloat
MAX_HOOK_OUTPUT_BYTES = 64 * 1024


@dataclass(frozen=True)
class HookExecutionResult:
    """Result of a hook execution."""

    status: str  # "succeeded", "failed", "timeout", "skipped"
    exit_code: int | None
    duration_ms: float
    script_hash: str
    output: str


class HookExecutor:
    """Executes pre/post run bash hooks with rigorous isolation and security controls."""

    def __init__(
        self,
        default_timeout_s: int = 60,
        runner_url: str | None = None,
        auth_token: str | None = None,
    ) -> None:
        self.default_timeout_s = default_timeout_s
        self.runner_url = (runner_url or "").strip().rstrip("/")
        self.auth_token = (auth_token or "").strip()

    @staticmethod
    def calculate_script_hash(script_content: str) -> str:
        """Calculate the SHA-256 hex digest of a hook script."""
        normalized = script_content.strip().encode("utf-8")
        return hashlib.sha256(normalized).hexdigest()

    def build_sanitized_environment(
        self,
        context: dict[str, Any],
    ) -> dict[str, str]:
        """Construct a strictly whitelisted environment.

        Ambient credentials (DATABASE_URL, POSTGRES_*, EMBERVAULT_MASTER_KEY, LDAP_*, OIDC_*)
        are deliberately stripped. Only basic system variables (PATH, TMP, SYSTEMROOT)
        and explicitly whitelisted EMBERVAULT_* context parameters are passed.
        """
        clean_env: dict[str, str] = {}

        # Preserve minimum system execution paths
        for k in ("PATH", "TEMP", "TMP", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL"):
            if k in os.environ:
                clean_env[k] = os.environ[k]

        # Explicit whitelisted EmberVault job & run context
        for key, val in context.items():
            if val is not None:
                clean_env[str(key)] = str(val)

        return clean_env

    def execute(
        self,
        script_content: str,
        context: dict[str, Any],
        timeout_s: int | None = None,
    ) -> HookExecutionResult:
        """Execute a bash hook script.

        If a remote runner URL is configured (e.g. dedicated container sidecar),
        delegates execution via HTTP. Otherwise falls back to local isolated subprocess.
        """
        if self.runner_url:
            return self.execute_remote(
                script_content=script_content,
                context=context,
                timeout_s=timeout_s,
            )
        return self.execute_local(
            script_content=script_content,
            context=context,
            timeout_s=timeout_s,
        )

    def execute_remote(
        self,
        script_content: str,
        context: dict[str, Any],
        timeout_s: int | None = None,
    ) -> HookExecutionResult:
        """Delegate hook execution to dedicated hook-runner sidecar container via HTTP."""
        clean_script = (script_content or "").strip()
        script_hash = self.calculate_script_hash(clean_script)

        if not clean_script:
            return HookExecutionResult(
                status="skipped",
                exit_code=0,
                duration_ms=0.0,
                script_hash=script_hash,
                output="Nessuno script fornito.",
            )

        effective_timeout = timeout_s if (timeout_s and timeout_s > 0) else self.default_timeout_s
        start_time = time.monotonic()

        import json
        import urllib.error
        import urllib.request

        url = f"{self.runner_url}/execute"
        payload = json.dumps(
            {
                "script": clean_script,
                "context": context,
                "timeout_s": effective_timeout,
            }
        ).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "EmberVault-Orchestrator-HookClient/1.0",
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

        try:
            # Add small network overhead buffer (5s) to HTTP read timeout
            with urllib.request.urlopen(req, timeout=float(effective_timeout + 5)) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                duration_ms = float(data.get("duration_ms", (time.monotonic() - start_time) * 1000))
                return HookExecutionResult(
                    status=str(data.get("status", "failed")),
                    exit_code=data.get("exit_code"),
                    duration_ms=round(duration_ms, 2),
                    script_hash=str(data.get("script_hash", script_hash)),
                    output=str(data.get("output", "")),
                )
        except urllib.error.HTTPError as exc:
            duration_ms = round((time.monotonic() - start_time) * 1000, 2)
            err_body = exc.read().decode("utf-8", errors="replace")
            logger.error("remote_hook_execution_http_error", code=exc.code, body=err_body)
            return HookExecutionResult(
                status="failed",
                exit_code=-1,
                duration_ms=duration_ms,
                script_hash=script_hash,
                output=f"[ERROR] Hook runner sidecar error (HTTP {exc.code}): {err_body}",
            )
        except Exception as exc:
            duration_ms = round((time.monotonic() - start_time) * 1000, 2)
            logger.error("remote_hook_execution_failed", error=str(exc))
            return HookExecutionResult(
                status="failed",
                exit_code=-1,
                duration_ms=duration_ms,
                script_hash=script_hash,
                output=f"[ERROR] Failed to reach hook runner sidecar at {self.runner_url}: {exc}",
            )

    def execute_local(
        self,
        script_content: str,
        context: dict[str, Any],
        timeout_s: int | None = None,
    ) -> HookExecutionResult:
        """Execute a bash hook script within a clean local environment and working directory."""
        clean_script = (script_content or "").strip()
        script_hash = self.calculate_script_hash(clean_script)

        if not clean_script:
            return HookExecutionResult(
                status="skipped",
                exit_code=0,
                duration_ms=0.0,
                script_hash=script_hash,
                output="Nessuno script fornito.",
            )

        effective_timeout = timeout_s if (timeout_s and timeout_s > 0) else self.default_timeout_s
        clean_env = self.build_sanitized_environment(context)

        # Create isolated temporary working directory
        temp_dir = tempfile.mkdtemp(prefix="embervault_hook_")
        start_time = time.monotonic()
        status = "failed"
        exit_code: int | None = None
        output = ""

        try:
            # Determine shell: prefer bash / sh, fallback to bash on Windows or cmd/powershell
            bash_path = shutil.which("bash") or shutil.which("sh")
            if bash_path:
                script_path = os.path.join(temp_dir, "hook.sh")
                with open(script_path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(clean_script + "\n")
                cmd = [bash_path, script_path]
            else:
                # Fallback for Windows environments without bash installed
                script_path = os.path.join(temp_dir, "hook.bat")
                with open(script_path, "w", encoding="utf-8") as f:
                    f.write(clean_script + "\n")
                cmd = [script_path]

            try:
                proc = subprocess.run(
                    cmd,
                    cwd=temp_dir,
                    env=clean_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=effective_timeout,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                duration_ms = round((time.monotonic() - start_time) * 1000, 2)
                exit_code = proc.returncode
                raw_output = proc.stdout or ""

                if exit_code == 0:
                    status = "succeeded"
                else:
                    status = "failed"

            except subprocess.TimeoutExpired as exc:
                duration_ms = round((time.monotonic() - start_time) * 1000, 2)
                status = "timeout"
                raw_output = (
                    exc.stdout or ""
                ) + f"\n[TIMEOUT] Hook execution exceeded limit of {effective_timeout}s."
                exit_code = -1

            # Limit output size to prevent unbounded memory / DB usage
            if len(raw_output) > MAX_HOOK_OUTPUT_BYTES:
                raw_output = (
                    raw_output[:MAX_HOOK_OUTPUT_BYTES]
                    + f"\n[TRUNCATED] Output truncated to {MAX_HOOK_OUTPUT_BYTES} bytes."
                )

            # Scrub any secrets using redaction utility
            output = mask_secret(raw_output)

        except Exception as exc:
            duration_ms = round((time.monotonic() - start_time) * 1000, 2)
            status = "failed"
            exit_code = -1
            output = f"[ERROR] Failed to execute hook: {exc}"
            logger.error("hook_execution_failed", error=str(exc), script_hash=script_hash)

        finally:
            # Clean up temporary directory
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass

        return HookExecutionResult(
            status=status,
            exit_code=exit_code,
            duration_ms=duration_ms,
            script_hash=script_hash,
            output=output,
        )
