"""Subprocess execution engine for RClone tasks with secret redaction and progress streaming."""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import threading
import time
from datetime import UTC, datetime
from uuid import UUID

from embervault_common.contracts.enums import (
    DiscoveryStatusLevel,
    ErrorClass,
    ErrorCode,
    TaskKind,
    TaskState,
)
from embervault_common.contracts.proxy import (
    DiscoverTaskResultPayload,
    RemoteConfigPayload,
    TaskCancelResponse,
    TaskDispatchPayload,
    TaskDispatchResponse,
    TaskLogLine,
    TaskProgress,
)
from embervault_common.observability import get_logger
from embervault_common.remotes import is_obscured_secret_field, rclone_obscure
from embervault_common.security.redaction import REDACTED_PLACEHOLDER

logger = get_logger("embervault_proxy.runner")


class SecretRedactor:
    """Masks secret substrings from logs and stderr output."""

    def __init__(self, secrets: set[str]) -> None:
        self.secrets = {s for s in secrets if len(s) >= 4}

    def redact(self, text: str) -> str:
        res = text
        for s in self.secrets:
            res = res.replace(s, REDACTED_PLACEHOLDER)
        return res


MAX_FILE_EXCLUSION_RETRIES = 20
_RCLONE_ERROR_PATH_RE = re.compile(r"\bERROR\s*:\s*(.+?):\s")
_NON_FILE_ERROR_PREFIXES = ("attempt ", "failed to", "fatal", "errors", "retry")


_DIR_ERROR_MARKERS = (
    "error reading source directory",
    "error reading destination directory",
    "error listing",
    "couldn't list directory",
    "failed to list",
    "directory not found",
    "failed to mkdir",
    "dir.mkdir",
    "failed to rmdir",
    "couldn't create directory",
    "failed to create directory",
)


def _extract_error_path(line: str) -> tuple[str, bool] | None:
    """Return (path, is_dir) from an rclone 'ERROR : <path>: <msg>' line, if any.

    ``is_dir`` is inferred from the error message (listing/mkdir errors are directory errors).
    """
    m = _RCLONE_ERROR_PATH_RE.search(line)
    if not m:
        return None
    raw = m.group(1).strip()
    path = raw.strip("/")
    if not path or path.lower().startswith(_NON_FILE_ERROR_PREFIXES):
        return None
    message = line[m.end() :].lower()
    is_dir = raw.endswith("/") or any(marker in message for marker in _DIR_ERROR_MARKERS)
    return path, is_dir


def _escape_glob(path: str) -> str:
    """Escape rclone glob metacharacters so the path matches literally."""
    return re.sub(r"([\\*?\[\]{}])", r"\\\1", path)


def utc_now() -> datetime:
    return datetime.now(UTC)


class TaskExecution:
    """In-memory tracking object for a discrete task attempt execution."""

    def __init__(self, payload: TaskDispatchPayload) -> None:
        self.payload = payload
        self.attempt_id = payload.attempt_id
        self.task_id = payload.task_id
        self.run_id = payload.run_id
        self.kind = payload.kind
        self.operation = payload.operation
        self.status: TaskState = TaskState.ASSIGNED
        self.started_at: datetime | None = None
        self.completed_at: datetime | None = None
        self.exit_code: int | None = None
        self.error_code: ErrorCode | None = None
        self.error_class: ErrorClass | None = None
        self.error_message: str | None = None
        self.progress = TaskProgress()
        self.log_lines: list[TaskLogLine] = []
        self.result: DiscoverTaskResultPayload | None = None
        self.process: subprocess.Popen[str] | None = None
        self.cancel_event = threading.Event()
        self.lock = threading.Lock()

    def add_log(self, message: str, level: str = "INFO") -> None:
        with self.lock:
            seq = len(self.log_lines)
            self.log_lines.append(
                TaskLogLine(
                    seq=seq,
                    ts=utc_now(),
                    level=level,
                    message=message,
                )
            )


class TaskRunner:
    """Manages spawning, streaming, and monitoring of rclone subprocesses."""

    def __init__(self, rclone_bin: str = "rclone") -> None:
        self.rclone_bin = rclone_bin
        self.executions: dict[UUID, TaskExecution] = {}
        self.lock = threading.Lock()

    @property
    def effective_rclone_bin(self) -> str:
        if self.rclone_bin and self.rclone_bin != "rclone":
            return self.rclone_bin
        try:
            from embervault_proxy.api import get_effective_rclone_bin

            return get_effective_rclone_bin()
        except Exception:
            return self.rclone_bin or "rclone"

    def get_execution(self, attempt_id: UUID) -> TaskExecution | None:
        with self.lock:
            return self.executions.get(attempt_id)

    def list_executions(self) -> list[TaskExecution]:
        with self.lock:
            return list(self.executions.values())

    def count_running_tasks(self) -> int:
        """Count task executions currently in ASSIGNED or RUNNING state."""
        with self.lock:
            return sum(
                1
                for e in self.executions.values()
                if e.status in (TaskState.ASSIGNED, TaskState.RUNNING)
            )

    def dispatch(self, payload: TaskDispatchPayload) -> tuple[TaskDispatchResponse, int]:
        """Dispatch task attempt. Returns (response, http_status_code)."""
        with self.lock:
            existing = self.executions.get(payload.attempt_id)
            if existing is not None:
                return (
                    TaskDispatchResponse(
                        attempt_id=payload.attempt_id,
                        status="already_known",
                        message="Task attempt already registered.",
                    ),
                    200,
                )

            execution = TaskExecution(payload)
            self.executions[payload.attempt_id] = execution

        # Launch worker thread
        thread = threading.Thread(
            target=self._run_task_worker,
            args=(execution,),
            daemon=True,
            name=f"task-exec-{payload.attempt_id}",
        )
        thread.start()

        return (
            TaskDispatchResponse(
                attempt_id=payload.attempt_id,
                status="accepted",
                message="Task attempt accepted for execution.",
            ),
            202,
        )

    def cancel(self, attempt_id: UUID) -> TaskCancelResponse:
        execution = self.get_execution(attempt_id)
        if execution is None:
            return TaskCancelResponse(
                attempt_id=attempt_id,
                status="not_found",
                message=f"Attempt {attempt_id} not found.",
            )

        with execution.lock:
            if execution.status in (TaskState.SUCCEEDED, TaskState.FAILED, TaskState.CANCELLED):
                return TaskCancelResponse(
                    attempt_id=attempt_id,
                    status=execution.status.value,
                    message="Task already finished.",
                )

            execution.cancel_event.set()
            execution.status = TaskState.CANCELLED
            execution.completed_at = utc_now()
            if execution.process is not None and execution.process.poll() is None:
                with contextlib.suppress(OSError):
                    execution.process.kill()
                if execution.process.stdout:
                    with contextlib.suppress(OSError):
                        execution.process.stdout.close()

        execution.add_log("Task execution cancelled by user request.", level="WARN")
        return TaskCancelResponse(
            attempt_id=attempt_id,
            status="cancelled",
            message="Task attempt cancelled successfully.",
        )

    def _run_task_worker(self, execution: TaskExecution) -> None:
        execution.started_at = utc_now()
        execution.status = TaskState.RUNNING
        execution.add_log(
            f"Starting execution of task {execution.task_id} (kind={execution.kind.value})."
        )

        # Collect secrets for redaction
        secret_values: set[str] = set()
        for k in execution.payload.secret_fields:
            if k in execution.payload.source.config:
                v = str(execution.payload.source.config[k])
                if len(v) >= 4:
                    secret_values.add(v)
                    if is_obscured_secret_field(execution.payload.source.backend_type, str(k)):
                        obs = rclone_obscure(v, rclone_bin=self.effective_rclone_bin)
                        if len(obs) >= 4:
                            secret_values.add(obs)
            if execution.payload.destination and k in execution.payload.destination.config:
                v = str(execution.payload.destination.config[k])
                if len(v) >= 4:
                    secret_values.add(v)
                    if is_obscured_secret_field(execution.payload.destination.backend_type, str(k)):
                        obs = rclone_obscure(v, rclone_bin=self.effective_rclone_bin)
                        if len(obs) >= 4:
                            secret_values.add(obs)
            for ref_rem in getattr(execution.payload, "referenced_remotes", []):
                if k in ref_rem.config:
                    v = str(ref_rem.config[k])
                    if len(v) >= 4:
                        secret_values.add(v)
                        if is_obscured_secret_field(ref_rem.backend_type, str(k)):
                            obs = rclone_obscure(v, rclone_bin=self.effective_rclone_bin)
                            if len(obs) >= 4:
                                secret_values.add(obs)

        redactor = SecretRedactor(secret_values)

        if not shutil.which(self.effective_rclone_bin):
            # Fallback simulator when rclone binary is not on host (dev environment)
            self._simulate_execution(execution, redactor)
            return

        # Prepare rclone command and env
        env = os.environ.copy()

        # Inject referenced remotes first
        for ref_rem in getattr(execution.payload, "referenced_remotes", []):
            ref_prefix = ref_rem.alias or getattr(ref_rem, "name", "")
            if ref_prefix:
                self._inject_rclone_env(env, ref_prefix, ref_rem)

        self._inject_rclone_env(env, "SRC", execution.payload.source)
        src_path = execution.payload.source.path.strip("/")
        src_target = f"SRC:{src_path}" if src_path else "SRC:"

        cmd: list[str] = [self.effective_rclone_bin, "--config", ""]
        filter_insert_idx: int | None = None

        if execution.kind == TaskKind.DISCOVER:
            cmd.extend(["lsd", src_target, "--timeout", f"{execution.payload.timeout_s}s"])
        else:
            op_str = execution.operation.value
            cmd.append(op_str)
            cmd.append(src_target)

            if execution.payload.destination:
                self._inject_rclone_env(env, "DST", execution.payload.destination)
                dst_path = execution.payload.destination.path.strip("/")
                dst_target = f"DST:{dst_path}" if dst_path else "DST:"
                cmd.append(dst_target)

            cmd.extend(["--stats", "1s", "--stats-log-level", "INFO", "-v"])

            # Apply transfer options
            if execution.payload.options:
                opts = execution.payload.options
                max_depth = (
                    opts.get("max_depth")
                    if opts.get("max_depth") is not None
                    else opts.get("max-depth")
                )
                if max_depth is not None:
                    cmd.extend(["--max-depth", str(int(max_depth))])
                elif opts.get("recurse") is False:
                    cmd.extend(["--max-depth", "1"])

                if opts.get("transfers") is not None:
                    cmd.extend(["--transfers", str(int(opts["transfers"]))])
                if opts.get("checkers") is not None:
                    cmd.extend(["--checkers", str(int(opts["checkers"]))])
                if opts.get("check_first") or opts.get("check-first"):
                    cmd.append("--check-first")

                order_by_val = opts.get("order_by") or opts.get("order-by") or opts.get("OrderBy")
                if order_by_val:
                    cmd.extend(["--order-by", str(order_by_val).strip()])

                if opts.get("bwlimit"):
                    cmd.extend(["--bwlimit", str(opts["bwlimit"])])

                # Apply customizable additional parameters
                additional_args = (
                    opts.get("additional_args")
                    if opts.get("additional_args") is not None
                    else opts.get("additional_params")
                )
                if additional_args is None:
                    additional_args = opts.get("extra_args")

                if isinstance(additional_args, list):
                    import shlex
                    from embervault_common.rclone.validator import sanitize_rclone_parameters

                    sanitized_args = sanitize_rclone_parameters(additional_args)
                    for arg_item in sanitized_args:
                        try:
                            tokens = shlex.split(arg_item.strip())
                        except Exception:
                            tokens = [arg_item.strip()]
                        cmd.extend(tokens)

                # Note: RClone forbids combining --filter / --include / --exclude with --files-from
                if not execution.payload.files_from:
                    raw_filters = opts.get("filters") or []
                    if isinstance(raw_filters, str):
                        from embervault_common.rclone.filters import parse_filter_rules

                        filters = parse_filter_rules(raw_filters)
                    else:
                        filters = raw_filters

                    filter_insert_idx = len(cmd)
                    for f_rule in filters:
                        clean_f = str(f_rule).strip()
                        if clean_f:
                            cmd.extend(["--filter", clean_f])

        files_from_file: str | None = None
        if execution.payload.files_from:
            import tempfile

            with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as f:
                for item in execution.payload.files_from:
                    f.write(f"{item}\n")
                files_from_file = f.name
            cmd.extend(["--files-from", files_from_file])

        clean_cmd = redactor.redact(" ".join(cmd))
        injected_remotes = sorted(
            {k.split("_")[2] for k in env if k.startswith("RCLONE_CONFIG_") and k.endswith("_TYPE")}
        )
        execution.add_log(f"Injected remotes: {', '.join(injected_remotes)}", level="DEBUG")
        execution.add_log(f"Executing: {clean_cmd}", level="DEBUG")

        # Execute subprocess (retrying with extra exclusions on per-file errors)
        excluded_paths: set[tuple[str, bool]] = set()
        files_from_items = list(execution.payload.files_from or [])
        try:
            while True:
                failed_paths: list[tuple[str, bool]] = []
                self._execute_once(execution, cmd, env, redactor, failed_paths)

                if (
                    execution.status != TaskState.FAILED
                    or execution.error_code != ErrorCode.RCLONE_FATAL
                    or execution.kind == TaskKind.DISCOVER
                    or execution.cancel_event.is_set()
                    or len(excluded_paths) >= MAX_FILE_EXCLUSION_RETRIES
                ):
                    break
                new_paths = [p for p in dict.fromkeys(failed_paths) if p not in excluded_paths]
                if not new_paths:
                    break

                if files_from_file:
                    new_files = {p for p, is_dir in new_paths if not is_dir}
                    remaining = [i for i in files_from_items if i.strip("/") not in new_files]
                    if len(remaining) == len(files_from_items) or not remaining:
                        break
                    files_from_items = remaining
                    with open(files_from_file, "w", encoding="utf-8") as ff:
                        for item in files_from_items:
                            ff.write(f"{item}\n")
                elif filter_insert_idx is not None:
                    new_rules: list[str] = []
                    for p, is_dir in new_paths:
                        esc = _escape_glob(p)
                        # Trailing '/' makes rclone match directories only; no slash matches files only.
                        rule = f"- /{esc}/" if is_dir else f"- /{esc}"
                        new_rules.extend(["--filter", rule])
                    cmd[filter_insert_idx:filter_insert_idx] = new_rules
                else:
                    break

                excluded_paths.update(new_paths)
                execution.add_log(
                    "Retrying task excluding failed item(s): "
                    + ", ".join(f"{p}/" if d else p for p, d in new_paths),
                    level="WARN",
                )
                with execution.lock:
                    execution.status = TaskState.RUNNING
                    execution.exit_code = None
                    execution.error_code = None
                    execution.error_class = None
                    execution.error_message = None
                    execution.progress = TaskProgress()

            if excluded_paths and execution.status == TaskState.SUCCEEDED:
                skipped = ", ".join(f"{p}/" if d else p for p, d in sorted(excluded_paths))
                execution.error_code = ErrorCode.FILES_EXCLUDED
                execution.error_message = (
                    f"Completed with warnings: excluded after errors: {skipped}"
                )
                execution.add_log(execution.error_message, level="WARN")
        except subprocess.TimeoutExpired:
            if execution.process:
                execution.process.kill()
            execution.status = TaskState.FAILED
            execution.error_code = ErrorCode.TASK_TIMEOUT
            execution.error_class = ErrorClass.TIMEOUT
            execution.error_message = (
                f"Task exceeded hard timeout of {execution.payload.timeout_s}s"
            )
            execution.add_log("Task exceeded timeout limit.", level="ERROR")
        except Exception as exc:
            execution.status = TaskState.FAILED
            execution.error_code = ErrorCode.UNKNOWN_ERROR
            execution.error_class = ErrorClass.PERMANENT
            execution.error_message = redactor.redact(str(exc))
            execution.add_log(f"Execution error: {execution.error_message}", level="ERROR")
        finally:
            execution.completed_at = utc_now()
            if files_from_file and os.path.exists(files_from_file):
                with contextlib.suppress(OSError):
                    os.remove(files_from_file)

    def _execute_once(
        self,
        execution: TaskExecution,
        cmd: list[str],
        env: dict[str, str],
        redactor: SecretRedactor,
        failed_paths: list[tuple[str, bool]],
    ) -> None:
        """Run a single rclone attempt, collecting paths of files that reported errors."""
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            bufsize=1,
        )
        execution.process = proc

        if proc.stdout:
            for line in proc.stdout:
                if execution.cancel_event.is_set():
                    with contextlib.suppress(OSError):
                        proc.kill()
                    break
                clean_line = redactor.redact(line.strip())
                if clean_line:
                    execution.add_log(clean_line)
                    self._parse_rclone_progress(clean_line, execution)
                    err_path = _extract_error_path(clean_line)
                    if err_path:
                        failed_paths.append(err_path)

        if execution.cancel_event.is_set():
            with contextlib.suppress(OSError):
                proc.kill()
            proc.wait(timeout=5.0)
        else:
            proc.wait(timeout=execution.payload.timeout_s)
        execution.exit_code = proc.returncode

        if execution.cancel_event.is_set():
            execution.status = TaskState.CANCELLED
        elif proc.returncode == 0:
            execution.status = TaskState.SUCCEEDED
            execution.progress.percentage = 100.0
            execution.add_log("Task finished successfully (exit code 0).")
        else:
            execution.status = TaskState.FAILED
            execution.error_code = ErrorCode.RCLONE_FATAL
            execution.error_class = ErrorClass.TEMPORARY
            execution.error_message = f"Rclone exited with code {proc.returncode}"
            execution.add_log(f"Task failed with exit code {proc.returncode}.", level="ERROR")

    def _simulate_execution(self, execution: TaskExecution, redactor: SecretRedactor) -> None:
        """Simulate realistic transfer or discovery progress when running without rclone binary."""
        total_steps = 4
        for step in range(1, total_steps + 1):
            if execution.cancel_event.is_set():
                execution.status = TaskState.CANCELLED
                execution.completed_at = utc_now()
                return

            time.sleep(0.15)
            pct = round((step / total_steps) * 100, 1)
            bytes_transferred = step * 25 * 1024 * 1024
            total_bytes = 100 * 1024 * 1024

            with execution.lock:
                execution.progress.percentage = pct
                execution.progress.bytes_transferred = bytes_transferred
                execution.progress.bytes_total = total_bytes
                execution.progress.files_transferred = step
                execution.progress.files_total = 4
                execution.progress.files_percentage = pct
                execution.progress.checks_completed = 1
                execution.progress.checks_total = 1
                execution.progress.checks_percentage = 100.0
                execution.progress.speed_bytes_per_sec = 25.0 * 1024 * 1024
                execution.progress.speed_str = "25.0 MiB/s"
                execution.progress.eta_str = "0s"

            msg_checks = "Checks:                 1 / 1, 100%"
            msg_files = f"Transferred:            {step} / 4, {int(pct)}%"
            msg_bytes = redactor.redact(
                f"Transferred: {bytes_transferred // (1024 * 1024)} MiB / 100 MiB, {pct}%, 25.0 MiB/s, ETA 0s"
            )
            execution.add_log(msg_checks)
            execution.add_log(msg_files)
            execution.add_log(msg_bytes)

        if execution.kind == TaskKind.DISCOVER:
            execution.result = DiscoverTaskResultPayload(
                subfolders=["archive", "documents", "media", "projects"],
                root_files=["summary.txt"],
                total_subfolders=4,
                total_root_files=1,
                task_count_estimate=5,
                status_level=DiscoveryStatusLevel.OK,
            )

        execution.status = TaskState.SUCCEEDED
        execution.exit_code = 0
        execution.completed_at = utc_now()
        execution.add_log("Transfer completed successfully (simulated).")

    def _inject_rclone_env(
        self, env: dict[str, str], prefix: str, remote: RemoteConfigPayload
    ) -> None:
        clean_prefix = re.sub(r"[^A-Za-z0-9_]", "_", prefix.upper())
        env[f"RCLONE_CONFIG_{clean_prefix}_TYPE"] = remote.backend_type
        for k, v in remote.config.items():
            clean_k = re.sub(r"[^A-Za-z0-9_]", "_", str(k).upper())
            val_str = str(v)
            if is_obscured_secret_field(remote.backend_type, str(k)):
                val_str = rclone_obscure(val_str, rclone_bin=self.effective_rclone_bin)
            env[f"RCLONE_CONFIG_{clean_prefix}_{clean_k}"] = val_str

    def _parse_rclone_progress(self, line: str, execution: TaskExecution) -> None:
        """Parse rclone standard progress output lines to update live metrics."""
        # 1. Checks: 1 / 1, 100%
        m_checks = re.search(r"Checks:\s*(\d+)\s*/\s*(\d+)(?:,\s*([\d.]+)%)?", line)
        if m_checks:
            try:
                c_done = int(m_checks.group(1))
                c_tot = int(m_checks.group(2))
                c_pct = (
                    float(m_checks.group(3))
                    if m_checks.group(3)
                    else (round((c_done / c_tot) * 100, 1) if c_tot > 0 else 0.0)
                )
                with execution.lock:
                    execution.progress.checks_completed = c_done
                    execution.progress.checks_total = c_tot
                    execution.progress.checks_percentage = c_pct
            except (ValueError, ZeroDivisionError):
                pass

        # 2. Files count: Transferred: 0 / 1, 0%
        m_files = re.search(r"Transferred:\s*(\d+)\s*/\s*(\d+)(?:,\s*([\d.]+)%)?", line)
        if m_files:
            try:
                f_done = int(m_files.group(1))
                f_tot = int(m_files.group(2))
                f_pct = (
                    float(m_files.group(3))
                    if m_files.group(3)
                    else (round((f_done / f_tot) * 100, 1) if f_tot > 0 else 0.0)
                )
                with execution.lock:
                    execution.progress.files_transferred = f_done
                    execution.progress.files_total = f_tot
                    execution.progress.files_percentage = f_pct
            except (ValueError, ZeroDivisionError):
                pass

        # 3. Transferred bytes: Transferred: 45.234 MiB / 100 MiB, 45%, 15.2 MiB/s, ETA 3s
        m_bytes = re.search(
            r"Transferred:\s+([\d.]+)\s*([KMGTP]?i?B)\s*/\s*([\d.]+)\s*([KMGTP]?i?B)", line
        )
        if m_bytes:
            cur_val, cur_unit, tot_val, tot_unit = m_bytes.groups()
            multipliers = {
                "B": 1,
                "K": 1024,
                "KB": 1024,
                "KIB": 1024,
                "M": 1048576,
                "MB": 1048576,
                "MIB": 1048576,
                "G": 1073741824,
                "GB": 1073741824,
                "GIB": 1073741824,
            }
            try:
                b_trans = int(float(cur_val) * multipliers.get(cur_unit.upper(), 1))
                b_tot = int(float(tot_val) * multipliers.get(tot_unit.upper(), 1))
                with execution.lock:
                    execution.progress.bytes_transferred = b_trans
                    execution.progress.bytes_total = b_tot
                    if b_tot > 0:
                        execution.progress.percentage = round((b_trans / b_tot) * 100, 1)
            except (ValueError, ZeroDivisionError):
                pass

        # 4. Speed & ETA: Transferred: 45.234 MiB / 100 MiB, 45%, 15.2 MiB/s, ETA 3s
        m_speed = re.search(r",\s*([\d.]+)\s*([KMGTP]?i?B/s)", line, re.IGNORECASE)
        if m_speed:
            s_val, s_unit = m_speed.groups()
            speed_multipliers = {
                "B/S": 1.0,
                "KB/S": 1024.0,
                "KIB/S": 1024.0,
                "MB/S": 1048576.0,
                "MIB/S": 1048576.0,
                "GB/S": 1073741824.0,
                "GIB/S": 1073741824.0,
                "TB/S": 1099511627776.0,
                "TIB/S": 1099511627776.0,
            }
            try:
                raw_speed = float(s_val) * speed_multipliers.get(s_unit.upper(), 1.0)
                with execution.lock:
                    execution.progress.speed_bytes_per_sec = raw_speed
                    execution.progress.speed_str = f"{s_val} {s_unit}"
            except ValueError:
                pass

        m_eta = re.search(r"\bETA\s+([^\s,]+)", line)
        if m_eta:
            eta_val = m_eta.group(1).strip()
            with execution.lock:
                execution.progress.eta_str = eta_val


# Global singleton instance for proxy app
GLOBAL_RUNNER: TaskRunner | None = None


def get_task_runner() -> TaskRunner:
    global GLOBAL_RUNNER
    if GLOBAL_RUNNER is None:
        GLOBAL_RUNNER = TaskRunner()
    return GLOBAL_RUNNER


def set_task_runner(runner: TaskRunner) -> None:
    global GLOBAL_RUNNER
    GLOBAL_RUNNER = runner
