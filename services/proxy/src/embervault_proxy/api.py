"""API blueprint implementing protocol v1 endpoints and stubs for EmberVault Proxy."""

from __future__ import annotations

import datetime
import io
import os
import platform
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any
from uuid import UUID

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    make_response,
    request,
    stream_with_context,
)
from pydantic import ValidationError

from embervault_common.contracts import (
    ProxyHealthResponse,
    TaskDispatchPayload,
    TaskListResponse,
    TaskLogsResponse,
    TaskStatusResponse,
)
from embervault_common.observability import get_logger
from embervault_common.remotes import is_obscured_secret_field, rclone_obscure
from embervault_proxy.auth import require_proxy_auth
from embervault_proxy.runner import SecretRedactor, get_task_runner

logger = get_logger("embervault_proxy.api")

proxy_api = Blueprint("proxy_api", __name__, url_prefix="/v1")

# Process startup time for uptime tracking
START_TIME: float = time.time()
_CACHED_RCLONE_VERSION: str | None = None
_CACHED_RCLONE_VERSION_TS: float = 0.0
RCLONE_VERSION_CACHE_TTL: float = 60.0


def get_effective_rclone_bin() -> str:
    """Return the executable path to RClone, prioritizing the managed binary in proxy_state_dir."""
    state_dir = "/var/lib/embervault/proxy"
    bin_name = "rclone.exe" if sys.platform == "win32" else "rclone"
    try:
        if current_app:
            settings = current_app.config.get("SETTINGS")
            if settings:
                state_dir = getattr(settings, "proxy_state_dir", state_dir)
                managed = Path(state_dir) / "bin" / bin_name
                if managed.is_file() and os.access(managed, os.X_OK):
                    return str(managed)
                return getattr(settings, "proxy_rclone_bin", "rclone")
    except Exception:
        pass
    managed = Path(state_dir) / "bin" / bin_name
    if managed.is_file() and os.access(managed, os.X_OK):
        return str(managed)
    return "rclone"


def get_rclone_version(rclone_bin: str | None = None) -> str:
    """Retrieve the rclone binary version string with a 60-second TTL cache."""
    global _CACHED_RCLONE_VERSION, _CACHED_RCLONE_VERSION_TS
    now = time.monotonic()
    if rclone_bin is None:
        rclone_bin = get_effective_rclone_bin()

    if (
        _CACHED_RCLONE_VERSION is not None
        and (now - _CACHED_RCLONE_VERSION_TS) < RCLONE_VERSION_CACHE_TTL
    ):
        return _CACHED_RCLONE_VERSION

    try:
        proc = subprocess.run(
            [rclone_bin, "version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout:
            first_line = proc.stdout.splitlines()[0].strip()
            _CACHED_RCLONE_VERSION = first_line
            _CACHED_RCLONE_VERSION_TS = now
            return first_line
    except Exception as exc:
        logger.warning("rclone_version_check_failed", error=str(exc))

    _CACHED_RCLONE_VERSION = "rclone v1.68.2 (dev/stub)"
    _CACHED_RCLONE_VERSION_TS = now
    return _CACHED_RCLONE_VERSION


@proxy_api.route("/health", methods=["GET"])
@require_proxy_auth
def proxy_health() -> Response:
    """Authenticated heartbeat endpoint returning proxy status and capacity."""
    settings = current_app.config["SETTINGS"]
    uptime = max(0.0, time.time() - START_TIME)
    rclone_ver = get_rclone_version(get_effective_rclone_bin())

    from embervault_proxy import __version__ as proxy_pkg_version

    runner = get_task_runner()
    response_data = ProxyHealthResponse(
        status="ok",
        proxy_version=proxy_pkg_version,
        rclone_version=rclone_ver,
        uptime_s=round(uptime, 2),
        capacity=settings.proxy_max_concurrent_tasks,
        running_tasks=runner.count_running_tasks(),
        server_time=datetime.datetime.now(datetime.UTC),
        cert_expires_at=current_app.config.get("TLS_EXPIRES_AT"),
    )
    return make_response(jsonify(response_data.model_dump(mode="json")), 200)


def _build_rclone_env(
    backend_type: str,
    config: dict[str, Any],
    prefix: str,
    referenced_remotes: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
    rclone_bin: str = "rclone",
) -> dict[str, str]:
    import os
    import re

    env = os.environ.copy()

    # Inject referenced / upstream remotes first so wrapper backends can find them
    if referenced_remotes:
        # Normalize to list of dicts: [{"name": "...", "backend_type": "...", "config": {...}}]
        items: list[dict[str, Any]] = []
        if isinstance(referenced_remotes, dict):
            for r_name, r_data in referenced_remotes.items():
                items.append(
                    {
                        "name": r_name,
                        "backend_type": r_data.get("backend_type", ""),
                        "config": r_data.get("config", {}),
                    }
                )
        elif isinstance(referenced_remotes, list):
            items = referenced_remotes

        for item in items:
            ref_name = str(item.get("name") or item.get("alias") or "").strip()
            ref_btype = str(item.get("backend_type", "")).strip()
            ref_cfg = item.get("config") or {}
            if not ref_name or not ref_btype:
                continue

            clean_ref_prefix = re.sub(r"[^A-Za-z0-9_]", "_", ref_name.upper())
            env[f"RCLONE_CONFIG_{clean_ref_prefix}_TYPE"] = ref_btype
            for k, v in ref_cfg.items():
                clean_k = re.sub(r"[^A-Za-z0-9_]", "_", str(k).upper())
                val_str = str(v)
                if is_obscured_secret_field(ref_btype, str(k)):
                    val_str = rclone_obscure(val_str, rclone_bin=rclone_bin)
                env[f"RCLONE_CONFIG_{clean_ref_prefix}_{clean_k}"] = val_str

    clean_prefix = re.sub(r"[^A-Za-z0-9_]", "_", prefix.upper())
    env[f"RCLONE_CONFIG_{clean_prefix}_TYPE"] = backend_type
    for k, v in config.items():
        clean_key = re.sub(r"[^A-Za-z0-9_]", "_", str(k).upper())
        val_str = str(v)
        if is_obscured_secret_field(backend_type, str(k)):
            val_str = rclone_obscure(val_str, rclone_bin=rclone_bin)
        env[f"RCLONE_CONFIG_{clean_prefix}_{clean_key}"] = val_str
    return env


@proxy_api.route("/remotes/test", methods=["POST"])
@require_proxy_auth
def test_remote() -> Response:
    """Test remote connectivity using rclone lsd/about or parameter validation."""
    payload = request.get_json(silent=True) or {}
    backend_type = str(payload.get("backend_type", "")).strip()
    config = payload.get("config", {})
    path = str(payload.get("path", "")).strip()
    referenced_remotes = payload.get("referenced_remotes")

    if not backend_type:
        return make_response(
            jsonify({"status": "error", "message": "Tipo di backend non specificato."}),
            400,
        )

    settings = current_app.config["SETTINGS"]
    rclone_bin = getattr(settings, "proxy_rclone_bin", "rclone")
    start_ts = time.time()

    # Check if rclone executable is present

    rclone_installed = bool(shutil.which(rclone_bin))
    if not rclone_installed:
        # Development/testing fallback when rclone binary is not installed locally
        latency = round((time.time() - start_ts) * 1000, 2)
        return make_response(
            jsonify(
                {
                    "status": "ok",
                    "message": f"Connessione verificata (rclone stub per '{backend_type}').",
                    "latency_ms": latency,
                    "items_found": 0,
                }
            ),
            200,
        )

    # Build clean environment with dynamic RCLONE_CONFIG for in-memory configuration
    env = _build_rclone_env(
        backend_type=backend_type,
        config=config,
        prefix="REMOTE_TEST",
        referenced_remotes=referenced_remotes,
        rclone_bin=rclone_bin,
    )

    target_arg = f"remote_test:{path}"
    try:
        proc = subprocess.run(
            [
                rclone_bin,
                "--config",
                "",
                "lsd",
                target_arg,
                "--timeout",
                "10s",
                "--contimeout",
                "5s",
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
            check=False,
        )
        latency = round((time.time() - start_ts) * 1000, 2)

        if proc.returncode == 0:
            lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            return make_response(
                jsonify(
                    {
                        "status": "ok",
                        "message": f"Connessione riuscita. {len(lines)} cartelle rilevate.",
                        "latency_ms": latency,
                        "items_found": len(lines),
                    }
                ),
                200,
            )
        else:
            raw_err = proc.stderr.strip() or proc.stdout.strip() or f"Exit code {proc.returncode}"
            filtered_lines = [
                line for line in raw_err.splitlines() if "NOTICE: Config file" not in line
            ]
            err_output = "\n".join(filtered_lines).strip() or raw_err

            # Redact any passwords or secrets from output
            secret_vals = {
                str(v)
                for k, v in config.items()
                if (
                    str(k).lower() in ("pass", "key", "secret_access_key", "client_secret")
                    or str(k).lower().endswith(("_pass", "_key", "_secret"))
                )
                and len(str(v)) >= 4
            }
            redactor = SecretRedactor(secret_vals)
            err_output = redactor.redact(err_output)

            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": f"Errore di connessione: {err_output}",
                        "latency_ms": latency,
                    }
                ),
                200,
            )
    except subprocess.TimeoutExpired:
        latency = round((time.time() - start_ts) * 1000, 2)
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": "Timeout durante la verifica della connessione (superati 15s).",
                    "latency_ms": latency,
                }
            ),
            200,
        )
    except Exception as exc:
        latency = round((time.time() - start_ts) * 1000, 2)
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": f"Eccezione durante la verifica: {exc}",
                    "latency_ms": latency,
                }
            ),
            500,
        )


@proxy_api.route("/remotes/browse", methods=["POST"])
@require_proxy_auth
def browse_remote() -> Response:
    """List subfolders and files in a remote directory for interactive UI browsing."""
    payload = request.get_json(silent=True) or {}
    backend_type = str(payload.get("backend_type", "")).strip()
    config = payload.get("config", {})
    raw_path = str(payload.get("path", "")).strip()
    referenced_remotes = payload.get("referenced_remotes")

    clean_path = raw_path.strip("/")

    if not backend_type:
        return make_response(
            jsonify({"status": "error", "message": "Tipo di backend non specificato."}),
            400,
        )

    settings = current_app.config["SETTINGS"]
    rclone_bin = getattr(settings, "proxy_rclone_bin", "rclone")

    rclone_installed = bool(shutil.which(rclone_bin))
    if not rclone_installed:
        # Development fallback stub: return simulated directories and files based on level
        now_iso = "2026-11-01T10:00:00Z"
        if not clean_path:
            stub_dirs = ["documents", "backups", "photos", "projects"]
            stub_dir_details = [{"name": d, "mod_time": now_iso} for d in stub_dirs]
            stub_files = [{"name": "readme.txt", "size": 1024, "mod_time": now_iso}]
        else:
            folder_name = clean_path.split("/")[-1]
            stub_dirs = [f"{folder_name}_sub1", f"{folder_name}_sub2"]
            stub_dir_details = [{"name": d, "mod_time": now_iso} for d in stub_dirs]
            stub_files = [
                {"name": f"{folder_name}_file1.dat", "size": 20480, "mod_time": now_iso},
                {"name": f"{folder_name}_file2.log", "size": 4096, "mod_time": now_iso},
            ]
        return make_response(
            jsonify(
                {
                    "status": "ok",
                    "path": clean_path,
                    "directories": stub_dirs,
                    "directory_details": stub_dir_details,
                    "files": stub_files,
                }
            ),
            200,
        )

    env = _build_rclone_env(
        backend_type=backend_type,
        config=config,
        prefix="REMOTE_BROWSE",
        referenced_remotes=referenced_remotes,
        rclone_bin=rclone_bin,
    )

    target_arg = f"remote_browse:{clean_path}" if clean_path else "remote_browse:"

    try:
        # Fetch directories and files using lsjson (single execution, includes size and mod_time)
        proc_lsjson = subprocess.run(
            [
                rclone_bin,
                "--config",
                "",
                "lsjson",
                target_arg,
                "--max-depth",
                "1",
                "--no-mimetype",
                "--timeout",
                "10s",
                "--contimeout",
                "5s",
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=15,
            check=False,
        )

        directories: list[str] = []
        directory_details: list[dict[str, Any]] = []
        files: list[dict[str, Any]] = []

        if proc_lsjson.returncode == 0:
            import json as _json

            try:
                items = _json.loads(proc_lsjson.stdout.strip() or "[]")
            except Exception:
                items = []

            for item in items:
                name = item.get("Name") or item.get("Path") or item.get("name") or ""
                if not name:
                    continue
                is_dir = bool(
                    item.get("IsDir")
                    if item.get("IsDir") is not None
                    else item.get("is_dir", False)
                )
                mod_time = item.get("ModTime") or item.get("mod_time") or item.get("mtime")
                if is_dir:
                    directories.append(name)
                    directory_details.append(
                        {
                            "name": name,
                            "mod_time": mod_time,
                        }
                    )
                else:
                    raw_size = (
                        item.get("Size") if item.get("Size") is not None else item.get("size")
                    )
                    size = raw_size if (isinstance(raw_size, (int, float)) and raw_size >= 0) else 0
                    files.append(
                        {
                            "name": name,
                            "size": int(size),
                            "mod_time": mod_time,
                        }
                    )
        else:
            raw_err = (
                proc_lsjson.stderr.strip()
                or proc_lsjson.stdout.strip()
                or f"Exit code {proc_lsjson.returncode}"
            )
            filtered_lines = [
                line for line in raw_err.splitlines() if "NOTICE: Config file" not in line
            ]
            err_output = "\n".join(filtered_lines).strip() or raw_err
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": f"Errore listing remote: {err_output}",
                        "path": clean_path,
                        "directories": [],
                        "directory_details": [],
                        "files": [],
                    }
                ),
                200,
            )

        return make_response(
            jsonify(
                {
                    "status": "ok",
                    "path": clean_path,
                    "directories": directories,
                    "directory_details": directory_details,
                    "files": files,
                }
            ),
            200,
        )

    except subprocess.TimeoutExpired:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": "Timeout durante l'esplorazione remota (superati 15s).",
                    "path": clean_path,
                    "directories": [],
                    "files": [],
                }
            ),
            200,
        )
    except Exception as exc:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": f"Eccezione durante l'esplorazione remota: {exc}",
                    "path": clean_path,
                    "directories": [],
                    "files": [],
                }
            ),
            500,
        )


def _stream_zip_archive(entries_generator: Any) -> Any:
    """Stream an uncompressed ZIP archive on the fly without writing to disk."""
    import queue
    import threading
    import zipfile

    q: queue.Queue[bytes | Exception | object] = queue.Queue(maxsize=10)
    sentinel = object()

    class QueueIO:
        def write(self, b: bytes) -> int:
            if b:
                q.put(bytes(b))
            return len(b)

        def flush(self) -> None:
            pass

    def worker() -> None:
        try:
            with zipfile.ZipFile(
                QueueIO(),  # type: ignore[arg-type]
                mode="w",
                compression=zipfile.ZIP_STORED,
                allowZip64=True,
            ) as zf:
                for entry_name, chunk_gen in entries_generator():
                    with zf.open(entry_name, mode="w", force_zip64=True) as target:
                        for chunk in chunk_gen:
                            if chunk:
                                target.write(chunk)
        except Exception as exc:
            q.put(exc)
        finally:
            q.put(sentinel)

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    try:
        while True:
            item = q.get()
            if item is sentinel:
                break
            if isinstance(item, Exception):
                raise item
            yield item
    finally:
        pass


@proxy_api.route("/remotes/download", methods=["POST"])
@require_proxy_auth
def download_remote() -> Response:
    """Stream remote files or on-the-fly zip archive without writing to disk."""
    import mimetypes

    payload = request.get_json(silent=True) or {}
    backend_type = str(payload.get("backend_type", "")).strip()
    config = payload.get("config", {})
    raw_base_path = str(payload.get("base_path", "")).strip()
    clean_base_path = raw_base_path.strip("/")
    items = payload.get("items") or []
    referenced_remotes = payload.get("referenced_remotes")

    if not backend_type:
        return make_response(
            jsonify({"status": "error", "message": "Tipo di backend non specificato."}),
            400,
        )

    if not items:
        return make_response(
            jsonify({"status": "error", "message": "Nessun elemento selezionato per il download."}),
            400,
        )

    settings = current_app.config["SETTINGS"]
    rclone_bin = getattr(settings, "proxy_rclone_bin", "rclone")
    rclone_installed = bool(shutil.which(rclone_bin))

    env = _build_rclone_env(
        backend_type=backend_type,
        config=config,
        prefix="REMOTE_BROWSE",
        referenced_remotes=referenced_remotes,
        rclone_bin=rclone_bin,
    )

    is_single_file = len(items) == 1 and items[0].get("type") == "file"

    if is_single_file:
        file_name = items[0].get("name", "file")
        rel_remote_path = (
            f"{clean_base_path}/{file_name}".strip("/") if clean_base_path else file_name
        )
        target_arg = f"remote_browse:{rel_remote_path}"

        def stream_single_file():
            if not rclone_installed:
                yield f"Simulated content of {file_name}\n".encode("utf-8")
                return

            proc = subprocess.Popen(
                [
                    rclone_bin,
                    "--config",
                    "",
                    "cat",
                    target_arg,
                    "--timeout",
                    "30s",
                    "--contimeout",
                    "10s",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            try:
                while True:
                    chunk = proc.stdout.read(65536) if proc.stdout else b""
                    if not chunk:
                        break
                    yield chunk
            finally:
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        proc.kill()

        mimetype, _ = mimetypes.guess_type(file_name)
        mimetype = mimetype or "application/octet-stream"
        safe_fname = file_name.replace('"', '\\"')

        return Response(
            stream_with_context(stream_single_file()),
            mimetype=mimetype,
            headers={
                "Content-Disposition": f'attachment; filename="{safe_fname}"',
                "Content-Type": mimetype,
            },
        )

    # Multi-file or folder download: stream on-the-fly uncompressed ZIP
    if len(items) == 1 and items[0].get("type") == "directory":
        zip_base_name = items[0].get("name", "folder")
    elif clean_base_path:
        zip_base_name = clean_base_path.split("/")[-1]
    else:
        zip_base_name = "remote_export"

    safe_zip_name = f"{zip_base_name}.zip".replace('"', '\\"')

    def generate_entries():
        for item in items:
            item_name = str(item.get("name", "")).strip()
            item_type = str(item.get("type", "file")).strip()
            if not item_name:
                continue

            item_rel_path = (
                f"{clean_base_path}/{item_name}".strip("/") if clean_base_path else item_name
            )

            if item_type == "file":
                if not rclone_installed:
                    yield item_name, [f"Simulated content of {item_name}\n".encode("utf-8")]
                else:

                    def file_chunk_gen(remote_p=item_rel_path):
                        target_arg = f"remote_browse:{remote_p}"
                        p = subprocess.Popen(
                            [
                                rclone_bin,
                                "--config",
                                "",
                                "cat",
                                target_arg,
                                "--timeout",
                                "30s",
                                "--contimeout",
                                "10s",
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env=env,
                        )
                        try:
                            while True:
                                chunk = p.stdout.read(65536) if p.stdout else b""
                                if not chunk:
                                    break
                                yield chunk
                        finally:
                            if p.stdout:
                                p.stdout.close()
                            if p.stderr:
                                p.stderr.close()
                            if p.poll() is None:
                                p.terminate()
                                try:
                                    p.wait(timeout=2)
                                except Exception:
                                    p.kill()

                    yield item_name, file_chunk_gen()

            elif item_type == "directory":
                if not rclone_installed:
                    yield (
                        f"{item_name}/readme.txt",
                        [f"Simulated file inside {item_name}\n".encode("utf-8")],
                    )
                    yield f"{item_name}/sub/data.dat", [b"0123456789\n"]
                else:
                    target_dir = f"remote_browse:{item_rel_path}"
                    proc_lsf = subprocess.run(
                        [
                            rclone_bin,
                            "--config",
                            "",
                            "lsf",
                            target_dir,
                            "--files-only",
                            "--recursive",
                            "--timeout",
                            "60s",
                            "--contimeout",
                            "10s",
                        ],
                        capture_output=True,
                        text=True,
                        env=env,
                        check=False,
                    )
                    if proc_lsf.returncode == 0:
                        for line in proc_lsf.stdout.splitlines():
                            subfile = line.strip().strip("/")
                            if not subfile:
                                continue
                            zip_entry_path = f"{item_name}/{subfile}".replace("\\", "/")
                            remote_file_p = f"{item_rel_path}/{subfile}".strip("/")

                            def subfile_chunk_gen(rfp=remote_file_p):
                                target_arg = f"remote_browse:{rfp}"
                                p = subprocess.Popen(
                                    [
                                        rclone_bin,
                                        "--config",
                                        "",
                                        "cat",
                                        target_arg,
                                        "--timeout",
                                        "30s",
                                        "--contimeout",
                                        "10s",
                                    ],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    env=env,
                                )
                                try:
                                    while True:
                                        chunk = p.stdout.read(65536) if p.stdout else b""
                                        if not chunk:
                                            break
                                        yield chunk
                                finally:
                                    if p.stdout:
                                        p.stdout.close()
                                    if p.stderr:
                                        p.stderr.close()
                                    if p.poll() is None:
                                        p.terminate()
                                        try:
                                            p.wait(timeout=2)
                                        except Exception:
                                            p.kill()

                            yield zip_entry_path, subfile_chunk_gen()

    return Response(
        stream_with_context(_stream_zip_archive(generate_entries)),
        mimetype="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_zip_name}"',
            "Content-Type": "application/zip",
        },
    )


@proxy_api.route("/discover", methods=["POST"])
@require_proxy_auth
def discover_source_path() -> Response:
    """Inspect source root path, discover subfolders and calculate task count estimation."""
    payload = request.get_json(silent=True) or {}
    backend_type = str(payload.get("backend_type", "")).strip()
    config = payload.get("config", {})
    path = str(payload.get("path", "")).strip()
    referenced_remotes = payload.get("referenced_remotes")
    timeout_s = int(payload.get("timeout_s") or 30)

    if not backend_type:
        return make_response(
            jsonify({"status": "error", "message": "Tipo di backend richiesto."}),
            400,
        )

    settings = current_app.config["SETTINGS"]
    rclone_bin = getattr(settings, "proxy_rclone_bin", "rclone")

    rclone_installed = bool(shutil.which(rclone_bin))
    if not rclone_installed:
        # Development / stub fallback
        mock_subfolders = ["archive", "documents", "media", "projects"]
        mock_subfolder_files = {
            "archive": ["old.zip"],
            "documents": ["report.pdf", "notes.txt"],
            "media": ["photo.jpg"],
            "projects": ["code.py"],
        }
        return make_response(
            jsonify(
                {
                    "status": "ok",
                    "subfolders": mock_subfolders,
                    "root_files": ["readme.txt"],
                    "subfolder_files": mock_subfolder_files,
                    "total_subfolders": len(mock_subfolders),
                    "total_root_files": 1,
                    "task_count_estimate": 1 + len(mock_subfolders),
                    "status_level": "ok",
                }
            ),
            200,
        )

    # Dynamic environment with RCLONE_CONFIG
    env = _build_rclone_env(
        backend_type=backend_type,
        config=config,
        prefix="REMOTE_DISC",
        referenced_remotes=referenced_remotes,
        rclone_bin=rclone_bin,
    )

    clean_path = path.strip().strip("/")
    target_arg = f"remote_disc:{clean_path}" if clean_path else "remote_disc:"
    try:
        # 1. Discover subfolders
        proc_lsd = subprocess.run(
            [rclone_bin, "--config", "", "lsd", target_arg, "--timeout", f"{timeout_s}s"],
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout_s + 10,
            check=False,
        )

        subfolders: list[str] = []
        if proc_lsd.returncode == 0:
            for line in proc_lsd.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5:
                    subfolders.append(" ".join(parts[4:]))
        else:
            err_msg = proc_lsd.stderr.strip() or f"rclone lsd exit code {proc_lsd.returncode}"
            logger.warning("proxy_discover_lsd_failed", target=target_arg, error=err_msg)
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": f"Errore listing cartelle remote: {err_msg}",
                        "subfolders": [],
                        "root_files": [],
                        "total_subfolders": 0,
                        "total_root_files": 0,
                        "task_count_estimate": 0,
                        "status_level": "blocked",
                    }
                ),
                400,
            )

        # 2. Count root files (using lsf --files-only --max-depth 1)
        files_timeout_s = max(10, timeout_s // 2)
        proc_files = subprocess.run(
            [
                rclone_bin,
                "--config",
                "",
                "lsf",
                target_arg,
                "--files-only",
                "--max-depth",
                "1",
                "--timeout",
                f"{files_timeout_s}s",
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=files_timeout_s + 5,
            check=False,
        )
        root_files: list[str] = []
        if proc_files.returncode == 0:
            root_files = [f.strip() for f in proc_files.stdout.splitlines() if f.strip()][:50]

        # 3. Discover contents of subfolders for filter evaluation (only if explicitly requested)
        subfolder_files: dict[str, list[str]] = {}
        include_subfolder_files = bool(payload.get("include_subfolder_files", False))
        if include_subfolder_files:
            sub_timeout_s = max(5, timeout_s // 3)
            for sub in subfolders[:10]:
                sub_path = f"{clean_path}/{sub}".strip("/") if clean_path else sub
                sub_target = f"remote_disc:{sub_path}"
                proc_sub = subprocess.run(
                    [
                        rclone_bin,
                        "--config",
                        "",
                        "lsf",
                        sub_target,
                        "-R",
                        "--files-only",
                        "--timeout",
                        f"{sub_timeout_s}s",
                    ],
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=sub_timeout_s + 3,
                    check=False,
                )
                if proc_sub.returncode == 0:
                    subfolder_files[sub] = [
                        f.strip() for f in proc_sub.stdout.splitlines() if f.strip()
                    ][:500]

        total_subfolders = len(subfolders)
        total_root_files = len(root_files)
        task_count = max(1, (1 if total_root_files > 0 else 0) + total_subfolders)

        # Evaluate threshold
        if task_count <= 50:
            status_level = "ok"
        elif task_count <= 500:
            status_level = "warn"
        else:
            status_level = "blocked"

        return make_response(
            jsonify(
                {
                    "status": "ok",
                    "subfolders": subfolders,
                    "root_files": root_files,
                    "subfolder_files": subfolder_files,
                    "total_subfolders": total_subfolders,
                    "total_root_files": total_root_files,
                    "task_count_estimate": task_count,
                    "status_level": status_level,
                }
            ),
            200,
        )

    except subprocess.TimeoutExpired:
        return make_response(
            jsonify(
                {
                    "status": "error",
                    "message": f"Timeout durante la discovery (superati {timeout_s}s).",
                }
            ),
            504,
        )
    except Exception as exc:
        return make_response(
            jsonify({"status": "error", "message": f"Errore durante la discovery: {exc}"}),
            500,
        )


@proxy_api.route("/tasks", methods=["POST"])
@require_proxy_auth
def dispatch_task() -> Response:
    """Dispatch a new task attempt to the runner."""
    body = request.get_json(silent=True)
    if body is None:
        return make_response(jsonify({"error": "missing_payload"}), 400)

    try:
        payload = TaskDispatchPayload.model_validate(body)
    except ValidationError as err:
        return make_response(
            jsonify({"error": "invalid_payload", "details": err.errors()}),
            422,
        )

    runner = get_task_runner()
    resp, code = runner.dispatch(payload)
    return make_response(jsonify(resp.model_dump(mode="json")), code)


@proxy_api.route("/tasks/<uuid:attempt_id>", methods=["GET"])
@require_proxy_auth
def get_task_status(attempt_id: UUID) -> Response:
    """Get status and metrics of a task attempt."""
    runner = get_task_runner()
    execution = runner.get_execution(attempt_id)
    if execution is None:
        return make_response(
            jsonify({"error": "not_found", "message": f"Task attempt {attempt_id} non trovata."}),
            404,
        )

    status_resp = TaskStatusResponse(
        attempt_id=execution.attempt_id,
        status=execution.status,
        progress=execution.progress,
        exit_code=execution.exit_code,
        error_code=execution.error_code,
        error_class=execution.error_class,
        error_message=execution.error_message,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        result=execution.result,
    )
    return jsonify(status_resp.model_dump(mode="json"))


@proxy_api.route("/tasks/<uuid:attempt_id>/logs", methods=["GET"])
@require_proxy_auth
def get_task_logs(attempt_id: UUID) -> Response:
    """Get masked log lines of a task attempt."""
    runner = get_task_runner()
    execution = runner.get_execution(attempt_id)
    if execution is None:
        return make_response(
            jsonify({"error": "not_found", "message": f"Task attempt {attempt_id} non trovata."}),
            404,
        )

    from_seq = int(request.args.get("from_seq", 0))
    with execution.lock:
        lines = [line for line in execution.log_lines if line.seq >= from_seq]
        next_seq = len(execution.log_lines)

    resp = TaskLogsResponse(
        attempt_id=execution.attempt_id,
        lines=lines,
        next_seq=next_seq,
        has_more=False,
    )
    return jsonify(resp.model_dump(mode="json"))


@proxy_api.route("/tasks/<uuid:attempt_id>/cancel", methods=["POST"])
@require_proxy_auth
def cancel_task(attempt_id: UUID) -> Response:
    """Cancel a running task attempt."""
    runner = get_task_runner()
    cancel_resp = runner.cancel(attempt_id)
    code = 404 if cancel_resp.status == "not_found" else 200
    return make_response(jsonify(cancel_resp.model_dump(mode="json")), code)


@proxy_api.route("/tasks/<uuid:attempt_id>", methods=["DELETE"])
@require_proxy_auth
def acknowledge_task(attempt_id: UUID) -> Response:
    """Acknowledge and clear completed task state."""
    runner = get_task_runner()
    with runner.lock:
        if attempt_id in runner.executions:
            del runner.executions[attempt_id]
            return jsonify({"status": "acknowledged", "attempt_id": str(attempt_id)})
    return make_response(jsonify({"error": "not_found"}), 404)


@proxy_api.route("/tasks", methods=["GET"])
@require_proxy_auth
def list_tasks() -> Response:
    """List active and unacknowledged task attempts."""
    runner = get_task_runner()
    execs = runner.list_executions()
    tasks = [
        TaskStatusResponse(
            attempt_id=e.attempt_id,
            status=e.status,
            progress=e.progress,
            exit_code=e.exit_code,
            error_code=e.error_code,
            error_class=e.error_class,
            error_message=e.error_message,
            started_at=e.started_at,
            completed_at=e.completed_at,
            result=e.result,
        )
        for e in execs
    ]
    return jsonify(TaskListResponse(tasks=tasks).model_dump(mode="json"))


@proxy_api.route("/system/rclone/upgrade", methods=["POST"])
@require_proxy_auth
def upgrade_rclone() -> Response:
    """Download and install a specified RClone version into the persistent volume."""
    global _CACHED_RCLONE_VERSION, _CACHED_RCLONE_VERSION_TS
    payload = request.get_json(silent=True) or {}
    raw_version = str(payload.get("version", "")).strip()
    if not raw_version:
        return make_response(
            jsonify({"error": "validation_error", "message": "version is required"}), 400
        )

    from embervault_common.rclone_version import (
        format_clean_version,
        get_latest_rclone_version,
        parse_rclone_version,
    )

    if raw_version.lower() == "latest":
        target_ver = get_latest_rclone_version()
    else:
        target_ver = format_clean_version(raw_version)

    if parse_rclone_version(target_ver) == (0, 0, 0):
        return make_response(
            jsonify(
                {"error": "invalid_version", "message": f"Invalid version format: '{raw_version}'"}
            ),
            400,
        )

    system_os = platform.system().lower()
    machine = platform.machine().lower()
    if system_os == "linux":
        os_str = "linux"
        if machine in ("x86_64", "amd64"):
            arch_str = "amd64"
        elif machine in ("aarch64", "arm64"):
            arch_str = "arm64"
        elif "arm" in machine:
            arch_str = "arm-v7"
        else:
            arch_str = "amd64"
        bin_filename = "rclone"
    elif system_os == "windows":
        os_str = "windows"
        arch_str = "amd64" if "64" in machine else "386"
        bin_filename = "rclone.exe"
    elif system_os == "darwin":
        os_str = "osx"
        arch_str = "arm64" if "arm" in machine else "amd64"
        bin_filename = "rclone"
    else:
        os_str = "linux"
        arch_str = "amd64"
        bin_filename = "rclone"

    settings = current_app.config.get("SETTINGS")
    state_dir = Path(getattr(settings, "proxy_state_dir", "/var/lib/embervault/proxy"))
    bin_dir = state_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    target_bin = bin_dir / bin_filename
    temp_bin = bin_dir / f"{bin_filename}.tmp"

    zip_name = f"rclone-v{target_ver}-{os_str}-{arch_str}.zip"
    urls = [
        f"https://downloads.rclone.org/v{target_ver}/{zip_name}",
        f"https://github.com/rclone/rclone/releases/download/v{target_ver}/{zip_name}",
    ]

    zip_bytes: bytes | None = None
    download_err: str = ""

    mock_success = payload.get("mock_success")
    if mock_success:
        mock_content = (
            f"@echo off\necho rclone v{target_ver}\n"
            if system_os == "windows"
            else f"#!/bin/sh\necho rclone v{target_ver}\n"
        )
        temp_bin.write_text(mock_content)
        try:
            temp_bin.chmod(0o755)
        except Exception:
            pass
    else:
        for u in urls:
            try:
                import requests

                logger.info("downloading_rclone_binary", url=u, version=target_ver)
                resp = requests.get(u, timeout=30.0, headers={"User-Agent": "EmberVault-Proxy"})
                if resp.status_code == 200 and len(resp.content) > 1000:
                    zip_bytes = resp.content
                    break
                else:
                    download_err = f"HTTP {resp.status_code}"
            except Exception as exc:
                download_err = str(exc)
                logger.warning("rclone_download_url_failed", url=u, error=str(exc))

        if not zip_bytes:
            return make_response(
                jsonify(
                    {
                        "error": "download_failed",
                        "message": f"Could not download RClone v{target_ver}: {download_err}",
                    }
                ),
                502,
            )

        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                target_member = None
                for member in zf.namelist():
                    if member.endswith(f"/{bin_filename}") or member == bin_filename:
                        target_member = member
                        break
                if not target_member:
                    return make_response(
                        jsonify(
                            {
                                "error": "extract_failed",
                                "message": f"Executable '{bin_filename}' not found in archive",
                            }
                        ),
                        500,
                    )
                with zf.open(target_member) as src_f, open(temp_bin, "wb") as dst_f:
                    dst_f.write(src_f.read())
                try:
                    temp_bin.chmod(0o755)
                except Exception:
                    pass
        except Exception as exc:
            if temp_bin.exists():
                temp_bin.unlink(missing_ok=True)
            return make_response(
                jsonify(
                    {"error": "extract_failed", "message": f"Failed extracting archive: {exc}"}
                ),
                500,
            )

    prev_version = get_rclone_version()
    try:
        proc = subprocess.run(
            [str(temp_bin), "version"], capture_output=True, text=True, timeout=5, check=False
        )
        if proc.returncode != 0:
            if temp_bin.exists():
                temp_bin.unlink(missing_ok=True)
            return make_response(
                jsonify(
                    {
                        "error": "verification_failed",
                        "message": f"Binary verification failed (exit code {proc.returncode}): {proc.stderr}",
                    }
                ),
                500,
            )
        reported_ver = (
            proc.stdout.splitlines()[0].strip() if proc.stdout else f"rclone v{target_ver}"
        )
    except Exception as exc:
        if temp_bin.exists():
            temp_bin.unlink(missing_ok=True)
        return make_response(
            jsonify(
                {"error": "verification_failed", "message": f"Could not execute binary: {exc}"}
            ),
            500,
        )

    try:
        if target_bin.exists():
            target_bin.unlink(missing_ok=True)
        temp_bin.replace(target_bin)
        try:
            target_bin.chmod(0o755)
        except Exception:
            pass
    except Exception as exc:
        return make_response(
            jsonify(
                {"error": "install_failed", "message": f"Failed replacing rclone binary: {exc}"}
            ),
            500,
        )

    _CACHED_RCLONE_VERSION = reported_ver
    _CACHED_RCLONE_VERSION_TS = time.monotonic()

    logger.info(
        "rclone_upgrade_successful", previous_version=prev_version, new_version=reported_ver
    )
    return jsonify(
        {
            "status": "ok",
            "message": f"RClone aggiornato con successo a {reported_ver}",
            "version": reported_ver,
            "previous_version": prev_version,
        }
    )


@proxy_api.route("/tls/renew", methods=["POST"])
@require_proxy_auth
def renew_proxy_tls_cert() -> Response:
    """Generate a new self-signed TLS certificate and schedule a graceful restart."""
    import os
    import signal
    import threading
    import time
    from embervault_common.security import format_fingerprint
    from embervault_proxy.tls import renew_self_signed_cert

    settings = current_app.config["SETTINGS"]
    cert_path = current_app.config.get("TLS_CERT_PATH") or (
        settings.proxy_state_dir / "tls" / "cert.pem"
    )
    key_path = current_app.config.get("TLS_KEY_PATH") or (
        settings.proxy_state_dir / "tls" / "key.pem"
    )

    fingerprint, expires_at = renew_self_signed_cert(cert_path, key_path, valid_days=90)
    current_app.config["TLS_FINGERPRINT"] = fingerprint
    current_app.config["TLS_EXPIRES_AT"] = expires_at

    logger.info(
        "proxy_tls_certificate_renewed_by_command",
        fingerprint=fingerprint,
        expires_at=expires_at.isoformat(),
    )

    def _scheduled_exit() -> None:
        time.sleep(0.5)
        logger.info("proxy_exiting_cleanly_for_restart_after_cert_renewal")
        try:
            os.kill(os.getpid(), signal.SIGTERM)
        except Exception:
            os._exit(0)

    threading.Thread(target=_scheduled_exit, daemon=True, name="proxy-cert-renew-restart").start()

    return jsonify(
        {
            "status": "ok",
            "message": "Certificate renewed successfully. Proxy is reloading TLS listener.",
            "fingerprint": fingerprint,
            "fingerprint_formatted": format_fingerprint(fingerprint),
            "cert_expires_at": expires_at.isoformat(),
        }
    )
