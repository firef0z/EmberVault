"""Internal authenticated API for communication between Web App and Orchestrator."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any
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
    CreateDiscoveryRequest,
    ProxyProbeRequest,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

from embervault_common.observability import get_logger
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.repositories.job_repository import JobRepository
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_orchestrator.proxy_client import (
    ProxyClient,
    ProxyUnauthorizedError,
    ProxyUnreachableError,
)

logger = get_logger("embervault_orchestrator.internal_api")

internal_api = Blueprint("internal_api", __name__, url_prefix="/internal/v1")
_PROXY_CLIENT: ProxyClient | None = None


def get_proxy_client() -> ProxyClient:
    """Retrieve or initialize singleton ProxyClient instance."""
    global _PROXY_CLIENT
    if _PROXY_CLIENT is None:
        _PROXY_CLIENT = ProxyClient()
    return _PROXY_CLIENT


def set_proxy_client(client: ProxyClient) -> None:
    """Set custom ProxyClient instance for testing."""
    global _PROXY_CLIENT
    _PROXY_CLIENT = client


def cancel_assignments_on_proxies(
    session: Session,
    assignments: list[Any],
    proxy_client: ProxyClient | None = None,
) -> None:
    """Send best-effort cancel requests to proxies for a list of TaskAssignment records."""
    if not assignments:
        return
    client = proxy_client or get_proxy_client()
    for assignment in assignments:
        if not assignment.proxy_id:
            continue
        p_entity = ProxyRepository.get_proxy_by_id(session, assignment.proxy_id)
        if not p_entity:
            continue
        try:
            dec_token = ProxyRepository.decrypt_token(p_entity.token_encrypted, p_entity.id)
            client.cancel_task(
                host=p_entity.host,
                port=p_entity.port,
                token=dec_token,
                expected_fingerprint=p_entity.cert_fingerprint_sha256,
                attempt_id=assignment.id,
                timeout=(3.0, 5.0),
            )
        except Exception as exc:
            logger.warning(
                "proxy_task_cancel_notification_failed",
                attempt_id=str(assignment.id),
                proxy_id=str(p_entity.id),
                error=str(exc),
            )


@internal_api.route("/proxies/probe", methods=["POST"])
def probe_proxy() -> Response:
    """Probe a remote proxy during registration: connect over TLS, read certificate and test auth."""
    body = request.get_json(silent=True)
    if body is None:
        return make_response(jsonify({"error": "Missing JSON request body"}), 400)

    try:
        probe_req = ProxyProbeRequest.model_validate(body)
    except ValidationError as err:
        return make_response(jsonify({"error": "Invalid payload", "details": err.errors()}), 422)

    from embervault_common.config import is_demo_mode
    if is_demo_mode():
        return make_response(
            jsonify(
                {
                    "host": probe_req.host,
                    "port": probe_req.port,
                    "status": "online",
                    "latency_ms": 1.5,
                    "version": "1.0.0",
                    "rclone_version": "v1.66.0",
                    "os_family": "linux",
                    "arch": "x86_64",
                    "max_concurrent_tasks": 2,
                    "active_tasks": 0,
                    "cert_fingerprint_sha256": "demo_fingerprint_proxy",
                }
            ),
            200,
        )

    client = get_proxy_client()
    try:
        response_model = client.probe(
            host=probe_req.host,
            port=probe_req.port,
            token=probe_req.token.get_secret_value(),
        )
        return make_response(jsonify(response_model.model_dump(mode="json")), 200)

    except ProxyUnauthorizedError as exc:
        logger.warning("probe_unauthorized", host=probe_req.host, port=probe_req.port)
        return make_response(
            jsonify(
                {
                    "error": "unauthorized",
                    "status": "unauthorized",
                    "message": str(exc),
                }
            ),
            401,
        )
    except ProxyUnreachableError as exc:
        logger.warning(
            "probe_unreachable", host=probe_req.host, port=probe_req.port, error=str(exc)
        )
        return make_response(
            jsonify(
                {
                    "error": "unreachable",
                    "status": "offline",
                    "message": str(exc),
                }
            ),
            502,
        )
    except Exception as exc:
        logger.error("probe_failed_unexpected", error=str(exc))
        return make_response(
            jsonify(
                {
                    "error": "probe_failed",
                    "status": "failed",
                    "message": str(exc),
                }
            ),
            500,
        )


@internal_api.route("/proxies/<uuid:proxy_id>/rclone/upgrade", methods=["POST"])
def upgrade_proxy_rclone(proxy_id: UUID) -> Response:
    """Trigger an RClone upgrade on a registered proxy via orchestrator."""
    body = request.get_json(silent=True) or {}
    version = str(body.get("version", "")).strip()
    if not version:
        return make_response(
            jsonify({"error": "validation_error", "message": "version is required"}), 400
        )

    from embervault_db.models.proxy import Proxy
    from embervault_db.repositories.proxy_repository import ProxyRepository

    session_factory = current_app.config["SESSION_FACTORY"]
    with session_factory() as session:
        proxy = session.get(Proxy, proxy_id)
        if not proxy:
            return make_response(jsonify({"error": "not_found", "message": "Proxy not found"}), 404)

        try:
            token = ProxyRepository.decrypt_token(proxy.token_encrypted, proxy.id)
        except Exception as exc:
            return make_response(jsonify({"error": "decrypt_failed", "message": str(exc)}), 500)

        host = proxy.host
        port = proxy.port
        fp = proxy.cert_fingerprint_sha256

    client = get_proxy_client()
    try:
        res = client.upgrade_rclone(
            host=host,
            port=port,
            token=token,
            expected_fingerprint=fp,
            version=version,
        )
        new_version = res.get("version")
        if new_version:
            with session_factory() as session:
                p_entity = session.get(Proxy, proxy_id)
                if p_entity:
                    p_entity.rclone_version = new_version
                    session.commit()
        return jsonify(res)
    except Exception as exc:
        logger.error("proxy_rclone_upgrade_failed", proxy_id=str(proxy_id), error=str(exc))
        return make_response(jsonify({"error": "upgrade_failed", "message": str(exc)}), 502)


@internal_api.route("/proxies/<uuid:proxy_id>/renew-cert", methods=["POST"])
def renew_proxy_cert(proxy_id: UUID) -> Response:
    """Trigger an early TLS certificate renewal on a registered proxy via orchestrator."""
    import datetime
    from embervault_db.models.proxy import Proxy
    from embervault_db.repositories.proxy_repository import ProxyRepository

    session_factory = current_app.config["SESSION_FACTORY"]
    with session_factory() as session:
        proxy = session.get(Proxy, proxy_id)
        if not proxy:
            return make_response(jsonify({"error": "not_found", "message": "Proxy not found"}), 404)

        try:
            token = ProxyRepository.decrypt_token(proxy.token_encrypted, proxy.id)
        except Exception as exc:
            return make_response(jsonify({"error": "decrypt_failed", "message": str(exc)}), 500)

        host = proxy.host
        port = proxy.port
        fp = proxy.cert_fingerprint_sha256

    client = get_proxy_client()
    try:
        res = client.renew_certificate(
            host=host,
            port=port,
            token=token,
            expected_fingerprint=fp,
        )
        new_expires_str = res.get("cert_expires_at")
        new_expires_dt = None
        if new_expires_str:
            try:
                new_expires_dt = datetime.datetime.fromisoformat(new_expires_str)
            except Exception as dt_exc:
                logger.warning("parse_new_cert_expires_failed", error=str(dt_exc))

        with session_factory() as session:
            p_entity = session.get(Proxy, proxy_id)
            if p_entity:
                from embervault_common.contracts import ErrorCode, ProxyState

                ProxyRepository.apply_probe_result(
                    session=session,
                    proxy=p_entity,
                    new_state=ProxyState.UNTRUSTED,
                    is_success=False,
                    error_code=ErrorCode.PROXY_CERT_MISMATCH,
                    reason="Certificato rinnovato anticipatamente. In attesa di conferma del nuovo fingerprint.",
                    cert_expires_at=new_expires_dt,
                )
                session.commit()

        # Send notification after commit in a fresh session
        try:
            from embervault_db.settings_store import SettingsStore
            from embervault_orchestrator.notifier import NotificationService

            settings_store = current_app.config.get("SETTINGS_STORE")
            if not settings_store:
                settings_store = SettingsStore(session_factory)
            notif_svc = NotificationService(settings_store)
            with session_factory() as notif_session:
                p_for_notif = notif_session.get(Proxy, proxy_id)
                if p_for_notif:
                    notif_svc.notify_proxy_untrusted(
                        session=notif_session,
                        proxy=p_for_notif,
                        reason="Certificato rinnovato anticipatamente. Ristabilire la fiducia confermando il nuovo fingerprint nella console web.",
                    )
        except Exception as notif_err:
            logger.warning(
                "renew_cert_notification_failed",
                proxy_id=str(proxy_id),
                error=str(notif_err),
            )

        return jsonify(res)
    except Exception as exc:
        logger.error("proxy_cert_renewal_failed", proxy_id=str(proxy_id), error=str(exc))
        return make_response(jsonify({"error": "renew_failed", "message": str(exc)}), 502)


@internal_api.route("/discoveries", methods=["POST"])
def create_discovery() -> Response:
    """Trigger preview discovery for job creation."""
    from flask import current_app

    body = request.get_json(silent=True) or {}
    try:
        req = CreateDiscoveryRequest.model_validate(body)
    except ValidationError as err:
        return make_response(jsonify({"error": "Invalid payload", "details": err.errors()}), 422)

    session_factory = current_app.config.get("SESSION_FACTORY")
    if not session_factory:
        return make_response(jsonify({"error": "Database session factory not configured"}), 500)

    from embervault_db.repositories.proxy_repository import ProxyRepository
    from embervault_db.repositories.remote_repository import RemoteRepository

    with session_factory() as session:
        remote = RemoteRepository.get_remote_by_id(session, req.source_remote_id)
        if remote is None:
            return make_response(jsonify({"error": "Remote sorgente non trovato"}), 404)

        decrypted_config = RemoteRepository.get_decrypted_config(remote)
        referenced_remotes = RemoteRepository.resolve_referenced_remotes(
            session=session,
            backend_type=remote.backend_type,
            config=decrypted_config,
        )
        settings_store = current_app.config.get("SETTINGS_STORE")

        from embervault_common.config import is_demo_mode
        if is_demo_mode(settings_store):
            subfolders = ["documents", "media", "projects", "database"]
            root_files = ["backup_manifest.json", "system_info.txt"]
            subfolder_files = {
                "documents": ["report2026.docx", "invoices.pdf"],
                "media": ["logo.png", "banner.webp"],
                "projects": ["app.py", "pyproject.toml"],
                "database": ["dump.sql", "schema.sql"],
            }
            disc = JobRepository.record_discovery(
                session=session,
                source_remote_id=req.source_remote_id,
                source_path=req.source_path,
                subfolders=subfolders,
                root_file_count=len(root_files),
                trigger="preview",
                status="succeeded",
                root_files=root_files,
                subfolder_files=subfolder_files,
                enabled_proxy_count=len(req.assigned_proxy_ids) if req.assigned_proxy_ids else 2,
            )
            session.commit()
            return jsonify(
                {
                    "status": "ok",
                    "discovery": {
                        "id": str(disc.id),
                        "source_remote_id": str(req.source_remote_id),
                        "source_path": req.source_path,
                        "folder_count": len(subfolders),
                        "root_file_count": len(root_files),
                        "task_count_estimate": len(subfolders) + (1 if root_files else 0),
                        "level": "ok",
                        "entries": {
                            "folders": subfolders,
                            "root_files": root_files,
                            "subfolder_files": subfolder_files,
                        },
                    },
                }
            )

        discovery_timeout_s = (
            int(settings_store.get_setting("discovery_timeout_s") or 30) if settings_store else 30
        )

        proxies = ProxyRepository.get_all_enabled_proxies(session)
        online_proxies = [p for p in proxies if p.status and p.status.state == "online"]
        if req.assigned_proxy_ids:
            for p in [p for p in proxies if p.id in req.assigned_proxy_ids]:
                if remote.id not in {r.id for r in p.reachable_remotes}:
                    return make_response(
                        jsonify(
                            {
                                "status": "error",
                                "message": f"Il proxy '{p.name}' attivato per questo job non può raggiungere il remote sorgente '{remote.name}'.",
                            }
                        ),
                        400,
                    )
            online_proxies = [p for p in online_proxies if p.id in req.assigned_proxy_ids]

        online_proxies = [
            p for p in online_proxies if remote.id in {r.id for r in p.reachable_remotes}
        ]

        if not online_proxies:
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": "Nessun proxy online disponibile per effettuare la discovery delle cartelle.",
                    }
                ),
                400,
            )

        # Prioritize proxies with fewer active tasks, but include all online proxies regardless of slot limits
        proxy_active_counts = ExecutionRepository.get_active_assignment_counts_by_proxies(session)
        online_proxies.sort(key=lambda p: proxy_active_counts.get(p.id, 0))

        client = get_proxy_client()
        subfolders = []
        root_files = []
        status = "failed"
        chosen_proxy_id: UUID | None = None
        last_error = "Nessun proxy online ha risposto con successo alla discovery."

        for p in online_proxies:
            dec_token = ProxyRepository.decrypt_token(p.token_encrypted, p.id)
            try:
                disc_res = client.discover(
                    host=p.host,
                    port=p.port,
                    token=dec_token,
                    expected_fingerprint=p.cert_fingerprint_sha256,
                    backend_type=remote.backend_type,
                    config=decrypted_config,
                    path=req.source_path,
                    referenced_remotes=referenced_remotes,
                    timeout_s=discovery_timeout_s,
                )
                if disc_res.get("status") == "ok":
                    subfolders = disc_res.get("subfolders", [])
                    root_files = disc_res.get("root_files", [])
                    status = "succeeded"
                    chosen_proxy_id = p.id
                    break
                elif disc_res.get("status") == "error":
                    last_error = disc_res.get("message", "Errore durante la discovery sul proxy")
                    logger.warning("proxy_discover_failed", proxy=p.name, error=last_error)
                else:
                    subfolders = disc_res.get("subfolders", [])
                    root_files = disc_res.get("root_files", [])
                    status = "succeeded"
                    chosen_proxy_id = p.id
                    break
            except Exception as exc:
                last_error = str(exc)
                logger.warning("proxy_discover_failed_exception", proxy=p.name, error=last_error)

        if not chosen_proxy_id:
            return make_response(
                jsonify({"status": "error", "message": last_error, "error": last_error}),
                400,
            )

        # Count enabled proxies that can execute this job (respecting assigned_proxy_ids if specified)
        enabled_target_proxies = [
            pr for pr in proxies if (not req.assigned_proxy_ids or pr.id in req.assigned_proxy_ids)
        ]
        enabled_proxy_count = max(1, len(enabled_target_proxies))

        disc = JobRepository.record_discovery(
            session=session,
            source_remote_id=req.source_remote_id,
            source_path=req.source_path,
            subfolders=subfolders,
            root_file_count=len(root_files),
            trigger="job_form",
            proxy_id=chosen_proxy_id,
            status=status,
            enabled_proxy_count=enabled_proxy_count,
        )
        session.commit()

        return jsonify(
            {
                "status": "ok",
                "id": str(disc.id),
                "source_remote_id": str(disc.source_remote_id),
                "source_path": disc.source_path,
                "discovery_status": disc.status,
                "subfolders": subfolders,
                "root_files": root_files,
                "total_subfolders": disc.folder_count,
                "total_root_files": disc.root_file_count,
                "folder_count": disc.folder_count,
                "root_file_count": disc.root_file_count,
                "task_count_estimate": disc.task_count_estimate,
                "status_level": disc.level,
                "level": disc.level,
                "entries": {
                    "folders": subfolders,
                    "subfolders": subfolders,
                    "root_files": root_files,
                },
                "created_at": disc.created_at.isoformat() if disc.created_at else None,
            }
        )


@internal_api.route("/discoveries/<uuid:discovery_id>", methods=["GET"])
def get_discovery(discovery_id: UUID) -> Response:
    """Fetch status and items of a discovery operation."""
    from flask import current_app

    session_factory = current_app.config.get("SESSION_FACTORY")
    if not session_factory:
        return make_response(jsonify({"error": "Database session factory not configured"}), 500)

    with session_factory() as session:
        disc = JobRepository.get_discovery_by_id(session, discovery_id)
        if disc is None:
            return make_response(jsonify({"error": "Discovery non trovata"}), 404)
        entries = disc.entries or {}
        return jsonify(
            {
                "id": str(disc.id),
                "source_remote_id": str(disc.source_remote_id),
                "source_path": disc.source_path,
                "status": disc.status,
                "subfolders": entries.get("subfolders", []),
                "total_subfolders": disc.folder_count,
                "total_root_files": disc.root_file_count,
                "task_count_estimate": disc.task_count_estimate,
                "status_level": disc.level,
                "created_at": disc.created_at.isoformat() if disc.created_at else None,
            }
        )


@internal_api.route("/remotes/test", methods=["POST"])
def test_remote() -> Response:
    """Test remote storage connection across available proxies."""
    from flask import current_app

    body = request.get_json(silent=True) or {}
    remote_id = body.get("remote_id")
    candidate_proxy_ids = body.get("candidate_proxy_ids")
    backend_type = str(body.get("backend_type", "")).strip()
    config = body.get("config", {})
    path = str(body.get("path", "")).strip()
    referenced_remotes = body.get("referenced_remotes")

    if not backend_type:
        return make_response(
            jsonify({"status": "error", "message": "Tipo di backend richiesto."}),
            400,
        )

    from embervault_common.config import is_demo_mode
    if is_demo_mode():
        return jsonify(
            {
                "status": "ok",
                "message": "Demo mode: connessione simulata con successo.",
                "entries_count": 6,
            }
        )

    # Check for DB session factory on app to find an online proxy
    session_factory = current_app.config.get("SESSION_FACTORY")
    if session_factory:
        from embervault_db.repositories.proxy_repository import ProxyRepository
        from embervault_db.repositories.remote_repository import RemoteRepository

        with session_factory() as session:
            # If referenced_remotes not supplied, attempt to resolve them from DB
            if not referenced_remotes:
                referenced_remotes = RemoteRepository.resolve_referenced_remotes(
                    session=session,
                    backend_type=backend_type,
                    config=config,
                )

            proxies = ProxyRepository.get_all_enabled_proxies(session)
            online_proxies = [p for p in proxies if p.status and p.status.state == "online"]
            if remote_id:
                try:
                    r_uuid = UUID(str(remote_id))
                    online_proxies = [
                        p for p in online_proxies if r_uuid in {r.id for r in p.reachable_remotes}
                    ]
                except Exception:
                    pass
            elif candidate_proxy_ids:
                try:
                    c_uuids = {UUID(str(cid)) for cid in candidate_proxy_ids}
                    online_proxies = [p for p in online_proxies if p.id in c_uuids]
                except Exception:
                    pass
            if (remote_id or candidate_proxy_ids) and not online_proxies:
                return jsonify(
                    {
                        "status": "error",
                        "message": "Nessun proxy online abilitato è configurato per raggiungere questo remote.",
                    }
                )
            if online_proxies:
                chosen_proxy = online_proxies[0]
                client = get_proxy_client()
                decrypted_token = ProxyRepository.decrypt_token(
                    chosen_proxy.token_encrypted, chosen_proxy.id
                )
                try:
                    res = client.test_remote(
                        host=chosen_proxy.host,
                        port=chosen_proxy.port,
                        token=decrypted_token,
                        expected_fingerprint=chosen_proxy.cert_fingerprint_sha256,
                        backend_type=backend_type,
                        config=config,
                        path=path,
                        referenced_remotes=referenced_remotes,
                    )
                    return jsonify(res)
                except Exception as exc:
                    return jsonify(
                        {
                            "status": "error",
                            "message": f"Errore durante l'esecuzione del test sul proxy '{chosen_proxy.name}': {exc}",
                        }
                    )

    # If no online proxy is available or running standalone, validate parameters
    from embervault_common.remotes.catalog import validate_and_split_remote_config

    try:
        validate_and_split_remote_config(backend_type, config)
        return jsonify(
            {
                "status": "ok",
                "message": f"Configurazione valida per '{backend_type}'. (Nessun proxy online: validazione sintattica completata)",
                "latency_ms": 1.0,
            }
        )
    except Exception as exc:
        return jsonify(
            {
                "status": "error",
                "message": f"Configurazione non valida: {exc}",
            }
        )


@internal_api.route("/remotes/browse", methods=["POST"])
def browse_remote() -> Response:
    """Browse remote directories and files via online proxy."""
    from flask import current_app

    body = request.get_json(silent=True) or {}
    remote_id = body.get("remote_id")
    candidate_proxy_ids = body.get("candidate_proxy_ids")
    backend_type = str(body.get("backend_type", "")).strip()
    config = body.get("config", {})
    path = str(body.get("path", "")).strip()
    referenced_remotes = body.get("referenced_remotes")

    if not backend_type:
        return make_response(
            jsonify({"status": "error", "message": "Tipo di backend richiesto."}),
            400,
        )

    from embervault_common.config import get_demo_browse_listing, is_demo_mode
    if is_demo_mode():
        return jsonify(get_demo_browse_listing(path))

    session_factory = current_app.config.get("SESSION_FACTORY")
    if session_factory:
        from embervault_db.repositories.proxy_repository import ProxyRepository
        from embervault_db.repositories.remote_repository import RemoteRepository

        with session_factory() as session:
            if not referenced_remotes:
                referenced_remotes = RemoteRepository.resolve_referenced_remotes(
                    session=session,
                    backend_type=backend_type,
                    config=config,
                )

            proxies = ProxyRepository.get_all_enabled_proxies(session)
            online_proxies = [p for p in proxies if p.status and p.status.state == "online"]
            if remote_id:
                try:
                    r_uuid = UUID(str(remote_id))
                    online_proxies = [
                        p for p in online_proxies if r_uuid in {r.id for r in p.reachable_remotes}
                    ]
                except Exception:
                    pass
            elif candidate_proxy_ids:
                try:
                    c_uuids = {UUID(str(cid)) for cid in candidate_proxy_ids}
                    online_proxies = [p for p in online_proxies if p.id in c_uuids]
                except Exception:
                    pass
            if not online_proxies:
                return jsonify(
                    {
                        "status": "error",
                        "message": "Nessun proxy online abilitato è configurato per raggiungere questo remote.",
                        "path": path,
                        "directories": [],
                        "files": [],
                    }
                )
            if online_proxies:
                chosen_proxy = online_proxies[0]
                client = get_proxy_client()
                decrypted_token = ProxyRepository.decrypt_token(
                    chosen_proxy.token_encrypted, chosen_proxy.id
                )
                try:
                    res = client.browse_remote(
                        host=chosen_proxy.host,
                        port=chosen_proxy.port,
                        token=decrypted_token,
                        expected_fingerprint=chosen_proxy.cert_fingerprint_sha256,
                        backend_type=backend_type,
                        config=config,
                        path=path,
                        referenced_remotes=referenced_remotes,
                    )
                    return jsonify(res)
                except Exception as exc:
                    return jsonify(
                        {
                            "status": "error",
                            "message": f"Errore durante la navigazione sul proxy '{chosen_proxy.name}': {exc}",
                            "path": path,
                            "directories": [],
                            "files": [],
                        }
                    )

    # Fallback if no proxies are online: return simulated browsing structure
    clean_p = path.strip("/")
    if not clean_p:
        dirs = ["documents", "backups", "photos", "projects"]
        directory_details = [{"name": d, "mod_time": "2026-11-01T10:00:00Z"} for d in dirs]
        files = [{"name": "readme.txt", "size": 1024, "mod_time": "2026-11-01T10:00:00Z"}]
    else:
        folder_name = clean_p.split("/")[-1]
        dirs = [f"{folder_name}_sub1", f"{folder_name}_sub2"]
        directory_details = [{"name": d, "mod_time": "2026-11-01T10:00:00Z"} for d in dirs]
        files = [
            {"name": f"{folder_name}_file1.dat", "size": 20480, "mod_time": "2026-11-01T10:00:00Z"},
            {"name": f"{folder_name}_file2.log", "size": 4096, "mod_time": "2026-11-01T10:00:00Z"},
        ]

    return jsonify(
        {
            "status": "ok",
            "path": clean_p,
            "directories": dirs,
            "directory_details": directory_details,
            "files": files,
        }
    )


@internal_api.route("/remotes/download", methods=["POST"])
def download_remote() -> Response:
    """Stream remote files or archive from a remote storage via online proxy."""
    from flask import current_app

    body = request.get_json(silent=True) or {}
    remote_id = body.get("remote_id")
    backend_type = str(body.get("backend_type", "")).strip()
    config = body.get("config", {})
    base_path = str(body.get("base_path", "")).strip()
    items = body.get("items") or []
    referenced_remotes = body.get("referenced_remotes")

    if not backend_type:
        return make_response(
            jsonify({"status": "error", "message": "Tipo di backend richiesto."}),
            400,
        )

    from embervault_common.config import is_demo_mode
    if is_demo_mode():
        import io
        import zipfile
        from flask import send_file

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "demo_simulated_file.txt",
                "EmberVault Demo Mode - Simulated file download.\nNo real operations were performed on remotes.\n",
            )
        buf.seek(0)
        return send_file(
            buf,
            mimetype="application/zip",
            as_attachment=True,
            download_name="demo_download.zip",
        )

    if not items:
        return make_response(
            jsonify({"status": "error", "message": "Nessun elemento specificato."}),
            400,
        )

    session_factory = current_app.config.get("SESSION_FACTORY")
    if session_factory:
        with session_factory() as session:
            if not referenced_remotes:
                referenced_remotes = RemoteRepository.resolve_referenced_remotes(
                    session=session,
                    backend_type=backend_type,
                    config=config,
                )

            proxies = ProxyRepository.get_all_enabled_proxies(session)
            online_proxies = [p for p in proxies if p.status and p.status.state == "online"]
            if remote_id:
                try:
                    r_uuid = UUID(str(remote_id))
                    online_proxies = [
                        p for p in online_proxies if r_uuid in {r.id for r in p.reachable_remotes}
                    ]
                except Exception:
                    pass
            if not online_proxies:
                return make_response(
                    jsonify(
                        {
                            "status": "error",
                            "message": "Nessun proxy online abilitato è in grado di raggiungere questo remote per il download.",
                        }
                    ),
                    400,
                )
            if online_proxies:
                chosen_proxy = online_proxies[0]
                client = get_proxy_client()
                decrypted_token = ProxyRepository.decrypt_token(
                    chosen_proxy.token_encrypted, chosen_proxy.id
                )
                try:
                    proxy_resp = client.download_remote(
                        host=chosen_proxy.host,
                        port=chosen_proxy.port,
                        token=decrypted_token,
                        expected_fingerprint=chosen_proxy.cert_fingerprint_sha256,
                        backend_type=backend_type,
                        config=config,
                        base_path=base_path,
                        items=items,
                        referenced_remotes=referenced_remotes,
                    )
                    if proxy_resp.status_code != 200:
                        return make_response(
                            jsonify(
                                {"status": "error", "message": f"Proxy error: {proxy_resp.text}"}
                            ),
                            proxy_resp.status_code,
                        )

                    headers: dict[str, str] = {}
                    if "Content-Disposition" in proxy_resp.headers:
                        headers["Content-Disposition"] = proxy_resp.headers["Content-Disposition"]
                    content_type = proxy_resp.headers.get(
                        "Content-Type", "application/octet-stream"
                    )

                    def forward_stream():
                        for chunk in proxy_resp.iter_content(chunk_size=65536):
                            if chunk:
                                yield chunk

                    return Response(
                        stream_with_context(forward_stream()),
                        status=200,
                        mimetype=content_type,
                        headers=headers,
                    )
                except Exception as exc:
                    return make_response(
                        jsonify(
                            {
                                "status": "error",
                                "message": f"Errore download sul proxy '{chosen_proxy.name}': {exc}",
                            }
                        ),
                        500,
                    )

    # Fallback if no proxies are online (development / simulated)
    is_single_file = len(items) == 1 and items[0].get("type") == "file"
    if is_single_file:
        fname = items[0].get("name", "file.txt")

        def stub_stream():
            yield f"Contenuto simulato del file {fname}\n".encode("utf-8")

        return Response(
            stream_with_context(stub_stream()),
            status=200,
            mimetype="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )
    else:
        import queue
        import threading
        import zipfile

        zip_name = (
            f"{items[0].get('name', 'export')}.zip" if len(items) == 1 else "remote_export.zip"
        )
        q: queue.Queue[bytes | Exception | object] = queue.Queue(maxsize=10)
        sentinel = object()

        class QueueIO:
            def write(self, b: bytes) -> int:
                if b:
                    q.put(bytes(b))
                return len(b)

            def flush(self) -> None:
                pass

        def stub_worker() -> None:
            try:
                with zipfile.ZipFile(
                    QueueIO(),  # type: ignore[arg-type]
                    mode="w",
                    compression=zipfile.ZIP_STORED,
                ) as zf:
                    for it in items:
                        iname = it.get("name", "item")
                        itype = it.get("type", "file")
                        if itype == "file":
                            zf.writestr(iname, f"Simulated content of {iname}\n".encode("utf-8"))
                        else:
                            zf.writestr(
                                f"{iname}/file1.txt", f"File 1 in {iname}\n".encode("utf-8")
                            )
                            zf.writestr(
                                f"{iname}/file2.txt", f"File 2 in {iname}\n".encode("utf-8")
                            )
            except Exception as e:
                q.put(e)
            finally:
                q.put(sentinel)

        t = threading.Thread(target=stub_worker, daemon=True)
        t.start()

        def stub_zip_stream():
            while True:
                chunk = q.get()
                if chunk is sentinel:
                    break
                if isinstance(chunk, Exception):
                    raise chunk
                yield chunk

        return Response(
            stream_with_context(stub_zip_stream()),
            status=200,
            mimetype="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{zip_name}"'},
        )


def _is_portal_enabled() -> bool:
    from embervault_db.settings_store import SettingsStore

    session_factory = current_app.config.get("SESSION_FACTORY")
    settings_store = current_app.config.get("SETTINGS_STORE")
    if settings_store is None and session_factory:
        settings_store = SettingsStore(session_factory)
        current_app.config["SETTINGS_STORE"] = settings_store
    if not settings_store:
        return True
    try:
        val = settings_store.get_setting("public_portal_enabled")
        if val is None:
            return True
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            return val.lower() in ("true", "1", "yes", "on")
        return bool(val)
    except Exception:
        return True


@internal_api.route("/public-shares/validate", methods=["POST"])
def validate_public_share() -> Response:
    """Validate credentials and expiration for a public share."""
    from embervault_db.repositories.public_share_repository import PublicShareRepository

    if not _is_portal_enabled():
        return make_response(
            jsonify({"status": "error", "message": "Il portale pubblico è disattivato."}), 403
        )

    body = request.get_json(silent=True) or {}
    token = str(body.get("token", "")).strip()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", "")).strip()

    if not token or not username or not password:
        return make_response(jsonify({"status": "error", "message": "Parametri mancanti."}), 400)

    session_factory = current_app.config.get("SESSION_FACTORY")
    if not session_factory:
        return make_response(
            jsonify({"status": "error", "message": "Database non disponibile."}), 503
        )

    with session_factory() as session:
        share = PublicShareRepository.get_share_by_token(session, token)
        if not share:
            return make_response(
                jsonify({"status": "error", "message": "Link pubblico non trovato."}), 404
            )

        if not PublicShareRepository.is_valid(share):
            return make_response(
                jsonify({"status": "error", "message": "Link pubblico scaduto o disattivato."}), 410
            )

        if not PublicShareRepository.verify_credentials(share, username, password):
            return make_response(
                jsonify({"status": "error", "message": "Credenziali non valide."}), 401
            )

        PublicShareRepository.record_first_access(session, share)
        session.commit()

        remote_name = share.remote.name if share.remote else "Remote"
        return jsonify(
            {
                "status": "ok",
                "token": share.token,
                "remote_name": remote_name,
                "base_path": share.base_path,
                "expires_at": share.expires_at.isoformat(),
                "first_accessed_at": share.first_accessed_at.isoformat()
                if share.first_accessed_at
                else None,
            }
        )


@internal_api.route("/public-shares/branding", methods=["GET"])
def get_public_share_branding() -> Response:
    """Retrieve public portal branding (app name and custom logo) for the public portal."""
    from embervault_db.settings_store import SettingsStore

    session_factory = current_app.config.get("SESSION_FACTORY")
    settings_store = current_app.config.get("SETTINGS_STORE")
    if settings_store is None and session_factory:
        settings_store = SettingsStore(session_factory)
        current_app.config["SETTINGS_STORE"] = settings_store

    portal_name = ""
    portal_logo = ""
    portal_language = "en"
    if settings_store:
        try:
            portal_name = str(settings_store.get_setting("portal_custom_app_name") or "").strip()
            portal_logo = str(settings_store.get_setting("portal_custom_logo") or "").strip()
            lang_val = str(settings_store.get_setting("portal_language") or "").strip().lower()
            if lang_val in ("it", "en", "de", "es", "fr", "zh", "ja", "ko", "ar"):
                portal_language = lang_val
        except Exception as exc:
            logger.debug("portal_branding_read_error", error=str(exc))

    portal_enabled = _is_portal_enabled()
    app_name = portal_name if portal_name else "EmberVault public portal"
    return jsonify(
        {
            "status": "ok",
            "enabled": portal_enabled,
            "app_name": app_name,
            "custom_app_name": portal_name,
            "has_custom_logo": bool(portal_logo),
            "logo_data": portal_logo or None,
            "language": portal_language,
        }
    )


@internal_api.route("/public-shares/browse", methods=["POST"])
def browse_public_share() -> Response:
    """Browse directories and files inside a public share's restricted path."""
    if not _is_portal_enabled():
        return make_response(
            jsonify({"status": "error", "message": "Il portale pubblico è disattivato."}), 403
        )

    from embervault_db.repositories.public_share_repository import PublicShareRepository
    from embervault_db.repositories.remote_repository import RemoteRepository
    from embervault_db.repositories.proxy_repository import ProxyRepository

    body = request.get_json(silent=True) or {}
    token = str(body.get("token", "")).strip()
    raw_subpath = str(body.get("subpath", "")).strip().strip("/")

    if not token:
        return make_response(jsonify({"status": "error", "message": "Token richiesto."}), 400)

    # Sanitize and strictly isolate subpath against path traversal
    parts = [p for p in raw_subpath.replace("\\", "/").split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        return make_response(jsonify({"status": "error", "message": "Percorso non valido."}), 400)
    clean_subpath = "/".join(parts)

    session_factory = current_app.config.get("SESSION_FACTORY")
    if not session_factory:
        return make_response(
            jsonify({"status": "error", "message": "Database non disponibile."}), 503
        )

    with session_factory() as session:
        share = PublicShareRepository.get_share_by_token(session, token)
        if not share or not PublicShareRepository.is_valid(share):
            return make_response(
                jsonify({"status": "error", "message": "Link pubblico non valido o scaduto."}), 404
            )

        remote = share.remote
        if not remote or not remote.is_enabled:
            return make_response(
                jsonify({"status": "error", "message": "Remote di archiviazione non disponibile."}),
                404,
            )

        backend_type = remote.backend_type
        full_config = RemoteRepository.get_decrypted_config(remote)
        referenced_remotes = RemoteRepository.resolve_referenced_remotes(
            session=session,
            backend_type=backend_type,
            config=full_config,
        )

        full_browse_path = (
            f"{share.base_path}/{clean_subpath}".strip("/") if share.base_path else clean_subpath
        )

        settings = current_app.config.get("SETTINGS")
        if getattr(settings, "demo_mode", False):
            sample_dirs = [
                {"name": "demo_documents", "mod_time": "2026-11-15T10:00:00Z"},
                {"name": "demo_archives", "mod_time": "2026-11-15T10:00:00Z"},
            ]
            sample_files = [
                {
                    "name": "EmberVault_Demo_Report.pdf",
                    "size": 245760,
                    "mod_time": "2026-11-15T10:30:00Z",
                },
                {
                    "name": "README_Demo.txt",
                    "size": 1024,
                    "mod_time": "2026-11-15T10:30:00Z",
                },
            ]
            return jsonify(
                {
                    "status": "ok",
                    "subpath": clean_subpath,
                    "directories": sample_dirs,
                    "directory_details": sample_dirs,
                    "files": sample_files,
                }
            )

        proxies = ProxyRepository.get_all_enabled_proxies(session)
        online_proxies = [
            p
            for p in proxies
            if p.status
            and p.status.state == "online"
            and (remote.id in {r.id for r in p.reachable_remotes})
        ]
        if not online_proxies:
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": "Nessun proxy online abilitato è configurato per raggiungere questo remote.",
                    }
                ),
                503,
            )
        if online_proxies:
            chosen_proxy = online_proxies[0]
            client = get_proxy_client()
            decrypted_token = ProxyRepository.decrypt_token(
                chosen_proxy.token_encrypted, chosen_proxy.id
            )
            try:
                res = client.browse_remote(
                    host=chosen_proxy.host,
                    port=chosen_proxy.port,
                    token=decrypted_token,
                    expected_fingerprint=chosen_proxy.cert_fingerprint_sha256,
                    backend_type=backend_type,
                    config=full_config,
                    path=full_browse_path,
                    referenced_remotes=referenced_remotes,
                )
                if isinstance(res, dict) and res.get("status") == "ok":
                    dirs = res.get("directory_details") or res.get("directories", [])
                    return jsonify(
                        {
                            "status": "ok",
                            "subpath": clean_subpath,
                            "directories": dirs,
                            "directory_details": res.get("directory_details", []),
                            "files": res.get("files", []),
                        }
                    )
                return jsonify(res)
            except Exception as exc:
                return make_response(
                    jsonify({"status": "error", "message": f"Errore navigazione: {exc}"}), 500
                )

        # Fallback stub if no online proxy
        stub_dirs = [
            {"name": "sample_folder1", "mod_time": "2026-11-01T10:00:00Z"},
            {"name": "sample_folder2", "mod_time": "2026-11-01T10:00:00Z"},
        ]
        return jsonify(
            {
                "status": "ok",
                "subpath": clean_subpath,
                "directories": stub_dirs,
                "directory_details": stub_dirs,
                "files": [
                    {
                        "name": "sample_document.pdf",
                        "size": 1024,
                        "mod_time": "2026-11-01T10:00:00Z",
                    }
                ],
            }
        )


@internal_api.route("/public-shares/download", methods=["POST"])
def download_public_share() -> Response:
    """Stream download for items inside a public share's restricted path."""
    if not _is_portal_enabled():
        return make_response(
            jsonify({"status": "error", "message": "Il portale pubblico è disattivato."}), 403
        )

    from embervault_db.repositories.public_share_repository import PublicShareRepository
    from embervault_db.repositories.remote_repository import RemoteRepository
    from embervault_db.repositories.proxy_repository import ProxyRepository

    body = request.get_json(silent=True) or {}
    token = str(body.get("token", "")).strip()
    raw_subpath = str(body.get("subpath", "")).strip().strip("/")
    items = body.get("items") or []

    if not token or not items:
        return make_response(jsonify({"status": "error", "message": "Parametri non validi."}), 400)

    # Sanitize subpath and each item name to forbid path traversal
    parts = [p for p in raw_subpath.replace("\\", "/").split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        return make_response(jsonify({"status": "error", "message": "Percorso non valido."}), 400)
    clean_subpath = "/".join(parts)

    safe_items: list[dict[str, Any]] = []
    for it in items:
        iname = str(it.get("name", "")).strip().strip("/")
        itype = str(it.get("type", "file")).strip()
        if not iname or ".." in iname or "/" in iname or "\\" in iname:
            return make_response(
                jsonify({"status": "error", "message": f"Nome elemento non valido: {iname}"}), 400
            )
        safe_items.append({"name": iname, "type": itype})

    session_factory = current_app.config.get("SESSION_FACTORY")
    if not session_factory:
        return make_response(
            jsonify({"status": "error", "message": "Database non disponibile."}), 503
        )

    with session_factory() as session:
        share = PublicShareRepository.get_share_by_token(session, token)
        if not share or not PublicShareRepository.is_valid(share):
            return make_response(
                jsonify({"status": "error", "message": "Link pubblico non valido o scaduto."}), 404
            )

        remote = share.remote
        if not remote or not remote.is_enabled:
            return make_response(
                jsonify({"status": "error", "message": "Remote di archiviazione non disponibile."}),
                404,
            )

        backend_type = remote.backend_type
        full_config = RemoteRepository.get_decrypted_config(remote)
        referenced_remotes = RemoteRepository.resolve_referenced_remotes(
            session=session,
            backend_type=backend_type,
            config=full_config,
        )

        full_base_path = (
            f"{share.base_path}/{clean_subpath}".strip("/") if share.base_path else clean_subpath
        )

        settings = current_app.config.get("SETTINGS")
        if getattr(settings, "demo_mode", False):
            import io
            import zipfile
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for it in safe_items:
                    fname = it.get("name", "sample.txt")
                    zf.writestr(fname, f"Simulated content for {fname} generated by EmberVault Demo Mode.\n")
            buf.seek(0)
            return Response(
                buf.getvalue(),
                mimetype="application/zip",
                headers={"Content-Disposition": 'attachment; filename="embervault_demo_share.zip"'},
            )

        proxies = ProxyRepository.get_all_enabled_proxies(session)
        online_proxies = [
            p
            for p in proxies
            if p.status
            and p.status.state == "online"
            and (remote.id in {r.id for r in p.reachable_remotes})
        ]
        if not online_proxies:
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": "Nessun proxy online abilitato è configurato per raggiungere questo remote.",
                    }
                ),
                503,
            )
        if online_proxies:
            chosen_proxy = online_proxies[0]
            client = get_proxy_client()
            decrypted_token = ProxyRepository.decrypt_token(
                chosen_proxy.token_encrypted, chosen_proxy.id
            )
            try:
                proxy_resp = client.download_remote(
                    host=chosen_proxy.host,
                    port=chosen_proxy.port,
                    token=decrypted_token,
                    expected_fingerprint=chosen_proxy.cert_fingerprint_sha256,
                    backend_type=backend_type,
                    config=full_config,
                    base_path=full_base_path,
                    items=safe_items,
                    referenced_remotes=referenced_remotes,
                )
                if proxy_resp.status_code != 200:
                    return make_response(
                        jsonify({"status": "error", "message": f"Proxy error: {proxy_resp.text}"}),
                        proxy_resp.status_code,
                    )

                headers: dict[str, str] = {}
                if "Content-Disposition" in proxy_resp.headers:
                    headers["Content-Disposition"] = proxy_resp.headers["Content-Disposition"]
                content_type = proxy_resp.headers.get("Content-Type", "application/octet-stream")

                def forward_stream():
                    for chunk in proxy_resp.iter_content(chunk_size=65536):
                        if chunk:
                            yield chunk

                return Response(
                    stream_with_context(forward_stream()),
                    status=200,
                    mimetype=content_type,
                    headers=headers,
                )
            except Exception as exc:
                return make_response(
                    jsonify({"status": "error", "message": f"Errore download: {exc}"}), 500
                )

        # Fallback stub stream
        is_single_file = len(safe_items) == 1 and safe_items[0].get("type") == "file"
        if is_single_file:
            fname = safe_items[0]["name"]

            def stub_stream():
                yield f"Contenuto file {fname}\n".encode("utf-8")

            return Response(
                stream_with_context(stub_stream()),
                status=200,
                mimetype="application/octet-stream",
                headers={"Content-Disposition": f'attachment; filename="{fname}"'},
            )
        else:
            import queue
            import threading
            import zipfile

            zname = (
                f"{safe_items[0]['name']}.zip"
                if len(safe_items) == 1
                else "public_share_download.zip"
            )
            q: queue.Queue = queue.Queue(maxsize=10)
            sentinel = object()

            class QueueIO:
                def write(self, b: bytes) -> int:
                    if b:
                        q.put(bytes(b))
                    return len(b)

                def flush(self):
                    pass

            def worker():
                try:
                    with zipfile.ZipFile(QueueIO(), mode="w", compression=zipfile.ZIP_STORED) as zf:
                        for it in safe_items:
                            iname = it["name"]
                            if it["type"] == "file":
                                zf.writestr(iname, f"File content {iname}\n".encode("utf-8"))
                            else:
                                zf.writestr(f"{iname}/file1.txt", b"File 1\n")
                except Exception as e:
                    q.put(e)
                finally:
                    q.put(sentinel)

            threading.Thread(target=worker, daemon=True).start()

            def stub_zip():
                while True:
                    c = q.get()
                    if c is sentinel:
                        break
                    if isinstance(c, Exception):
                        raise c
                    yield c

            return Response(
                stream_with_context(stub_zip()),
                status=200,
                mimetype="application/zip",
                headers={"Content-Disposition": f'attachment; filename="{zname}"'},
            )


def execute_job_run(
    session: Session,
    job_id: UUID,
    trigger: str = "manual",
    requested_by: UUID | None = None,
    settings_store: Any | None = None,
    proxy_client: ProxyClient | None = None,
) -> dict[str, Any]:
    """Execute planning, task creation, and initial dispatch for a job run."""
    from embervault_common.contracts.enums import RunState, TaskOperation
    from embervault_common.rclone.options import resolve_job_rclone_options
    from embervault_db.models.base import utc_now
    from embervault_db.repositories.execution_repository import ExecutionRepository
    from embervault_db.repositories.proxy_repository import ProxyRepository
    from embervault_db.repositories.remote_repository import RemoteRepository
    from embervault_db.settings_store import SettingsStore
    from embervault_orchestrator.planner.spec import (
        DiscoveryResult,
        JobPlanningSpec,
        plan_job_tasks,
    )

    job = JobRepository.get_job_by_id(session, job_id)
    if job is None:
        raise ValueError(f"Job {job_id} non trovato.")
    if not job.enabled:
        raise ValueError(f"Il job '{job.name}' è disabilitato.")

    # Validate reachability of assigned proxies
    JobRepository.validate_job_proxies_reachability(
        session=session,
        source_remote_id=job.source_remote_id,
        destination_remote_id=job.destination_remote_id,
        assigned_proxies=job.assigned_proxies,
    )

    if settings_store is None:
        settings_store = SettingsStore(session)

    resolved_options, resolved_max_attempts = resolve_job_rclone_options(job, settings_store)

    hooks_enabled = False
    timeout_s = 60
    hook_runner_url = ""
    if job.pre_run_hook and job.pre_run_hook.strip():
        hooks_enabled = bool(settings_store.get_setting("hooks_enabled"))
        timeout_s = int(settings_store.get_setting("hooks_timeout_s") or 60)
        hook_runner_url = str(
            settings_store.get_setting("hook_runner_url")
            or os.environ.get("EMBERVAULT_HOOK_RUNNER_URL")
            or ""
        )

    run = ExecutionRepository.create_job_run(
        session=session,
        job_id=job_id,
        trigger=trigger,
        requested_by=requested_by,
    )

    snap = dict(run.job_snapshot or {})
    snap["resolved_rclone_options"] = resolved_options
    snap["max_attempts"] = resolved_max_attempts
    run.job_snapshot = snap

    # M8 Bash Hook: Pre-Run Execution
    if job.pre_run_hook and job.pre_run_hook.strip():
        from embervault_common.hooks.executor import HookExecutor
        from embervault_db.models.auth import AuditLog

        if not hooks_enabled:
            # Feature flag disabled: record skipped hook and audit log
            hook_record = ExecutionRepository.record_run_hook(
                session=session,
                run_id=run.id,
                hook_type="pre_run",
                script_hash=HookExecutor.calculate_script_hash(job.pre_run_hook),
                status="skipped",
                exit_code=0,
                duration_ms=0.0,
                output="Esecuzione hook disabilitata globalmente nelle impostazioni (hooks_enabled=false).",
            )
            session.add(
                AuditLog(
                    action="hook.pre_run.skipped",
                    actor_user_id=requested_by,
                    entity_type="job_run",
                    entity_id=str(run.id),
                    details={
                        "job_id": str(job.id),
                        "reason": "hooks_disabled",
                        "script_hash": hook_record.script_hash,
                    },
                )
            )
        else:
            from embervault_common.config import SecuritySettings

            sec_settings = SecuritySettings.load()
            internal_token = (
                sec_settings.internal_api_token.get_secret_value()
                if sec_settings and sec_settings.internal_api_token
                else os.environ.get("EMBERVAULT_INTERNAL_API_TOKEN", "")
            )
            executor = HookExecutor(
                default_timeout_s=timeout_s,
                runner_url=hook_runner_url,
                auth_token=internal_token,
            )
            try:
                hook_res = executor.execute(
                    script_content=job.pre_run_hook,
                    context={
                        "EMBERVAULT_JOB_ID": str(job.id),
                        "EMBERVAULT_JOB_NAME": job.name,
                        "EMBERVAULT_RUN_ID": str(run.id),
                        "EMBERVAULT_TRIGGER": trigger,
                        "EMBERVAULT_HOOK_TYPE": "pre_run",
                    },
                    timeout_s=timeout_s,
                )
            except Exception as exc:
                logger.error("pre_run_hook_execution_error", run_id=str(run.id), error=str(exc))
                from embervault_common.hooks.executor import HookExecutionResult

                hook_res = HookExecutionResult(
                    status="failed",
                    exit_code=-1,
                    duration_ms=0.0,
                    script_hash=HookExecutor.calculate_script_hash(job.pre_run_hook),
                    output=f"[ERROR] Errore inaspettato durante l'esecuzione dell'hook: {exc}",
                )

            hook_record = ExecutionRepository.record_run_hook(
                session=session,
                run_id=run.id,
                hook_type="pre_run",
                script_hash=hook_res.script_hash,
                status=hook_res.status,
                exit_code=hook_res.exit_code,
                duration_ms=hook_res.duration_ms,
                output=hook_res.output,
            )
            session.add(
                AuditLog(
                    action=f"hook.pre_run.{hook_res.status}",
                    actor_user_id=requested_by,
                    entity_type="job_run",
                    entity_id=str(run.id),
                    details={
                        "job_id": str(job.id),
                        "status": hook_res.status,
                        "exit_code": hook_res.exit_code,
                        "script_hash": hook_res.script_hash,
                        "duration_ms": hook_res.duration_ms,
                    },
                )
            )

            if hook_res.status != "succeeded":
                # Pre-run hook failed or timed out: log warning, notify, but continue job startup
                logger.warning(
                    "pre_run_hook_failed_continuing_job",
                    run_id=str(run.id),
                    job_id=str(job.id),
                    status=hook_res.status,
                    exit_code=hook_res.exit_code,
                )
                run.warning_code = "PRE_HOOK_FAILED"
                try:
                    from embervault_orchestrator.notifier import NotificationService

                    notif_svc = NotificationService(settings_store)
                    notif_svc.notify_hook_failure(
                        session=session,
                        run=run,
                        hook_type="pre_run",
                        status=hook_res.status,
                        exit_code=hook_res.exit_code,
                        duration_ms=hook_res.duration_ms,
                        output=hook_res.output,
                        job_name=job.name,
                    )
                except Exception as notif_err:
                    logger.error(
                        "pre_run_hook_notification_failed",
                        run_id=str(run.id),
                        error=str(notif_err),
                    )

    # Plan tasks
    from embervault_common.config import is_demo_mode
    if is_demo_mode(settings_store):
        discovery_res: DiscoveryResult | None = None
        if job.parallelization == "by_subfolder":
            subfolders = ["documents", "media", "projects", "database"]
            root_files = ["backup_manifest.json", "system_info.txt"]
            subfolder_files = {
                "documents": ["report2026.docx", "invoices.pdf"],
                "media": ["logo.png", "banner.webp"],
                "projects": ["app.py", "pyproject.toml"],
                "database": ["dump.sql", "schema.sql"],
            }
            proxy_cand = (
                job.assigned_proxies[0] if getattr(job, "assigned_proxies", None) else None
            )
            fresh_disc = JobRepository.record_discovery(
                session=session,
                source_remote_id=job.source_remote_id,
                source_path=job.source_path,
                subfolders=subfolders,
                root_file_count=len(root_files),
                trigger="run_start",
                job_id=job.id,
                proxy_id=proxy_cand.id if proxy_cand else None,
                status="succeeded",
                root_files=root_files,
                subfolder_files=subfolder_files,
                enabled_proxy_count=(
                    max(1, len(job.assigned_proxies))
                    if getattr(job, "assigned_proxies", None)
                    else 1
                ),
            )
            job.last_discovery_id = fresh_disc.id
            discovery_res = DiscoveryResult(
                subfolders=subfolders,
                root_files=root_files,
                subfolder_files=subfolder_files,
            )

        spec = JobPlanningSpec(
            source_type="folder",
            parallel_mode=job.parallelization,  # type: ignore[arg-type]
            operation=TaskOperation(job.operation),
            source_path=job.source_path,
            dest_path=job.destination_path,
            first_level_filters=resolved_options.get("first_level_filters", []),
            second_level_filters=resolved_options.get("second_level_filters", []),
            options=resolved_options,
        )
        planned_tasks = plan_job_tasks(spec, discovery=discovery_res)
        tasks = ExecutionRepository.materialize_planned_tasks(session, run.id, planned_tasks)
        session.flush()

        available_proxies = (
            list(job.assigned_proxies)
            if getattr(job, "assigned_proxies", None)
            else ProxyRepository.get_all_enabled_proxies(session)
        )
        if not available_proxies:
            available_proxies = ProxyRepository.get_all_proxies(session)

        for idx, task in enumerate(tasks):
            proxy = available_proxies[idx % len(available_proxies)] if available_proxies else None
            proxy_id = proxy.id if proxy else None
            proxy_name = proxy.name if proxy else "Demo Proxy"
            task_src = (task.spec or {}).get("source_path") or task.scope or "/"
            task_dst = (task.spec or {}).get("dest_path") or (task.spec or {}).get("destination_path") or "/"
            if proxy_id:
                assignment = ExecutionRepository.create_assignment(session, task.id, proxy_id)
                ExecutionRepository.record_task_log(
                    session,
                    assignment.id,
                    task.id,
                    run.id,
                    f"[DEMO] Simulating execution of task '{task_src}' on proxy '{proxy_name}'...",
                    level="info",
                )
                ExecutionRepository.record_task_log(
                    session,
                    assignment.id,
                    task.id,
                    run.id,
                    f"[DEMO] Synchronizing files towards destination '{task_dst}'",
                    level="info",
                )
                ExecutionRepository.record_task_log(
                    session,
                    assignment.id,
                    task.id,
                    run.id,
                    "Checks: 12 / 12, 100%",
                    level="info",
                )
                ExecutionRepository.record_task_log(
                    session,
                    assignment.id,
                    task.id,
                    run.id,
                    "Transferred: 18.4 MiB / 18.4 MiB, 100%, 14.2 MiB/s",
                    level="info",
                )
                ExecutionRepository.record_task_log(
                    session,
                    assignment.id,
                    task.id,
                    run.id,
                    f"[DEMO] Task '{task_src}' completed successfully (simulated).",
                    level="info",
                )
                sim_bytes = 18 * 1024 * 1024 + (idx * 2 * 1024 * 1024)
                sim_files = 12 + idx * 3
                ExecutionRepository.update_assignment_status(
                    session=session,
                    assignment_id=assignment.id,
                    status="succeeded",
                    exit_code=0,
                    bytes_transferred=sim_bytes,
                    files_transferred=sim_files,
                    duration_ms=1150 + idx * 50,
                )
                ExecutionRepository.record_throughput_sample(
                    session=session,
                    bytes_per_sec=14.2 * 1024 * 1024,
                    active_runs=1,
                )

        session.commit()
        return {
            "status": "completed",
            "run_id": str(run.id),
            "job_id": str(job.id),
            "job_name": job.name,
            "planned_task_count": len(tasks),
            "dispatched_count": len(tasks),
            "message": f"Run per '{job.name}' completata con successo (simulazione modalità demo).",
        }

    discovery_res: DiscoveryResult | None = None
    if job.parallelization == "by_subfolder":
        if not job.source_remote:
            error_msg = f"Remote sorgente non configurato o non trovato per il job '{job.name}'."
            run.status = RunState.FAILED.value
            run.finished_at = utc_now()
            run.error_message = error_msg
            session.commit()
            raise ValueError(error_msg)

        subfolders: list[str] = []
        root_files: list[str] = []
        subfolder_files: dict[str, list[str]] = {}
        discovered_live = False

        # Dynamic live discovery via proxy at run start (§4.1)
        # Prioritize proxies currently marked 'online', but try any eligible enabled proxy
        discovery_timeout_s = (
            int(settings_store.get_setting("discovery_timeout_s") or 30) if settings_store else 30
        )

        proxies = ProxyRepository.get_all_enabled_proxies(session)
        assigned_proxy_ids = (
            {p.id for p in job.assigned_proxies}
            if getattr(job, "assigned_proxies", None)
            else set()
        )
        eligible_proxies = [
            p
            for p in proxies
            if (not assigned_proxy_ids or p.id in assigned_proxy_ids)
            and (job.source_remote_id in {r.id for r in p.reachable_remotes})
        ]
        if not eligible_proxies:
            error_msg = f"Nessun proxy disponibile è in grado di raggiungere il remote sorgente '{job.source_remote.name}' per la discovery."
            run.status = RunState.FAILED.value
            run.finished_at = utc_now()
            run.error_message = error_msg
            session.commit()
            raise ValueError(error_msg)
        # Prioritize online proxies, then by fewest active tasks (prefer proxies with free slots),
        # but NEVER exclude busy proxies - discovery runs even if all slots are occupied!
        proxy_active_counts = ExecutionRepository.get_active_assignment_counts_by_proxies(session)
        candidate_proxies = sorted(
            eligible_proxies,
            key=lambda p: (
                0 if (p.status and p.status.state == "online") else 1,
                proxy_active_counts.get(p.id, 0),
            ),
        )

        client = proxy_client or get_proxy_client()
        last_disc_error: str | None = None

        for p in candidate_proxies:
            dec_token = ProxyRepository.decrypt_token(p.token_encrypted, p.id)
            src_config = RemoteRepository.get_decrypted_config(job.source_remote)
            src_referenced_remotes = RemoteRepository.resolve_referenced_remotes(
                session=session,
                backend_type=job.source_remote.backend_type,
                config=src_config,
            )
            try:
                disc_res = client.discover(
                    host=p.host,
                    port=p.port,
                    token=dec_token,
                    expected_fingerprint=p.cert_fingerprint_sha256,
                    backend_type=job.source_remote.backend_type,
                    config=src_config,
                    path=job.source_path,
                    referenced_remotes=src_referenced_remotes,
                    include_subfolder_files=bool(resolved_options.get("second_level_filters")),
                    timeout_s=discovery_timeout_s,
                )
                if disc_res.get("status") == "ok":
                    subfolders = disc_res.get("subfolders", [])
                    root_files = disc_res.get("root_files", [])
                    subfolder_files = disc_res.get("subfolder_files", {})
                    discovered_live = True

                    enabled_proxy_count = max(1, len(eligible_proxies))
                    fresh_disc = JobRepository.record_discovery(
                        session=session,
                        source_remote_id=job.source_remote_id,
                        source_path=job.source_path,
                        subfolders=subfolders,
                        root_file_count=len(root_files),
                        trigger="run_start",
                        job_id=job.id,
                        proxy_id=p.id,
                        status="succeeded",
                        root_files=root_files,
                        subfolder_files=subfolder_files,
                        enabled_proxy_count=enabled_proxy_count,
                    )
                    job.last_discovery_id = fresh_disc.id
                    session.flush()
                    break
                else:
                    err_msg = (
                        disc_res.get("message")
                        or disc_res.get("error")
                        or f"Status: {disc_res.get('status')}"
                    )
                    last_disc_error = f"Proxy '{p.name}': {err_msg}"
                    logger.warning(
                        "run_live_discovery_proxy_error",
                        proxy_id=str(p.id),
                        proxy_name=p.name,
                        job_id=str(job.id),
                        error=err_msg,
                    )
            except Exception as exc:
                last_disc_error = f"Proxy '{p.name}': {exc}"
                logger.warning(
                    "run_live_discovery_failed_on_proxy",
                    proxy_id=str(p.id),
                    proxy_name=p.name,
                    job_id=str(job.id),
                    error=str(exc),
                )

        if not discovered_live:
            if not candidate_proxies:
                if assigned_proxy_ids:
                    err = f"Nessun proxy assegnato ({len(assigned_proxy_ids)}) risulta abilitato."
                else:
                    err = "Nessun proxy abilitato disponibile nel sistema."
            else:
                err = last_disc_error or "Nessun proxy ha risposto con successo alla scansione."

            error_msg = f"Impossibile eseguire la discovery live delle cartelle sorgente all'avvio del job '{job.name}': {err}"
            logger.error(
                "run_live_discovery_failed_aborting_run",
                job_id=str(job.id),
                run_id=str(run.id),
                error=error_msg,
            )
            run.status = RunState.FAILED.value
            run.finished_at = utc_now()
            run.error_message = error_msg
            session.commit()
            raise ValueError(error_msg)

        discovery_res = DiscoveryResult(
            subfolders=subfolders,
            root_files=root_files,
            subfolder_files=subfolder_files,
        )

    spec = JobPlanningSpec(
        source_type="folder",
        parallel_mode=job.parallelization,  # type: ignore[arg-type]
        operation=TaskOperation(job.operation),
        source_path=job.source_path,
        dest_path=job.destination_path,
        first_level_filters=resolved_options.get("first_level_filters", []),
        second_level_filters=resolved_options.get("second_level_filters", []),
        options=resolved_options,
    )

    planned_tasks = plan_job_tasks(spec, discovery=discovery_res)
    tasks = ExecutionRepository.materialize_planned_tasks(session, run.id, planned_tasks)

    # Immediate dispatch for ready tasks respecting proxy concurrency and job parallelism
    client = proxy_client or get_proxy_client()
    dispatched_count = _dispatch_ready_tasks_for_job(session, job, client)
    session.commit()

    return {
        "status": "dispatched",
        "run_id": str(run.id),
        "job_id": str(job.id),
        "job_name": job.name,
        "planned_task_count": len(tasks),
        "dispatched_count": dispatched_count,
        "message": f"Run per '{job.name}' avviata ({len(tasks)} task pianificati, {dispatched_count} inviati).",
    }


@internal_api.route("/jobs/<uuid:job_id>/run", methods=["POST"])
def trigger_job_run(job_id: UUID) -> Response:
    """Trigger execution of a backup job and dispatch planned tasks to online proxies."""
    from flask import current_app

    session_factory = current_app.config.get("SESSION_FACTORY")
    if not session_factory:
        return make_response(jsonify({"error": "Database session factory not configured"}), 500)

    from embervault_db.settings_store import SettingsStore

    settings_store = current_app.config.get("SETTINGS_STORE")
    if settings_store is None:
        settings_store = SettingsStore(session_factory)
        current_app.config["SETTINGS_STORE"] = settings_store

    body = request.get_json(silent=True) or {}
    trigger = str(body.get("trigger", "manual"))
    requested_by_str = body.get("requested_by")
    requested_by = UUID(requested_by_str) if requested_by_str else None

    with session_factory() as session:
        try:
            result = execute_job_run(
                session=session,
                job_id=job_id,
                trigger=trigger,
                requested_by=requested_by,
                settings_store=settings_store,
                proxy_client=get_proxy_client(),
            )
            return jsonify(result)
        except ValueError as err:
            msg = str(err)
            status_code = 404 if "non trovato" in msg else 400 if "disabilitato" in msg else 409
            return make_response(jsonify({"status": "error", "message": msg}), status_code)


def _dispatch_single_task(
    session: Session,
    task: Any,
    proxy: Any,
    job: Any,
    client: ProxyClient,
) -> bool:
    """Helper to lease and dispatch a single task to a proxy worker."""
    if not job or not job.source_remote or not job.destination_remote:
        logger.warning("task_dispatch_skipped_missing_remote", task_id=str(task.id))
        return False

    assignment = ExecutionRepository.create_assignment(session, task.id, proxy.id)
    dec_token = ProxyRepository.decrypt_token(proxy.token_encrypted, proxy.id)
    src_config = RemoteRepository.get_decrypted_config(job.source_remote)
    dst_config = RemoteRepository.get_decrypted_config(job.destination_remote)

    # Resolve any referenced / upstream remotes (for alias, crypt, etc.)
    src_refs = RemoteRepository.resolve_referenced_remotes(
        session=session,
        backend_type=job.source_remote.backend_type,
        config=src_config,
    )
    dst_refs = RemoteRepository.resolve_referenced_remotes(
        session=session,
        backend_type=job.destination_remote.backend_type,
        config=dst_config,
    )
    combined_refs = {**src_refs, **dst_refs}
    referenced_remotes_payload = [
        {
            "alias": r_name,
            "backend_type": r_data["backend_type"],
            "config": r_data["config"],
            "path": "",
        }
        for r_name, r_data in combined_refs.items()
    ]

    all_secret_fields = (
        list(job.source_remote.secret_field_names)
        + list(job.destination_remote.secret_field_names)
        + ["pass", "password", "password2", "secret_access_key", "client_secret", "key"]
    )

    subpath = task.spec.get("source_subpath", "")
    final_src_path = f"{job.source_path.rstrip('/')}/{subpath}" if subpath else job.source_path
    final_dst_path = (
        f"{job.destination_path.rstrip('/')}/{subpath}" if subpath else job.destination_path
    )

    task_options = dict(task.spec.get("options") or {})
    if task.spec.get("filters"):
        task_options["filters"] = list(task.spec.get("filters"))
    if task.spec.get("max_depth") is not None:
        task_options["max_depth"] = task.spec["max_depth"]
    elif task.scope == "root_files" or task.spec.get("include_root_files_only"):
        task_options["max_depth"] = 1

    files_from = list(task.spec.get("files_from") or [])

    payload = {
        "attempt_id": str(assignment.id),
        "task_id": str(task.id),
        "run_id": str(task.run_id),
        "kind": task.kind,
        "operation": task.spec.get("operation", job.operation),
        "timeout_s": task.spec.get("timeout_s", 3600),
        "source": {
            "alias": "src",
            "backend_type": job.source_remote.backend_type,
            "config": src_config,
            "path": final_src_path,
        },
        "destination": {
            "alias": "dst",
            "backend_type": job.destination_remote.backend_type,
            "config": dst_config,
            "path": final_dst_path,
        },
        "referenced_remotes": referenced_remotes_payload,
        "files_from": files_from,
        "options": task_options,
        "secret_fields": all_secret_fields,
    }

    try:
        res = client.dispatch_task(
            host=proxy.host,
            port=proxy.port,
            token=dec_token,
            expected_fingerprint=proxy.cert_fingerprint_sha256,
            payload=payload,
        )
        accepted = bool(res.get("status") in ("accepted", "already_known"))
        if not accepted:
            err_code = str(res.get("error") or "PROXY_DISPATCH_REJECTED")
            ExecutionRepository.update_assignment_status(
                session=session,
                assignment_id=assignment.id,
                status="failed",
                error_class="dispatch_error",
                error_code=err_code,
            )
        return accepted
    except Exception as exc:
        logger.warning("task_dispatch_failed", task_id=str(task.id), error=str(exc))
        try:
            ExecutionRepository.update_assignment_status(
                session=session,
                assignment_id=assignment.id,
                status="failed",
                error_class="dispatch_error",
                error_code="PROXY_DISPATCH_EXCEPTION",
            )
        except Exception:
            pass
        return False


def _dispatch_ready_tasks_for_job(
    session: Session,
    job: Any,
    client: ProxyClient,
) -> int:
    """Find ready tasks for a job and dispatch them to available proxies respecting concurrency limits."""
    proxies = ProxyRepository.get_all_enabled_proxies(session)
    online_proxies = [p for p in proxies if p.status and p.status.state == "online"]
    assigned_proxy_ids = (
        {p.id for p in job.assigned_proxies} if getattr(job, "assigned_proxies", None) else set()
    )
    if assigned_proxy_ids:
        online_proxies = [p for p in online_proxies if p.id in assigned_proxy_ids]
    if not online_proxies:
        logger.warning("dispatch_skipped_no_online_proxy", job_id=str(job.id))
        return 0

    max_job_tasks = job.max_parallel_tasks or 4
    active_job_tasks = ExecutionRepository.get_active_task_count_by_job(session, job.id)
    if active_job_tasks >= max_job_tasks:
        logger.warning(
            "dispatch_skipped_job_parallelism_limit",
            job_id=str(job.id),
            active=active_job_tasks,
            limit=max_job_tasks,
        )
        return 0

    proxy_active_counts = ExecutionRepository.get_active_assignment_counts_by_proxies(session)
    ready_tasks = ExecutionRepository.get_ready_tasks(session, limit=20)
    # Filter ready tasks belonging to this job
    job_ready_tasks = [t for t in ready_tasks if t.run and t.run.job_id == job.id]

    dispatched = 0
    for task in job_ready_tasks:
        if active_job_tasks >= max_job_tasks:
            break

        # Proxies with capacity
        eligible = [
            p for p in online_proxies if proxy_active_counts.get(p.id, 0) < p.max_concurrent_tasks
        ]
        if not eligible:
            logger.warning(
                "dispatch_skipped_no_proxy_capacity",
                job_id=str(job.id),
                proxy_active_counts={str(k): v for k, v in proxy_active_counts.items()},
            )
            break

        # Select proxy with fewest active tasks
        eligible.sort(key=lambda p: proxy_active_counts.get(p.id, 0))
        target_proxy = eligible[0]

        if _dispatch_single_task(session, task, target_proxy, job, client):
            dispatched += 1
            active_job_tasks += 1
            proxy_active_counts[target_proxy.id] = proxy_active_counts.get(target_proxy.id, 0) + 1
        else:
            # If dispatch to target_proxy failed, do not assign more tasks to it in this cycle
            online_proxies = [p for p in online_proxies if p.id != target_proxy.id]

    return dispatched


@internal_api.route("/runs/<uuid:run_id>/cancel", methods=["POST"])
def cancel_job_run(run_id: UUID) -> Response:
    """Cancel an active or queued job run."""
    from flask import current_app

    session_factory = current_app.config.get("SESSION_FACTORY")
    if not session_factory:
        return make_response(jsonify({"error": "Database session factory not configured"}), 500)

    from embervault_db.repositories.execution_repository import ExecutionRepository

    with session_factory() as session:
        ok, active_assignments = ExecutionRepository.cancel_run(session, run_id)
        if not ok:
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": "Impossibile annullare: la run non esiste o è già terminata.",
                    }
                ),
                400,
            )

        # Notify proxies for all cancelled active assignments
        cancel_assignments_on_proxies(session, active_assignments, get_proxy_client())

        session.commit()

    return jsonify({"status": "cancelled", "run_id": str(run_id), "message": "Run annullata."})


@internal_api.route("/runs", methods=["GET"])
def list_runs() -> Response:
    """List execution history."""
    from flask import current_app

    session_factory = current_app.config.get("SESSION_FACTORY")
    if not session_factory:
        return make_response(jsonify({"error": "Database session factory not configured"}), 500)

    from embervault_db.repositories.execution_repository import ExecutionRepository

    job_id_str = request.args.get("job_id")
    job_id = UUID(job_id_str) if job_id_str else None
    limit = int(request.args.get("limit", 50))

    with session_factory() as session:
        runs = ExecutionRepository.list_runs(session, job_id=job_id, limit=limit)
        data = [
            {
                "id": str(r.id),
                "job_id": str(r.job_id),
                "job_name": r.job.name if r.job else r.job_snapshot.get("name", "N/A"),
                "status": r.status,
                "trigger": r.trigger,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                "planned_task_count": r.planned_task_count,
                "tasks_succeeded": r.tasks_succeeded,
                "tasks_failed": r.tasks_failed,
                "error_code": r.error_code,
                "error_message": r.error_message,
                "bytes_transferred": r.bytes_transferred,
                "files_transferred": r.files_transferred,
            }
            for r in runs
        ]

    return jsonify({"status": "ok", "runs": data})


@internal_api.route("/runs/<uuid:run_id>", methods=["GET"])
def get_run_details(run_id: UUID) -> Response:
    """Fetch full run details with task breakdown and status reconciliation."""
    from flask import current_app

    session_factory = current_app.config.get("SESSION_FACTORY")
    if not session_factory:
        return make_response(jsonify({"error": "Database session factory not configured"}), 500)

    from embervault_db.repositories.execution_repository import ExecutionRepository
    from embervault_db.repositories.proxy_repository import ProxyRepository

    with session_factory() as session:
        run = ExecutionRepository.get_run_by_id(session, run_id)
        if run is None:
            return make_response(jsonify({"error": "Run non trovata"}), 404)

        # Reconcile any active task assignments with proxies
        client = get_proxy_client()
        for task in run.tasks:
            if task.status in ("assigned", "running"):
                for assignment in task.assignments:
                    if assignment.status in ("assigned", "running"):
                        proxy = assignment.task.assignments[-1].proxy_id
                        p_entity = ProxyRepository.get_proxy_by_id(session, proxy)
                        if p_entity:
                            dec_token = ProxyRepository.decrypt_token(
                                p_entity.token_encrypted, p_entity.id
                            )
                            try:
                                p_status = client.get_task_status(
                                    host=p_entity.host,
                                    port=p_entity.port,
                                    token=dec_token,
                                    expected_fingerprint=p_entity.cert_fingerprint_sha256,
                                    attempt_id=assignment.id,
                                )
                                new_st = p_status.get("status")
                                if new_st:
                                    prog = p_status.get("progress", {})
                                    ExecutionRepository.update_assignment_status(
                                        session=session,
                                        assignment_id=assignment.id,
                                        status=new_st,
                                        exit_code=p_status.get("exit_code"),
                                        error_class=p_status.get("error_class"),
                                        error_code=p_status.get("error_code"),
                                        bytes_transferred=prog.get("bytes_transferred", 0),
                                        files_transferred=prog.get("files_transferred", 0),
                                        checks_count=prog.get("checks_completed")
                                        or prog.get("checks_count")
                                        or 0,
                                    )
                                    # Fetch and sync logs with from_seq to avoid duplicates
                                    from_seq = (
                                        ExecutionRepository.get_max_task_log_seq(
                                            session, assignment.id
                                        )
                                        + 1
                                    )
                                    p_logs = client.get_task_logs(
                                        host=p_entity.host,
                                        port=p_entity.port,
                                        token=dec_token,
                                        expected_fingerprint=p_entity.cert_fingerprint_sha256,
                                        attempt_id=assignment.id,
                                        from_seq=from_seq,
                                    )
                                    ExecutionRepository.record_task_logs_batch(
                                        session=session,
                                        assignment_id=assignment.id,
                                        task_id=task.id,
                                        run_id=run.id,
                                        lines=p_logs.get("lines", []),
                                        from_seq=from_seq,
                                    )
                            except Exception as exc:
                                logger.debug(
                                    "proxy_status_reconcile_skipped",
                                    assignment_id=str(assignment.id),
                                    error=str(exc),
                                )
        # If the run is still active, attempt to dispatch any ready tasks to available proxies
        if run.status in ("planning", "running", "queued") and run.job:
            _dispatch_ready_tasks_for_job(session, run.job, client)

        session.commit()

        # Build response
        tasks_stats = ExecutionRepository.get_run_tasks_progress_stats(session, run)
        tasks_data = []
        for t in run.tasks:
            assigned_proxy_name = None
            assigned_proxy_id = None
            if t.assignments:
                latest_assign = t.assignments[-1]
                if latest_assign.proxy:
                    assigned_proxy_name = latest_assign.proxy.name
                    assigned_proxy_id = str(latest_assign.proxy.id)
                elif latest_assign.proxy_id:
                    p_entity = ProxyRepository.get_proxy_by_id(session, latest_assign.proxy_id)
                    if p_entity:
                        assigned_proxy_name = p_entity.name
                        assigned_proxy_id = str(p_entity.id)

            t_stats = tasks_stats.get(t.id, {})
            tasks_data.append(
                {
                    "id": str(t.id),
                    "seq": t.seq,
                    "kind": t.kind,
                    "scope": t.scope,
                    "status": t.status,
                    "last_error_code": t.last_error_code,
                    "attempt_count": t.attempt_count,
                    "max_attempts": t.max_attempts,
                    "spec": t.spec,
                    "finished_at": t.finished_at.isoformat() if t.finished_at else None,
                    "proxy_name": assigned_proxy_name,
                    "proxy_id": assigned_proxy_id,
                    "checks_display": t_stats.get("checks_display", "-"),
                    "transferred_display": t_stats.get("transferred_display", "-"),
                    "speed_display": t_stats.get("speed_display", "0 B/s"),
                    "eta_display": t_stats.get("eta_display", "-"),
                }
            )

        proxies_data = ExecutionRepository.get_run_proxies_activity(session, run)
        total_speed_bytes = sum(p.get("speed_bytes_per_sec", 0.0) for p in proxies_data)
        total_throughput_str = ExecutionRepository.format_speed(total_speed_bytes)

        hooks_data = []
        for h in run.hooks or []:
            hooks_data.append(
                {
                    "id": str(h.id),
                    "hook_type": h.hook_type,
                    "script_hash": h.script_hash,
                    "status": h.status,
                    "exit_code": h.exit_code,
                    "duration_ms": h.duration_ms,
                    "output": h.output,
                    "executed_at": h.executed_at.isoformat() if h.executed_at else None,
                }
            )

        return jsonify(
            {
                "status": "ok",
                "run": {
                    "id": str(run.id),
                    "job_id": str(run.job_id),
                    "job_name": run.job.name if run.job else run.job_snapshot.get("name", "N/A"),
                    "status": run.status,
                    "trigger": run.trigger,
                    "started_at": run.started_at.isoformat() if run.started_at else None,
                    "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                    "planned_task_count": run.planned_task_count,
                    "tasks_succeeded": run.tasks_succeeded,
                    "tasks_failed": run.tasks_failed,
                    "warning_code": run.warning_code,
                    "error_code": run.error_code,
                    "error_message": run.error_message,
                    "bytes_transferred": run.bytes_transferred,
                    "files_transferred": run.files_transferred,
                    "total_throughput_str": total_throughput_str,
                    "job_snapshot": run.job_snapshot,
                    "tasks": tasks_data,
                    "proxies": proxies_data,
                    "hooks": hooks_data,
                },
            }
        )


@internal_api.route("/tasks/<uuid:task_id>/logs", methods=["GET"])
def get_task_logs(task_id: UUID) -> Response:
    """Fetch stored execution logs for a task."""
    from flask import current_app

    session_factory = current_app.config.get("SESSION_FACTORY")
    if not session_factory:
        return make_response(jsonify({"error": "Database session factory not configured"}), 500)

    from embervault_db.models.execution import Task
    from embervault_db.repositories.execution_repository import ExecutionRepository
    from embervault_db.repositories.proxy_repository import ProxyRepository

    with session_factory() as session:
        # On-demand sync latest logs from assigned proxy if task is running or recently finished
        task = session.get(Task, task_id)
        if task and task.assignments:
            latest_assignment = task.assignments[-1]
            p_entity = ProxyRepository.get_proxy_by_id(session, latest_assignment.proxy_id)
            if p_entity:
                client = get_proxy_client()
                dec_token = ProxyRepository.decrypt_token(p_entity.token_encrypted, p_entity.id)
                from_seq = (
                    ExecutionRepository.get_max_task_log_seq(session, latest_assignment.id) + 1
                )
                try:
                    p_logs = client.get_task_logs(
                        host=p_entity.host,
                        port=p_entity.port,
                        token=dec_token,
                        expected_fingerprint=p_entity.cert_fingerprint_sha256,
                        attempt_id=latest_assignment.id,
                        from_seq=from_seq,
                    )
                    ExecutionRepository.record_task_logs_batch(
                        session=session,
                        assignment_id=latest_assignment.id,
                        task_id=task.id,
                        run_id=task.run_id,
                        lines=p_logs.get("lines", []),
                        from_seq=from_seq,
                    )
                    session.commit()
                except Exception as exc:
                    logger.debug("on_demand_proxy_log_sync_skipped", error=str(exc))

        limit_param = request.args.get("limit")
        limit = int(limit_param) if limit_param and limit_param.isdigit() else None
        from_seq_param = request.args.get("from_seq")
        from_seq = int(from_seq_param) if from_seq_param and from_seq_param.isdigit() else 0
        tail = request.args.get("tail", "false").lower() in ("true", "1")

        logs = ExecutionRepository.get_task_logs(
            session, task_id, limit=limit, from_seq=from_seq, tail=tail
        )
        lines = [
            {
                "seq": log_entry.seq,
                "ts": log_entry.ts.isoformat(),
                "level": log_entry.level,
                "stream": log_entry.stream,
                "message": log_entry.message,
            }
            for log_entry in logs
        ]

    return jsonify({"status": "ok", "task_id": str(task_id), "lines": lines})


@internal_api.route("/tasks/<uuid:task_id>/cancel", methods=["POST"])
def cancel_task(task_id: UUID) -> Response:
    """Cancel an active or queued task manually."""
    from flask import current_app

    session_factory = current_app.config.get("SESSION_FACTORY")
    if not session_factory:
        return make_response(jsonify({"error": "Database session factory not configured"}), 500)

    from embervault_db.repositories.execution_repository import ExecutionRepository
    from embervault_db.repositories.proxy_repository import ProxyRepository

    with session_factory() as session:
        ok, task, active_assignments = ExecutionRepository.cancel_task(session, task_id)
        if task is None:
            return make_response(jsonify({"status": "error", "message": "Task non trovato."}), 404)
        if not ok:
            return make_response(
                jsonify(
                    {
                        "status": "error",
                        "message": f"Impossibile annullare: il task è già in stato '{task.status}'.",
                    }
                ),
                400,
            )

        # Notify proxies for any active assignments
        client = get_proxy_client()
        for assignment in active_assignments:
            p_entity = ProxyRepository.get_proxy_by_id(session, assignment.proxy_id)
            if p_entity:
                try:
                    dec_token = ProxyRepository.decrypt_token(p_entity.token_encrypted, p_entity.id)
                    client.cancel_task(
                        host=p_entity.host,
                        port=p_entity.port,
                        token=dec_token,
                        expected_fingerprint=p_entity.cert_fingerprint_sha256,
                        attempt_id=assignment.id,
                        timeout=(3.0, 5.0),
                    )
                except Exception as exc:
                    logger.warning(
                        "proxy_task_cancel_notification_failed",
                        attempt_id=str(assignment.id),
                        error=str(exc),
                    )

        # Record manual cancellation log if assignment exists
        target_assignment_id = active_assignments[0].id if active_assignments else None
        if not target_assignment_id and task.assignments:
            target_assignment_id = task.assignments[-1].id

        if target_assignment_id:
            ExecutionRepository.record_task_log(
                session=session,
                assignment_id=target_assignment_id,
                task_id=task.id,
                run_id=task.run_id,
                message="Task annullato manualmente dall'utente.",
                stream="system",
                level="warn",
            )
        session.commit()

    return jsonify(
        {
            "status": "cancelled",
            "task_id": str(task_id),
            "message": "Task annullato con successo.",
        }
    )
