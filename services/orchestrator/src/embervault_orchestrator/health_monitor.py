"""Health monitor polling execution proxies with TLS fingerprint pinning and hysteresis transitions."""

from __future__ import annotations

import threading
import time
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from embervault_common.config import OrchestratorSettings
from embervault_common.contracts import ErrorCode, ProxyState
from embervault_common.observability import get_logger
from embervault_common.security import TLSFingerprintMismatchError
from embervault_common.version import (
    MIN_COMPATIBLE_PROXY_VERSION,
    is_proxy_version_compatible,
)
from embervault_db.models import Setting
from embervault_db.models.proxy import Proxy
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.settings_store import SettingsStore
from embervault_orchestrator.notifier import NotificationService
from embervault_orchestrator.proxy_client import (
    ProxyClient,
    ProxyUnauthorizedError,
    ProxyUnreachableError,
)

logger = get_logger("embervault_orchestrator.health_monitor")


class HealthMonitor:
    """Monitors registered proxies, evaluates health with hysteresis, and manages state transitions."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        settings: OrchestratorSettings | None = None,
        proxy_client: ProxyClient | None = None,
        notification_service: NotificationService | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings or OrchestratorSettings.load()
        self.proxy_client = proxy_client or ProxyClient()
        self.settings_store = SettingsStore(session_factory)
        self.notification_service = notification_service or NotificationService(self.settings_store)

        self.heartbeat_interval_s = self.settings.heartbeat_interval_s
        self.offline_after_failures = self.settings.offline_after_failures
        self.online_after_successes = self.settings.online_after_successes
        self.connect_timeout_s = float(self.settings.http_connect_timeout_s)
        self.read_timeout_s = float(self.settings.http_read_timeout_s)

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def check_proxy(self, session: Session, proxy: Proxy) -> str:
        """Execute a single health poll against a proxy and update its state.

        Args:
            session: Active database session.
            proxy: Proxy database model.

        Returns:
            The resulting ProxyState string ('online', 'offline', 'unauthorized', 'untrusted', etc.).
        """
        status = ProxyRepository.get_or_create_status(session, proxy.id)
        current_state = status.state

        from embervault_common.config import is_demo_mode
        if is_demo_mode(self.settings):
            ProxyRepository.apply_probe_result(
                session=session,
                proxy=proxy,
                new_state=ProxyState.ONLINE,
                latency_ms=1.5,
                version=status.version or "1.0.0",
                rclone_version=status.rclone_version or "v1.66.0",
                os_family="linux",
                arch="x86_64",
                max_tasks=proxy.max_concurrent_tasks or 2,
                active_tasks=0,
            )
            return ProxyState.ONLINE

        try:
            token = ProxyRepository.decrypt_token(proxy.token_encrypted, proxy.id)
        except Exception as exc:
            logger.error("proxy_token_decrypt_failed", proxy_id=str(proxy.id), error=str(exc))
            ProxyRepository.apply_probe_result(
                session=session,
                proxy=proxy,
                new_state=ProxyState.OFFLINE,
                error_code=ErrorCode.CREDENTIAL_DECRYPT_FAILED,
                reason="Failed to decrypt proxy authentication token",
            )
            return ProxyState.OFFLINE

        try:
            health, latency_ms = self.proxy_client.get_health(
                host=proxy.host,
                port=proxy.port,
                token=token,
                expected_fingerprint=proxy.cert_fingerprint_sha256,
                timeout=(self.connect_timeout_s, self.read_timeout_s),
            )

            # Check version compatibility
            min_ver = getattr(self.settings, "min_proxy_version", MIN_COMPATIBLE_PROXY_VERSION)
            try:
                setting_row = session.get(Setting, "min_proxy_version")
                if setting_row and setting_row.value:
                    min_ver = str(setting_row.value)
            except Exception:
                pass
            if not is_proxy_version_compatible(health.proxy_version, min_ver):
                incompat_reason = (
                    f"Versione proxy incompatibile: v{health.proxy_version or 'sconosciuta'} "
                    f"(richiesta >= v{min_ver})"
                )
                logger.warning(
                    "proxy_version_incompatible",
                    proxy_id=str(proxy.id),
                    proxy_name=proxy.name,
                    detected_version=health.proxy_version,
                    min_version=min_ver,
                )
                if (
                    current_state != ProxyState.OFFLINE
                    or status.last_error_code != ErrorCode.PROXY_VERSION_INCOMPATIBLE
                ):
                    try:
                        self.notification_service.notify_proxy_offline(
                            session=session,
                            proxy=proxy,
                            reason=incompat_reason,
                            consecutive_failures=status.consecutive_failures + 1,
                            is_incompatible=True,
                            detected_version=health.proxy_version,
                            min_version=min_ver,
                        )
                    except Exception as exc:
                        logger.error(
                            "notify_proxy_incompatible_failed",
                            proxy_id=str(proxy.id),
                            error=str(exc),
                        )

                ProxyRepository.apply_probe_result(
                    session=session,
                    proxy=proxy,
                    new_state=ProxyState.OFFLINE,
                    is_success=False,
                    error_code=ErrorCode.PROXY_VERSION_INCOMPATIBLE,
                    latency_ms=latency_ms,
                    running_tasks=health.running_tasks,
                    capacity=health.capacity,
                    proxy_version=health.proxy_version,
                    rclone_version=health.rclone_version,
                    reason=incompat_reason,
                )
                return str(ProxyState.OFFLINE)

            # Health poll succeeded
            new_successes = status.consecutive_successes + 1
            target_state: str
            if current_state == ProxyState.ONLINE:
                target_state = ProxyState.ONLINE
                reason = None
            elif new_successes >= self.online_after_successes:
                target_state = ProxyState.ONLINE
                reason = f"Online after {new_successes} consecutive successful health checks"
            else:
                target_state = current_state
                reason = None

            ProxyRepository.apply_probe_result(
                session=session,
                proxy=proxy,
                new_state=target_state,
                latency_ms=latency_ms,
                running_tasks=health.running_tasks,
                capacity=health.capacity,
                proxy_version=health.proxy_version,
                rclone_version=health.rclone_version,
                cert_expires_at=health.cert_expires_at,
                reason=reason,
            )
            return target_state

        except TLSFingerprintMismatchError as exc:
            # Immediate transition to untrusted on certificate mismatch
            logger.warning("proxy_untrusted_detected", proxy_id=str(proxy.id), error=str(exc))
            if current_state != ProxyState.UNTRUSTED:
                try:
                    self.notification_service.notify_proxy_untrusted(
                        session=session,
                        proxy=proxy,
                        reason=str(exc),
                    )
                except Exception as notif_exc:
                    logger.error(
                        "notify_proxy_untrusted_failed",
                        proxy_id=str(proxy.id),
                        error=str(notif_exc),
                    )

            ProxyRepository.apply_probe_result(
                session=session,
                proxy=proxy,
                new_state=ProxyState.UNTRUSTED,
                is_success=False,
                error_code=ErrorCode.PROXY_CERT_MISMATCH,
                reason=f"TLS certificate mismatch: {exc}",
            )
            return str(ProxyState.UNTRUSTED)

        except ProxyUnauthorizedError as exc:
            # Immediate transition to unauthorized on HTTP 401
            logger.warning("proxy_unauthorized_detected", proxy_id=str(proxy.id), error=str(exc))
            ProxyRepository.apply_probe_result(
                session=session,
                proxy=proxy,
                new_state=ProxyState.UNAUTHORIZED,
                is_success=False,
                error_code=ErrorCode.PROXY_UNAUTHORIZED,
                reason=f"Proxy rejected token: {exc}",
            )
            return str(ProxyState.UNAUTHORIZED)

        except ProxyUnreachableError:
            # Connection or timeout error -> evaluate hysteresis before marking offline
            new_failures = status.consecutive_failures + 1
            if current_state == ProxyState.OFFLINE:
                target_state = ProxyState.OFFLINE
                reason = None
            elif new_failures >= self.offline_after_failures:
                target_state = ProxyState.OFFLINE
                reason = f"Offline after {new_failures} consecutive connection failures"
            else:
                target_state = current_state
                reason = None

            if current_state != ProxyState.OFFLINE and target_state == ProxyState.OFFLINE:
                try:
                    self.notification_service.notify_proxy_offline(
                        session=session,
                        proxy=proxy,
                        reason=reason or "Proxy non raggiungibile",
                        consecutive_failures=new_failures,
                    )
                except Exception as exc:
                    logger.error(
                        "notify_proxy_offline_failed", proxy_id=str(proxy.id), error=str(exc)
                    )

            ProxyRepository.apply_probe_result(
                session=session,
                proxy=proxy,
                new_state=target_state,
                is_success=False,
                error_code=ErrorCode.PROXY_UNREACHABLE,
                reason=reason,
            )
            return target_state

    def tick(self) -> dict[UUID, str]:
        """Perform a single monitoring pass over all enabled proxies."""
        results: dict[UUID, str] = {}
        with self.session_factory() as session:
            try:
                proxies = ProxyRepository.get_all_enabled_proxies(session)
                for proxy in proxies:
                    res_state = self.check_proxy(session, proxy)
                    results[proxy.id] = res_state
                session.commit()
            except Exception as exc:
                session.rollback()
                logger.error("health_monitor_tick_failed", error=str(exc))
        return results

    def start(self) -> None:
        """Start the background monitoring loop."""
        if self._thread is not None and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="HealthMonitorLoop",
            daemon=True,
        )
        self._thread.start()
        logger.info("health_monitor_started", interval_s=self.heartbeat_interval_s)

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the background monitoring loop."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info("health_monitor_stopped")

    def _run_loop(self) -> None:
        """Internal background loop execution."""
        while not self._stop_event.is_set():
            start_ts = time.time()
            self.tick()
            elapsed = time.time() - start_ts
            sleep_time = max(0.1, self.heartbeat_interval_s - elapsed)
            self._stop_event.wait(timeout=sleep_time)
