"""Supervisor entrypoint for EmberVault Orchestrator service."""

from __future__ import annotations

import signal
import sys
import time
from typing import Any

from embervault_common.config import DatabaseSettings, OrchestratorSettings
from embervault_common.observability import configure_logging, get_logger
from embervault_db.session import create_engine_from_settings, create_session_factory
from embervault_orchestrator.advisory_lock import PostgresAdvisoryLock
from embervault_orchestrator.factory import create_orchestrator_app
from embervault_orchestrator.health_monitor import HealthMonitor
from embervault_orchestrator.reconciler import ExecutionReconciler

logger = get_logger("embervault_orchestrator.main")


class OrchestratorSupervisor:
    """Coordinates leader election, background health monitoring, and web service lifecycle."""

    def __init__(
        self,
        orch_settings: OrchestratorSettings | None = None,
        db_settings: DatabaseSettings | None = None,
    ) -> None:
        self.orch_settings = orch_settings or OrchestratorSettings.load()
        self.db_settings = db_settings or DatabaseSettings.load()

        configure_logging(
            service="orchestrator",
            log_level=self.orch_settings.log_level,
            log_format=self.orch_settings.log_format,
        )

        self.engine = create_engine_from_settings(self.db_settings)
        self.session_factory = create_session_factory(self.engine)
        self.advisory_lock = PostgresAdvisoryLock(self.session_factory)
        self.health_monitor = HealthMonitor(
            session_factory=self.session_factory,
            settings=self.orch_settings,
        )
        self.execution_reconciler = ExecutionReconciler(
            session_factory=self.session_factory,
        )
        self.app = create_orchestrator_app(self.orch_settings)
        self._running = False

    def start(self) -> bool:
        """Attempt to acquire leader lock and start orchestrator subsystems.

        Returns:
            True if started as leader, False if standby (lock busy).
        """
        logger.info("orchestrator_startup_attempt")

        if not self.advisory_lock.acquire():
            logger.warning(
                "orchestrator_standby",
                message="Another orchestrator instance holds the leader lock. Remaining in standby.",
            )
            return False

        logger.info("orchestrator_leader_active")
        self._running = True

        # Abort or retry stale active runs left over from prior crash or reboot
        try:
            from embervault_db.repositories.execution_repository import ExecutionRepository

            with self.session_factory() as session:
                policy_events: list[dict[str, Any]] = []
                aborted = ExecutionRepository.abort_stale_running_runs_on_startup(
                    session, policy_events_out=policy_events
                )
                for ev in policy_events:
                    ev_job = ev.get("job")
                    if ev_job and getattr(ev_job, "pending_notify", False):
                        self.execution_reconciler.notification_service.notify_job_policy_executed(
                            session,
                            ev_job,
                            policy_type="pending",
                            policy_value=ev["policy_value"],
                            message=ev["message"],
                            run_id=ev["run"].id,
                        )
                if aborted:
                    session.commit()
                    logger.warning("stale_running_runs_aborted_on_startup", count=aborted)
        except Exception as exc:
            logger.error("stale_runs_cleanup_on_startup_failed", error=str(exc))

        self.health_monitor.start()
        self.execution_reconciler.start()
        return True

    def stop(self) -> None:
        """Stop background services and release leadership lock."""
        logger.info("orchestrator_shutdown_initiating")
        self._running = False
        self.execution_reconciler.stop()
        self.health_monitor.stop()
        self.advisory_lock.release()
        logger.info("orchestrator_shutdown_complete")

    def run_forever(self) -> None:
        """Run supervisor in foreground with signal handlers."""

        def _signal_handler(signum: int, _frame: Any) -> None:
            logger.info("signal_received", signal=signum)
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        if not self.start():
            # In standby mode, sleep until signaled
            while True:
                time.sleep(10)

        while self._running:
            time.sleep(1)


def main() -> None:
    """CLI entrypoint for running the Orchestrator service."""
    supervisor = OrchestratorSupervisor()
    supervisor.run_forever()


if __name__ == "__main__":
    main()
