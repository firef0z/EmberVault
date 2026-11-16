"""Data access repository for backup jobs, job sources, and discoveries."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from embervault_common.cron import compute_next_cron_run, validate_timezone_name
from embervault_db.models.execution import JobRun
from embervault_db.models.proxy import Proxy
from embervault_db.models.remotes import Job, JobDiscovery, RcloneRemote


def calculate_discovery_level(
    task_count: int,
    warn_limit: int = 50,
    hard_limit: int = 500,
    enabled_proxy_count: int = 1,
) -> str:
    """Calculate discovery status level ('ok', 'warn', 'blocked') based on task count and enabled proxies."""
    if task_count > hard_limit:
        return "blocked"
    proxies = max(1, enabled_proxy_count)
    if (task_count / proxies) > warn_limit:
        return "warn"
    return "ok"


def compute_next_run_at(
    cron_expr: str | None,
    tz_name: str = "UTC",
    base_time: Any | None = None,
    previous_fire_time: Any | None = None,
    follow_dst: bool = True,
) -> Any | None:
    """Calculate the next fire time for a cron expression in UTC."""
    return compute_next_cron_run(
        cron_expr=cron_expr,
        tz_name=tz_name,
        base_time=base_time,
        previous_fire_time=previous_fire_time,
        follow_dst=follow_dst,
    )


_UNSET = object()

VALID_MISSED_RUN_POLICIES = frozenset({"skip", "run_once", "fail"})
VALID_OVERLAP_POLICIES = frozenset({"skip", "allow", "cancel_previous", "queue", "fail"})
VALID_PENDING_POLICIES = frozenset({"fail", "retry"})


class JobRepository:
    """Repository handling CRUD, discovery records, and execution integrity for Jobs."""

    @staticmethod
    def create_job(
        session: Session,
        name: str,
        source_remote_id: UUID,
        source_path: str,
        destination_remote_id: UUID,
        destination_path: str,
        operation: str = "copy",
        parallelization: str = "none",
        discovery_status: str = "not_required",
        last_discovery_id: UUID | None = None,
        schedule_cron: str | None = None,
        timezone: str = "UTC",
        follow_dst: bool = True,
        missed_run_policy: str | None = None,
        overlap_policy: str | None = None,
        pending_policy: str | None = None,
        max_runtime_minutes: int | None = None,
        missed_run_notify: bool = False,
        overlap_notify: bool = False,
        pending_notify: bool = False,
        max_runtime_notify: bool = False,
        max_parallel_tasks: int | None = None,
        files_per_task: int | None = None,
        task_timeout_s: int | None = 3600,
        rclone_options: dict[str, Any] | None = None,
        created_by: UUID | None = None,
        is_enabled: bool = True,
        notifications_enabled: bool = True,
        notification_policy: str | None = None,
        assigned_proxy_ids: list[UUID] | None = None,
        pre_run_hook: str | None = None,
        post_run_hook: str | None = None,
    ) -> Job:
        """Create and persist a new backup job."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Il nome del job non può essere vuoto.")

        # Ensure uniqueness
        existing = JobRepository.get_job_by_name(session, clean_name)
        if existing is not None:
            raise ValueError(f"Un job con il nome '{clean_name}' esiste già.")

        # Validate remotes exist
        src_remote = session.get(RcloneRemote, source_remote_id)
        if src_remote is None:
            raise ValueError(f"Remote sorgente {source_remote_id} non trovato.")

        dst_remote = session.get(RcloneRemote, destination_remote_id)
        if dst_remote is None:
            raise ValueError(f"Remote destinazione {destination_remote_id} non trovato.")

        if (
            source_remote_id == destination_remote_id
            and source_path.strip() == destination_path.strip()
        ):
            raise ValueError(
                "Sorgente e destinazione non possono coincidere sullo stesso percorso dello stesso remote."
            )

        # Validate operations and policies
        if operation not in ("copy", "sync"):
            raise ValueError(
                f"Operazione non supportata: {operation}. Valori ammessi: 'copy', 'sync'."
            )

        if parallelization not in ("none", "by_subfolder"):
            raise ValueError(
                f"Parallelizzazione non valida: {parallelization}. Valori ammessi: 'none', 'by_subfolder'."
            )

        if missed_run_policy is not None and missed_run_policy not in VALID_MISSED_RUN_POLICIES:
            raise ValueError(f"Missed run policy non valida: {missed_run_policy}.")

        if overlap_policy is not None and overlap_policy not in VALID_OVERLAP_POLICIES:
            raise ValueError(f"Overlap policy non valida: {overlap_policy}.")

        if pending_policy is not None and pending_policy not in VALID_PENDING_POLICIES:
            raise ValueError(f"Pending policy non valida: {pending_policy}.")

        if max_runtime_minutes is not None:
            max_runtime_minutes = int(max_runtime_minutes)
            if max_runtime_minutes < 1:
                raise ValueError("Max runtime deve essere almeno 1 minuto.")

        if notification_policy:
            notification_policy = notification_policy.strip()
            if notification_policy not in ("always", "only_errors"):
                raise ValueError(
                    f"Notification policy non valida: {notification_policy}. Valori ammessi: 'always', 'only_errors'."
                )
        else:
            notification_policy = None

        assigned_proxies = []
        if assigned_proxy_ids:
            proxies = list(
                session.scalars(select(Proxy).where(Proxy.id.in_(assigned_proxy_ids))).all()
            )
            found_ids = {p.id for p in proxies}
            missing = set(assigned_proxy_ids) - found_ids
            if missing:
                raise ValueError(f"Proxy con ID {missing} non trovati.")
            assigned_proxies = proxies

        # Validate that assigned proxies can reach the required remotes
        JobRepository.validate_job_proxies_reachability(
            session=session,
            source_remote_id=source_remote_id,
            destination_remote_id=destination_remote_id,
            assigned_proxies=assigned_proxies,
        )

        clean_cron = schedule_cron.strip() if schedule_cron else None
        clean_tz = validate_timezone_name(timezone or "UTC")
        clean_follow_dst = bool(follow_dst)
        computed_next_run = (
            compute_next_run_at(clean_cron, clean_tz, follow_dst=clean_follow_dst)
            if (is_enabled and clean_cron)
            else None
        )

        job_id = uuid4()
        job = Job(
            id=job_id,
            name=clean_name,
            enabled=is_enabled,
            notifications_enabled=notifications_enabled,
            notification_policy=notification_policy,
            source_remote_id=source_remote_id,
            source_path=source_path.strip(),
            destination_remote_id=destination_remote_id,
            destination_path=destination_path.strip(),
            source_kind="folder",
            operation=operation,
            parallelization=parallelization,
            discovery_status=discovery_status,
            last_discovery_id=last_discovery_id,
            schedule_cron=clean_cron,
            timezone=clean_tz,
            follow_dst=clean_follow_dst,
            missed_run_policy=missed_run_policy,
            overlap_policy=overlap_policy,
            pending_policy=pending_policy,
            max_runtime_minutes=max_runtime_minutes,
            missed_run_notify=bool(missed_run_notify),
            overlap_notify=bool(overlap_notify),
            pending_notify=bool(pending_notify),
            max_runtime_notify=bool(max_runtime_notify),
            max_parallel_tasks=max_parallel_tasks or 4,
            files_per_task=files_per_task,
            task_timeout_s=task_timeout_s or 3600,
            rclone_options=rclone_options or {},
            pre_run_hook=pre_run_hook.strip() if pre_run_hook and pre_run_hook.strip() else None,
            post_run_hook=post_run_hook.strip()
            if post_run_hook and post_run_hook.strip()
            else None,
            next_run_at=computed_next_run,
            created_by=created_by,
        )
        if assigned_proxies:
            job.assigned_proxies = assigned_proxies

        session.add(job)
        session.flush()
        return job

    @staticmethod
    def get_job_by_id(session: Session, job_id: UUID) -> Job | None:
        """Retrieve job by primary key UUID."""
        return session.get(Job, job_id)

    @staticmethod
    def get_job_by_name(session: Session, name: str) -> Job | None:
        """Retrieve job by unique name."""
        return session.scalar(select(Job).where(Job.name == name.strip()))

    @staticmethod
    def list_jobs(session: Session, include_disabled: bool = True) -> list[Job]:
        """List all configured jobs ordered by name."""
        stmt = select(Job)
        if not include_disabled:
            stmt = stmt.where(Job.enabled.is_(True))
        stmt = stmt.order_by(Job.name)
        return list(session.scalars(stmt).all())

    @staticmethod
    def update_job(
        session: Session,
        job_id: UUID,
        name: str | None = None,
        source_remote_id: UUID | None = None,
        source_path: str | None = None,
        destination_remote_id: UUID | None = None,
        destination_path: str | None = None,
        operation: str | None = None,
        parallelization: str | None = None,
        discovery_status: str | None = None,
        last_discovery_id: UUID | None = None,
        schedule_cron: str | None = None,
        timezone: str | None = None,
        follow_dst: bool | None = None,
        missed_run_policy: str | None | object = _UNSET,
        overlap_policy: str | None | object = _UNSET,
        pending_policy: str | None | object = _UNSET,
        max_runtime_minutes: int | None = None,
        clear_max_runtime: bool = False,
        missed_run_notify: bool | None = None,
        overlap_notify: bool | None = None,
        pending_notify: bool | None = None,
        max_runtime_notify: bool | None = None,
        max_parallel_tasks: int | None = None,
        task_timeout_s: int | None = None,
        rclone_options: dict[str, Any] | None = None,
        is_enabled: bool | None = None,
        notifications_enabled: bool | None = None,
        notification_policy: str | None | object = _UNSET,
        assigned_proxy_ids: list[UUID] | None = None,
        pre_run_hook: str | None = None,
        post_run_hook: str | None = None,
    ) -> Job:
        """Update job configuration."""
        job = session.get(Job, job_id)
        if job is None:
            raise ValueError(f"Job con ID '{job_id}' non trovato.")

        if name is not None:
            clean_name = name.strip()
            if not clean_name:
                raise ValueError("Il nome del job non può essere vuoto.")
            existing = JobRepository.get_job_by_name(session, clean_name)
            if existing is not None and existing.id != job_id:
                raise ValueError(f"Un job con il nome '{clean_name}' esiste già.")
            job.name = clean_name

        if is_enabled is not None:
            job.enabled = is_enabled

        if notifications_enabled is not None:
            job.notifications_enabled = notifications_enabled

        if notification_policy is not _UNSET:
            if notification_policy:
                clean_policy = str(notification_policy).strip()
                if clean_policy not in ("always", "only_errors"):
                    raise ValueError(
                        f"Notification policy non valida: {clean_policy}. Valori ammessi: 'always', 'only_errors'."
                    )
                job.notification_policy = clean_policy
            else:
                job.notification_policy = None

        if source_remote_id is not None:
            src = session.get(RcloneRemote, source_remote_id)
            if src is None:
                raise ValueError(f"Remote sorgente {source_remote_id} non trovato.")
            job.source_remote_id = source_remote_id

        if source_path is not None:
            job.source_path = source_path.strip()

        if destination_remote_id is not None:
            dst = session.get(RcloneRemote, destination_remote_id)
            if dst is None:
                raise ValueError(f"Remote destinazione {destination_remote_id} non trovato.")
            job.destination_remote_id = destination_remote_id

        if destination_path is not None:
            job.destination_path = destination_path.strip()

        if operation is not None:
            if operation not in ("copy", "sync"):
                raise ValueError(f"Operazione non valida: {operation}.")
            job.operation = operation

        if parallelization is not None:
            if parallelization not in ("none", "by_subfolder"):
                raise ValueError(f"Parallelizzazione non valida: {parallelization}.")
            job.parallelization = parallelization

        if discovery_status is not None:
            job.discovery_status = discovery_status

        if last_discovery_id is not None:
            job.last_discovery_id = last_discovery_id

        if (
            schedule_cron is not None
            or timezone is not None
            or follow_dst is not None
            or is_enabled is not None
        ):
            if schedule_cron is not None:
                job.schedule_cron = schedule_cron.strip() if schedule_cron else None
            if timezone is not None:
                job.timezone = validate_timezone_name(timezone)
            if follow_dst is not None:
                job.follow_dst = bool(follow_dst)
            if job.enabled and job.schedule_cron:
                job.next_run_at = compute_next_run_at(
                    job.schedule_cron,
                    job.timezone,
                    follow_dst=bool(getattr(job, "follow_dst", True)),
                )
            else:
                job.next_run_at = None

        if missed_run_policy is not _UNSET:
            if missed_run_policy is not None:
                m_str = str(missed_run_policy).strip()
                if m_str not in VALID_MISSED_RUN_POLICIES:
                    raise ValueError(f"Missed run policy non valida: {missed_run_policy}.")
                job.missed_run_policy = m_str
            else:
                job.missed_run_policy = None

        if overlap_policy is not _UNSET:
            if overlap_policy is not None:
                o_str = str(overlap_policy).strip()
                if o_str not in VALID_OVERLAP_POLICIES:
                    raise ValueError(f"Overlap policy non valida: {overlap_policy}.")
                job.overlap_policy = o_str
            else:
                job.overlap_policy = None

        if pending_policy is not _UNSET:
            if pending_policy is not None:
                p_str = str(pending_policy).strip()
                if p_str not in VALID_PENDING_POLICIES:
                    raise ValueError(f"Pending policy non valida: {pending_policy}.")
                job.pending_policy = p_str
            else:
                job.pending_policy = None

        if clear_max_runtime:
            job.max_runtime_minutes = None
        elif max_runtime_minutes is not None:
            parsed_max_rt = int(max_runtime_minutes)
            if parsed_max_rt < 1:
                raise ValueError("Max runtime deve essere almeno 1 minuto.")
            job.max_runtime_minutes = parsed_max_rt

        if missed_run_notify is not None:
            job.missed_run_notify = bool(missed_run_notify)

        if overlap_notify is not None:
            job.overlap_notify = bool(overlap_notify)

        if pending_notify is not None:
            job.pending_notify = bool(pending_notify)

        if max_runtime_notify is not None:
            job.max_runtime_notify = bool(max_runtime_notify)

        if max_parallel_tasks is not None:
            job.max_parallel_tasks = max_parallel_tasks

        if task_timeout_s is not None:
            job.task_timeout_s = task_timeout_s

        if rclone_options is not None:
            job.rclone_options = rclone_options

        if assigned_proxy_ids is not None:
            if assigned_proxy_ids:
                proxies = list(
                    session.scalars(select(Proxy).where(Proxy.id.in_(assigned_proxy_ids))).all()
                )
                found_ids = {p.id for p in proxies}
                missing = set(assigned_proxy_ids) - found_ids
                if missing:
                    raise ValueError(f"Proxy con ID {missing} non trovati.")
                job.assigned_proxies = proxies
            else:
                job.assigned_proxies = []

        if pre_run_hook is not None:
            job.pre_run_hook = pre_run_hook.strip() if pre_run_hook.strip() else None

        if post_run_hook is not None:
            job.post_run_hook = post_run_hook.strip() if post_run_hook.strip() else None

        JobRepository.validate_job_proxies_reachability(
            session=session,
            source_remote_id=job.source_remote_id,
            destination_remote_id=job.destination_remote_id,
            assigned_proxies=job.assigned_proxies,
        )

        session.flush()
        return job

    @staticmethod
    def delete_job(session: Session, job_id: UUID) -> tuple[bool, str | None]:
        """Delete job if not actively executing."""
        job = session.get(Job, job_id)
        if job is None:
            return False, "Job non trovato."

        # Check active runs
        active_run = session.scalar(
            select(JobRun)
            .where(JobRun.job_id == job_id)
            .where(JobRun.status.in_(["queued", "planning", "awaiting_confirmation", "running"]))
            .limit(1)
        )
        if active_run is not None:
            return (
                False,
                f"Impossibile eliminare il job '{job.name}': ha un'esecuzione attiva in corso (ID: {active_run.id}).",
            )

        session.delete(job)
        session.flush()
        return True, None

    @staticmethod
    def record_discovery(
        session: Session,
        source_remote_id: UUID,
        source_path: str,
        subfolders: list[str],
        root_file_count: int = 0,
        trigger: str = "job_form",
        job_id: UUID | None = None,
        requested_by: UUID | None = None,
        proxy_id: UUID | None = None,
        status: str = "succeeded",
        error_code: str | None = None,
        root_files: list[str] | None = None,
        subfolder_files: dict[str, list[str]] | None = None,
        enabled_proxy_count: int = 1,
    ) -> JobDiscovery:
        """Persist a source discovery result with task count estimate and threshold level."""
        src_remote = session.get(RcloneRemote, source_remote_id)
        version = src_remote.version if src_remote else 1

        folder_count = len(subfolders)
        include_root_files = root_file_count > 0
        task_count = max(1, (1 if include_root_files else 0) + folder_count)
        level = calculate_discovery_level(task_count, enabled_proxy_count=enabled_proxy_count)

        entries: dict[str, Any] = {
            "subfolders": subfolders,
            "root_file_count": root_file_count,
        }
        if root_files is not None:
            entries["root_files"] = root_files
        if subfolder_files is not None:
            entries["subfolder_files"] = subfolder_files

        discovery_id = uuid4()
        disc = JobDiscovery(
            id=discovery_id,
            job_id=job_id,
            source_remote_id=source_remote_id,
            source_remote_version=version,
            source_path=source_path.strip(),
            requested_by=requested_by,
            trigger=trigger,
            proxy_id=proxy_id,
            status=status,
            folder_count=folder_count,
            root_file_count=root_file_count,
            task_count_estimate=task_count,
            level=level,
            entries=entries,
            error_code=error_code,
        )
        session.add(disc)
        session.flush()

        # If associated with a job, update last_discovery_id
        if job_id:
            job = session.get(Job, job_id)
            if job:
                job.last_discovery_id = discovery_id
                job.discovery_status = "verified" if status == "succeeded" else "unverified"
                session.flush()

        return disc

    @staticmethod
    def get_discovery_by_id(session: Session, discovery_id: UUID) -> JobDiscovery | None:
        """Retrieve discovery result by UUID."""
        return session.get(JobDiscovery, discovery_id)

    @staticmethod
    def get_job_required_remote_ids(session: Session, job: Job) -> set[UUID]:
        """Return all remote IDs required by a job, including source, destination, and referenced remotes."""
        from embervault_db.repositories.remote_repository import RemoteRepository

        required_remote_ids: set[UUID] = set()
        if job.source_remote_id:
            required_remote_ids.add(job.source_remote_id)
        if job.destination_remote_id:
            required_remote_ids.add(job.destination_remote_id)

        for rem_id in [job.source_remote_id, job.destination_remote_id]:
            if not rem_id:
                continue
            rem = session.get(RcloneRemote, rem_id)
            if rem:
                try:
                    cfg = RemoteRepository.get_decrypted_config(rem)
                    refs = RemoteRepository.resolve_referenced_remotes(
                        session=session, backend_type=rem.backend_type, config=cfg
                    )
                    for ref_dict in refs.values():
                        if isinstance(ref_dict, dict) and "id" in ref_dict:
                            required_remote_ids.add(UUID(str(ref_dict["id"])))
                except Exception:
                    pass
        return required_remote_ids

    @staticmethod
    def validate_job_proxies_reachability(
        session: Session,
        source_remote_id: UUID,
        destination_remote_id: UUID,
        assigned_proxies: list[Proxy],
    ) -> None:
        """Ensure all assigned proxies can reach the job's remotes, or at least one proxy can reach both if unassigned."""
        from embervault_db.repositories.remote_repository import RemoteRepository

        src_remote = session.get(RcloneRemote, source_remote_id)
        dst_remote = session.get(RcloneRemote, destination_remote_id)
        src_name = src_remote.name if src_remote else str(source_remote_id)
        dst_name = dst_remote.name if dst_remote else str(destination_remote_id)

        required_remote_ids = {source_remote_id, destination_remote_id}
        if src_remote:
            try:
                src_config = RemoteRepository.get_decrypted_config(src_remote)
                src_refs = RemoteRepository.resolve_referenced_remotes(
                    session=session, backend_type=src_remote.backend_type, config=src_config
                )
                for ref_dict in src_refs.values():
                    if isinstance(ref_dict, dict) and "id" in ref_dict:
                        required_remote_ids.add(UUID(str(ref_dict["id"])))
            except Exception:
                pass

        if dst_remote:
            try:
                dst_config = RemoteRepository.get_decrypted_config(dst_remote)
                dst_refs = RemoteRepository.resolve_referenced_remotes(
                    session=session, backend_type=dst_remote.backend_type, config=dst_config
                )
                for ref_dict in dst_refs.values():
                    if isinstance(ref_dict, dict) and "id" in ref_dict:
                        required_remote_ids.add(UUID(str(ref_dict["id"])))
            except Exception:
                pass

        if assigned_proxies:
            proxies_to_check = assigned_proxies
        else:
            proxies_to_check = list(
                session.scalars(select(Proxy).where(Proxy.is_enabled.is_(True))).all()
            )

        for p in proxies_to_check:
            reachable_ids = {r.id for r in p.reachable_remotes}
            if source_remote_id not in reachable_ids:
                raise ValueError(
                    f"Il proxy '{p.name}' attivato per questo job non può raggiungere il remote sorgente '{src_name}'."
                )
            if destination_remote_id not in reachable_ids:
                raise ValueError(
                    f"Il proxy '{p.name}' attivato per questo job non può raggiungere il remote di destinazione '{dst_name}'."
                )
            for req_id in required_remote_ids:
                if req_id not in reachable_ids:
                    ref_rem = session.get(RcloneRemote, req_id)
                    ref_name = ref_rem.name if ref_rem else str(req_id)
                    raise ValueError(
                        f"Il proxy '{p.name}' attivato per questo job non può raggiungere il remote referenziato '{ref_name}'."
                    )
