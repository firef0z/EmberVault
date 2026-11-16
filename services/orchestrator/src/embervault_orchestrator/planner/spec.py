"""Pure planning specifications and task generation for EmberVault backup jobs."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Literal

from embervault_common.contracts.enums import TaskKind, TaskOperation, TaskScope
from embervault_common.rclone.filters import evaluate_filters, filter_paths


@dataclass(frozen=True)
class DiscoveryResult:
    """Outcome of a folder discovery listing."""

    subfolders: list[str] = field(default_factory=list)
    root_files: list[str] = field(default_factory=list)
    subfolder_files: dict[str, list[str]] = field(default_factory=dict)
    truncated: bool = False


@dataclass(frozen=True)
class JobPlanningSpec:
    """Pure definition parameters of a backup job required for planning."""

    source_type: Literal["folder", "files"]
    parallel_mode: Literal["none", "by_subfolder"]
    operation: TaskOperation = TaskOperation.COPY
    source_path: str = ""
    dest_path: str = ""
    files_list: list[str] | None = None
    files_per_task: int | None = None
    first_level_filters: list[str] = field(default_factory=list)
    second_level_filters: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PlannedTask:
    """Planned unit of work ready to be materialized as a database Task."""

    kind: TaskKind
    scope: TaskScope
    operation: TaskOperation
    source_subpath: str = ""
    dest_subpath: str = ""
    files_from: list[str] | None = None
    max_depth: int | None = None
    include_root_files_only: bool = False
    status: str = "ready"
    skip_reason: str | None = None
    filters: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)


def plan_job_tasks(
    job: JobPlanningSpec,
    discovery: DiscoveryResult | None = None,
) -> list[PlannedTask]:
    """Pure planning function generating tasks according to §4.1 and filter specifications.

    Args:
        job: Job planning configuration parameters and filters.
        discovery: Authoritative discovery listing (required for by_subfolder).

    Returns:
        List of PlannedTask specifications with status 'ready' or 'skipped'.

    Raises:
        ValueError: On incompatible options, missing discovery, or empty files list.
    """
    f1_rules = list(job.first_level_filters)
    f2_rules = list(job.second_level_filters)
    base_options = dict(job.options)

    # 1. Recursive parallelized by subfolder (§4.1)
    if job.parallel_mode == "by_subfolder":
        if job.source_type != "folder":
            raise ValueError("by_subfolder planning mode requires source_type='folder'.")

        # R5: by_subfolder is only permitted with copy, not sync
        if job.operation == TaskOperation.SYNC:
            raise ValueError(
                "by_subfolder parallelization is not supported with destructive sync operation (Rule R5)."
            )

        if discovery is None:
            raise ValueError("DiscoveryResult is required for by_subfolder planning mode.")

        tasks: list[PlannedTask] = []

        # Task 1: Root files task (--max-depth 1)
        root_status = "ready"
        root_skip_reason: str | None = None
        root_files_from: list[str] | None = None
        if f1_rules and discovery.root_files:
            accepted_root_files = filter_paths(discovery.root_files, f1_rules, is_dir=False)
            if len(accepted_root_files) == 0:
                root_status = "skipped"
                root_skip_reason = (
                    "Tutti i file della radice sono stati esclusi dai filtri di primo livello"
                )
            else:
                root_files_from = accepted_root_files

        tasks.append(
            PlannedTask(
                kind=TaskKind.TRANSFER,
                scope=TaskScope.ROOT_FILES,
                operation=job.operation,
                source_subpath="",
                dest_subpath="",
                max_depth=1,
                include_root_files_only=True,
                files_from=root_files_from,
                status=root_status,
                skip_reason=root_skip_reason,
                filters=[] if root_files_from is not None else f1_rules,
                options=base_options,
            )
        )

        # Task 2..N: Exactly one task per discovered subfolder
        for sub in sorted(discovery.subfolders):
            cleaned_sub = sub.strip("/").strip()
            if not cleaned_sub:
                continue

            # First level filter check on subfolder directory
            if f1_rules:
                is_sub_accepted = evaluate_filters(cleaned_sub, f1_rules, is_dir=True)
                if not is_sub_accepted:
                    tasks.append(
                        PlannedTask(
                            kind=TaskKind.TRANSFER,
                            scope=TaskScope.SUBFOLDER,
                            operation=job.operation,
                            source_subpath=cleaned_sub,
                            dest_subpath=cleaned_sub,
                            max_depth=None,
                            include_root_files_only=False,
                            status="skipped",
                            skip_reason=f"Cartella '{cleaned_sub}' esclusa dai filtri di primo livello",
                            filters=f2_rules,
                            options=base_options,
                        )
                    )
                    continue

            # Second level filter check on files inside subfolder (if known)
            sub_files = discovery.subfolder_files.get(cleaned_sub)
            if sub_files is not None and f2_rules:
                accepted_sub_files = filter_paths(sub_files, f2_rules, is_dir=False)
                if len(accepted_sub_files) == 0:
                    tasks.append(
                        PlannedTask(
                            kind=TaskKind.TRANSFER,
                            scope=TaskScope.SUBFOLDER,
                            operation=job.operation,
                            source_subpath=cleaned_sub,
                            dest_subpath=cleaned_sub,
                            max_depth=None,
                            include_root_files_only=False,
                            status="skipped",
                            skip_reason=f"Nessun contenuto da sincronizzare in '{cleaned_sub}' dopo i filtri di secondo livello",
                            filters=f2_rules,
                            options=base_options,
                        )
                    )
                    continue

            # Task is ready
            tasks.append(
                PlannedTask(
                    kind=TaskKind.TRANSFER,
                    scope=TaskScope.SUBFOLDER,
                    operation=job.operation,
                    source_subpath=cleaned_sub,
                    dest_subpath=cleaned_sub,
                    max_depth=None,
                    include_root_files_only=False,
                    status="ready",
                    filters=f2_rules,
                    options=base_options,
                )
            )

        return tasks

    # 2. Files list mode (§4.1)
    if job.source_type == "files":
        if not job.files_list:
            raise ValueError("files_list cannot be empty when source_type='files'.")

        filtered_files = (
            filter_paths(job.files_list, f1_rules, is_dir=False)
            if f1_rules
            else list(job.files_list)
        )
        if not filtered_files:
            return [
                PlannedTask(
                    kind=TaskKind.TRANSFER,
                    scope=TaskScope.FILES,
                    operation=job.operation,
                    source_subpath="",
                    dest_subpath="",
                    files_from=[],
                    status="skipped",
                    skip_reason="Tutti i file sono stati esclusi dai filtri",
                    filters=f1_rules,
                    options=base_options,
                )
            ]

        chunk_size = job.files_per_task
        if chunk_size is None or chunk_size <= 0 or chunk_size >= len(filtered_files):
            return [
                PlannedTask(
                    kind=TaskKind.TRANSFER,
                    scope=TaskScope.FILES,
                    operation=job.operation,
                    source_subpath="",
                    dest_subpath="",
                    files_from=list(filtered_files),
                    status="ready",
                    filters=f1_rules,
                    options=base_options,
                )
            ]

        # Partition files into N tasks
        file_tasks: list[PlannedTask] = []
        total_chunks = math.ceil(len(filtered_files) / chunk_size)
        for i in range(total_chunks):
            chunk = filtered_files[i * chunk_size : (i + 1) * chunk_size]
            file_tasks.append(
                PlannedTask(
                    kind=TaskKind.TRANSFER,
                    scope=TaskScope.FILES,
                    operation=job.operation,
                    source_subpath="",
                    dest_subpath="",
                    files_from=list(chunk),
                    status="ready",
                    filters=f1_rules,
                    options=base_options,
                )
            )
        return file_tasks

    # 3. Whole folder mode (§4.1)
    return [
        PlannedTask(
            kind=TaskKind.TRANSFER,
            scope=TaskScope.WHOLE,
            operation=job.operation,
            source_subpath="",
            dest_subpath="",
            max_depth=None,
            include_root_files_only=False,
            status="ready",
            filters=f1_rules,
            options=base_options,
        )
    ]
