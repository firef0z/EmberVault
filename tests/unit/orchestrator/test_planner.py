"""Unit and property-based tests for task planning (§4.1)."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from embervault_common.contracts.enums import TaskKind, TaskOperation, TaskScope
from embervault_orchestrator.planner.spec import (
    DiscoveryResult,
    JobPlanningSpec,
    plan_job_tasks,
)


class TestPlanningModes:
    """Test the three planning modes specified in §4.1."""

    def test_mode_1_whole_folder(self) -> None:
        """Mode 1: Cartella intera generates exactly 1 whole transfer task."""
        job = JobPlanningSpec(
            source_type="folder",
            parallel_mode="none",
            operation=TaskOperation.COPY,
            source_path="/data/photos",
            dest_path="/backup/photos",
        )
        tasks = plan_job_tasks(job)
        assert len(tasks) == 1
        assert tasks[0].kind == TaskKind.TRANSFER
        assert tasks[0].scope == TaskScope.WHOLE
        assert tasks[0].source_subpath == ""
        assert tasks[0].dest_subpath == ""

    def test_mode_2_files_single_task(self) -> None:
        """Mode 2: Files list without chunking generates 1 files transfer task."""
        job = JobPlanningSpec(
            source_type="files",
            parallel_mode="none",
            operation=TaskOperation.COPY,
            files_list=["file1.txt", "file2.txt", "file3.txt"],
        )
        tasks = plan_job_tasks(job)
        assert len(tasks) == 1
        assert tasks[0].kind == TaskKind.TRANSFER
        assert tasks[0].scope == TaskScope.FILES
        assert tasks[0].files_from == ["file1.txt", "file2.txt", "file3.txt"]

    def test_mode_2_files_chunked(self) -> None:
        """Mode 2: Files list with files_per_task partitions into N tasks."""
        files = [f"file_{i}.dat" for i in range(10)]
        job = JobPlanningSpec(
            source_type="files",
            parallel_mode="none",
            operation=TaskOperation.COPY,
            files_list=files,
            files_per_task=3,
        )
        tasks = plan_job_tasks(job)
        assert len(tasks) == 4  # ceil(10 / 3) = 4 (3, 3, 3, 1)
        assert tasks[0].files_from == files[0:3]
        assert tasks[1].files_from == files[3:6]
        assert tasks[2].files_from == files[6:9]
        assert tasks[3].files_from == files[9:10]

    def test_mode_2_empty_files_raises_error(self) -> None:
        job = JobPlanningSpec(
            source_type="files",
            parallel_mode="none",
            files_list=[],
        )
        with pytest.raises(ValueError, match="files_list cannot be empty"):
            plan_job_tasks(job)

    def test_mode_3_by_subfolder_task_generation(self) -> None:
        """Mode 3: Generates 1 root_files task + 1 task per subfolder."""
        discovery = DiscoveryResult(
            subfolders=["2024", "2025", "archive"],
            root_files=["index.html", "manifest.json"],
        )
        job = JobPlanningSpec(
            source_type="folder",
            parallel_mode="by_subfolder",
            operation=TaskOperation.COPY,
            source_path="/vault",
            dest_path="/backup",
        )
        tasks = plan_job_tasks(job, discovery)

        # Expected: 1 (root_files) + 3 (subfolders) = 4 tasks
        assert len(tasks) == 4

        # Task 0: Root files
        root_task = tasks[0]
        assert root_task.scope == TaskScope.ROOT_FILES
        assert root_task.max_depth == 1
        assert root_task.include_root_files_only is True
        assert root_task.source_subpath == ""

        # Tasks 1..3: Subfolder tasks
        subfolder_tasks = tasks[1:]
        subpaths = [t.source_subpath for t in subfolder_tasks]
        assert subpaths == ["2024", "2025", "archive"]
        for t in subfolder_tasks:
            assert t.scope == TaskScope.SUBFOLDER
            assert t.max_depth is None
            assert t.include_root_files_only is False

    def test_mode_3_sync_is_forbidden(self) -> None:
        """Rule R5: by_subfolder is strictly forbidden with sync operation."""
        job = JobPlanningSpec(
            source_type="folder",
            parallel_mode="by_subfolder",
            operation=TaskOperation.SYNC,
        )
        discovery = DiscoveryResult(subfolders=["sub1"])
        with pytest.raises(ValueError, match="Rule R5"):
            plan_job_tasks(job, discovery)

    def test_mode_3_missing_discovery_raises_error(self) -> None:
        job = JobPlanningSpec(
            source_type="folder",
            parallel_mode="by_subfolder",
            operation=TaskOperation.COPY,
        )
        with pytest.raises(ValueError, match="DiscoveryResult is required"):
            plan_job_tasks(job, None)


class TestPlanningPropertyBased:
    """Hypothesis property-based tests for by_subfolder task count and scope isolation."""

    @given(
        st.lists(
            st.text(
                alphabet=st.characters(categories=["L", "N"]),
                min_size=1,
                max_size=20,
            ),
            min_size=0,
            max_size=50,
            unique=True,
        )
    )
    def test_by_subfolder_exact_count_and_scope_isolation(self, subfolder_names: list[str]) -> None:
        """Verify:

        1. Total tasks = 1 + len(subfolders)
        2. Root task has max_depth=1 and include_root_files_only=True
        3. All subfolder tasks have unique, non-empty, non-overlapping subpaths
        4. No subfolder task duplicates root_files
        """
        discovery = DiscoveryResult(
            subfolders=subfolder_names,
            root_files=["file1.txt"],
        )
        job = JobPlanningSpec(
            source_type="folder",
            parallel_mode="by_subfolder",
            operation=TaskOperation.COPY,
        )
        tasks = plan_job_tasks(job, discovery)

        # 1. Exact count: 1 (root_files) + N (subfolders)
        assert len(tasks) == 1 + len(subfolder_names)

        # 2. Root files task isolation
        root_task = tasks[0]
        assert root_task.scope == TaskScope.ROOT_FILES
        assert root_task.max_depth == 1
        assert root_task.include_root_files_only is True
        assert root_task.source_subpath == ""

        # 3. Subfolder tasks isolation: unique and strictly separated
        sub_tasks = tasks[1:]
        subpaths = [t.source_subpath for t in sub_tasks]
        assert len(subpaths) == len(set(subpaths))  # No duplicates

        # No subfolder subpath is empty (which would overlap root)
        for sp in subpaths:
            assert len(sp) > 0
            assert sp in subfolder_names


class TestRCloneOptionsAndFilters:
    """Test RClone filters, task skipping, and option inheritance according to specification."""

    def test_user_filter_specification_example(self) -> None:
        """Verify the exact user example from the prompt:

        Source structure:
          3 root files: 'file1.pdf', 'file2.pdf', 'file3.txt'
          folder1: 'file4.pdf', 'file5.txt'
          folder2: 'file6.pdf', 'file7.txt'
          folder3: 'File8.pdf', 'file9.txt'

        First level filters:
          - folder1/**
          - *.txt
          + */**

        Second level filters:
          - *.txt
          - File*
          + */**

        Expected:
          Root task: 'file3.txt' discarded, keeps 'file1.pdf', 'file2.pdf' -> READY
          folder1 task: excluded by first-level filter -> SKIPPED
          folder2 task: keeps 'file6.pdf', discards 'file7.txt' -> READY
          folder3 task: discards 'File8.pdf' and 'file9.txt' -> SKIPPED (no files remaining)
        """
        discovery = DiscoveryResult(
            subfolders=["folder1", "folder2", "folder3"],
            root_files=["file1.pdf", "file2.pdf", "file3.txt"],
            subfolder_files={
                "folder1": ["file4.pdf", "file5.txt"],
                "folder2": ["file6.pdf", "file7.txt"],
                "folder3": ["File8.pdf", "file9.txt"],
            },
        )
        spec = JobPlanningSpec(
            source_type="folder",
            parallel_mode="by_subfolder",
            operation=TaskOperation.COPY,
            source_path="/source",
            dest_path="/dest",
            first_level_filters=["- folder1/**", "- *.txt", "+ */**"],
            second_level_filters=["- *.txt", "- File*", "+ */**"],
            options={
                "checkers": 16,
                "transfers": 8,
                "check_first": True,
                "recurse": True,
                "order_by": "size,desc",
            },
        )
        tasks = plan_job_tasks(spec, discovery=discovery)

        # 4 planned tasks total: 1 root + 3 subfolders
        assert len(tasks) == 4

        # 1. Root task
        root_task = tasks[0]
        assert root_task.scope == TaskScope.ROOT_FILES
        assert root_task.status == "ready"
        assert set(root_task.files_from or []) == {"file1.pdf", "file2.pdf"}
        assert "file3.txt" not in (root_task.files_from or [])
        assert root_task.options.get("checkers") == 16
        assert root_task.options.get("transfers") == 8
        assert root_task.options.get("check_first") is True
        assert root_task.options.get("order_by") == "size,desc"

        # 2. folder1 task: filtered by first-level filter -> skipped
        folder1_task = next(t for t in tasks if t.source_subpath == "folder1")
        assert folder1_task.status == "skipped"
        assert "primo livello" in (folder1_task.skip_reason or "").lower()

        # 3. folder2 task: keeps file6.pdf -> ready
        folder2_task = next(t for t in tasks if t.source_subpath == "folder2")
        assert folder2_task.status == "ready"
        assert folder2_task.filters == ["- *.txt", "- File*", "+ */**"]

        # 4. folder3 task: no files remaining after second-level filter -> skipped
        folder3_task = next(t for t in tasks if t.source_subpath == "folder3")
        assert folder3_task.status == "skipped"
        assert "secondo livello" in (folder3_task.skip_reason or "").lower()

    def test_root_files_all_filtered_marks_skipped(self) -> None:
        """If all root files are filtered out by first-level filters, the root task is skipped."""
        discovery = DiscoveryResult(
            subfolders=["folder1"],
            root_files=["file1.tmp", "file2.bak"],
            subfolder_files={"folder1": ["data.csv"]},
        )
        spec = JobPlanningSpec(
            source_type="folder",
            parallel_mode="by_subfolder",
            operation=TaskOperation.COPY,
            first_level_filters=["- *.tmp", "- *.bak", "+ */**"],
        )
        tasks = plan_job_tasks(spec, discovery=discovery)
        assert len(tasks) == 2
        root_task = tasks[0]
        assert root_task.scope == TaskScope.ROOT_FILES
        assert root_task.status == "skipped"
        assert "primo livello" in (root_task.skip_reason or "").lower()
        assert tasks[1].status == "ready"
