"""Unit tests for RClone options and filters inheritance and resolution."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from embervault_common.rclone.filters import (
    evaluate_filters,
    filter_paths,
    match_path_rule,
    parse_filter_rules,
)
from embervault_common.rclone.options import resolve_job_rclone_options


class DummyJob:
    def __init__(
        self,
        max_attempts: int | None = None,
        rclone_options: dict[str, Any] | None = None,
    ) -> None:
        self.max_attempts = max_attempts
        self.rclone_options = rclone_options or {}


class TestFilterParsingAndMatching:
    """Test filter parsing, wildcard matching, and evaluation."""

    def test_parse_filter_rules_string_and_list(self) -> None:
        raw_str = "+ *.pdf\n- *.tmp\n# comment\n+ */**"
        parsed = parse_filter_rules(raw_str)
        assert parsed == ["+ *.pdf", "- *.tmp", "+ */**"]

        raw_list = ["+ *.pdf", "- *.tmp", "unprefixed_pattern"]
        parsed_list = parse_filter_rules(raw_list)
        assert parsed_list == ["+ *.pdf", "- *.tmp", "- unprefixed_pattern"]

    def test_first_level_and_second_level_filter_logic(self) -> None:
        """Test prompt's filter rules on directories and files."""
        f1_rules = ["- folder1/**", "- *.txt", "+ */**"]
        f2_rules = ["- *.txt", "- File*", "+ */**"]

        # First-level filter directory evaluation
        assert evaluate_filters("folder1", f1_rules, is_dir=True) is False
        assert evaluate_filters("folder2", f1_rules, is_dir=True) is True
        assert evaluate_filters("folder3", f1_rules, is_dir=True) is True

        # First-level filter root files evaluation
        root_files = ["file1.pdf", "file2.pdf", "file3.txt"]
        filtered_root = filter_paths(root_files, f1_rules, is_dir=False)
        assert filtered_root == ["file1.pdf", "file2.pdf"]

        # Second-level filter on folder2 files
        f2_folder2 = ["file6.pdf", "file7.txt"]
        filtered_folder2 = filter_paths(f2_folder2, f2_rules, is_dir=False)
        assert filtered_folder2 == ["file6.pdf"]

        # Second-level filter on folder3 files (case sensitive 'File*')
        f3_folder3 = ["File8.pdf", "file9.txt"]
        filtered_folder3 = filter_paths(f3_folder3, f2_rules, is_dir=False)
        assert filtered_folder3 == []


class TestOptionsInheritance:
    """Test resolution of per-job parameters overriding global settings."""

    def test_job_overrides_global_settings(self) -> None:
        store = MagicMock()
        store.get_setting.side_effect = lambda k: {
            "task_retries": 2,
            "rclone_checkers": 8,
            "rclone_transfers": 4,
            "rclone_check_first": False,
            "rclone_recurse": True,
            "rclone_order_by": "size,asc",
            "rclone_first_level_filters": ["+ *.jpg"],
            "rclone_second_level_filters": ["+ *.png"],
        }.get(k)

        job = DummyJob(
            rclone_options={
                "retry_count": 5,
                "checkers": 16,
                "transfers": 8,
                "check_first": True,
                "recurse": False,
                "order_by": "name,desc",
                "first_level_filters": ["- folder1/**", "+ */**"],
                "second_level_filters": ["- *.txt", "+ */**"],
            }
        )

        resolved_opts, max_attempts = resolve_job_rclone_options(job, store)

        assert max_attempts == 6  # retry_count 5 -> max_attempts 6
        assert resolved_opts["retry_count"] == 5
        assert resolved_opts["checkers"] == 16
        assert resolved_opts["transfers"] == 8
        assert resolved_opts["check_first"] is True
        assert resolved_opts["recurse"] is False
        assert resolved_opts["order_by"] == "name,desc"
        assert resolved_opts["first_level_filters"] == ["- folder1/**", "+ */**"]
        assert resolved_opts["second_level_filters"] == ["- *.txt", "+ */**"]

    def test_job_inherits_globals_when_unspecified(self) -> None:
        store = MagicMock()
        store.get_setting.side_effect = lambda k: {
            "task_retries": 3,
            "rclone_checkers": 12,
            "rclone_transfers": 6,
            "rclone_check_first": True,
            "rclone_recurse": False,
            "rclone_order_by": "size,desc",
            "rclone_first_level_filters": ["- *.tmp", "+ */**"],
            "rclone_second_level_filters": ["- *.log", "+ */**"],
        }.get(k)

        job = DummyJob(rclone_options={})

        resolved_opts, max_attempts = resolve_job_rclone_options(job, store)

        assert max_attempts == 4  # retry_count 3 -> max_attempts 4
        assert resolved_opts["retry_count"] == 3
        assert resolved_opts["checkers"] == 12
        assert resolved_opts["transfers"] == 6
        assert resolved_opts["check_first"] is True
        assert resolved_opts["recurse"] is False
        assert resolved_opts["order_by"] == "size,desc"
        assert resolved_opts["first_level_filters"] == ["- *.tmp", "+ */**"]
        assert resolved_opts["second_level_filters"] == ["- *.log", "+ */**"]

    def test_job_additional_args_resolution_and_sanitization(self) -> None:
        store = MagicMock()
        store.get_setting.return_value = None

        job = DummyJob(
            rclone_options={
                "additional_args": [
                    "--fast-list",
                    "--min-size 10M",
                    "invalid-flag",
                    "--rc",
                    "--fast-list",  # duplicate
                    "--ignore-existing",
                ]
            }
        )

        resolved_opts, _ = resolve_job_rclone_options(job, store)
        assert resolved_opts["additional_args"] == [
            "--fast-list",
            "--min-size 10M",
            "--ignore-existing",
        ]
