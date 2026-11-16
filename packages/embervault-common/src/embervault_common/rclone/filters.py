"""RClone pattern matching and filter evaluation engine.

Implements RClone's filtering specification:
- Rules start with '+' (include) or '-' (exclude).
- Globbing patterns:
  - '*' matches any character except '/'
  - '**' matches any character including '/'
  - '?' matches any single character except '/'
  - Character ranges '[a-z]'
- Case-sensitive by default.
- Rules are evaluated sequentially: the first matching rule decides the outcome.
- If no rule matches, default is include (True).
"""

from __future__ import annotations

import fnmatch
import re
from typing import Sequence


def parse_filter_rules(rules: str | Sequence[str] | None) -> list[str]:
    """Parse a multiline string or sequence of rules into a normalized list of filter rules."""
    if not rules:
        return []

    lines: Sequence[str]
    if isinstance(rules, str):
        lines = rules.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    else:
        lines = rules

    normalized: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Normalize "+rule" to "+ rule" and "-rule" to "- rule"
        if line.startswith("+"):
            pattern = line[1:].strip()
            if pattern:
                normalized.append(f"+ {pattern}")
        elif line.startswith("-"):
            pattern = line[1:].strip()
            if pattern:
                normalized.append(f"- {pattern}")
        else:
            # Default to exclusion or raw rule if prefix missing
            normalized.append(f"- {line}")

    return normalized


def _glob_to_regex(pattern: str) -> str:
    """Translate an rclone glob pattern into a compiled regex pattern string."""
    # Handle leading slash (anchored to root)
    anchored = pattern.startswith("/")
    if anchored:
        pattern = pattern[1:]

    # Split pattern by '**' to handle directory recursion wildcards correctly
    parts = pattern.split("**")
    regex_parts: list[str] = []

    for i, part in enumerate(parts):
        # Escape special regex chars inside part, but keep '*' and '?' for conversion
        subparts = part.split("*")
        sub_regex_parts: list[str] = []
        for j, subpart in enumerate(subparts):
            # Convert '?' to '[^/]' and escape the rest
            escaped = ""
            k = 0
            while k < len(subpart):
                char = subpart[k]
                if char == "?":
                    escaped += "[^/]"
                elif char == "[" and "]" in subpart[k:]:
                    # Character range: keep as is
                    close_idx = subpart.find("]", k)
                    range_content = subpart[k : close_idx + 1]
                    escaped += range_content
                    k = close_idx
                else:
                    escaped += re.escape(char)
                k += 1
            sub_regex_parts.append(escaped)

        # Re-join '*' as '[^/]*'
        part_regex = "[^/]*".join(sub_regex_parts)
        regex_parts.append(part_regex)

    # Re-join '**' as '.*'
    full_regex = ".*".join(regex_parts)

    if anchored:
        return f"^{full_regex}$"
    # If pattern does not contain '/', it matches basename anywhere in the tree
    if "/" not in pattern:
        return f"(?:^|.*/){full_regex}$"
    return f"^{full_regex}$"


def match_path_rule(path: str, pattern: str, is_dir: bool = False) -> bool:
    """Test whether a relative path or directory name matches an RClone glob pattern."""
    clean_path = path.strip().strip("/")
    clean_pattern = pattern.strip()

    # Empty pattern check
    if not clean_pattern:
        return False

    # Directory check: if pattern is e.g. "folder1/**" and we are testing directory "folder1"
    if is_dir:
        # Match "folder1/**", "folder1/*", "folder1/" against directory name "folder1"
        dir_stripped_pattern = clean_pattern.rstrip("/*").rstrip("/")
        if clean_path == dir_stripped_pattern:
            return True
        if fnmatch.fnmatchcase(clean_path, dir_stripped_pattern):
            return True

    # Check exact or glob match
    regex_str = _glob_to_regex(clean_pattern)
    try:
        compiled = re.compile(regex_str)
        if compiled.match(clean_path):
            return True
    except re.error:
        # Fallback to fnmatchcase
        if fnmatch.fnmatchcase(clean_path, clean_pattern):
            return True

    # If is_dir and path + "/*" or path + "/file" could match
    if is_dir:
        test_child = f"{clean_path}/_embervault_test_file_"
        try:
            compiled = re.compile(_glob_to_regex(clean_pattern))
            if compiled.match(test_child):
                return True
        except re.error:
            pass

    return False


def evaluate_filters(
    path: str,
    rules: Sequence[str],
    is_dir: bool = False,
    default_include: bool = True,
) -> bool:
    """Evaluate a path against a list of RClone filter rules.

    Returns:
        True if the path is INCLUDED.
        False if the path is EXCLUDED.
    """
    if not rules:
        return default_include

    clean_path = path.strip().strip("/")

    for raw_rule in rules:
        rule = raw_rule.strip()
        if not rule or rule.startswith("#"):
            continue

        if rule.startswith("+"):
            pattern = rule[1:].strip()
            if match_path_rule(clean_path, pattern, is_dir=is_dir):
                return True
        elif rule.startswith("-"):
            pattern = rule[1:].strip()
            if match_path_rule(clean_path, pattern, is_dir=is_dir):
                return False
        else:
            # Default to exclusion
            if match_path_rule(clean_path, rule, is_dir=is_dir):
                return False

    return default_include


def filter_paths(
    paths: Sequence[str],
    rules: Sequence[str],
    is_dir: bool = False,
) -> list[str]:
    """Filter a list of relative paths, returning only those included."""
    if not rules:
        return list(paths)
    return [p for p in paths if evaluate_filters(p, rules, is_dir=is_dir)]
