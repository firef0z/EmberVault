"""Unit tests for zero-dependency CRON validation and next run calculation."""

from __future__ import annotations

import builtins
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from embervault_common.cron import (
    compute_next_cron_run,
    validate_cron_expression,
    validate_timezone_name,
)


def test_validate_cron_expression_valid() -> None:
    """Verify that standard 5-part crontabs and aliases pass validation."""
    assert validate_cron_expression("0 2 * * *") == "0 2 * * *"
    assert validate_cron_expression("*/15 * * * *") == "*/15 * * * *"
    assert validate_cron_expression("0 0 1,15 * *") == "0 0 1,15 * *"
    assert validate_cron_expression("30 4 * * 1-5") == "30 4 * * 1-5"
    assert validate_cron_expression("59 23 31 12 7") == "59 23 31 12 0"

    # Aliases
    assert validate_cron_expression("@hourly") == "0 * * * *"
    assert validate_cron_expression("@daily") == "0 0 * * *"
    assert validate_cron_expression("@midnight") == "0 0 * * *"
    assert validate_cron_expression("@weekly") == "0 0 * * 0"
    assert validate_cron_expression("@monthly") == "0 0 1 * *"


def test_validate_cron_expression_invalid() -> None:
    """Verify that invalid crontabs raise descriptive ValueErrors."""
    # Empty
    with pytest.raises(ValueError, match="non può essere vuota"):
        validate_cron_expression("")

    # Fewer than 5 parts
    with pytest.raises(ValueError, match="esattamente 5 campi"):
        validate_cron_expression("0 2 * *")

    # More than 5 parts
    with pytest.raises(ValueError, match="esattamente 5 campi"):
        validate_cron_expression("0 2 * * * *")

    # Minute out of bounds (0-59)
    with pytest.raises(ValueError, match="Minuto|60"):
        validate_cron_expression("60 2 * * *")

    # Hour out of bounds (0-23)
    with pytest.raises(ValueError, match="Ora|24"):
        validate_cron_expression("0 24 * * *")

    # Month out of bounds (1-12)
    with pytest.raises(ValueError, match="Mese|13"):
        validate_cron_expression("0 0 1 13 *")

    # Day of week out of bounds (0-7)
    with pytest.raises(ValueError, match="Giorno della settimana|8"):
        validate_cron_expression("0 0 * * 8")


def test_validate_cron_expression_without_apscheduler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that validation NEVER fails with 'No module named apscheduler' even if apscheduler is uninstalled."""
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "apscheduler" in name:
            raise ModuleNotFoundError(f"No module named '{name}'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)

    # Must succeed without throwing ModuleNotFoundError!
    res = validate_cron_expression("0 3 * * *")
    assert res == "0 3 * * *"

    res_alias = validate_cron_expression("@daily")
    assert res_alias == "0 0 * * *"

    # Invalid expression must raise ValueError, NOT ModuleNotFoundError
    with pytest.raises(ValueError, match="Minuto|esattamente 5 campi"):
        validate_cron_expression("99 * * * *")


def test_compute_next_cron_run() -> None:
    """Verify calculation of next fire time."""
    base = datetime(2026, 10, 25, 10, 0, 0, tzinfo=UTC)

    # Next hour
    next_hourly = compute_next_cron_run("0 * * * *", tz_name="UTC", base_time=base)
    assert next_hourly == datetime(2026, 10, 25, 11, 0, 0, tzinfo=UTC)

    # Next 15 min
    next_15m = compute_next_cron_run("*/15 * * * *", tz_name="UTC", base_time=base)
    assert next_15m == datetime(2026, 10, 25, 10, 15, 0, tzinfo=UTC)

    # Daily at 03:00 Europe/Rome (UTC+1 on 2026-10-25) -> 02:00 UTC
    next_daily = compute_next_cron_run("0 3 * * *", tz_name="Europe/Rome", base_time=base)
    assert next_daily == datetime(2026, 10, 26, 2, 0, 0, tzinfo=UTC)


def test_compute_next_cron_run_without_apscheduler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify next run calculation fallback works accurately without apscheduler."""
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "apscheduler" in name:
            raise ModuleNotFoundError(f"No module named '{name}'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)

    base = datetime(2026, 10, 25, 10, 0, 0, tzinfo=UTC)
    next_hourly = compute_next_cron_run("0 * * * *", tz_name="UTC", base_time=base)
    assert next_hourly == datetime(2026, 10, 25, 11, 0, 0, tzinfo=UTC)


def test_validate_timezone_name() -> None:
    """Verify IANA timezone validation."""
    assert validate_timezone_name(None) == "UTC"
    assert validate_timezone_name("") == "UTC"
    assert validate_timezone_name("utc") == "UTC"
    assert validate_timezone_name("Europe/Rome") == "Europe/Rome"
    assert validate_timezone_name("America/New_York") == "America/New_York"

    with pytest.raises(ValueError, match="Timezone non valida"):
        validate_timezone_name("Invalid/Timezone_Name")


def test_compute_next_cron_run_follow_dst_true_and_false() -> None:
    """Verify 0 1 * * * in Europe/Rome with follow_dst=True vs follow_dst=False."""
    winter_base = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
    summer_base = datetime(2026, 7, 15, 12, 0, 0, tzinfo=UTC)

    # follow_dst=True: always 01:00 Italian wall-clock time
    assert compute_next_cron_run(
        "0 1 * * *", tz_name="Europe/Rome", base_time=winter_base, follow_dst=True
    ) == datetime(2026, 1, 16, 0, 0, 0, tzinfo=UTC)
    assert compute_next_cron_run(
        "0 1 * * *", tz_name="Europe/Rome", base_time=summer_base, follow_dst=True
    ) == datetime(2026, 7, 15, 23, 0, 0, tzinfo=UTC)

    # follow_dst=False: stays anchored to standard solar offset (UTC+1 for Europe/Rome)
    assert compute_next_cron_run(
        "0 1 * * *", tz_name="Europe/Rome", base_time=winter_base, follow_dst=False
    ) == datetime(2026, 1, 16, 0, 0, 0, tzinfo=UTC)
    assert compute_next_cron_run(
        "0 1 * * *", tz_name="Europe/Rome", base_time=summer_base, follow_dst=False
    ) == datetime(2026, 7, 16, 0, 0, 0, tzinfo=UTC)

    # Across DST spring-forward (2026-03-29 02:00 -> 03:00 in Europe/Rome)
    t1 = datetime(2026, 3, 28, 12, 0, 0, tzinfo=UTC)
    run_before_switch = compute_next_cron_run(
        "0 1 * * *", tz_name="Europe/Rome", base_time=t1, follow_dst=True
    )
    assert run_before_switch == datetime(2026, 3, 29, 0, 0, 0, tzinfo=UTC)

    run_after_switch = compute_next_cron_run(
        "0 1 * * *",
        tz_name="Europe/Rome",
        base_time=run_before_switch,
        previous_fire_time=run_before_switch,
        follow_dst=True,
    )
    assert run_after_switch == datetime(2026, 3, 29, 23, 0, 0, tzinfo=UTC)

    # Fall-back repeated 02:30 hour (2026-10-25 in Europe/Rome) does not hang or regress
    fall_base = datetime(2026, 10, 24, 12, 0, 0, tzinfo=UTC)
    f1 = compute_next_cron_run("30 2 * * *", tz_name="Europe/Rome", base_time=fall_base, follow_dst=True)
    assert f1 == datetime(2026, 10, 25, 0, 30, 0, tzinfo=UTC)
    f2 = compute_next_cron_run(
        "30 2 * * *", tz_name="Europe/Rome", base_time=f1, previous_fire_time=f1, follow_dst=True
    )
    assert f2 == datetime(2026, 10, 25, 1, 30, 0, tzinfo=UTC)
    f3 = compute_next_cron_run(
        "30 2 * * *", tz_name="Europe/Rome", base_time=f2, previous_fire_time=f2, follow_dst=True
    )
    assert f3 == datetime(2026, 10, 26, 1, 30, 0, tzinfo=UTC)


def test_compute_next_cron_run_follow_dst_fallback_without_apscheduler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify fallback evaluation handles follow_dst=True and follow_dst=False without apscheduler."""
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "apscheduler" in name:
            raise ModuleNotFoundError(f"No module named '{name}'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)

    summer_base = datetime(2026, 7, 15, 12, 0, 0, tzinfo=UTC)
    assert compute_next_cron_run(
        "0 1 * * *", tz_name="Europe/Rome", base_time=summer_base, follow_dst=True
    ) == datetime(2026, 7, 15, 23, 0, 0, tzinfo=UTC)
    assert compute_next_cron_run(
        "0 1 * * *", tz_name="Europe/Rome", base_time=summer_base, follow_dst=False
    ) == datetime(2026, 7, 16, 0, 0, 0, tzinfo=UTC)
