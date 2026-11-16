"""Unit tests for browser timezone normalization and datetime formatting."""

from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest
from flask import Flask

from embervault_app.factory import create_app
from embervault_app.timezones import (
    DEFAULT_FALLBACK_TZ,
    format_user_date,
    format_user_datetime,
    format_user_time,
    get_user_timezone,
    init_timezones,
    parse_user_datetime_input,
    to_user_tz,
    to_utc_iso,
)


def test_get_user_timezone_from_cookie() -> None:
    """Ensure user timezone is resolved from the 'embervault_tz' cookie."""
    app = Flask(__name__)
    init_timezones(app)

    with app.test_request_context("/", headers={"Cookie": "embervault_tz=Europe/Rome"}):
        tz = get_user_timezone()
        assert tz == ZoneInfo("Europe/Rome")

    with app.test_request_context("/", headers={"Cookie": "embervault_tz=America/New_York"}):
        tz = get_user_timezone()
        assert tz == ZoneInfo("America/New_York")


def test_get_user_timezone_invalid_or_missing_cookie() -> None:
    """Ensure invalid or missing timezone cookies fall back safely to UTC."""
    app = Flask(__name__)
    init_timezones(app)

    # Missing cookie
    with app.test_request_context("/"):
        tz = get_user_timezone()
        assert tz == DEFAULT_FALLBACK_TZ

    # Invalid timezone string
    with app.test_request_context(
        "/", headers={"Cookie": "embervault_tz=Invalid/NonExistent_Zone"}
    ):
        tz = get_user_timezone()
        assert tz == DEFAULT_FALLBACK_TZ


def test_to_user_tz_dst_transition() -> None:
    """Verify UTC to Europe/Rome conversion before and after the 2026-10-25 DST change."""
    rome_tz = ZoneInfo("Europe/Rome")

    # 1. Summer time (CEST = UTC+2): 2026-10-24 10:00:00 UTC -> 12:00:00 CEST
    summer_utc = datetime(2026, 10, 24, 10, 0, 0, tzinfo=UTC)
    summer_local = to_user_tz(summer_utc, target_tz=rome_tz)
    assert summer_local is not None
    assert summer_local.hour == 12
    assert summer_local.strftime("%Z") == "CEST"

    # 2. Winter time (CET = UTC+1, clock moved back on 2026-10-25): 2026-10-25 10:00:00 UTC -> 11:00:00 CET
    winter_utc = datetime(2026, 10, 25, 10, 0, 0, tzinfo=UTC)
    winter_local = to_user_tz(winter_utc, target_tz=rome_tz)
    assert winter_local is not None
    assert winter_local.hour == 11
    assert winter_local.strftime("%Z") == "CET"


def test_to_user_tz_handles_naive_and_iso_strings() -> None:
    """Verify conversion properly handles naive datetimes (assumed UTC) and ISO strings."""
    rome_tz = ZoneInfo("Europe/Rome")

    # Naive datetime
    naive_utc = datetime(2026, 10, 25, 10, 30, 0)
    res_naive = to_user_tz(naive_utc, target_tz=rome_tz)
    assert res_naive is not None
    assert res_naive.hour == 11
    assert res_naive.minute == 30

    # ISO string with Z
    iso_z = "2026-10-25T10:45:00Z"
    res_iso = to_user_tz(iso_z, target_tz=rome_tz)
    assert res_iso is not None
    assert res_iso.hour == 11
    assert res_iso.minute == 45

    # None and empty
    assert to_user_tz(None) is None
    assert to_user_tz("") is None


def test_format_user_datetime_and_filters() -> None:
    """Verify formatted output in user's browser timezone."""
    rome_tz = ZoneInfo("Europe/Rome")
    utc_dt = datetime(2026, 10, 25, 10, 15, 30, tzinfo=UTC)

    # Full datetime
    full_str = format_user_datetime(utc_dt, "%d/%m/%Y %H:%M:%S", target_tz=rome_tz)
    assert full_str == "25/10/2026 11:15:30"

    # Date only
    date_str = format_user_date(utc_dt, target_tz=rome_tz)
    assert date_str == "25/10/2026"

    # Time only
    time_str = format_user_time(utc_dt, target_tz=rome_tz)
    assert time_str == "11:15:30"

    # Fallback on None
    assert format_user_datetime(None, fallback="In attesa") == "In attesa"


def test_parse_user_datetime_input() -> None:
    """Verify parsing datetime-local strings in user timezone and converting to UTC."""
    rome_tz = ZoneInfo("Europe/Rome")

    # Winter (UTC+1): user inputs 11:00 Rome time -> must convert to 10:00 UTC
    parsed_winter = parse_user_datetime_input("2026-10-25T11:00", user_tz=rome_tz)
    assert parsed_winter is not None
    assert parsed_winter.tzinfo == UTC
    assert parsed_winter.hour == 10
    assert parsed_winter.minute == 0

    # Summer (UTC+2): user inputs 12:00 Rome time -> must convert to 10:00 UTC
    parsed_summer = parse_user_datetime_input("2026-10-24T12:00", user_tz=rome_tz)
    assert parsed_summer is not None
    assert parsed_summer.tzinfo == UTC
    assert parsed_summer.hour == 10
    assert parsed_summer.minute == 0

    # End of day date-only (2026-10-25)
    parsed_eod = parse_user_datetime_input("2026-10-25", is_end_of_day=True, user_tz=rome_tz)
    assert parsed_eod is not None
    assert parsed_eod.tzinfo == UTC
    assert parsed_eod.hour == 22  # 23:59:59 Rome winter (UTC+1) = 22:59:59 UTC
    assert parsed_eod.minute == 59


def test_jinja_rendering_with_user_timezone() -> None:
    """Verify Jinja templates render user_dt filter correctly using the request cookie."""
    app = Flask(__name__)
    init_timezones(app)

    @app.route("/test-time")
    def test_view():
        sample_dt = datetime(2026, 10, 25, 10, 0, 0, tzinfo=UTC)
        from flask import render_template_string

        return render_template_string(
            "Time: {{ sample_dt|user_dt('%H:%M') }} | Date: {{ sample_dt|user_date }}",
            sample_dt=sample_dt,
        )

    client = app.test_client()

    # Request with Rome timezone cookie (UTC+1 on 2026-10-25)
    client.set_cookie("embervault_tz", "Europe/Rome")
    resp = client.get("/test-time")
    assert resp.status_code == 200
    assert "Time: 11:00" in resp.text
    assert "Date: 25/10/2026" in resp.text

    # Request with New York timezone cookie (EDT = UTC-4 on 2026-10-25)
    client.set_cookie("embervault_tz", "America/New_York")
    resp_ny = client.get("/test-time")
    assert resp_ny.status_code == 200
    assert "Time: 06:00" in resp_ny.text
