"""Timezone normalization and local datetime formatting utilities.

Detects user timezone from browser cookies (or HTTP headers) and normalizes
all datetime formatting (server-side Jinja templates and client data attributes)
to display in the user's local browser timezone.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from flask import Flask, g, request


DEFAULT_FALLBACK_TZ = ZoneInfo("UTC")

_EXCLUDED_TIMEZONES = frozenset({"UTC", "localtime", "Factory", "tzdata.zi"})


def get_available_timezones(extra_tz: str | None = None) -> list[str]:
    """Return sorted list of valid IANA timezone names starting with 'UTC'."""
    zones = {
        tz
        for tz in available_timezones()
        if tz not in _EXCLUDED_TIMEZONES and not tz.startswith("SystemV/")
    }
    if extra_tz:
        clean_extra = extra_tz.strip()
        if clean_extra and clean_extra.upper() != "UTC":
            zones.add(clean_extra)
    return ["UTC", *sorted(zones)]


def get_user_timezone() -> ZoneInfo:
    """Resolve the active user timezone for the current request.

    Resolution order:
    1. Flask request 'g.user_timezone' if already resolved in request lifecycle.
    2. 'embervault_tz' cookie (set by JavaScript via Intl.DateTimeFormat).
    3. 'X-Timezone' HTTP request header.
    4. Server fallback timezone (UTC).
    """
    if hasattr(g, "user_timezone") and isinstance(g.user_timezone, ZoneInfo):
        return g.user_timezone

    tz_str: str | None = None
    if request:
        try:
            tz_str = request.cookies.get("embervault_tz")
            if not tz_str:
                tz_str = request.headers.get("X-Timezone")
        except RuntimeError:
            pass  # Outside request context

    resolved_tz = DEFAULT_FALLBACK_TZ
    if tz_str:
        clean_tz = tz_str.strip()
        try:
            resolved_tz = ZoneInfo(clean_tz)
        except (ZoneInfoNotFoundError, ValueError):
            resolved_tz = DEFAULT_FALLBACK_TZ

    if request:
        try:
            g.user_timezone = resolved_tz
        except RuntimeError:
            pass

    return resolved_tz


def to_user_tz(
    dt: datetime | str | None,
    target_tz: ZoneInfo | None = None,
) -> datetime | None:
    """Convert a UTC or naive datetime to the user's target timezone.

    Naive datetimes from the database/SQLite are assumed to be in UTC.
    """
    if dt is None:
        return None

    if isinstance(dt, str):
        s = dt.strip()
        if not s:
            return None
        # Handle ISO strings with Z or offsets
        try:
            dt_parsed = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            # Try common space-separated SQL timestamp format: YYYY-MM-DD HH:MM:SS
            try:
                dt_parsed = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                return None
        dt = dt_parsed

    if not isinstance(dt, datetime):
        return None

    # If datetime is naive, treat as UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)

    tz = target_tz or get_user_timezone()
    return dt.astimezone(tz)


def format_user_datetime(
    dt: datetime | str | None,
    fmt: str = "%d/%m/%Y %H:%M:%S",
    fallback: str = "N/A",
    target_tz: ZoneInfo | None = None,
) -> str:
    """Format a datetime in the user's browser timezone with the given format."""
    converted = to_user_tz(dt, target_tz=target_tz)
    if converted is None:
        return fallback
    return converted.strftime(fmt)


def format_user_date(
    dt: datetime | str | None,
    fmt: str = "%d/%m/%Y",
    fallback: str = "N/A",
    target_tz: ZoneInfo | None = None,
) -> str:
    """Format the date portion in the user's browser timezone."""
    return format_user_datetime(dt, fmt=fmt, fallback=fallback, target_tz=target_tz)


def format_user_time(
    dt: datetime | str | None,
    fmt: str = "%H:%M:%S",
    fallback: str = "N/A",
    target_tz: ZoneInfo | None = None,
) -> str:
    """Format the time portion in the user's browser timezone."""
    return format_user_datetime(dt, fmt=fmt, fallback=fallback, target_tz=target_tz)


def to_utc_iso(dt: datetime | str | None) -> str:
    """Return ISO-8601 string explicitly in UTC with '+00:00' or 'Z'."""
    if dt is None:
        return ""
    if isinstance(dt, str):
        dt_val = to_user_tz(dt, target_tz=UTC)
    else:
        dt_val = dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
        dt_val = dt_val.astimezone(UTC)
    return dt_val.isoformat() if dt_val else ""


def parse_user_datetime_input(
    dt_str: str | None,
    is_end_of_day: bool = False,
    user_tz: ZoneInfo | None = None,
) -> datetime | None:
    """Parse local datetime input from datetime-local/date inputs and convert to UTC for queries.

    The browser's <input type="datetime-local"> sends values in local time (e.g., '2026-10-25T11:00').
    This function interprets that string in the user's timezone and converts it to a UTC datetime
    for querying database timestamp columns.
    """
    if not dt_str:
        return None
    clean = dt_str.strip()
    if not clean:
        return None

    tz = user_tz or get_user_timezone()
    try:
        # Date only (YYYY-MM-DD)
        if len(clean) == 10 and clean.count("-") == 2:
            dt = datetime.strptime(clean, "%Y-%m-%d")
            if is_end_of_day:
                dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
            dt = dt.replace(tzinfo=tz)
            return dt.astimezone(UTC)

        # Datetime without tz (e.g., YYYY-MM-DDTHH:MM or YYYY-MM-DDTHH:MM:SS)
        parsed = datetime.fromisoformat(clean)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=tz)
        if is_end_of_day and len(clean) <= 10:
            parsed = parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
        return parsed.astimezone(UTC)
    except (ValueError, TypeError):
        return None


def init_timezones(app: Flask) -> None:
    """Register timezone filters and context processors with Flask."""

    @app.before_request
    def set_request_timezone() -> None:
        g.user_timezone = get_user_timezone()

    @app.context_processor
    def inject_timezone_context() -> dict[str, Any]:
        tz = getattr(g, "user_timezone", DEFAULT_FALLBACK_TZ)
        tz_name = str(tz)
        return {
            "user_timezone_name": tz_name,
            "available_timezones": get_available_timezones(tz_name),
            "format_user_datetime": format_user_datetime,
        }

    # Register Jinja template filters
    app.jinja_env.filters["user_dt"] = format_user_datetime
    app.jinja_env.filters["user_date"] = format_user_date
    app.jinja_env.filters["user_time"] = format_user_time
    app.jinja_env.filters["utc_iso"] = to_utc_iso
