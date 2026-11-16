"""Zero-dependency CRON validation and next-run calculation utilities.

Works out of the box with or without APScheduler installed.
Supports standard 5-part crontabs and standard aliases (@hourly, @daily, etc.).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

CRON_ALIASES: dict[str, str] = {
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
    "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
}

FIELD_RANGES = [
    (0, 59, "Minuto"),
    (0, 23, "Ora"),
    (1, 31, "Giorno del mese"),
    (1, 12, "Mese"),
    (0, 7, "Giorno della settimana"),
]

MONTH_NAMES = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

DOW_NAMES = {
    "sun": 0,
    "mon": 1,
    "tue": 2,
    "wed": 3,
    "thu": 4,
    "fri": 5,
    "sat": 6,
}


def _match_cron_field(val: int, field_str: str, min_v: int, max_v: int) -> bool:
    """Check if an integer value matches a crontab field expression."""
    clean = field_str.strip()
    if clean == "*":
        return True

    for part in clean.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            sub, step_str = part.split("/", 1)
            try:
                step = int(step_str)
                if step <= 0:
                    continue
            except ValueError:
                continue
            start = min_v if sub == "*" else int(sub)
            if (val - start) % step == 0 and val >= start:
                return True
        elif "-" in part:
            s_str, e_str = part.split("-", 1)
            try:
                s, e = int(s_str), int(e_str)
                if s <= val <= e:
                    return True
            except ValueError:
                continue
        else:
            try:
                if val == int(part):
                    return True
            except ValueError:
                continue
    return False


def _validate_cron_native(expr: str) -> None:
    """Validate 5-part crontab syntax and value bounds natively."""
    clean = expr.strip()
    parts = clean.split()
    if len(parts) != 5:
        raise ValueError(
            "L'espressione CRON deve contenere esattamente 5 campi separati da spazi (es. '0 2 * * *')."
        )

    for idx, (min_v, max_v, name) in enumerate(FIELD_RANGES):
        field = parts[idx]
        if field == "*":
            continue

        for item in field.split(","):
            item = item.strip()
            if not item:
                raise ValueError(f"Sintassi non valida nel campo {name}: elemento vuoto.")

            # Step values
            if "/" in item:
                sub, step_s = item.split("/", 1)
                try:
                    step = int(step_s)
                    if step <= 0:
                        raise ValueError(
                            f"Passo del campo {name} deve essere maggiore di 0: '{step_s}'"
                        )
                except ValueError:
                    raise ValueError(f"Passo non numerico nel campo {name}: '{step_s}'")
                if sub != "*":
                    if "-" in sub:
                        s_s, e_s = sub.split("-", 1)
                        s, e = int(s_s), int(e_s)
                        if s < min_v or e > max_v or s > e:
                            raise ValueError(
                                f"Intervallo non valido nel campo {name}: '{sub}' (consentito {min_v}-{max_v})"
                            )
                    else:
                        s = int(sub)
                        if s < min_v or s > max_v:
                            raise ValueError(
                                f"Valore non valido nel campo {name}: '{s}' (consentito {min_v}-{max_v})"
                            )
            elif "-" in item:
                s_s, e_s = item.split("-", 1)
                try:
                    s, e = int(s_s), int(e_s)
                    if s < min_v or e > max_v or s > e:
                        raise ValueError(
                            f"Intervallo non valido nel campo {name}: '{item}' (consentito {min_v}-{max_v})"
                        )
                except ValueError:
                    raise ValueError(f"Intervallo non numerico nel campo {name}: '{item}'")
            else:
                try:
                    val = int(item)
                    if val < min_v or val > max_v:
                        raise ValueError(
                            f"Valore fuori limite nel campo {name}: {val} (consentito {min_v}-{max_v})"
                        )
                except ValueError:
                    raise ValueError(f"Valore non valido nel campo {name}: '{item}'")


def validate_cron_expression(expr: str | None) -> str:
    """Validate a cron expression and return the resolved 5-part string.

    Raises ValueError with a friendly message if invalid.
    Gracefully handles missing apscheduler without throwing ImportError.
    """
    if not expr or not str(expr).strip():
        raise ValueError("L'espressione CRON non può essere vuota.")

    clean = str(expr).strip()
    resolved = CRON_ALIASES.get(clean.lower(), clean)

    parts = resolved.split()
    if len(parts) != 5:
        raise ValueError(
            f"L'espressione CRON deve contenere esattamente 5 campi separati da spazi; trovati {len(parts)}."
        )

    # Normalize 7 to 0 in day_of_week for standard cron implementations that use 7 as Sunday
    parts[4] = re.sub(r"(?<!\d)7(?!\d)", "0", parts[4])
    normalized = " ".join(parts)

    # 1. Try APScheduler if installed
    try:
        from apscheduler.triggers.cron import CronTrigger

        CronTrigger.from_crontab(normalized)
        return normalized
    except (ImportError, ModuleNotFoundError):
        pass
    except Exception as exc:
        raise ValueError(f"Espressione CRON non valida: {exc}")

    # 2. Native validator fallback
    _validate_cron_native(normalized)
    return normalized


def validate_timezone_name(tz_name: str | None) -> str:
    """Validate an IANA timezone name (or 'UTC') and return the normalized string."""
    clean = str(tz_name).strip() if tz_name else "UTC"
    if not clean or clean.upper() == "UTC":
        return "UTC"
    try:
        ZoneInfo(clean)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"Timezone non valida: '{clean}'.") from exc
    return clean


def resolve_cron_tzinfo(
    tz_name: str = "UTC",
    follow_dst: bool = True,
    ref_utc: datetime | None = None,
) -> tzinfo:
    """Resolve the tzinfo used for cron evaluation.

    When ``follow_dst`` is True, returns the full IANA ``ZoneInfo`` so schedules
    track daylight saving time transitions automatically. When ``follow_dst`` is
    False, returns a fixed-offset ``timezone`` representing the zone's standard
    (solar / non-DST) offset.
    """
    clean = tz_name.strip() if tz_name and tz_name.strip() else "UTC"
    if clean.upper() == "UTC":
        return UTC
    try:
        iana_tz = ZoneInfo(clean)
    except (ZoneInfoNotFoundError, ValueError):
        return UTC

    if follow_dst:
        return iana_tz

    ref = ref_utc or datetime.now(UTC)
    if getattr(ref, "tzinfo", None) is None:
        ref = ref.replace(tzinfo=UTC)
    dt_in_tz = ref.astimezone(iana_tz)
    utcoffset = dt_in_tz.utcoffset() or timedelta(0)
    dst_shift = dt_in_tz.dst() or timedelta(0)
    return timezone(utcoffset - dst_shift)


def compute_next_cron_run(
    cron_expr: str | None,
    tz_name: str = "UTC",
    base_time: datetime | None = None,
    previous_fire_time: datetime | None = None,
    follow_dst: bool = True,
) -> datetime | None:
    """Compute the next fire time for a cron expression in UTC."""
    if not cron_expr or not str(cron_expr).strip():
        return None

    clean = str(cron_expr).strip()
    resolved = CRON_ALIASES.get(clean.lower(), clean)

    parts = resolved.split()
    if len(parts) == 5:
        parts[4] = re.sub(r"(?<!\d)7(?!\d)", "0", parts[4])
        resolved = " ".join(parts)

    base = base_time or datetime.now(UTC)
    if getattr(base, "tzinfo", None) is None:
        base = base.replace(tzinfo=UTC)
    base_utc = base.astimezone(UTC)

    if previous_fire_time is not None:
        prev = previous_fire_time
        if getattr(prev, "tzinfo", None) is None:
            prev = prev.replace(tzinfo=UTC)
        prev_utc = prev.astimezone(UTC)
        cutoff_utc = max(base_utc, prev_utc)
    else:
        cutoff_utc = base_utc

    tz = resolve_cron_tzinfo(tz_name=tz_name, follow_dst=follow_dst, ref_utc=cutoff_utc)

    # 1. Try APScheduler if available
    try:
        from apscheduler.triggers.cron import CronTrigger

        trigger = CronTrigger.from_crontab(resolved, timezone=tz)
        search_utc = cutoff_utc.replace(second=0, microsecond=0) + timedelta(minutes=1)
        next_fire = trigger.get_next_fire_time(None, search_utc.astimezone(tz))
        for _ in range(8):
            if next_fire is None:
                return None
            next_fire_utc = next_fire.astimezone(UTC)
            if next_fire_utc > cutoff_utc:
                return next_fire_utc
            search_utc = max(search_utc, next_fire_utc).replace(second=0, microsecond=0) + timedelta(
                minutes=1
            )
            next_fire = trigger.get_next_fire_time(None, search_utc.astimezone(tz))
        return None
    except (ImportError, ModuleNotFoundError):
        pass
    except Exception:
        pass

    # 2. Pure Python fallback evaluation
    try:
        _validate_cron_native(resolved)
    except Exception:
        return None

    cur = (cutoff_utc.replace(second=0, microsecond=0) + timedelta(minutes=1)).astimezone(tz)
    fields = resolved.split()
    f_min, f_hr, f_day, f_mon, f_dow = fields

    # Limit search to 365 days of minutes
    for _ in range(365 * 24 * 60):
        if not _match_cron_field(cur.month, f_mon, 1, 12):
            cur = (cur.replace(day=1, hour=0, minute=0) + timedelta(days=32)).replace(day=1)
            continue
        dow = (cur.weekday() + 1) % 7  # 0=Sun, 6=Sat
        if not _match_cron_field(cur.day, f_day, 1, 31) or not _match_cron_field(dow, f_dow, 0, 7):
            cur = (cur + timedelta(days=1)).replace(hour=0, minute=0)
            continue
        if not _match_cron_field(cur.hour, f_hr, 0, 23):
            cur = (cur + timedelta(hours=1)).replace(minute=0)
            continue
        if not _match_cron_field(cur.minute, f_min, 0, 59):
            cur += timedelta(minutes=1)
            continue
        return cur.astimezone(UTC)

    return None
