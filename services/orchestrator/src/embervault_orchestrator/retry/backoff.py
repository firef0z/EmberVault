"""Exponential backoff calculation with jitter for retry intervals (§5.4)."""

from __future__ import annotations

import random


def calculate_backoff_delay(
    attempt: int,
    base_s: float = 30.0,
    max_s: float = 900.0,
    jitter_pct: float = 0.1,
    random_factor: float | None = None,
) -> float:
    """Calculate exponential backoff delay for a retry attempt (§5.4).

    Formula:
        base_delay = min(base_s * (2 ** max(0, attempt - 1)), max_s)
        jitter = base_delay * jitter_pct * random_factor (-1.0 to 1.0)
        final_delay = max(0.0, base_delay + jitter)

    Properties:
        - Strictly monotonic base delay (doubles each attempt up to max_s).
        - Bounded: never exceeds max_s * (1 + jitter_pct).
        - Non-negative: always >= 0.0.

    Args:
        attempt: 1-indexed attempt number (1, 2, 3...).
        base_s: Initial delay base in seconds (default 30s).
        max_s: Ceiling maximum delay in seconds (default 900s).
        jitter_pct: Fractional jitter spread (default 0.1 = +/-10%).
        random_factor: Optional fixed float in [-1.0, 1.0] for deterministic testing.

    Returns:
        Delay in seconds until the next attempt.
    """
    if attempt < 1:
        attempt = 1

    # Exponential growth capped at max_s
    exponent = min(attempt - 1, 30)  # Avoid float overflow
    base_delay = min(base_s * (2.0**exponent), max_s)

    # Determine random factor in [-1.0, 1.0]
    if random_factor is None:
        rnd = random.uniform(-1.0, 1.0)
    else:
        rnd = max(-1.0, min(1.0, float(random_factor)))

    jitter = base_delay * jitter_pct * rnd
    delay = max(0.0, base_delay + jitter)
    return round(delay, 3)


def get_base_backoff_delay(
    attempt: int,
    base_s: float = 30.0,
    max_s: float = 900.0,
) -> float:
    """Return the unjittered base backoff delay (strictly monotonic up to max_s)."""
    if attempt < 1:
        attempt = 1
    exponent = min(attempt - 1, 30)
    return min(base_s * (2.0**exponent), max_s)
