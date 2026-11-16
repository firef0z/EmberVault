"""Proxy cooldown calculation on consecutive infrastructure failures (§5.4)."""

from __future__ import annotations


def calculate_proxy_cooldown(
    consecutive_failures: int,
    base_cooldown_s: int = 60,
    max_cooldown_s: int = 600,
    cooldown_threshold_failures: int = 3,
) -> int | None:
    """Calculate proxy cooldown seconds following consecutive infra failures (§5.4).

    Rules:
    - If consecutive_failures < threshold (3): No cooldown (returns None).
    - If consecutive_failures == threshold (3): base_cooldown_s (60s).
    - Doubles on each subsequent failure: 60s -> 120s -> 240s -> ... capped at max_cooldown_s (600s / 10 min).

    Args:
        consecutive_failures: Count of consecutive infrastructure failures on this proxy.
        base_cooldown_s: Initial cooldown in seconds (default 60s).
        max_cooldown_s: Ceiling maximum cooldown in seconds (default 600s).
        cooldown_threshold_failures: Minimum consecutive failures to trigger cooldown (default 3).

    Returns:
        Cooldown duration in seconds, or None if threshold is not reached.
    """
    if consecutive_failures < cooldown_threshold_failures:
        return None

    extra_failures = consecutive_failures - cooldown_threshold_failures
    exponent = min(extra_failures, 20)  # Avoid overflow
    cooldown = int(base_cooldown_s * (2**exponent))
    return int(min(cooldown, max_cooldown_s))
