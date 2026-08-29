"""Shared pacing helper: sleep for `seconds` of simulated time while honoring
the current speed multiplier (0 => paused)."""
from __future__ import annotations

import time


def paced_wait(seconds: float, speed_fn, stop_event) -> None:
    rem = max(0.0, seconds)
    while rem > 1e-9 and not stop_event.is_set():
        sp = speed_fn()
        if sp is None or sp <= 0:      # paused
            time.sleep(0.1)
            continue
        step = min(0.05, rem / sp)
        time.sleep(step)
        rem -= step * sp
