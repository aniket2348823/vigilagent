"""
broadcast_throttle.py — coalescing helper for the orchestrator's WebSocket
broadcast hot path.

WHY: During a real scan the orchestrator's ``event_listener`` emits ~10
``manager.broadcast(...)`` calls per ``VULN_CONFIRMED``. We routinely see
1500+ such events per scan, which is enough to saturate the
``SocketManager._process_batch_queue`` even though the UI only needs the
*latest* per (type, url, agent) within a short window.

WHAT: ``BroadcastThrottle.should_emit(key)`` returns ``True`` the first time
a key is seen and ``False`` while the same key is still inside its window.
Internally we keep an O(1) FIFO ``deque`` of ``(key, expiry_ts)`` tuples
and a parallel ``dict`` for fast lookup, evicting expired entries lazily on
each call. No background task, no locks — the listener is single-consumer
per scan (see EventBus._scan_event_loop) so the data structure does not
need to be thread-safe.

USAGE:
    throttle = BroadcastThrottle(window_ms=500)
    if throttle.should_emit(("LIVE_THREAT_LOG", url, agent)):
        await manager.broadcast(...)

Behavior is documented + opt-in: the throttle is bypassed if you pass
``window_ms=0``, which keeps the legacy "broadcast every event" semantics
for tests that assert on broadcast counts.
"""

from __future__ import annotations

import time
from collections import deque
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Hashable


class BroadcastThrottle:
    """Time-window suppressor for repeated broadcast keys.

    Args:
        window_ms: Suppress duplicates within this many milliseconds of the
            most recent emit for the same key. ``0`` disables throttling.
        max_keys: Hard cap on tracked keys. When exceeded, oldest entries
            are evicted regardless of whether they are still inside their
            window. Prevents unbounded memory under pathological key churn.
    """

    __slots__ = ("_window_s", "_max_keys", "_seen_at", "_fifo")

    def __init__(self, window_ms: int = 500, max_keys: int = 4096) -> None:
        if window_ms < 0:
            raise ValueError("window_ms must be >= 0")
        self._window_s: float = window_ms / 1000.0
        self._max_keys: int = max(64, int(max_keys))
        # key -> expiry monotonic timestamp (seconds)
        self._seen_at: dict[Hashable, float] = {}
        # Parallel FIFO so we can evict the oldest entry in O(1) without
        # paying for a full dict scan when we hit the cap.
        self._fifo: deque[tuple[Hashable, float]] = deque()

    def should_emit(self, key: Hashable) -> bool:
        """Return True the first time ``key`` is seen inside the window.

        Subsequent calls with the same key return False until the window
        expires. Calling ``should_emit`` always *records* a new emit time
        on a True result — i.e. the throttle stays suppressed for another
        full window after each emitted broadcast.
        """
        # Throttle disabled — always emit.
        if self._window_s <= 0.0:
            return True

        now = time.monotonic()
        expiry = self._seen_at.get(key)

        if expiry is not None and expiry > now:
            # Still suppressing this key.
            return False

        # Evict any obviously expired entries from the front of the FIFO.
        # Lazy eviction keeps the data structure cheap on the hot path.
        while self._fifo and self._fifo[0][1] <= now:
            stale_key, _ = self._fifo.popleft()
            # Only delete if the dict entry hasn't been re-stamped by a
            # later emit (the dict is the source of truth).
            cur = self._seen_at.get(stale_key)
            if cur is not None and cur <= now:
                self._seen_at.pop(stale_key, None)

        # Hard cap to prevent unbounded growth on attacker-controlled keys.
        while len(self._seen_at) >= self._max_keys and self._fifo:
            old_key, _ = self._fifo.popleft()
            self._seen_at.pop(old_key, None)

        new_expiry = now + self._window_s
        self._seen_at[key] = new_expiry
        self._fifo.append((key, new_expiry))
        return True

    def clear(self) -> None:
        """Reset all suppression state. Mostly useful in tests."""
        self._seen_at.clear()
        self._fifo.clear()

    def __len__(self) -> int:
        return len(self._seen_at)

    def stats(self) -> dict[str, Any]:
        """Lightweight diagnostics for /api/runtime/health."""
        return {
            "tracked_keys": len(self._seen_at),
            "window_ms": int(self._window_s * 1000),
            "max_keys": self._max_keys,
        }
