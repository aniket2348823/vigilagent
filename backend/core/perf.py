"""
Vigilagent shared performance helpers.
================================================================================
Tiny, zero-dependency utilities used across hot paths:

  - dumps_fast(obj): orjson when available (~3-5x faster than json.dumps for
    nested dicts), graceful fallback to stdlib json. Returns ``str``.
  - TTLCache: small, thread-safe TTL cache used by knowledge graph queries
    that are invoked on every planner iteration but only change when the graph
    is mutated.

Designed to add zero overhead at import time and never raise at the call site.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Hashable

logger = logging.getLogger(__name__)

try:  # orjson is in requirements.txt; treat as optional in case of slim builds.
    import orjson  # type: ignore[import-untyped]

    def dumps_fast(obj: Any) -> str:
        """Serialize ``obj`` to a JSON string. orjson when available."""
        try:
            return orjson.dumps(obj, default=str).decode("utf-8")
        except TypeError:
            # orjson is strict; fall back to stdlib for anything it rejects.
            return json.dumps(obj, default=str)
except Exception as _exc:  # pragma: no cover — orjson missing; keep stdlib path.
    import logging as _log

    _log.getLogger(__name__).debug("orjson unavailable, using stdlib json: %s", _exc)

    def dumps_fast(obj: Any) -> str:
        return json.dumps(obj, default=str)


class TTLCache:
    """Tiny thread-safe TTL cache for graph queries (Architecture §12 hot path).

    Used by ``GraphEngine.predict_next`` / ``find_chains`` which the planner
    calls on every iteration. Invalidation hook fires whenever the graph
    mutates (new node/edge ingestion).
    """

    __slots__ = ("_ttl", "_data", "_lock")

    def __init__(self, ttl_seconds: float = 30.0) -> None:
        self._ttl = float(ttl_seconds)
        self._data: dict[Hashable, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get_or_compute(self, key: Hashable, compute: Callable[[], Any]) -> Any:
        now = time.monotonic()
        with self._lock:
            entry = self._data.get(key)
            if entry and (now - entry[0]) < self._ttl:
                return entry[1]
        value = compute()
        with self._lock:
            self._data[key] = (now, value)
        return value

    def invalidate(self) -> None:
        with self._lock:
            self._data.clear()
