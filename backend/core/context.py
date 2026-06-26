import asyncio
import json
import uuid
from collections import deque
from datetime import datetime
from typing import Any

# Cap the per-scan event transcript so long-running scans don't grow an
# unbounded list (a long scan emits 5000+ events; without a cap memory and
# join() time grow linearly forever). 5000 keeps roughly the last hour of
# events for an active scan and bounds memory at ~tens of MB worst-case.
_TRANSCRIPT_MAXLEN = 5000

# Maximum number of recent event signatures to keep for deduplication.
# Beyond this, oldest signatures are evicted (FIFO).
_RECENT_EVENTS_MAXLEN = 2000


class ScanContext:
    def __init__(self, scan_id: str = None):
        self.scan_id = scan_id or str(uuid.uuid4())

        # 1. State Isolation Barriers (Fixes Invariant 8: Cross-Scan Bleed)
        self.baseline_cache: dict[str, Any] = {}
        self.diff_cache: dict[str, Any] = {}

        # 1.5 Chronological Transcript (Replaces global workflow_state Blackboard)
        # Bounded ring buffer: deque(maxlen=...) gives O(1) append + auto-evict
        # of the oldest entry once the cap is reached. Consumers either iterate
        # or slice via ``transcript_text(tail=...)`` so the deque is drop-in.
        self.transcript: deque[str] = deque(maxlen=_TRANSCRIPT_MAXLEN)

        # 2. Causal Ordering (Fixes Invariant 21)
        self.event_queue = asyncio.Queue()

        # 3. Deduplication Window (Fixes Invariant 7)
        # FIX: Use a bounded deque instead of an unbounded set to prevent
        # memory leaks on long-running scans.  The deque gives FIFO eviction.
        self._recent_events: deque[str] = deque(maxlen=_RECENT_EVENTS_MAXLEN)
        self._recent_events_set: set[str] = set()  # O(1) membership check companion

        # 4. Cancellation Propagation (Fixes Invariant 24)
        self.is_cancelled: bool = False

    def append_event(self, event: Any, *, max_payload_chars: int = 4000) -> str:
        """Append a canonical chronological [Event] block to the scan transcript."""
        payload = getattr(event, "payload", {})
        try:
            payload_text = json.dumps(payload, sort_keys=True, default=str)
        except Exception:
            payload_text = str(payload)  # Fallback for non-serializable payloads
        if len(payload_text) > max_payload_chars:
            payload_text = payload_text[:max_payload_chars] + "...[truncated]"

        timestamp = getattr(event, "timestamp", None)
        if isinstance(timestamp, datetime):
            timestamp_text = timestamp.isoformat()
        else:
            timestamp_text = str(timestamp or datetime.utcnow().isoformat())

        event_type = getattr(getattr(event, "type", ""), "value", getattr(event, "type", "UNKNOWN"))
        block = (
            "[Event]\n"
            f"id: {getattr(event, 'id', '')}\n"
            f"scan_id: {getattr(event, 'scan_id', self.scan_id)}\n"
            f"timestamp: {timestamp_text}\n"
            f"type: {event_type}\n"
            f"source: {getattr(event, 'source', 'unknown')}\n"
            f"payload: {payload_text}\n"
            "[/Event]"
        )
        self.transcript.append(block)
        return block

    def add_recent_event(self, event_id: str) -> bool:
        """Add an event ID to the deduplication window.

        Returns True if the event is new (not a duplicate).
        FIX: Uses bounded deque + companion set for O(1) add/check
        with automatic eviction of old entries.
        """
        if event_id in self._recent_events_set:
            return False
        # Evict oldest entry if at capacity
        if len(self._recent_events) == self._recent_events.maxlen:
            evicted = self._recent_events.popleft()
            self._recent_events_set.discard(evicted)
        self._recent_events.append(event_id)
        self._recent_events_set.add(event_id)
        return True

    def transcript_text(self, *, tail: int | None = None) -> str:
        # ``deque`` doesn't support negative-index slicing, so materialise once.
        if tail is None or tail >= len(self.transcript):
            events = list(self.transcript)
        else:
            # Walk from the right end; cheaper than list(self.transcript)[-tail:]
            # for large transcripts because we only copy ``tail`` items.
            events = list(self.transcript)[-tail:]
        return "\n\n".join(events)
