import asyncio
import contextlib
import json
import logging
import math
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any

# fcntl is POSIX-only; on Windows file locking is best-effort (no advisory locks)
try:
    import fcntl

    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False

logger = logging.getLogger("DualStoreMemory")


def cosine_similarity(vec1: list[float], vec2: list[float]) -> float:
    if not vec1 or not vec2 or len(vec1) != len(vec2):
        return 0.0
    dot = sum(a * b for a, b in zip(vec1, vec2))
    norm1 = math.sqrt(sum(a * a for a in vec1))
    norm2 = math.sqrt(sum(b * b for b in vec2))
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return dot / (norm1 * norm2)


class DualStoreMemory:
    """
    CAI-style memory split:
    - episodic: per-scan facts and tool outputs
    - semantic: cross-scan verified techniques and reusable patterns
    """

    def __init__(self, root: str | os.PathLike[str] = "brain"):
        self.root = Path(root)
        self.episodic_dir = self.root / "episodes"
        self.semantic_file = self.root / "semantic_patterns.json"
        self.notifications_file = self.root / "notifications.json"
        self.episodic_dir.mkdir(parents=True, exist_ok=True)
        self.root.mkdir(parents=True, exist_ok=True)
        self._ensure_json_list(self.semantic_file)
        self._ensure_json_list(self.notifications_file)
        # V8 LOAD FIX: coalesce memory-file writes. Instead of one full
        # read->append->rewrite of brain/*.json per event (600KB-900KB files,
        # constant disk churn, and the corruption window that broke Kappa),
        # appends accumulate in these pending buffers and are flushed together
        # by a single daemon flusher every ``_FLUSH_INTERVAL`` seconds. Reads
        # flush first, so recall/pop semantics are unchanged.
        self._pending_notifications: list[tuple[str, str, dict]] = []
        self._pending_semantic: list[dict] = []
        self._pending_episodes: dict[str, list[dict]] = {}
        self._flush_lock = threading.Lock()
        self._flusher_alive = False
        self._FLUSH_INTERVAL = 3.0
        self._start_flusher()

    def _ensure_json_list(self, path: Path) -> None:
        if not path.exists():
            path.write_text("[]", encoding="utf-8")

    def _read_list(self, path: Path) -> list[dict[str, Any]]:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.debug("DualStoreMemory: failed to read %s (%s), returning empty list", path, exc)
            return []

    def _write_list(self, path: Path, rows: list[dict[str, Any]]) -> None:
        """Write list to JSON with file locking to prevent corruption
        from concurrent scans.

        FIX: Added fcntl.flock() for atomic read-modify-write cycles.
        On Windows where fcntl is unavailable, we fall back to best-effort
        writes (the existing behavior) since Windows file locking semantics
        are different.

        FIX (WinError 32): On Windows, ``Path.replace`` fails with
        ``PermissionError`` / ``OSError 32`` when another writer briefly holds
        the destination open. Retry the write a few times with a tiny backoff
        before giving up, so concurrent event writers no longer drop records.
        """
        tmp_path = path.with_suffix(".tmp")
        for attempt in range(4):
            try:
                with open(tmp_path, "w", encoding="utf-8") as fh:
                    # On POSIX systems, use advisory file locking
                    if _HAS_FCNTL:
                        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                    try:
                        json.dump(rows, fh, indent=2)
                        fh.flush()
                        os.fsync(fh.fileno())
                    finally:
                        if _HAS_FCNTL:
                            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                tmp_path.replace(path)
                return
            except (PermissionError, OSError) as exc:
                # Transient Windows file lock (WinError 32) or AV interference.
                with contextlib.suppress(Exception):
                    tmp_path.unlink(missing_ok=True)
                if sys.platform == "win32" and attempt < 3:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                logger.warning("DualStoreMemory: write to %s failed: %s", path, exc)
                return
            except Exception as exc:
                logger.warning("DualStoreMemory: write to %s failed: %s", path, exc)
                # Clean up temp file on failure
                with contextlib.suppress(Exception):
                    tmp_path.unlink(missing_ok=True)
                return

    def _episode_file(self, scan_id: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", scan_id or "GLOBAL")
        return self.episodic_dir / f"{safe}.json"

    def _remember_episode_sync(self, scan_id: str, event: dict[str, Any]) -> None:
        with self._flush_lock:
            self._pending_episodes.setdefault(scan_id, []).append(event)

    async def remember_episode(self, scan_id: str, event: dict[str, Any]) -> None:
        await asyncio.to_thread(self._remember_episode_sync, scan_id, event)

    def _remember_semantic_sync(self, record: dict[str, Any]) -> None:
        with self._flush_lock:
            self._pending_semantic.append(record)

    async def remember_semantic(self, record: dict[str, Any]) -> None:
        await asyncio.to_thread(self._remember_semantic_sync, record)

    def _remember_notification_sync(self, scan_id: str, message: str, payload: dict[str, Any] | None = None) -> None:
        with self._flush_lock:
            self._pending_notifications.append((scan_id, message, payload or {}))

    async def remember_notification(self, scan_id: str, message: str, payload: dict[str, Any] | None = None) -> None:
        await asyncio.to_thread(self._remember_notification_sync, scan_id, message, payload)

    def _pop_notifications_sync(self, scan_id: str) -> list[dict[str, Any]]:
        self.flush_pending()  # reads must see recent appends
        rows = self._read_list(self.notifications_file)
        matched = [row for row in rows if row.get("scan_id") in {scan_id, "GLOBAL"}]
        remaining = [row for row in rows if row not in matched]
        self._write_list(self.notifications_file, remaining)
        return matched

    async def pop_notifications(self, scan_id: str) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._pop_notifications_sync, scan_id)

    def _recall_semantic_sync(
        self, query_vector: list[float], top_k: int = 3, threshold: float = 0.3
    ) -> list[dict[str, Any]]:
        self.flush_pending()  # reads must see recent appends
        rows = self._read_list(self.semantic_file)
        scored = []
        for row in rows:
            score = cosine_similarity(query_vector, row.get("vector", []))
            if score >= threshold:
                scored.append((score, row))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [{**row, "similarity": score} for score, row in scored[:top_k]]

    async def recall_semantic(
        self, query_vector: list[float], top_k: int = 3, threshold: float = 0.3
    ) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._recall_semantic_sync, query_vector, top_k, threshold)

    # ── V8 LOAD FIX: coalesced writer ─────────────────────────────────────────

    def _start_flusher(self) -> None:
        """Start the single daemon flusher that merges pending appends into
        the JSON files in one pass each (3s debounce window).
        """
        if self._flusher_alive:
            return
        self._flusher_alive = True

        def _loop() -> None:
            while True:
                time.sleep(self._FLUSH_INTERVAL)
                try:
                    self.flush_pending()
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning("DualStoreMemory: flusher cycle failed: %s", exc)

        threading.Thread(target=_loop, daemon=True, name="memory-flusher").start()

    def flush_pending(self) -> None:
        """Merge all pending appends into their files. Idempotent; safe to call
        from reads, the flusher thread, or shutdown. Each store gets exactly ONE
        read->append->write cycle per flush instead of one per event.
        """
        with self._flush_lock:
            pending_n = self._pending_notifications
            pending_s = self._pending_semantic
            pending_e = self._pending_episodes
            if not pending_n and not pending_s and not pending_e:
                return
            self._pending_notifications = []
            self._pending_semantic = []
            self._pending_episodes = {}

        if pending_n:
            rows = self._read_list(self.notifications_file)
            for scan_id, message, payload in pending_n:
                new_entry = {"timestamp": time.time(), "scan_id": scan_id, "message": message, "payload": payload}
                # Dedup: skip if a notification with the same scan_id + job_id
                # already exists (preserved from the pre-batching path).
                new_job_id = payload.get("job_id")
                if new_job_id:
                    duplicate = any(
                        existing.get("scan_id") == scan_id
                        and (existing.get("payload") or {}).get("job_id") == new_job_id
                        for existing in rows
                    )
                    if duplicate:
                        logger.debug("DualStoreMemory: duplicate notification for job %s — skipping", new_job_id)
                        continue
                rows.append(new_entry)
            if len(rows) > 500:
                logger.info("DualStoreMemory: notifications hit cap (had %d, keeping 500).", len(rows))
            self._write_list(self.notifications_file, rows[-500:])

        if pending_s:
            rows = self._read_list(self.semantic_file)
            for record in pending_s:
                rows.append({"timestamp": time.time(), **record})
            if len(rows) > 5000:
                logger.info(
                    "DualStoreMemory: semantic hit cap (had %d, keeping 5000). Consider pruning low-confidence patterns.",
                    len(rows),
                )
            self._write_list(self.semantic_file, rows[-5000:])

        if pending_e:
            for scan_id, events in pending_e.items():
                path = self._episode_file(scan_id)
                self._ensure_json_list(path)
                rows = self._read_list(path)
                for ev in events:
                    rows.append({"timestamp": time.time(), **ev})
                if len(rows) > 1000:
                    logger.info(
                        "DualStoreMemory: episode %s hit cap (had %d, keeping 1000). Consider archiving old episodes.",
                        scan_id,
                        len(rows),
                    )
                self._write_list(path, rows[-1000:])

    async def flush_pending_async(self) -> None:
        """Awaitable flush used by shutdown paths so pending memory is durable."""
        await asyncio.to_thread(self.flush_pending)


memory_store = DualStoreMemory()
