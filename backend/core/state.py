import asyncio
import contextlib
import hashlib
import json
import logging
import os
import threading
from typing import Any

logger = logging.getLogger("StateManager")

STATE_FILE = "stats.json"
TMP_STATE_FILE = "stats.json.tmp"


class StateManager:
    def __init__(self):
        self._dirty = False
        self._task = None
        self._lock = asyncio.Lock()
        self._sync_lock = (
            threading.RLock()
        )  # RLock: complete_scan() acquires then calls flush_immediate() -> _save_sync() which also acquires
        # ── V8 LOAD FIX: events no longer live inside ``_stats`` ──────────────
        # ``_scan_events`` is the LIVE in-memory event log per scan (hot path for
        # the events/findings/report APIs — every event stays visible). Full
        # events are ALSO flushed durably to SQLite (scan_state_db.events) so
        # nothing is lost on restart. ``_stats`` therefore stays small (scan
        # metadata + findings + results only) which makes the 2s background
        # write and ``get_stats()`` deepcopy ~instant instead of ~0.3s on a
        # 24MB blob. ``get_scan_state()`` merges the buffer back so existing
        # consumers (events endpoint, _findings_from_scan, reports) see exactly
        # the same data they did before.
        self._scan_events: dict[str, list[dict[str, Any]]] = {}
        self._events_hydrated: set[str] = set()  # scans whose SQLite log is already in _scan_events
        self._pending_events: list[dict[str, Any]] = []  # batch awaiting SQLite flush
        self._sqlite_flush_lock = threading.Lock()
        # Small stats.json / get_stats() snapshot cache (invalidated on write).
        self._stats_cache: dict[str, Any] | None = None
        self._stats = {
            "scans": [],
            "active_scans": 0,
            "total_scans": 0,
            "total_requests": 0,  # Total requests sent in active session
            "vulnerabilities": 0,
            "critical": 0,
            "history": [0] * 30,  # Initialize with flatline for graph
            # V6: New Metrics
            "v6_metrics": {"injections_blocked": 0, "deceptive_ui_blocked": 0, "risk_score": 0},
        }
        self._seen_signatures = {}  # {scan_id: set(signatures)}
        self._load()

    def _load(self) -> None:
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, encoding="utf-8") as f:
                    saved_data = json.load(f)
                    # Update local stats with saved data while preserving structure
                    self._stats.update(saved_data)
                    # Ensure scans list exists
                    if "scans" not in self._stats:
                        self._stats["scans"] = []
                    # V8 LOAD FIX (migration): legacy stats.json blobs embed every
                    # event inside each scan record (that's what made the file
                    # 24MB+). Move them into the live event buffer + durable
                    # SQLite, then drop them from the in-memory scan records so
                    # the NEXT save writes a compact stats.json. Nothing is lost:
                    # the events endpoint still sees every event via
                    # ``get_scan_state``.
                    migrated = 0
                    for s in self._stats["scans"]:
                        legacy = s.pop("events", None)
                        if isinstance(legacy, list) and legacy:
                            sid = s.get("id") or s.get("scan_id") or ""
                            if sid:
                                buf = self._scan_events.setdefault(sid, [])
                                buf[:] = legacy[-20000:]
                                with self._sqlite_flush_lock:
                                    self._pending_events.extend(
                                        {"scan_id": sid, "event": e} for e in legacy
                                    )
                                migrated += len(legacy)
                    if migrated:
                        logger.info("[StateManager] Migrated %d legacy embedded events out of stats.json", migrated)
                        self._ensure_writer()
            except Exception as e:
                logger.error(f"[StateManager] Load Error: {e}")

    async def _background_writer(self) -> None:
        """Coalesces dirty stats into a single disk write every 2s AND flushes
        the batched event log to SQLite (durable, all events kept).

        V8 LOAD FIX: events no longer mark ``_stats`` dirty, so a chatty scan
        writes the small stats.json (metadata/findings only) at most every 2s
        instead of rewriting a 24MB blob per event burst.
        """
        try:
            while True:
                await asyncio.sleep(2.0)
                self._flush_events_to_sqlite()
                if self._dirty:
                    async with self._lock:
                        self._save_sync()
        except asyncio.CancelledError:
            # Final flush on shutdown
            self._flush_events_to_sqlite()
            if self._dirty:
                self._save_sync()
            raise

    def _flush_events_to_sqlite(self) -> None:
        """Drain the pending event batch into the durable SQLite event log.

        Best-effort: on SQLite failure the events stay in the in-memory buffer
        (still visible via the API) and are retried next cycle.
        """
        with self._sqlite_flush_lock:
            if not self._pending_events:
                return
            batch = self._pending_events
            self._pending_events = []
        try:
            from backend.core.scan_state_db import scan_state_db

            rows = [
                {
                    "scan_id": item["scan_id"],
                    "type": str(item["event"].get("type", "")),
                    "source": str(item["event"].get("source", "")),
                    "payload": item["event"],  # full event dict — nothing lost
                }
                for item in batch
            ]
            scan_state_db.add_events_bulk(rows)
        except Exception as exc:
            logger.warning("[StateManager] SQLite event flush failed (%s); %d events stay in memory", exc, len(batch))
            with self._sqlite_flush_lock:
                self._pending_events[:0] = batch  # retry next cycle

    async def shutdown(self) -> None:
        """Cancel the background writer cleanly and flush any pending writes.

        Eliminates the Windows warning ``Task was destroyed but it is pending``
        seen in the unified lifecycle (Architecture §29.13). Safe to call
        multiple times; safe to call when the writer was never started.
        """
        task = self._task
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._task = None
        # Final flush (synchronous) — best effort.
        try:
            self.flush_immediate()
        except Exception as e:
            logger.debug("[State] flush_immediate deferred: %s", e)

    def _mark_dirty(self) -> None:
        self._dirty = True
        self._stats_cache = None  # invalidate the get_stats() snapshot cache
        self._ensure_writer()

    def _ensure_writer(self) -> None:
        """Start the background writer task if it is not already running."""
        try:
            loop = asyncio.get_running_loop()
            if self._task is None or self._task.done():
                self._task = loop.create_task(self._background_writer())
        except RuntimeError:
            # No event loop — synchronous fallback
            self._save_sync()

    def flush_immediate(self) -> None:
        """Immediately force-save state to disk (Critical for report readiness).

        WHY: Previously this acquired ``_sync_lock`` then called
        ``_save_sync`` which *also* acquires ``_sync_lock``. ``threading.Lock``
        is non-reentrant, so the second acquisition blocked forever and every
        ``complete_scan`` / ``mark_report_ready`` deadlocked the calling
        thread. ``_save_sync`` already takes the lock itself, so we just
        delegate to it.

        WHEN: Triggered every time a scan finishes (``complete_scan``,
        ``sync_complete_scan``, ``mark_report_ready``) or during shutdown
        flush.
        """
        try:
            self._save_sync()
        except Exception as e:
            logger.error(f"[StateManager] flush_immediate error: {e}")

    async def _async_save(self) -> None:
        async with self._lock:
            self._save_sync()

    def _save_sync(self) -> None:
        with self._sync_lock:
            # Invalidate the get_stats() snapshot cache on EVERY write path.
            # Some mutators (complete_scan, sync_complete_scan, mark_report_ready)
            # call _save_sync() directly without going through _mark_dirty() —
            # without this, get_stats() would serve stale scan status/results
            # after a scan completes.
            self._stats_cache = None
            try:
                with open(TMP_STATE_FILE, "w", encoding="utf-8") as f:
                    json.dump(self._stats, f, indent=4, default=str)
                os.replace(TMP_STATE_FILE, STATE_FILE)
                self._dirty = False
            except Exception as e:
                logger.error(f"[StateManager] Save Error: {e}")

    # Aliasing remaining references to old _save()
    def _save(self) -> None:
        self._mark_dirty()

    def get_stats(self) -> dict[str, Any]:
        """Return a deep copy of stats to prevent mutation by callers.

        V8 LOAD FIX: the copy is served from ``_stats_cache`` which is rebuilt
        only after a real write (``_mark_dirty``), NOT on every call. Events
        live outside ``_stats`` (see ``__init__``), so ``_stats`` is small and
        this is ~instant instead of a 0.27s deepcopy of a 24MB blob on every
        dashboard poll / VULN_CONFIRMED broadcast.
        """
        import copy

        if self._stats_cache is None:
            self._stats_cache = copy.deepcopy(self._stats)
        return copy.deepcopy(self._stats_cache)

    async def register_scan(self, scan_data: dict[str, Any]):
        async with self._lock:
            # Initialize event buffer for this scan to satisfy reporting requirements
            if "events" not in scan_data:
                scan_data["events"] = []
            # Ensure scan_id alias exists for test compatibility
            if "id" in scan_data and "scan_id" not in scan_data:
                scan_data["scan_id"] = scan_data["id"]

            existing_index = next(
                (idx for idx, scan in enumerate(self._stats["scans"]) if scan.get("id") == scan_data.get("id")),
                None,
            )
            if existing_index is None:
                self._stats["scans"].append(scan_data)
                self._stats["total_scans"] += 1
            else:
                self._stats["scans"][existing_index] = scan_data
            self._stats["active_scans"] = sum(
                1 for scan in self._stats["scans"] if scan.get("status") in {"Initializing", "Running", "Finalizing"}
            )
            self._save()

    async def add_scan_event(self, scan_id: str, event: dict[str, Any]) -> None:
        """Append a live event to a scan WITHOUT touching the stats.json blob.

        V8 LOAD FIX: events are written to the per-scan in-memory buffer
        (``_scan_events`` — every event stays visible through the events
        endpoint) and batched into ``_pending_events`` for the durable SQLite
        event log (``scan_state_db.events``). The global ``_stats`` structure is
        NOT modified and NOT marked dirty — a scan that emits 2000 events no
        longer triggers a 24MB stats.json rewrite every 2 seconds. ``_load``
        migrates any legacy embedded events into the same buffer/SQLite so
        nothing is lost on restart.

        WHEN: Every scan event (DOM mutation, network probe, AI thought,
        etc.). On a typical scan that is 100s–1000s of events per minute.
        """
        async with self._lock:
            buf = self._scan_events.setdefault(scan_id, [])
            buf.append(event)
            # Bound in-memory history per scan (the SQLite log keeps EVERYTHING,
            # so this cap only bounds RAM, never evidence).
            if len(buf) > 20000:
                del buf[: len(buf) - 20000]
            with self._sqlite_flush_lock:
                self._pending_events.append({"scan_id": scan_id, "event": event})
                # Bounded queue: if SQLite is persistently down the batch would
                # otherwise grow without limit (memory leak). On overflow drop
                # the OLDEST pending events — they stay visible via
                # ``_scan_events`` for the session; only SQLite durability is
                # forfeited for them, which is already forfeit while it's down.
                if len(self._pending_events) > 100_000:
                    del self._pending_events[: len(self._pending_events) - 100_000]
            # Keep the writer alive so the SQLite flush actually runs, but do
            # NOT mark the stats blob dirty (events don't live in _stats).
            self._ensure_writer()

    async def increment_request_count(self, count: int = 1) -> None:
        """Atomically increment the global request counter for performance tracking.

        This is the per-intercepted-request hot path (socket_manager calls it
        for EVERY request event). It must NOT go through ``_mark_dirty()``:
        that invalidates ``_stats_cache``, forcing the next ``get_stats()`` to
        re-deepcopy every scan record just because a scalar counter bumped —
        turning a counter increment into O(scans) work per request. The counter
        stays live via ``get_total_requests()``; persistence is unchanged
        (the dirty flag still schedules the next 2s write).
        """
        async with self._lock:
            self._stats["total_requests"] += count
            self._dirty = True
            self._ensure_writer()

    async def get_total_requests(self) -> int:
        """Cheap read of the live request counter (no deepcopy of the stats blob)."""
        async with self._lock:
            return int(self._stats.get("total_requests", 0))

    async def record_finding(
        self, scan_id: str, severity: str = "Medium", signature_data: dict[str, Any] = None
    ) -> None:
        """Real-time update for a found vulnerability with async-safe deduplication.

        Persists the finding in BOTH places:
          * Global counters (``stats.vulnerabilities`` / ``stats.critical``).
          * The scan record itself under ``scan["findings"]`` so the
            ``GET /api/scans/{scan_id}/findings`` endpoint can surface it
            mid-scan (Architecture §22). Without this, findings only become
            visible after ``complete_scan`` writes ``scan["results"]``.
        """
        async with self._lock:
            is_duplicate = False
            if signature_data:
                # Generate stable signature
                sig_str = json.dumps(signature_data, sort_keys=True, default=str)
                sig = hashlib.sha256(sig_str.encode()).hexdigest()

                if scan_id not in self._seen_signatures:
                    self._seen_signatures[scan_id] = set()

                if sig in self._seen_signatures[scan_id]:
                    is_duplicate = True
                else:
                    self._seen_signatures[scan_id].add(sig)

            if is_duplicate:
                return  # Skip duplicate

            self._stats["vulnerabilities"] += 1

            if severity.upper() in ["CRITICAL", "HIGH"]:
                self._stats["critical"] += 1

            # Update history for graph spike (INSIDE lock to prevent race condition)
            current_total = self._stats["vulnerabilities"]
            self._stats["history"].append(current_total)
            if len(self._stats["history"]) > 30:
                self._stats["history"].pop(0)

            # Persist to per-scan ``findings`` so GET /api/scans/{id}/findings
            # surfaces this immediately, not just after the scan completes.
            # The enriched_finding dict (from orchestrator) includes CVSS 4.0
            # scores, evidence, remediation, CWE, and reproduction steps.
            if signature_data:
                finding_record = dict(signature_data)
                finding_record.setdefault("severity", severity)
                for s in self._stats.get("scans", []):
                    if s.get("id") == scan_id or s.get("scan_id") == scan_id:
                        if "findings" not in s:
                            s["findings"] = []
                        s["findings"].append(finding_record)
                        break

            # Route through _mark_dirty so the background writer is alive
            # and writes are debounced (see add_scan_event).
            self._mark_dirty()

    async def record_threat(self, threat_type: str, risk_score: int) -> None:
        """V6: Record a detected threat for metrics (Async-Safe)."""
        async with self._lock:
            v6 = self._stats.get("v6_metrics", {})

            # Categorize by threat type
            if threat_type.upper() in ["PROMPT_INJECTION", "HIDDEN_TEXT", "INVISIBLE_TEXT"]:
                v6["injections_blocked"] = v6.get("injections_blocked", 0) + 1
            elif threat_type.upper() in ["DARK_PATTERN_BLOCK", "DECEPTIVE_UI", "PHISHING"]:
                v6["deceptive_ui_blocked"] = v6.get("deceptive_ui_blocked", 0) + 1

            # Update cumulative risk score (Track peak risk)
            current_risk = v6.get("risk_score", 0)
            v6["risk_score"] = max(current_risk, risk_score)

            self._stats["v6_metrics"] = v6
            self._save()

    def complete_scan(self, scan_id: str, results: list[Any], duration: float) -> None:
        with self._sync_lock:
            self._stats["active_scans"] = max(0, self._stats["active_scans"] - 1)

            # Clean up ephemeral signatures for this scan
            if scan_id in self._seen_signatures:
                del self._seen_signatures[scan_id]

        # Canonical dedup: collapse Docker gateway / host aliases so the
        # same vuln on 127.0.0.1 / host.docker.internal / 192.168.65.254
        # appears exactly once in the final results list.
        from backend.reporting.finding_normalizer import canonical_finding_key

        _target_url = ""
        for s in self._stats["scans"]:
            if s["id"] == scan_id:
                _target_url = str(s.get("target_url") or s.get("target") or "")
                break

        seen_results: set[tuple] = set()
        unique_results = []

        for r in results:
            payload = r.get("payload", {})
            key = canonical_finding_key(
                str(payload.get("url", "")),
                str(payload.get("type", "")),
                target_url=_target_url,
            )
            if key is None or key in seen_results:
                continue
            seen_results.add(key)
            unique_results.append(r)

        for s in self._stats["scans"]:
            if s["id"] == scan_id:
                s["status"] = "Finalizing"  # V6: AI is building the report
                # Defensive duration formatting
                try:
                    s["duration"] = f"{float(duration):.2f}s"
                except (TypeError, ValueError):
                    s["duration"] = "N/A"
                s["results"] = unique_results
                s["report_ready"] = s.get("report_ready", False)
                break

        self.flush_immediate()

    def sync_complete_scan(self, scan_id: str, status: str = "Completed", report_ready: bool = True) -> None:
        """Atomic completion to avoid race conditions between 'Completed' and 'Report Ready'."""
        self._stats["active_scans"] = max(0, self._stats["active_scans"] - 1)
        for s in self._stats["scans"]:
            if s["id"] == scan_id:
                s["status"] = status
                s["report_ready"] = report_ready
                break
        self.flush_immediate()

    def mark_report_ready(self, scan_id: str) -> None:
        """V6: Mark the AI report as generated and ready for instant download."""
        for s in self._stats["scans"]:
            if s["id"] == scan_id:
                s["report_ready"] = True
                # Safety: If it's ready, it shouldn't be in a 'Finalizing' or 'Running' state anymore
                if s["status"] in ["Finalizing", "Running"]:
                    s["status"] = "Completed"
                break
        self.flush_immediate()

    async def wipe_scans(self) -> None:
        """Wipe all historical scan records from the database and sharded files.

        FIX-060: Made async and wrapped sync filesystem I/O in asyncio.to_thread
        to avoid blocking the event loop (Architecture §29.13).
        """
        import shutil

        # Clear in-memory stats
        self._stats["scans"] = []
        self._stats["total_scans"] = 0
        self._stats["active_scans"] = 0
        self._stats["vulnerabilities"] = 0
        self._stats["critical"] = 0
        self._stats["history"] = [0] * 30
        self._stats["v6_metrics"] = {"injections_blocked": 0, "deceptive_ui_blocked": 0, "risk_score": 0}
        # V8: clear the live event buffers + pending SQLite batch too
        self._scan_events.clear()
        self._events_hydrated.clear()
        with self._sqlite_flush_lock:
            self._pending_events.clear()
        try:
            from backend.core.scan_state_db import scan_state_db

            scan_state_db.clear_events()
        except Exception as exc:
            logger.warning("[StateManager] SQLite event wipe failed: %s", exc)

        def _wipe_files_sync():
            # Clear sharded scan state files in scan_states/
            self._ensure_scans_dir()
            try:
                if os.path.exists(self.SCANS_DIR):
                    for fname in os.listdir(self.SCANS_DIR):
                        if fname.startswith("scan_") and fname.endswith(".json"):
                            file_path = os.path.join(self.SCANS_DIR, fname)
                            try:
                                os.remove(file_path)
                                logger.info(f"[StateManager] Deleted sharded scan file: {fname}")
                            except Exception as e:
                                logger.error(f"[StateManager] Error deleting sharded scan file {fname}: {e}")
            except Exception as e:
                logger.error(f"[StateManager] Error accessing scan_states directory: {e}")

            # Clear brain episodes
            episodes_dir = "brain/episodes"
            if os.path.exists(episodes_dir):
                try:
                    for fname in os.listdir(episodes_dir):
                        if fname.endswith(".json"):
                            file_path = os.path.join(episodes_dir, fname)
                            try:
                                os.remove(file_path)
                                logger.info(f"[StateManager] Deleted brain episode: {fname}")
                            except Exception as e:
                                logger.error(f"[StateManager] Error deleting brain episode {fname}: {e}")
                except Exception as e:
                    logger.error(f"[StateManager] Error accessing brain/episodes directory: {e}")

            # Clear scan_states subdirectories (forensics, sandboxes, sessions)
            subdirs_to_clean = ["forensics", "sandboxes", "sessions"]
            for subdir in subdirs_to_clean:
                subdir_path = os.path.join(self.SCANS_DIR, subdir)
                if os.path.exists(subdir_path):
                    try:
                        for item in os.listdir(subdir_path):
                            item_path = os.path.join(subdir_path, item)
                            try:
                                if os.path.isfile(item_path):
                                    os.remove(item_path)
                                elif os.path.isdir(item_path):
                                    shutil.rmtree(item_path)
                                logger.info(f"[StateManager] Deleted {subdir}/{item}")
                            except Exception as e:
                                logger.error(f"[StateManager] Error deleting {subdir}/{item}: {e}")
                    except Exception as e:
                        logger.error(f"[StateManager] Error accessing {subdir_path}: {e}")

        await asyncio.to_thread(_wipe_files_sync)

        # Save to disk
        self._save()
        logger.info("[StateManager] All historical scans wiped successfully.")

    def reset_stale_scans(self) -> int:
        """Called on startup to clean up zombie scans."""
        cleaned = 0
        for s in self._stats["scans"]:
            if s["status"] == "Running":
                s["status"] = "Interrupted"
                cleaned += 1
        self._stats["active_scans"] = 0
        if cleaned > 0:
            self._save()
        return cleaned

    # --- PROBLEM 9 FIX: Sharded per-scan state storage ---
    SCANS_DIR = "scan_states"

    def _ensure_scans_dir(self) -> None:
        os.makedirs(self.SCANS_DIR, exist_ok=True)

    def _scan_file(self, scan_id: str) -> str:
        self._ensure_scans_dir()
        safe_id = scan_id.replace("/", "_").replace("\\", "_")
        return os.path.join(self.SCANS_DIR, f"scan_{safe_id}.json")

    async def write_scan_state(self, scan_id: str, data: dict) -> None:
        """Write individual scan to its own file — no contention with stats.json."""
        path = self._scan_file(scan_id)
        tmp = path + ".tmp"
        async with self._lock:
            try:

                def _write():
                    with open(tmp, "w") as f:
                        json.dump(data, f, indent=2, default=str)
                    os.replace(tmp, path)

                await asyncio.to_thread(_write)
            except Exception as e:
                logger.error(f"[StateManager] Sharded write error: {e}")

    async def read_scan_state(self, scan_id: str) -> dict[str, Any]:
        path = self._scan_file(scan_id)
        try:

            def _read():
                with open(path) as f:
                    return json.load(f)

            return await asyncio.to_thread(_read)
        except FileNotFoundError:
            return {}
        except Exception as e:
            logger.debug("[State] load scan failed: %s", e)
            return {}

    async def list_scan_states(self) -> list[dict[str, Any]]:
        """Read all sharded scan state files via thread pool to avoid blocking the event loop."""
        return await asyncio.to_thread(self._list_scan_states_sync)

    def _list_scan_states_sync(self) -> list[dict[str, Any]]:
        """Synchronous implementation of list_scan_states."""
        self._ensure_scans_dir()
        scans = []
        for fname in os.listdir(self.SCANS_DIR):
            if fname.startswith("scan_") and fname.endswith(".json"):
                try:
                    with open(os.path.join(self.SCANS_DIR, fname), encoding="utf-8") as f:
                        scans.append(json.load(f))
                except Exception as e:
                    logger.debug("[State] parse scan file skipped: %s", e)
                    continue
        return sorted(scans, key=lambda x: x.get("started_at", 0), reverse=True)

    async def find_vulnerability(self, vuln_id: str) -> dict[str, Any] | None:
        """Search across all sharded scan files for a specific vulnerability."""

        def _search():
            self._ensure_scans_dir()
            for fname in os.listdir(self.SCANS_DIR):
                if fname.startswith("scan_") and fname.endswith(".json"):
                    try:
                        with open(os.path.join(self.SCANS_DIR, fname)) as f:
                            scan = json.load(f)
                            for v in scan.get("vulnerabilities", []):
                                if v.get("vuln_id") == vuln_id:
                                    return v
                    except Exception as e:
                        logger.debug("[State] parse scan file skipped: %s", e)
                        continue
            return None

        result = await asyncio.to_thread(_search)
        if result:
            return result
        # Fallback: search in stats.json scans
        for s in self._stats.get("scans", []):
            for r in s.get("results", []):
                payload = r.get("payload", {})
                if payload.get("vuln_id") == vuln_id or payload.get("id") == vuln_id:
                    return payload
        return None

    async def initialize_scan(self, scan_id: str, target_url: str) -> None:
        """Initialize a new scan with the given scan_id and target_url."""
        scan_data = {
            "id": scan_id,
            "scan_id": scan_id,
            "target_url": target_url,
            "status": "initialized",
            "timestamp": str(asyncio.get_event_loop().time()),
            "results": [],
            "events": [],
        }
        await self.register_scan(scan_data)
        await self.write_scan_state(scan_id, scan_data)

    def _hydrate_events_from_sqlite(self, scan_id: str) -> None:
        """Load a scan's durable SQLite event log into the live buffer once.

        Post-restart the in-memory ``_scan_events`` is empty; this restores the
        full event history from the SQLite log so the events API keeps showing
        every event (the user-visible proof contract is unchanged).

        OPTIMIZATION: ``_events_hydrated`` records that a scan's SQLite log was
        loaded (or found empty) so the API list endpoint doesn't re-query
        SQLite for every scan on every poll — the per-scan event buffer is
        authoritative once hydrated, and ``add_scan_event`` appends to it
        directly.
        """
        if scan_id in self._events_hydrated:
            return
        self._events_hydrated.add(scan_id)
        try:
            from backend.core.scan_state_db import scan_state_db

            events = scan_state_db.get_events(scan_id, limit=20000)
            if events:
                self._scan_events[scan_id] = events[-20000:]
        except Exception as exc:
            logger.debug("[StateManager] SQLite event hydrate skipped for %s: %s", scan_id, exc)

    def get_scan_state(self, scan_id: str, include_events: bool = True) -> dict[str, Any] | None:
        """Get the current state of a scan by scan_id.

        V8 LOAD FIX: the returned dict is a shallow copy of the scan record with
        the LIVE event list attached (``_scan_events``), so every consumer that
        previously read ``scan["events"]`` (events endpoint, ``_findings_from_scan``,
        reports) sees exactly the same data — all events, always visible.

        ``include_events=False`` skips the event-buffer copy entirely (used by
        the scan LIST endpoint, which only needs persisted findings/results and
        must stay fast even with 100+ historical scans).
        """
        for scan in self._stats.get("scans", []):
            if scan.get("id") == scan_id or scan.get("scan_id") == scan_id:
                out = dict(scan)
                if include_events:
                    events = self._scan_events.get(scan_id)
                    if not events:
                        self._hydrate_events_from_sqlite(scan_id)
                        events = self._scan_events.get(scan_id)
                    out["events"] = list(events or [])
                return out
        return None

    def get_scan_events_page(
        self, scan_id: str, *, limit: int = 500, offset: int = 0, newest_first: bool = False
    ) -> tuple[list[dict[str, Any]], int]:
        """Page a scan's event log WITHOUT copying the whole scan record.

        The events endpoint previously went through ``get_scan_state()`` which
        shallow-copies the scan record AND ``list(events)``-copies every event
        (up to 20k) just to slice out a page. This slices the live buffer
        directly, so a 2000-event scan costs a 500-item slice instead of a
        2000-item copy plus the scan-record copy on every request.
        """
        events = self._scan_events.get(scan_id)
        if not events:
            self._hydrate_events_from_sqlite(scan_id)
            events = self._scan_events.get(scan_id) or []
        total = len(events)
        if newest_first:
            # Slice from the tail without materialising a reversed copy.
            start = max(0, total - offset - limit)
            end = max(0, total - offset)
            page = list(reversed(events[start:end]))
        else:
            page = events[offset : offset + limit]
        return page, total

    def update_scan_status(self, scan_id: str, status: str) -> None:
        """Update the status of a scan."""
        for scan in self._stats["scans"]:
            if scan.get("id") == scan_id or scan.get("scan_id") == scan_id:
                scan["status"] = status
                self._mark_dirty()
                break

    def add_finding(self, scan_id: str, finding: dict[str, Any]) -> None:
        """Add a finding to a scan."""
        for scan in self._stats["scans"]:
            if scan.get("id") == scan_id or scan.get("scan_id") == scan_id:
                if "findings" not in scan:
                    scan["findings"] = []
                scan["findings"].append(finding)
                self._mark_dirty()
                break

    def get_findings(self, scan_id: str) -> list[dict[str, Any]]:
        """Get all findings for a scan."""
        for scan in self._stats.get("scans", []):
            if scan.get("id") == scan_id or scan.get("scan_id") == scan_id:
                return scan.get("findings", [])
        return []

    def add_error(self, scan_id: str, error_msg: str) -> None:
        """Add an error message to a scan."""
        for scan in self._stats["scans"]:
            if scan.get("id") == scan_id or scan.get("scan_id") == scan_id:
                if "errors" not in scan:
                    scan["errors"] = []
                scan["errors"].append({"message": error_msg, "timestamp": str(asyncio.get_event_loop().time())})
                self._mark_dirty()
                break

    def update_scan_metadata(self, scan_id: str, metadata: dict[str, Any]) -> None:
        """Update metadata for a scan."""
        for scan in self._stats["scans"]:
            if scan.get("id") == scan_id or scan.get("scan_id") == scan_id:
                if "metadata" not in scan:
                    scan["metadata"] = {}
                scan["metadata"].update(metadata)
                self._mark_dirty()
                break

    def update_scan_progress(self, scan_id: str, progress: dict[str, Any]) -> None:
        """Update progress information for a scan."""
        for scan in self._stats["scans"]:
            if scan.get("id") == scan_id or scan.get("scan_id") == scan_id:
                scan["progress"] = progress
                self._mark_dirty()
                break


# Singleton Instance
stats_db_manager = StateManager()
# NOTE: stats_db global alias removed — it exposed mutable _stats without locking.
# All access should go through stats_db_manager.get_stats() which returns a copy.
