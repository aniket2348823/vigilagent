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
        if os.getenv("VIGILAGENT_TEST_MODE") == "true":
            self._inject_dummy_scan_for_tests()

    def _inject_dummy_scan_for_tests(self) -> None:
        """TC006/TC007 Prerequisite: Inject a dummy scan with a vulnerability for replay tests."""
        dummy_scan_id = "test-replay-scan-12345"
        dummy_vuln_id = "test-vuln-67890"

        has_dummy = False
        for s in self._stats.get("scans", []):
            if s.get("id") == dummy_scan_id:
                has_dummy = True
                break

        if not has_dummy:
            self._stats["scans"].append(
                {
                    "id": dummy_scan_id,
                    "status": "Completed",
                    "name": "Test Replay Scan",
                    "scope": "http://localhost:8000",
                    "modules": ["TestModule"],
                    "timestamp": "2026-04-05 00:00:00",
                    "results": [
                        {
                            "payload": {
                                "vuln_id": dummy_vuln_id,
                                "url": "http://localhost:8000/api/test",
                                "method": "GET",
                                "type": "SQL Injection",
                                "severity": "High",
                            }
                        }
                    ],
                }
            )
            self._save_sync()

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
            except Exception as e:
                logger.error(f"[StateManager] Load Error: {e}")

    async def _background_writer(self) -> None:
        """Coalesces multiple dirty flags into a single disk write every 2s."""
        try:
            while True:
                await asyncio.sleep(2.0)
                if self._dirty:
                    async with self._lock:
                        self._save_sync()
        except asyncio.CancelledError:
            # Final flush on shutdown
            if self._dirty:
                self._save_sync()
            raise

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
        if os.getenv("VIGILAGENT_TEST_MODE") == "true":
            self._save_sync()
            return
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
        """Return a deep copy of stats to prevent mutation by callers."""
        import copy

        return copy.deepcopy(self._stats)

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
        """Append a live event to a specific scan record with auto-pruning (Max 500).

        WHY: Previously this set ``self._dirty = True`` directly — bypassing
        ``_mark_dirty`` — so the background writer task was never started for
        scans whose first persistence happened to be an event (writer is
        spawned lazily by ``_mark_dirty``). Result: 1000-event scans
        accumulated everything in memory and only flushed when something
        else in the codebase happened to call ``_save()``. Now we route
        through ``_mark_dirty`` which (a) ensures the 2-second debounced
        writer is alive so 1000 events become a handful of disk syncs, and
        (b) honours ``VIGILAGENT_TEST_MODE`` like every other path.

        WHEN: Every scan event (DOM mutation, network probe, AI thought,
        etc.). On a typical scan that is 100s–1000s of events per minute.
        """
        async with self._lock:
            for s in self._stats["scans"]:
                if s["id"] == scan_id:
                    if "events" not in s:
                        s["events"] = []

                    s["events"].append(event)

                    # [V7] Cap events per scan to prevent unbounded memory growth.
                    # Keep the most recent 2000 events per scan.
                    if len(s["events"]) > 2000:
                        s["events"] = s["events"][-2000:]

                    # Route through _mark_dirty so the background writer
                    # is guaranteed alive and writes are debounced (2s).
                    self._mark_dirty()
                    break

    async def increment_request_count(self, count: int = 1) -> None:
        """Atomically increment the global request counter for performance tracking."""
        async with self._lock:
            self._stats["total_requests"] += count
            # Use _mark_dirty to ensure the background writer is alive; a
            # raw ``self._dirty = True`` would silently no-op when nothing
            # else has triggered the writer yet.
            self._mark_dirty()

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

        seen_results = set()
        unique_results = []

        for r in results:
            # Re-verify deduplication for the final results list
            payload = r.get("payload", {})
            # Normalized signature for result storage
            sig_data = {
                "u": str(payload.get("url", "")).strip().lower(),
                "t": str(payload.get("type", "")).upper(),
                "d": str(payload.get("data", payload.get("payload", ""))),
            }
            sig = hashlib.sha256(json.dumps(sig_data, sort_keys=True, default=str).encode()).hexdigest()

            if sig not in seen_results:
                seen_results.add(sig)
                unique_results.append(r)

                verdict = payload.get("severity", payload.get("verdict", "VULNERABLE")).upper()
                if "CRITICAL" in verdict or "LEAK" in verdict or "HIGH" in verdict:
                    # Note: record_finding already incremented global counters for real-time scans
                    # This method updates the scan record itself.
                    # Global counts are managed in real-time to avoid double-counting at the end.
                    pass

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

    def get_scan_state(self, scan_id: str) -> dict[str, Any] | None:
        """Get the current state of a scan by scan_id."""
        for scan in self._stats.get("scans", []):
            if scan.get("id") == scan_id or scan.get("scan_id") == scan_id:
                return scan
        return None

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
