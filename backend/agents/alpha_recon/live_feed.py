"""
Alpha V6 Live Recon Feed — WebSocket endpoint for dashboard.

Provides real-time streaming of recon progress, phase transitions,
entity discoveries, and vulnerability findings to the React frontend.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from typing import Any

logger = logging.getLogger("alpha.livefeed")


class ReconLiveFeed:
    """Manages WebSocket subscriptions for live recon data streaming."""

    def __init__(self):
        self._subscribers: dict[str, list[asyncio.Queue]] = defaultdict(list)
        self._scan_stats: dict[str, dict[str, Any]] = {}

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        """Subscribe to live updates for a scan."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subscribers[scan_id].append(queue)
        logger.info(f"LiveFeed subscriber added for scan {scan_id}")
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue):
        """Remove a subscriber."""
        if scan_id in self._subscribers:
            self._subscribers[scan_id] = [q for q in self._subscribers[scan_id] if q is not queue]

    async def broadcast(self, scan_id: str, event_type: str, data: dict[str, Any]):
        """Broadcast an event to all subscribers of a scan."""
        message = {
            "type": event_type,
            "scan_id": scan_id,
            "timestamp": time.time(),
            "data": data,
        }
        dead_queues = []
        for queue in self._subscribers.get(scan_id, []):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                dead_queues.append(queue)
        # Remove dead queues
        for dq in dead_queues:
            self.unsubscribe(scan_id, dq)

    # ── Event Handlers (called from orchestrator) ─────────────

    async def on_phase_started(self, scan_id: str, phase: str, meta: dict = None):
        stats = self._ensure_stats(scan_id)
        stats["current_phase"] = phase
        stats["phase_started_at"] = time.time()
        await self.broadcast(
            scan_id, "phase_started", {"phase": phase, "meta": meta or {}, "stats": self._public_stats(stats)}
        )

    async def on_phase_completed(self, scan_id: str, phase: str, entities_count: int, tools_count: int):
        stats = self._ensure_stats(scan_id)
        stats["phases_completed"] = stats.get("phases_completed", 0) + 1
        stats["total_entities"] = stats.get("total_entities", 0) + entities_count
        stats["total_tools_run"] = stats.get("total_tools_run", 0) + tools_count
        await self.broadcast(
            scan_id,
            "phase_completed",
            {
                "phase": phase,
                "entities_found": entities_count,
                "tools_run": tools_count,
                "stats": self._public_stats(stats),
            },
        )

    async def on_entity_discovered(self, scan_id: str, kind: str, label: str, source_tool: str):
        stats = self._ensure_stats(scan_id)
        kind_counts = stats.setdefault("entity_counts", {})
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
        # Throttle entity events to max 10/sec per kind
        throttle_key = f"entity_{kind}"
        now = time.time()
        if now - stats.get(f"last_{throttle_key}", 0) < 0.1:
            return
        stats[f"last_{throttle_key}"] = now
        await self.broadcast(
            scan_id,
            "entity_discovered",
            {"kind": kind, "label": label[:200], "source_tool": source_tool, "kind_total": kind_counts[kind]},
        )

    async def on_vulnerability_found(self, scan_id: str, name: str, severity: str, target: str, confidence: float):
        stats = self._ensure_stats(scan_id)
        stats["vulns_found"] = stats.get("vulns_found", 0) + 1
        await self.broadcast(
            scan_id,
            "vulnerability_found",
            {
                "name": name,
                "severity": severity,
                "target": target,
                "confidence": confidence,
                "total_vulns": stats["vulns_found"],
            },
        )

    async def on_tool_started(self, scan_id: str, tool_name: str, phase: str):
        await self.broadcast(scan_id, "tool_started", {"tool": tool_name, "phase": phase})

    async def on_tool_completed(self, scan_id: str, tool_name: str, status: str, duration_ms: int, output_bytes: int):
        await self.broadcast(
            scan_id,
            "tool_completed",
            {"tool": tool_name, "status": status, "duration_ms": duration_ms, "output_bytes": output_bytes},
        )

    async def on_scan_complete(self, scan_id: str, summary: dict[str, Any]):
        stats = self._ensure_stats(scan_id)
        stats["status"] = "completed"
        stats["completed_at"] = time.time()
        await self.broadcast(scan_id, "scan_complete", {"summary": summary, "stats": self._public_stats(stats)})
        # Clean up stats after a delay
        asyncio.get_event_loop().call_later(300, lambda: self._scan_stats.pop(scan_id, None))

    async def on_error(self, scan_id: str, error: str, context: str = ""):
        await self.broadcast(scan_id, "error", {"error": error, "context": context})

    # ── Internal ──────────────────────────────────────────────

    def _ensure_stats(self, scan_id: str) -> dict[str, Any]:
        if scan_id not in self._scan_stats:
            self._scan_stats[scan_id] = {
                "started_at": time.time(),
                "status": "running",
                "current_phase": "initialization",
                "phases_completed": 0,
                "total_entities": 0,
                "total_tools_run": 0,
                "vulns_found": 0,
                "entity_counts": {},
            }
        return self._scan_stats[scan_id]

    def _public_stats(self, stats: dict) -> dict:
        elapsed = time.time() - stats.get("started_at", time.time())
        return {
            "elapsed_seconds": int(elapsed),
            "current_phase": stats.get("current_phase", ""),
            "phases_completed": stats.get("phases_completed", 0),
            "total_entities": stats.get("total_entities", 0),
            "total_tools_run": stats.get("total_tools_run", 0),
            "vulns_found": stats.get("vulns_found", 0),
            "entity_counts": stats.get("entity_counts", {}),
        }

    def get_scan_stats(self, scan_id: str) -> dict[str, Any] | None:
        """Get current stats for a scan (REST endpoint support)."""
        stats = self._scan_stats.get(scan_id)
        return self._public_stats(stats) if stats else None


# Singleton instance
recon_live_feed = ReconLiveFeed()
