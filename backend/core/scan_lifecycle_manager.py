"""
ScanLifecycleManager - Control Plane for Scan Lifecycle
========================================================
Extracted from the HiveOrchestrator as part of Two-Tiered Architecture Phase 1.

Responsibilities:
  1. Scan registration and idempotency
  2. Agent activation and global registry wiring
  3. Self-healing registration for all agents
  4. Phase transitions with lifecycle event broadcasting
  5. Scan finalization (telemetry collection, report generation)
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ScanLifecycleManager:
    """Manages scan lifecycle: registration, agent bootstrapping, phase transitions, finalization."""

    def __init__(self, *, manager: Any, stats_db: Any, phase_gate: Any,
                 event_bus: Any, scan_id: str, target_config: Dict[str, Any],
                 scan_events: deque, broadcast_throttle: Any):
        self._manager = manager
        self._stats_db = stats_db
        self._phase_gate = phase_gate
        self._event_bus = event_bus
        self._scan_id = scan_id
        self._target_config = target_config
        self._scan_events = scan_events
        self._broadcast_throttle = broadcast_throttle
        self._start_time: float = time.time()
        self._phase_durations: Dict[str, float] = {}

    # -- 1. Scan Registration -------------------------------------------

    async def register_scan(self) -> bool:
        """Register the scan in the database with idempotency check.
        Returns True if new, False if already registered.

        Uses stats_db_manager's actual API:
          - get_scan_state(scan_id) -> dict|None  (lookup by id)
          - update_scan_status(scan_id, status)   (set status)
          - register_scan(scan_record)             (async insert)
        """
        existing = self._stats_db.get_scan_state(self._scan_id)
        if existing:
            logger.info("[Lifecycle] Scan %s already registered", self._scan_id)
            self._stats_db.update_scan_status(self._scan_id, "Running")
            return False

        scan_record = {
            "id": self._scan_id,
            "status": "Initializing",
            "target_url": self._target_config["url"],
            "modules": self._target_config.get("modules", []),
            "started_at": self._start_time,
            "results": [],
        }
        try:
            await self._stats_db.register_scan(scan_record)
        except Exception as exc:
            logger.warning("[Lifecycle] register_scan failed: %s", exc)

        await self._broadcast_scan_update("Initializing")
        await self._broadcast_live_feed("SCAN_INITIALIZED", {
            "action": "Target Acquired",
            "url": self._target_config["url"],
            "scan_id": self._scan_id,
            "timestamp": time.strftime("%H:%M:%S"),
            "agent": "Orchestrator",
            "threat_type": "LIFECYCLE",
            "severity": "INFO", "risk_score": 0,
        })
        return True

    # -- 2. Agent Activation & Registry Wiring --------------------------

    async def activate_agents(self, agents: List[Any], *,
                              mission_config: Dict[str, Any]) -> None:
        """Start all agents and register them in the global active_agents registry.

        This replaces the inline ``for agent in agents:`` loop that was
        previously duplicated inside bootstrap_hive().

        Args:
            agents: List of agent instances (each must have .name, .start()).
            mission_config: Dict with target, scan_id, modules to pass to agents.
        """
        from backend.core.orchestrator import HiveOrchestrator

        for agent in agents:
            try:
                # Pass mission profile if the agent supports it
                if hasattr(agent, "set_mission"):
                    agent.set_mission(mission_config)
                await agent.start()
                agent._is_active = True
                # Register in global state under both string key and name
                async with HiveOrchestrator._get_lock():
                    HiveOrchestrator.active_agents[agent.name] = agent
                await self._broadcast_live_feed("AGENT_ACTIVATED", {
                    "action": f"Agent {agent.name} online",
                    "url": self._target_config.get("url", ""),
                    "scan_id": self._scan_id,
                    "timestamp": time.strftime("%H:%M:%S"),
                    "agent": agent.name,
                    "threat_type": "LIFECYCLE",
                    "severity": "INFO", "risk_score": 0,
                })
            except Exception as exc:
                logger.error("[Lifecycle] Failed to start agent %s: %s",
                             getattr(agent, "name", "?"), exc)

        logger.info("[Lifecycle] Activated %d agents for scan %s",
                    len(agents), self._scan_id)

    # -- 3. Self-Healing Registration -----------------------------------

    def register_self_healing(self, agents: List[Any], *,
                              healing_engine: Any) -> None:
        """Register restart callbacks for all agents with the healing engine.

        This replaces the inline ``for agent in agents: healing_engine.register_restart_callback(...)``
        block that was previously duplicated inside bootstrap_hive().

        Args:
            agents: List of agent instances.
            healing_engine: The recovery_engine.healing_engine singleton.
        """
        for agent in agents:
            async def restart_callback(a=agent):
                try:
                    await a.start()
                    a._is_active = True
                    await self._manager.broadcast({
                        "type": "GI5_LOG",
                        "payload": f"SELF-HEALING: Restarted agent {a.name}"
                    })
                except Exception as e:
                    logger.error("[SelfHealing] Failed to restart %s: %s",
                                 a.name, e)

            healing_engine.register_restart_callback(agent.name, restart_callback)

        logger.info("[Lifecycle] Self-healing callbacks registered for %d agents",
                    len(agents))

    # -- 4. Phase Transitions -------------------------------------------

    async def advance_phase(self, to_phase: Any, *,
                            metadata: Optional[Dict[str, Any]] = None) -> None:
        """Advance to the next scan phase and broadcast lifecycle events."""
        from_phase = getattr(self._phase_gate, "current_phase", "UNKNOWN")
        phase_start = time.time()
        try:
            self._phase_gate.advance_to(to_phase)
        except Exception as exc:
            logger.error("[Lifecycle] Phase advance failed: %s", exc)
            return
        if from_phase != "UNKNOWN":
            self._phase_durations[str(from_phase)] = time.time() - phase_start
        await self._broadcast_event("PHASE_COMPLETED", {
            "phase": str(from_phase),
            "scan_id": self._scan_id,
            "timestamp": time.strftime("%H:%M:%S"),
            **(metadata or {}),
        })
        await self._broadcast_event("PHASE_STARTED", {
            "phase": str(to_phase),
            "scan_id": self._scan_id,
            "timestamp": time.strftime("%H:%M:%S"),
        })
        logger.info("[Lifecycle] Phase: %s -> %s", from_phase, to_phase)

    async def broadcast_phase_feed(self, phase_name: str, message: str,
                                   **extra: Any) -> None:
        """Broadcast a LIVE_ATTACK_FEED update for a phase event."""
        await self._broadcast_live_feed(phase_name, {
            "action": message,
            "scan_id": self._scan_id,
            "timestamp": time.strftime("%H:%M:%S"),
            "agent": "Orchestrator",
            "threat_type": "PHASE_TRANSITION",
            "severity": "INFO", "risk_score": 0,
            **extra,
        })

    # -- 5. Scan Finalization -------------------------------------------

    async def finalize(self, *, report_generator: Any = None,
                       ai_cortex: Any = None) -> Dict[str, Any]:
        """Finalize the scan: collect telemetry, generate report."""
        telemetry = self._collect_telemetry(ai_cortex=ai_cortex)
        if report_generator:
            try:
                await report_generator.generate(self._scan_id)
            except Exception as exc:
                logger.error("[Lifecycle] Report generation failed: %s", exc)
        await self._broadcast_event("SCAN_COMPLETE", {
            "scan_id": self._scan_id,
            "telemetry": telemetry,
            "timestamp": time.strftime("%H:%M:%S"),
        })
        return telemetry

    # -- Internal helpers -----------------------------------------------

    def _collect_telemetry(self, *, ai_cortex: Any = None) -> Dict[str, Any]:
        """Collect scan-level telemetry metrics.

        This is used by finalize() to produce the telemetry payload.
        ai_cortex is optional — if provided, its get_telemetry() is merged.
        """
        elapsed = time.time() - self._start_time
        telemetry: Dict[str, Any] = {
            "scan_id": self._scan_id,
            "duration_seconds": round(elapsed, 1),
            "phase_durations": dict(self._phase_durations),
            "total_events": len(self._scan_events),
        }
        if ai_cortex and hasattr(ai_cortex, "get_telemetry"):
            try:
                cortex_data = ai_cortex.get_telemetry()
                telemetry["llm_calls"] = cortex_data.get("llm_calls", 0)
                telemetry["avg_llm_latency"] = cortex_data.get("avg_llm_latency", 0.0)
                telemetry["circuit_breaker_trips"] = cortex_data.get("circuit_breaker_trips", 0)
            except Exception as exc:
                logger.debug("[Lifecycle] cortex telemetry unavailable: %s", exc)
        return telemetry

    async def _broadcast_scan_update(self, status: str) -> None:
        try:
            await self._manager.broadcast({
                "type": "SCAN_UPDATE", "scan_id": self._scan_id,
                "status": status, "timestamp": time.strftime("%H:%M:%S"),
            })
        except Exception as exc:
            logger.debug("[Lifecycle] broadcast_scan_update: %s", exc)

    async def _broadcast_live_feed(self, action: str, data: Dict[str, Any]) -> None:
        try:
            await self._manager.broadcast({"type": "LIVE_ATTACK_FEED", **data})
        except Exception as exc:
            logger.debug("[Lifecycle] broadcast_live_feed: %s", exc)

    async def _broadcast_event(self, event_type: str, data: Dict[str, Any]) -> None:
        try:
            await self._manager.broadcast({"type": event_type, **data})
        except Exception as exc:
            logger.debug("[Lifecycle] broadcast_event: %s", exc)
