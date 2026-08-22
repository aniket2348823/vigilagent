"""
AGENT ALPHA — Unified Recon Commander (Architecture §5.1, §5.1.1)
================================================================================
Alpha is ONE unified agent family. The recon runtime spine lives in the
`backend.agents.alpha_recon` package (phase control, parsers, entity ingestion,
artifacts, scoring, dedupe, live feed, scope gates). The former separate
"alpha_v6" name is gone — there is a single Alpha agent over a single recon
spine: no second orchestration path, no duplicate parser registry, no duplicate
artifact storage, no duplicate scoring.

Responsibilities (Architecture §5.1.1 — Alpha Unified):
  - Passive + active recon, LAN/private-scope discovery when authorized.
  - Browser-aware recon through Delta/Prism/OpenClaw/PinchTab.
  - API/schema discovery; normalize every output into graph entities.
  - Emit live events; produce recon confidence scores.
  - Hand validated surface data to Omega and Sigma.
"""

import logging

from backend.ai.cortex import get_cortex_engine
from backend.core.browser_agent import BrowserEnabledAgent
from backend.core.config import settings
from backend.core.hive import EventType, HiveEvent
from backend.core.protocol import AgentID, JobPacket, ModuleConfig

logger = logging.getLogger("AgentAlpha")


class AlphaAgent(BrowserEnabledAgent):
    """Unified Alpha recon commander over the single recon spine."""

    # Long-running WORK handler: handle_target_acquired runs the FULL recon
    # pipeline (minutes). The generic 30s event-bus handler ceiling would
    # cancel it mid-phase (observed: nmap/tlsx killed at 0 bytes) — opt out.
    _HANDLER_TIMEOUT_SECONDS = None

    def __init__(self, bus):
        super().__init__("agent_alpha", bus)
        self.cortex = get_cortex_engine()
        self.MAX_CRAWL_DEPTH = 5
        # Single recon spine. A browser provider (lazy) is injected so the
        # spine's browser_recon module can drive OpenClaw/PinchTab during the
        # async HTTP phase without forcing browser init at construction time
        # (Architecture §5.1.1).
        # AlphaOrchestrator imported lazily: it drags in the whole alpha_recon
        # toolchain (~9s of import time). Construction happens once per scan,
        # so the deferral only saves boot time, never scan behavior.
        from backend.agents.alpha_recon import AlphaOrchestrator

        self.alpha_recon = AlphaOrchestrator(bus, agent_name=self.name, browser_provider=lambda: self.browser)
        # Governance: throttle flag from Zeta (Architecture §5.2/§29.4).
        self._throttled = False

    async def setup(self):
        self.bus.subscribe(EventType.JOB_ASSIGNED, self.handle_job)
        self.bus.subscribe(EventType.TARGET_ACQUIRED, self.handle_target_acquired)
        # Honor Zeta's runtime governor — pause new recon dispatch on
        # THROTTLE/STEALTH_MODE rather than spawning more browser/HTTP tasks.
        self.bus.subscribe(EventType.CONTROL_SIGNAL, self.handle_control_signal)

    async def _detect_spa(self, url: str) -> bool:
        """Detect if a URL is a Single Page Application."""
        try:
            result = await self.browser.navigate(url, stealth=False)
            if not result.get("success"):
                return False
            framework = await self.browser.detect_framework(url)
            is_spa = framework.lower() in ("react", "vue", "angular", "svelte")
            return is_spa
        except Exception as exc:
            logger.debug(f"[{self.name}] SPA detection failed for {url}: {exc}")
            return False

    async def _merge_endpoints(self, endpoints1: list, endpoints2: list) -> list:
        """Merge and deduplicate endpoint lists."""
        seen = set()
        merged = []
        for ep in endpoints1 + endpoints2:
            key = (ep.get("url"), ep.get("method", "GET"))
            if key not in seen:
                seen.add(key)
                merged.append(ep)
        return merged

    async def handle_control_signal(self, event: HiveEvent):
        signal = event.payload.get("signal", "")
        if signal in ("THROTTLE", "STEALTH_MODE"):
            self._throttled = True
            logger.info(f"[{self.name}] Governance: {signal} received. Pausing new recon dispatch.")
        elif signal == "RESUME":
            self._throttled = False
            logger.info(f"[{self.name}] Governance: RESUME received. Recon dispatch unpaused.")

    def _resolve_mode(self, *sources) -> str:
        for s in sources:
            if s:
                return s
        return getattr(settings, "ALPHA_DEFAULT_MODE", "STANDARD")

    async def handle_target_acquired(self, event: HiveEvent):
        """React to new targets by running the unified recon spine."""
        target_url = event.payload.get("url")
        if not target_url:
            return

        # When the orchestrator drives recon via the Mission Planner, wait for
        # the planner's assignment instead of double-running.
        if event.source == "Orchestrator" and getattr(settings, "ALPHA_RECON_VIA_PLANNER", True):
            logger.info(f"[{self.name}] Target received; waiting for Mission Planner recon assignment.")
            return

        if self._throttled:
            logger.warning(f"[{self.name}] [THROTTLE] New target {target_url} deferred under governance signal.")
            return

        logger.info(f"[{self.name}] TARGET ACQUIRED: {target_url}. Initiating unified recon...")
        await self.bus.publish(
            HiveEvent(
                type=EventType.LIVE_ATTACK,
                source=self.name,
                scan_id=event.scan_id,
                payload={
                    "url": target_url,
                    "arsenal": "Unified Recon Engine",
                    "action": "Initiating HTTP + Browser Recon",
                    "payload": "N/A",
                },
            )
        )

        mode = self._resolve_mode(event.payload.get("scan_mode"), event.payload.get("mode"))
        try:
            await self.alpha_recon.run(target_url, scan_id=event.scan_id, mode=mode)
        except Exception as exc:
            logger.error(f"[{self.name}] Unified recon failed: {exc}")

    async def handle_job(self, event: HiveEvent):
        """Process an assigned recon job through the single spine."""
        payload = event.payload
        try:
            packet = JobPacket(**payload)
        except Exception as e:
            logger.error(f"[{self.name}] Error parsing job: {e}")
            return

        if packet.config.agent_id != AgentID.ALPHA:
            return

        # Unified recon entry point (the only orchestration path). The legacy
        # "alpha_v6_recon" module id is still accepted for backward compatibility.
        if packet.config.module_id in ("alpha_recon", "alpha_v6_recon", "recon"):
            params = packet.config.params or {}
            mode = self._resolve_mode(params.get("scan_mode"), params.get("mode"))
            logger.info(f"[{self.name}] Planner assigned unified recon on {packet.target.url} (mode={mode}).")
            status, error = "SUCCESS", ""
            try:
                await self.alpha_recon.run(packet.target.url, scan_id=event.scan_id, mode=mode)
            except Exception as exc:
                status, error = "FAILED", str(exc)[:300]
                logger.error(f"[{self.name}] Unified recon failed: {exc}")
            await self.bus.publish(
                HiveEvent(
                    type=EventType.JOB_COMPLETED,
                    source=self.name,
                    scan_id=event.scan_id,
                    payload={
                        "job_id": packet.id,
                        "status": status,
                        "module_id": packet.config.module_id,
                        **({"error": error} if error else {}),
                    },
                )
            )
            return

        # Non-recon module jobs are delegated to Sigma for arsenal execution.
        logger.info(f"[{self.name}] Delegating {packet.config.module_id} to SIGMA on {packet.target.url}")
        sigma_job = JobPacket(
            priority=packet.priority,
            target=packet.target,
            config=ModuleConfig(
                module_id=packet.config.module_id,
                agent_id=AgentID.SIGMA,
                params=packet.config.params,
                aggression=packet.config.aggression,
                session_id=packet.config.session_id,
            ),
        )
        await self.bus.publish(HiveEvent(type=EventType.JOB_ASSIGNED, source=self.name, payload=sigma_job.model_dump()))


# Architecture §5.1.1 unified naming.
AlphaUnifiedAgent = AlphaAgent
