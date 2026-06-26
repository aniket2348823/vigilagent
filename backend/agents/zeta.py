import asyncio
import logging
import random
import time
from collections import deque
from typing import Any

import psutil

# Hybrid AI Engine
from backend.ai.cortex import get_cortex_engine
from backend.core.browser_agent import BrowserEnabledAgent
from backend.core.hive import EventType, HiveEvent
from backend.core.protocol import JobPacket
from backend.core.queue import command_lane

logger = logging.getLogger("AgentZeta")


class ZetaAgent(BrowserEnabledAgent):
    """
    AGENT ZETA: THE CORTEX
    Capabilities:
    - Predictive Auto-Scaling (Linear Regression).
    - Error Budget Economy.
    - QoS Multiplexing.
    - Dynamic IP Rotation.
    - SOTA: Sentiment Analysis (Server Stress).
    - SOTA: Adaptive Gaussian Jitter.
    - Browser resource monitoring and cleanup
    """

    def __init__(self, bus):
        super().__init__("agent_zeta", bus)

        self.latency_window = deque(maxlen=50)
        self.error_window = deque(maxlen=50)

        self.error_budget_max = 50
        self.error_budget_current = 50
        self.last_budget_refill = time.time()

        self.priority_queue = {0: [], 1: [], 2: []}
        # Hybrid AI Engine for stress analysis
        self.cortex = get_cortex_engine()

        # Browser resource tracking
        self.browser_memory_threshold = 500 * 1024 * 1024  # 500MB
        self.max_browser_contexts = 5

        # ===== RUNTIME GOVERNOR STATE (Architecture §5.1/§5.2/§29.4) =====
        # Zeta actively controls RPS, concurrency, backoff, and WAF pressure.
        self.base_rps = 5.0  # nominal requests-per-second target
        self.min_rps = 0.5  # floor when heavily throttled
        self.base_concurrency = command_lane.max_concurrent
        self.throttled = False  # current governor throttle state
        self.waf_pressure = 0  # rolling 403/429/5xx burst pressure (0..10)
        self._skill_rec_cache: dict[str, Any] = {}  # HIGH-69: bounded via SkillRecallMixin or manual eviction

    async def setup(self):
        self.bus.subscribe(EventType.JOB_COMPLETED, self.handle_job_completion)
        self.bus.subscribe(EventType.RECON_PACKET, self.handle_recon_packet)

    async def handle_recon_packet(self, event: HiveEvent):
        status = str(event.payload.get("status", event.payload.get("http_status", "")))
        evidence = str(event.payload.get("evidence", "")).lower()
        is_5xx = status.startswith("5") and len(status) == 3
        if status in {"403", "429"} or is_5xx or "forbidden" in evidence or "rate limit" in evidence:
            self.error_window.append(True)
            self.error_budget_current = max(0, self.error_budget_current - 2)
            # WAF/instability pressure rises on each block burst; decays in lifecycle.
            self.waf_pressure = min(10, self.waf_pressure + 1)
            # Recall WAF/rate-limiting/anomaly skills for this target (Architecture §5.3.5).
            self._recall_governance_skills(str(event.payload.get("url", "")))

    def _recall_governance_skills(self, target_url: str = "") -> list:
        """Kappa-style skill recall (Architecture §5.3.5, §29.9): Zeta receives
        rate-limiting, anomaly-detection, detection-of-scan, WAF-pressure, and
        runtime-governance skills. Cached per target to avoid rework."""
        # HIGH-69: Use SkillRecallMixin._skill_cache() for bounded eviction
        cache = self._skill_cache()
        cache_key = (target_url, ("rate-limit", "waf", "anomaly", "runtime-governance"))
        if cache_key in cache:
            return cache[cache_key]
        recs = []
        try:
            from backend.core.skill_library import skill_library

            for vuln_class in ("rate-limit", "waf", "anomaly", "runtime-governance"):
                recs.extend(skill_library.get_recommendations(target_url=target_url, vuln_class=vuln_class, limit=3))
        except Exception as e:
            logger.debug(f"[{self.name}] Governance skill recall failed: {e}")
            recs = []
        cache[cache_key] = recs
        return recs

    async def handle_job_completion(self, event: HiveEvent):
        payload = event.payload
        # ScanContext: record event for transcript causality
        if hasattr(self.bus, "get_or_create_context"):
            _ctx = self.bus.get_or_create_context(getattr(event, "scan_id", "GLOBAL"))
            _ctx.append_event(event)
        if "duration_ms" in payload:
            self.latency_window.append(payload["duration_ms"])

        if "status" in payload:
            status_val = payload["status"]
            is_error = status_val in ("FAILED", "BLOCKED", "ERROR") or (isinstance(status_val, bool) and not status_val)
            self.error_window.append(is_error)

            # HYBRID AI: Deep Server Stress Analysis
            if is_error and "data" in payload:
                error_msg = str(payload["data"])
                stress_analysis = await self.cortex.analyze_server_stress(error_msg)
                stress_level = stress_analysis.get("stress_level", "NORMAL")
                indicators = stress_analysis.get("indicators", [])
                action = stress_analysis.get("recommended_action", "CONTINUE")

                if stress_level in ["HIGH", "MEDIUM"]:
                    penalty = 10 if stress_level == "HIGH" else 5
                    self.error_budget_current -= penalty
                    logger.warning(
                        f"[{self.name}] Server Sentiment: {stress_level} (AI: {indicators}) -> Action: {action}"
                    )

                    if action == "ABORT":
                        await self.broadcast_signal("STEALTH_MODE", {"reason": f"AI: Server Stress {stress_level}"})
                    elif action == "THROTTLE":
                        await self.broadcast_signal("THROTTLE", {"level": "HIGH", "reason": f"AI: {indicators}"})

    async def lifecycle(self):
        while self.active:
            await self.governance_cycle()
            await self.refill_budget()
            await self.drain_queue()
            await asyncio.sleep(1.0)

    async def governance_cycle(self):
        # 1. PREDICTIVE AUTO-SCALING
        if len(self.latency_window) > 10:
            trend = self.calculate_trend(list(self.latency_window))
            if trend > 0.5:
                await self.broadcast_signal("THROTTLE", {"level": "HIGH", "reason": "Latency Acceleration"})

        # 2. ERROR BUDGET CHECK
        if self.error_budget_current < 5:
            await self.broadcast_signal("STEALTH_MODE", {"reason": "Error Budget Depleted"})

        # 3. DYNAMIC IP ROTATION
        if len(self.error_window) > 20:
            block_count = sum(1 for x in self.error_window if x is True)
            block_rate = block_count / len(self.error_window)
            if block_rate > 0.02:
                await self.broadcast_signal("INFRA_ROTATE", {"reason": "High Block Rate"})
                self.error_window.clear()

        # 4. STATISTICAL ANOMALY DETECTION (Z-Score)
        is_anomaly, reason = self.detect_anomalies()
        if is_anomaly:
            logger.warning(f"[{self.name}] ANOMALY DETECTED: {reason}")
            await self.broadcast_signal("THROTTLE", {"level": "CRITICAL", "reason": reason})
            self.error_budget_current -= 10  # Severe penalty for triggering defensive mechanisms

        telemetry = command_lane.telemetry
        if telemetry["active_count"] >= telemetry["max_concurrent"] or telemetry["total_timed_out"] > 0:
            await self.broadcast_signal(
                "THROTTLE",
                {
                    "level": "HIGH",
                    "reason": f"CommandLane pressure active={telemetry['active_count']} timed_out={telemetry['total_timed_out']}",
                },
            )

        # 5. RUNTIME GOVERNOR DECISION (Architecture §5.2/§29.4)
        # Decide whether to slow/pause or resume based on aggregate instability,
        # then pace the swarm to the recommended RPS/concurrency.
        if self.should_throttle():
            if not self.throttled:
                self.throttled = True
                await self.broadcast_signal(
                    "THROTTLE",
                    {
                        "level": "HIGH",
                        "reason": f"Governor pacing: rps={self.recommended_rps():.2f} waf_pressure={self.waf_pressure}",
                    },
                )
        else:
            # Target is stable again: decay WAF pressure and resume normal pacing.
            self.waf_pressure = max(0, self.waf_pressure - 1)
            if self.throttled and self.waf_pressure == 0:
                self.throttled = False
                await self.broadcast_signal(
                    "RESUME", {"reason": f"Governor resume: stability recovered, rps={self.recommended_rps():.2f}"}
                )

    def detect_anomalies(self) -> tuple[bool, str]:
        """SOTA: Z-Score Statistical Anomaly Detection for WAF/Firewall triggers."""
        if len(self.latency_window) > 15:
            latencies = list(self.latency_window)
            mean = sum(latencies) / len(latencies)
            variance = sum((x - mean) ** 2 for x in latencies) / len(latencies)
            std_dev = max(variance**0.5, 0.001)

            latest_latency = latencies[-1]
            z_score = (latest_latency - mean) / std_dev

            if z_score > 3.0:  # 3 standard deviations = anomaly (e.g. sudden WAF tarpit)
                return True, f"Latency Spike Anomaly (Z-Score: {z_score:.2f})"
        return False, ""

    # ===== RUNTIME GOVERNOR INTERFACE (Architecture §5.1/§5.2/§29.4) =====
    # Public, documented control surface other agents/the orchestrator can query
    # to pace work. Zeta is the Runtime Governor: it controls RPS, concurrency,
    # backoff, and WAF pressure and slows/pauses when the target is unstable.

    def should_throttle(self) -> bool:
        """Return True when the swarm should slow down or pause.

        Triggers on depleted error budget, sustained block/instability bursts
        (403/429/5xx tracked as WAF pressure), high recent block rate, or
        CommandLane saturation/timeouts.
        """
        if self.error_budget_current < 10:
            return True
        if self.waf_pressure >= 3:
            return True
        if self.error_window:
            block_rate = sum(1 for x in self.error_window if x is True) / len(self.error_window)
            if block_rate > 0.10:
                return True
        telemetry = command_lane.telemetry
        return telemetry["total_timed_out"] > 0

    def recommended_rps(self) -> float:
        """Recommended requests-per-second for the swarm right now.

        Scales the nominal RPS down as WAF pressure and error-budget depletion
        rise, never falling below the configured floor.
        """
        rps = self.base_rps
        # WAF pressure halves throughput roughly every ~3 pressure points.
        rps *= 0.5 ** (self.waf_pressure / 3.0)
        # Error budget below half starts trimming throughput linearly.
        if self.error_budget_max:
            budget_ratio = self.error_budget_current / self.error_budget_max
            if budget_ratio < 0.5:
                rps *= max(0.1, budget_ratio * 2.0)
        return round(max(self.min_rps, rps), 3)

    def recommended_concurrency(self) -> int:
        """Recommended concurrent execution slots, derived from current pacing."""
        if not self.base_rps:
            return 1
        factor = self.recommended_rps() / self.base_rps
        return max(1, int(round(self.base_concurrency * factor)))

    def recommended_backoff(self) -> float:
        """Recommended backoff (seconds) before the next request burst.

        Grows with WAF pressure; combined with adaptive jitter for human-like
        pacing.
        """
        return round(self.calculate_jitter() * (1 + self.waf_pressure), 3)

    def calculate_jitter(self):
        """
        SOTA: Adaptive Gaussian Jitter.
        Instead of random(0, 5), use Gaussian distribution to mimic human variance.
        """
        # Mean = 1.5s, StdDev = 0.5s
        jitter = random.gauss(1.5, 0.5)
        return max(0.1, jitter)

    def calculate_trend(self, data: list[float]) -> float:
        n = len(data)
        if n < 2:
            return 0.0
        x = range(n)
        y = data
        x_mean = sum(x) / n
        y_mean = sum(y) / n
        numerator = sum((xi - x_mean) * (yi - y_mean) for xi, yi in zip(x, y))
        denominator = sum((xi - x_mean) ** 2 for xi in x)
        return numerator / denominator if denominator != 0 else 0.0

    async def refill_budget(self):
        now = time.time()
        if now - self.last_budget_refill > 60:
            if self.error_budget_current < self.error_budget_max:
                self.error_budget_current += 1
            self.last_budget_refill = now

    async def drain_queue(self):
        """Process queued jobs from the priority queue."""
        for priority in [0, 1, 2]:  # 0 = highest priority
            while self.priority_queue[priority]:
                self.priority_queue[priority].pop(0)
                # Process or delegate job
                pass

    async def broadcast_signal(self, type: str, payload: dict[str, Any]):
        await self.bus.publish(
            HiveEvent(type=EventType.CONTROL_SIGNAL, source=self.name, payload={"signal": type, "data": payload})
        )
        # Broadcast to Dashboard: Governance action
        await self.bus.publish(
            HiveEvent(
                type=EventType.LIVE_ATTACK,
                source=self.name,
                payload={
                    "url": "System",
                    "arsenal": f"Governance: {type}",
                    "action": type,
                    "payload": str(payload.get("reason", ""))[:50],
                },
            )
        )

    def validate_job(self, packet: JobPacket) -> bool:
        """
        Cyber-Organism Protocol: Pre-Flight Check.
        Called by other agents before execution (Simulating synchronous RPC or shared state).
        """
        # 1. Latency Check (> 500ms?)
        if self.latency_window:
            avg_latency = sum(self.latency_window) / len(self.latency_window)
            if avg_latency > 500:
                logger.warning(f"[{self.name}]: DENY JOB {packet.id}. High Latency ({avg_latency:.1f}ms).")
                return False

        # 2. Budget Check (< 10?)
        if self.error_budget_current < 10:
            logger.warning(f"[{self.name}]: DENY JOB {packet.id}. Low Budget ({self.error_budget_current}).")
            return False

        return True

    # ============ BROWSER RESOURCE MONITORING (Phase 4) ============

    async def _monitor_browser_memory(self) -> dict:
        """Monitor browser memory usage and detect leaks."""
        try:
            # Get current process memory
            process = psutil.Process()
            memory_info = process.memory_info()

            # Check if browser memory exceeds threshold
            if memory_info.rss > self.browser_memory_threshold:
                logger.warning(
                    f"[{self.name}] Browser memory threshold exceeded: {memory_info.rss / 1024 / 1024:.1f}MB"
                )

                # Trigger cleanup
                await self._close_idle_contexts()

                return {
                    "memory_mb": memory_info.rss / 1024 / 1024,
                    "threshold_exceeded": True,
                    "action": "cleanup_triggered",
                }

            return {"memory_mb": memory_info.rss / 1024 / 1024, "threshold_exceeded": False}

        except Exception as e:
            logger.error(f"[{self.name}] Browser memory monitoring failed: {e}")
            return {}

    async def _get_active_contexts(self) -> list:
        """Get list of active browser contexts from the orchestrator."""
        try:
            # Access browser orchestrator through the browser property
            if not hasattr(self, "browser") or not self.browser:
                return []

            # Get the orchestrator from browser agent
            orchestrator = self.browser_orchestrator

            if not orchestrator:
                return []

            # Get context statistics
            orchestrator.get_context_stats()

            # Build list of active contexts with metadata
            active_contexts = []
            current_time = time.time()

            async with orchestrator._context_lock:
                for context_id, context_data in orchestrator._active_contexts.items():
                    idle_time = current_time - context_data["last_activity"]

                    active_contexts.append(
                        {
                            "context_id": context_id,
                            "scan_id": context_data["scan_id"],
                            "created_at": context_data["created_at"],
                            "last_activity": context_data["last_activity"],
                            "idle_time": idle_time,
                            "engine": context_data.get("engine", "unknown"),
                        }
                    )

            return active_contexts

        except Exception as e:
            logger.error(f"[{self.name}] Context enumeration failed: {e}")
            return []

    async def _close_idle_contexts(self) -> int:
        """Close idle browser contexts to free memory."""
        try:
            logger.debug(f"[{self.name}] Closing idle browser contexts...")

            # Access browser orchestrator through the browser property
            if not hasattr(self, "browser") or not self.browser:
                return 0

            orchestrator = self.browser_orchestrator

            if not orchestrator:
                return 0

            # Get active contexts
            active_contexts = await self._get_active_contexts()

            closed_count = 0
            for context in active_contexts:
                # Close contexts idle for more than 5 minutes (300 seconds)
                if context.get("idle_time", 0) > 300:
                    try:
                        await orchestrator.close_context(context["context_id"])
                        closed_count += 1
                        logger.debug(
                            f"[{self.name}] Closed idle context: {context['context_id']} (idle: {context['idle_time']:.0f}s)"
                        )
                    except Exception as close_err:
                        logger.error(f"[{self.name}] Failed to close context {context['context_id']}: {close_err}")

            if closed_count > 0:
                logger.debug(f"[{self.name}] Closed {closed_count} idle contexts")

            return closed_count

        except Exception as e:
            logger.error(f"[{self.name}] Context cleanup failed: {e}")
            return 0
