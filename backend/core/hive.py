import asyncio
import hashlib as _hashlib
import hmac as _hmac
import json
import logging
import os as _os
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- 1. THE VOCABULARY (Strict Schemas) ---


class EventType(StrEnum):
    SYSTEM_START = "SYSTEM_START"
    LOG = "LOG"
    TARGET_ACQUIRED = "TARGET_ACQUIRED"
    VULN_CANDIDATE = "VULN_CANDIDATE"
    VULN_CONFIRMED = "VULN_CONFIRMED"
    AGENT_STATUS = "AGENT_STATUS"
    JOB_ASSIGNED = "JOB_ASSIGNED"
    JOB_COMPLETED = "JOB_COMPLETED"
    CONTROL_SIGNAL = "CONTROL_SIGNAL"
    LIVE_ATTACK = "LIVE_ATTACK"
    RECON_PACKET = "RECON_PACKET"
    RECON_COMPLETE = "RECON_COMPLETE"
    SCHEMA_DISCOVERED = "SCHEMA_DISCOVERED"
    MOBILE_ENDPOINT_DISCOVERED = "MOBILE_ENDPOINT_DISCOVERED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    REPORT_READY = "REPORT_READY"
    PATTERN_LEARNED = "PATTERN_LEARNED"

    # V6 Lifecycle Management Events
    MISSION_PLANNED = "MISSION_PLANNED"
    PHASE_STARTED = "PHASE_STARTED"
    PHASE_COMPLETED = "PHASE_COMPLETED"
    PHASE_STATUS = "PHASE_STATUS"
    ENDPOINT_DISCOVERED = "ENDPOINT_DISCOVERED"
    ENDPOINT_TESTED = "ENDPOINT_TESTED"
    COVERAGE_UPDATE = "COVERAGE_UPDATE"


class HiveEvent(BaseModel):
    """
    The fundamental unit of communication.
    Every whisper in the hive must follow this structure.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = "GLOBAL"  # CRITICAL FIX 2: Scan Context Isolation
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    type: EventType
    source: str  # The Agent Name
    payload: dict[str, Any] = {}


# --- 2. THE NERVOUS SYSTEM (Event Bus) ---

import contextlib

from backend.core.content_boundary import content_boundary
from backend.core.context import ScanContext
from backend.core.guard_layer import PromptInjectionBlocked, guard_layer
from backend.core.memory import memory_store
from backend.core.protocol import ResultPacket
from backend.core.stdout_watchdog import watch_output
from backend.core.task_manager import TaskManager
from backend.core.unified_knowledge_graph import knowledge_graph

# EventBus message authentication (security hardening)
_EVENT_BUS_HMAC_KEY = _os.getenv("VIGILAGENT_EVENT_BUS_HMAC_KEY", "")


def _sign_event(event_json: str) -> str:
    if not _EVENT_BUS_HMAC_KEY:
        return ""
    return _hmac.new(_EVENT_BUS_HMAC_KEY.encode(), event_json.encode(), _hashlib.sha256).hexdigest()


def _verify_event_signature(event_json: str, signature: str) -> bool:
    if not _EVENT_BUS_HMAC_KEY:
        return True
    if not signature:
        return False
    expected = _hmac.new(_EVENT_BUS_HMAC_KEY.encode(), event_json.encode(), _hashlib.sha256).hexdigest()
    return _hmac.compare_digest(expected, signature)


class EventBus:
    """
    The central message broker.
    Decouples agents so they never talk directly.
    """

    def __init__(self):
        self.subscribers: dict[EventType, list[Callable[[HiveEvent], Awaitable[None]]]] = {}
        self.scan_contexts: dict[str, ScanContext] = {}
        self._context_tasks: dict[str, asyncio.Task] = {}
        self._global_tasks = set()
        self.dead_letters: list[dict[str, Any]] = []  # Dead Letter Queue
        self._max_dead_letters = 500  # Prevent unbounded DLQ growth
        self._task_manager = TaskManager("EventBus")

    def get_or_create_context(self, scan_id: str) -> ScanContext:
        if scan_id not in self.scan_contexts:
            ctx = ScanContext(scan_id=scan_id)
            self.scan_contexts[scan_id] = ctx
            # CRITICAL FIX 3: Single consumer per scan ensures causal A->B->C ordering
            task = self._task_manager.create_task(self._scan_event_loop(ctx), name=f"scan_event_loop_{scan_id}")
            self._context_tasks[scan_id] = task
        return self.scan_contexts[scan_id]

    async def _scan_event_loop(self, ctx: ScanContext):
        try:
            while not ctx.is_cancelled:
                event = await ctx.event_queue.get()
                if event.type in self.subscribers:
                    handlers = self.subscribers[event.type]
                    for handler in handlers:
                        # Wait strictly instead of fire-and-forget
                        await self._safe_execute(handler, event)
                ctx.event_queue.task_done()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logging.error(f"[EventBus] Scan Loop failed for {ctx.scan_id}: {e}")

    def subscribe(self, event_type: EventType, handler: Callable[[HiveEvent], Awaitable[None]]):
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(handler)
        # logging.debug(f"🔌 Handler subscribed to {event_type}")

    def unsubscribe(self, event_type: EventType, handler: Callable[[HiveEvent], Awaitable[None]]):
        if event_type in self.subscribers and handler in self.subscribers[event_type]:
            self.subscribers[event_type].remove(handler)

    def _sanitize_event_payload(self, event: HiveEvent) -> dict[str, Any]:
        # Internal event types that carry legitimate attack payloads (SQLi, XSS,
        # command injection test strings). These naturally contain keywords like
        # "execute", "exec", "eval", "subprocess", "shell" that the
        # guard_layer's prompt-injection patterns match. We must NOT run
        # guard_layer sanitization on these events — only control-token
        # sanitization to strip terminal escapes.
        _internal_event_types = {
            EventType.LIVE_ATTACK,
            EventType.JOB_ASSIGNED,
            EventType.JOB_COMPLETED,
            EventType.VULN_CANDIDATE,
            EventType.VULN_CONFIRMED,
            EventType.RECON_PACKET,
            EventType.RECON_COMPLETE,
            EventType.AGENT_STATUS,
            EventType.TARGET_ACQUIRED,
            EventType.LOG,
            EventType.PHASE_STARTED,
            EventType.PHASE_COMPLETED,
            EventType.PHASE_STATUS,
            EventType.ENDPOINT_DISCOVERED,
            EventType.ENDPOINT_TESTED,
            EventType.COVERAGE_UPDATE,
        }

        def sanitize_value(value: Any, key: str = "") -> Any:
            if event.type in _internal_event_types:
                # For internal events, only sanitize control tokens — never
                # run prompt-injection checks on legitimate attack payloads.
                if isinstance(value, str):
                    return content_boundary.sanitize_control_tokens(value)[:4096]
                if isinstance(value, list):
                    return [sanitize_value(item, key) for item in value[:100]]
                if isinstance(value, dict):
                    return {k: sanitize_value(v, k) for k, v in value.items()}
                return value
            # For external/untrusted events, run full guard_layer sanitization
            if isinstance(value, dict):
                return {k: sanitize_value(v, k) for k, v in value.items()}
            if isinstance(value, list):
                return [sanitize_value(item, key) for item in value]
            return guard_layer.sanitize_payload(value)

        return sanitize_value(event.payload)

    async def publish(self, event: HiveEvent):
        """
        Broadcasts an event to all interested agents.
        Routes to purely causal queue isolation by default.
        """
        try:
            event.payload = self._sanitize_event_payload(event)
            watched_payload = await watch_output(event.payload)
            if watched_payload.truncated:
                event.payload = {"guarded_payload": watched_payload.content}
        except PromptInjectionBlocked as exc:
            logging.warning("[EventBus] Blocked unsafe event payload from %s: %s", event.source, exc)
            event = HiveEvent(
                type=EventType.LOG,
                source="guard_layer",
                scan_id=event.scan_id,
                payload={
                    "message": "Unsafe prompt-injection-like payload blocked before agent ingestion.",
                    "reason": str(exc),
                },
            )
        except Exception as exc:
            logging.warning("[EventBus] Guard layer failed open for event %s: %s", event.id, exc)

        if event.type == EventType.JOB_COMPLETED:
            await memory_store.remember_notification(event.scan_id, "Background job completed", event.payload)
        if event.type in {EventType.RECON_PACKET, EventType.RECON_COMPLETE, EventType.SCHEMA_DISCOVERED}:
            await memory_store.remember_episode(
                event.scan_id,
                {
                    "event_type": event.type.value,
                    "source": event.source,
                    "payload": event.payload,
                },
            )
            if event.type == EventType.RECON_PACKET:
                try:
                    knowledge_graph.ingest_http_record(event.payload, scan_id=event.scan_id)
                except Exception as e:
                    logger.debug("[EventBus] ingest_http_record failed: %s", e)
        if event.type == EventType.VULN_CONFIRMED:
            knowledge_graph.ingest_finding(event.payload, scan_id=event.scan_id)
            try:
                from backend.core.metrics import metrics as _m

                severity = (event.payload or {}).get("severity", "MEDIUM")
                _m.record_vuln(str(severity))
            except Exception:
                pass

        if event.scan_id == "GLOBAL":
            if event.type in self.subscribers:
                for handler in self.subscribers[event.type]:
                    self._task_manager.create_task(self._safe_execute(handler, event), name=f"handler_{event.type}")
            return

        ctx = self.get_or_create_context(event.scan_id)

        # CRITICAL FIX 1: Exact-once deduplication window (FIFO)
        # Uses ScanContext.add_recent_event() for bounded dedup with O(1) lookup.
        if not ctx.add_recent_event(event.id):
            return  # Drop duplicate

        # OpenClaw-style no-blackboard chronology: every scan-local event becomes
        # a linear transcript block before any agent consumes it.
        ctx.append_event(event)

        # Enqueue for causal execution
        await ctx.event_queue.put(event)

    async def _safe_execute(self, handler, event):
        try:
            await handler(event)
        except Exception as e:
            err_msg = str(e).encode("ascii", errors="replace").decode("ascii")
            logging.error(f"[CRITICAL] Handler failed processing {event.type}: {err_msg}")

            # Dead Letter Queue: Capture failed events instead of losing them
            dead_entry = {
                "event_id": event.id,
                "event_type": str(event.type),
                "scan_id": event.scan_id,
                "source": event.source,
                "handler": handler.__qualname__,
                "error": err_msg,
                "timestamp": datetime.utcnow().isoformat(),
                "payload_summary": str(event.payload)[:200],
            }
            self.dead_letters.append(dead_entry)
            try:
                from backend.core.metrics import metrics as _m

                _m.event_handler_errors_total.inc()
            except Exception:
                pass

            # Enforce DLQ size limit
            if len(self.dead_letters) > self._max_dead_letters:
                self.dead_letters = self.dead_letters[-self._max_dead_letters :]

    def get_dead_letters(self, limit: int = 50) -> list:
        """Retrieve recent dead letter entries for diagnostics."""
        return self.dead_letters[-limit:]

    def flush_dead_letters(self):
        """Clear the dead letter queue after processing."""
        flushed = len(self.dead_letters)
        self.dead_letters = []
        return flushed

    def dispatch_deferred(self, coro, *, name: str = "deferred_handler") -> asyncio.Task:
        """Schedule a coroutine off the event-loop critical path.

        WHY: Per-scan event handlers run sequentially inside
        ``_scan_event_loop`` to preserve causal A→B→C ordering. When a
        handler needs to fire-and-forget a side-effect (Supabase write,
        WebSocket fan-out, etc.) that round-trip would otherwise block
        the next event in the queue. ``dispatch_deferred`` parks the
        coroutine on the EventBus' ``TaskManager`` so it's tracked,
        cancelled on shutdown, and won't leak.

        WHEN: Use only for *side-effects* that must not influence later
        handlers. Anything in the causal chain (scope checks, dedup,
        guard layer) must still ``await`` inline.

        The returned task is the same object the TaskManager tracks; the
        caller can ``await`` it in tests if needed.
        """
        return self._task_manager.create_task(coro, name=name)

    async def shutdown(self):
        """Gracefully waits for and cancels all pending EventBus tasks."""
        if self.dead_letters:
            logging.warning(f"⚠️ [EventBus] Shutting down with {len(self.dead_letters)} dead letters in queue.")
        for ctx in self.scan_contexts.values():
            ctx.is_cancelled = True
        for task in self._context_tasks.values():
            task.cancel()

        if self._context_tasks:
            await asyncio.gather(*self._context_tasks.values(), return_exceptions=True)

        # Cancel all tracked tasks
        await self._task_manager.cancel_all()

    async def evict_scan_context(self, scan_id: str):
        """Standard Memory Guard: Purge historical scan state and tasks."""
        if scan_id in self.scan_contexts:
            ctx = self.scan_contexts.pop(scan_id)
            ctx.is_cancelled = True
            task = self._context_tasks.pop(scan_id, None)
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            logging.info(f"🧹 Scan Context {scan_id} successfully evicted from Hive memory.")


class DistributedEventBus(EventBus):
    """
    XYTHERION DISTRIBUTED NERVOUS SYSTEM
    Role: Bridges local agent events to the global Redis cluster.
    """

    def __init__(self, redis_url: str):
        super().__init__()
        self._redis_url = redis_url
        self.redis_client = None  # Initialized lazily in start()
        self.pubsub = None
        self.is_running = False
        self._is_redis_online = None  # Lazy check

    async def ping(self) -> bool:
        """Verifies Redis connectivity."""
        try:
            await self.redis_client.ping()
            self._is_redis_online = True
            return True
        except Exception as exc:
            self._is_redis_online = False
            logger.debug("[Hive] Redis ping failed: %s", exc)
            logger.debug("[Hive] Redis ping failed")
            return False

    async def start(self):
        """Activates the distributed bridge."""
        self.is_running = True
        try:
            from backend.core.redis_client import get_redis_client

            rc = await get_redis_client()
            self.redis_client = rc.client
            self.pubsub = self.redis_client.pubsub()
            await self.pubsub.subscribe("xytherion_events")
            self._task_manager.create_task(self._listen_loop(), name="redis_listener")
            logging.info("📡 Distributed Event Bus Online (Async).")
        except Exception as e:
            # V6-OMEGA HARDENING: If we can't subscribe, we stay in local-only mode
            self.is_running = False
            logging.warning(f"⚠️ [Hive] Redis subscribe failed: {e}. Event Bus staying local.")

    async def _listen_loop(self):
        """Listens for global events and injects them into the local hive.

        SECURITY FIX (C-13): Verify HMAC signature on Redis messages before
        deserializing and publishing to the local bus.

        RESILIENCE: On Redis timeout/connection errors, the loop sleeps with
        exponential backoff (2s → 4s → 8s → 30s cap) and reconnects instead
        of crashing permanently. After _REDIS_RECREATE_THRESHOLD consecutive
        reconnect failures, the entire redis_client connection pool is
        recreated from the original redis_url to recover from broken pools.
        """
        backoff = 2.0
        max_backoff = 30.0
        _reconnect_failures = 0
        _REDIS_RECREATE_THRESHOLD = 5
        while self.is_running:
            try:
                async for message in self.pubsub.listen():
                    if not self.is_running:
                        break
                    # Reset backoff and reconnect counter on successful message
                    backoff = 2.0
                    _reconnect_failures = 0
                    if message["type"] == "message":
                        try:
                            raw_data = message["data"]
                            # Extract signature if present (format: "signature|json")
                            signature = None
                            if isinstance(raw_data, str) and "|" in raw_data:
                                sep_idx = raw_data.index("|")
                                signature = raw_data[:sep_idx]
                                raw_data = raw_data[sep_idx + 1 :]

                            event_data = json.loads(raw_data)

                            # HMAC verification when key is configured
                            if _EVENT_BUS_HMAC_KEY:
                                if not _verify_event_signature(raw_data, signature or ""):
                                    logging.warning(
                                        "[DistributedEventBus] HMAC verification failed — "
                                        "dropping potentially tampered event"
                                    )
                                continue

                            event = HiveEvent(**event_data)

                            # Local Broadcast
                            await super().publish(event)
                        except Exception as e:
                            logging.error(f"[DistributedEventBus] Remote injection failed: {e}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                if not self.is_running:
                    break
                logging.warning("[DistributedEventBus] Listen loop error: %s — reconnecting in %.1fs", e, backoff)
                try:
                    await asyncio.sleep(backoff)
                except asyncio.CancelledError:
                    break
                backoff = min(backoff * 2, max_backoff)
                _reconnect_failures += 1
                # After N consecutive failures, recreate the entire connection
                # pool — a broken pool (e.g. stale socket) won't heal by just
                # creating a new pubsub object on the same pool.
                if _reconnect_failures >= _REDIS_RECREATE_THRESHOLD:
                    try:
                        from backend.core.redis_client import get_redis_client

                        rc = await get_redis_client()
                        self.redis_client = rc.client
                        logging.info(
                            "[DistributedEventBus] Refreshed Redis client after %d failed reconnects",
                            _reconnect_failures,
                        )
                        _reconnect_failures = 0
                    except Exception as pool_err:
                        logging.warning("[DistributedEventBus] Client refresh failed: %s", pool_err)
                # Attempt to re-subscribe
                try:
                    self.pubsub = self.redis_client.pubsub()
                    await self.pubsub.subscribe("xytherion_events")
                    logging.info("[DistributedEventBus] Reconnected to Redis")
                except Exception as re_err:
                    logging.warning("[DistributedEventBus] Reconnect failed: %s", re_err)

    async def publish(self, event: HiveEvent):
        """Broadcasts local events to the global cluster and routes jobs with safety locking."""
        # 1. Local Broadcast (Memory-only sink always happens)
        await super().publish(event)

        # 2. Global Broadcast (Resilient Redis Attempt)
        try:
            event_json = event.model_dump_json()
            # HIGH-15: Sign events with HMAC before publishing to Redis
            # so _listen_loop can verify integrity on the receiving end.
            signature = _sign_event(event_json)
            signed_payload = f"{signature}|{event_json}" if signature else event_json
            await self.redis_client.publish("xytherion_events", signed_payload)

            # 3. WORKER ROUTING & SAFETY LOCKING (Async-Harden)
            if event.type == EventType.JOB_ASSIGNED:
                task_id = event.payload.get("task_id", event.id)
                lock_key = f"job_lock:{task_id}"

                # Check Redis connection or health
                if await self.redis_client.set(lock_key, "LOCKED", nx=True, ex=3600):
                    # ROUTE A: Audit Layer
                    await self.redis_client.lpush("xytherion_audit_queue", event_json)

                    # ROUTE B: Work Queue
                    logging.info(f"🚀 [Hive] Routing Job {task_id} to global work queue.")
                    await self.redis_client.lpush("pending_tasks", event_json)
                else:
                    logging.debug(f"[DistributedEventBus] Job {task_id} already locked.")

        except Exception as e:
            # V6-OMEGA Resilience: If Redis fails, we stop the global sync but keep the process alive
            err_type = type(e).__name__
            logging.warning(f"⚠️ [Hive] Distributed broadcast failed ({err_type}). Reverting to Local memory sink.")


# --- 3. THE DNA (Base Agent) ---

from backend.core.database import db_manager

logger = logging.getLogger(__name__)


class _HiveFacade:
    """Facade providing agent registry access to dashboard/self-awareness endpoints.

    Uses lazy import to avoid circular dependency with orchestrator.py
    (which imports from hive.py at module level).
    """

    def get_all_agents(self):
        """Return all currently active agent instances."""
        try:
            from backend.core.orchestrator import HiveOrchestrator

            return list(HiveOrchestrator.active_agents.values())
        except Exception:
            return []

    def get_agent(self, agent_id: str):
        """Look up a single agent by id.

        Tries exact match first, then case-insensitive key match, then
        suffix match (e.g. ``"omega"`` matches ``"OMEGA"`` or
        ``"agent_omega"``).  Unlike a plain substring check, this avoids
        false positives like ``"a"`` matching ``"alpha"``.
        """
        try:
            from backend.core.orchestrator import HiveOrchestrator
        except Exception:
            return None
        # 1. Exact key match
        agent = HiveOrchestrator.active_agents.get(agent_id)
        if agent is not None:
            return agent
        # 2. Case-insensitive exact key match
        lower_id = agent_id.lower()
        for key, val in HiveOrchestrator.active_agents.items():
            if str(key).lower() == lower_id:
                return val
        # 3. Key *ends with* the requested id (e.g. "agent_chi" for "chi")
        for key, val in HiveOrchestrator.active_agents.items():
            k = str(key).lower()
            if k.endswith("_" + lower_id) or k.endswith("." + lower_id):
                return val
        return None


# Module-level singleton used by dashboard.py and self_awareness.py
# via ``from backend.core.hive import hive``.
hive = _HiveFacade()


class BaseAgent:
    """
    The template for all Hive Agents.
    Enforces a standard lifecycle: Wake -> Think -> Act.
    """

    def __init__(self, name: str, bus: EventBus):
        self.name = name
        self.bus = bus
        self.db = db_manager  # Distributed Intelligence Backbone
        self.active = False
        self.status = "IDLE"
        self._delegation_mgr = None  # Lazy-init via delegation_mgr property

        # Health monitoring
        self._last_task_time = time.time()
        self._task_count = 0
        self._task_success_count = 0

        # Self-awareness (optional)
        self.self_awareness = None
        self._init_self_awareness()

    def _init_self_awareness(self):
        """Initialize self-awareness if enabled.

        Self-awareness is feature-flag-gated (defaults OFF). The dataclass uses
        ``enable_self_awareness`` (master) and per-agent ``enable_self_awareness_<name>``
        booleans rather than a generic ``is_enabled(...)`` method, so we read them
        with ``getattr`` and short-circuit cleanly when disabled. This silences the
        old import-error noise that fired for every agent on every startup.
        """
        try:
            from backend.core.feature_flags import get_feature_flags
            from backend.core.self_awareness_config import SelfAwarenessConfig
            from backend.core.self_awareness_module import SelfAwarenessModule

            flags = get_feature_flags()
            if not getattr(flags, "enable_self_awareness", False):
                return

            short = self.name.replace("agent_", "").lower()
            agent_attr = f"enable_self_awareness_{short}"
            if not getattr(flags, agent_attr, False):
                return

            config = SelfAwarenessConfig()
            self.self_awareness = SelfAwarenessModule(agent=self, config=config)
            logging.info(f"[BaseAgent] Self-awareness enabled for {self.name}")
        except Exception as e:
            logging.error(f"[BaseAgent] Failed to initialize self-awareness: {e}")
            self.self_awareness = None

    async def start(self):
        """Wakes the agent up."""
        self.active = True
        self.status = "ACTIVE"
        self._agent_tasks = set()

        # Task manager for agent background tasks
        self._task_manager = TaskManager(f"Agent-{self.name}")

        # Ensure DB connections are active
        await self.db.initialize()

        logging.info(f"🤖 {self.name} is ONLINE. Intelligence backbone synced.")

        # Initialize self-awareness
        if self.self_awareness:
            await self.self_awareness.initialize()

        # Subscribe to relevant events
        await self.setup()

        # Announce presence
        # Don't track this publish, it's safe to fire-and-forget to bus, because bus tracks it
        await self.bus.publish(HiveEvent(type=EventType.AGENT_STATUS, source=self.name, payload={"status": "ONLINE"}))

        # Start the internal thinking loop (if needed)
        task = self._task_manager.create_task(self.lifecycle(), name=f"lifecycle_{self.name}")
        self._agent_tasks.add(task)
        # Store primary task reference so the zombie sweep health check
        # can detect crashed agents (checks self._task.done()).
        self._task = task

        # Start health reporting loop
        health_task = self._task_manager.create_task(
            self._health_reporting_loop(), name=f"health_reporting_{self.name}"
        )
        self._agent_tasks.add(health_task)
        self._background_task = health_task

    async def stop(self):
        """Puts the agent to sleep."""
        self.active = False
        self.status = "OFFLINE"

        # Shutdown self-awareness
        if self.self_awareness:
            await self.self_awareness.shutdown()

        # Shutdown AI Engine if it exists (CortexEngine holds aiohttp session)
        for attr in ["cortex", "ai"]:
            engine = getattr(self, attr, None)
            if engine and hasattr(engine, "shutdown"):
                await engine.shutdown()

        # Cancel all tracked tasks
        if hasattr(self, "_task_manager"):
            await self._task_manager.cancel_all()

        logging.info(f"💤 {self.name} is OFFLINE.")

    async def _health_reporting_loop(self):
        """Report health metrics periodically."""
        import time as time_module

        import psutil

        while self.active:
            try:
                await asyncio.sleep(10)  # Report every 10 seconds

                # Calculate metrics.
                #
                # WHY: ``_last_task_time`` is the wall-clock time of the most
                # recent ``report_task_result`` call (or agent start), so the
                # value below is "time since last task" — i.e. *idle* time, not
                # per-task latency. If we report it as ``response_time_ms``
                # without flagging it, AgentHealthMonitor escalates a CRITICAL
                # alert every minute for every idle agent (11 agents × 60s
                # floods the log during normal scans where commanders are
                # waiting on workers).
                #
                # WHEN: Triggers any time an agent goes >5s without completing
                # a task, which is the common case for commander/coordinator
                # agents that mostly delegate. Genuine unresponsiveness is
                # still detected by ``check_heartbeats`` (heartbeat_timeout).
                idle_ms = (time_module.time() - self._last_task_time) * 1000
                self._task_success_count / self._task_count if self._task_count > 0 else 1.0

                # Get resource usage
                process = psutil.Process()
                memory_mb = process.memory_info().rss / 1024 / 1024
                cpu_percent = process.cpu_percent(interval=0.1)

                # Report to health monitor. ``idle=True`` tells the monitor
                # this is a keep-alive sample, not a real per-task latency,
                # so response_time alerts are suppressed for it. The numeric
                # value is still recorded under ``idle_time_ms`` for
                # diagnostics.
                from backend.core.agent_health_monitor import health_monitor

                health_monitor.report_metrics(
                    self.name,
                    {
                        "idle_time_ms": idle_ms,
                        "idle": True,
                        "memory_mb": memory_mb,
                        "cpu_percent": cpu_percent,
                        "task_queue_depth": len(getattr(self, "_agent_tasks", [])),
                    },
                )

                # Send heartbeat
                health_monitor.report_heartbeat(self.name)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"[{self.name}] Health reporting error: {e}")

    @property
    def delegation_mgr(self) -> "DelegationManager":
        """Lazy-init DelegationManager singleton per agent.

        WHY lazy: Prevents circular imports (delegation_manager imports from core,
        which may import from hive). Also avoids creating DelegationManager for
        agents that never delegate (Prism, Chi for safety reasons).
        """
        if self._delegation_mgr is None:
            from backend.core.delegation_manager import DelegationManager

            self._delegation_mgr = DelegationManager()
        return self._delegation_mgr

    async def delegate(
        self,
        objective: str,
        *,
        agent_class: str | None = None,
        worker_specialty: str | None = None,
        budget: int = 10,
        timeout: int = 30,
        tools: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> "ChildResult":
        """Delegate work to an isolated child worker.

        EXAMPLE:
            result = await self.delegate(
                "Run subfinder on target.com",
                agent_class="AlphaAgent",
                worker_specialty="recon",
                budget=5,
                timeout=30,
                tools=["subfinder", "dnsx"],
                context={"target": "target.com"},
            )
            if result.status == "completed":
                findings = result.findings

        WHY this pattern:
        - Child gets its own IterationBudget (can't drain parent's)
        - Child gets sanitized context (no API keys/tokens)
        - Child gets restricted tool set (can't delegate further)
        - Parent blocks until child completes (or timeout)
        """
        from backend.core.delegation_manager import ChildSpec

        spec = ChildSpec(
            objective=objective,
            agent_class=agent_class or self.__class__.__name__,
            worker_specialty=worker_specialty or "hybrid",
            budget=budget,
            timeout_s=timeout,
            tools=tools or [],
            context=context or {},
        )
        return await self.delegation_mgr.spawn(spec)

    def report_task_result(self, success: bool):
        """Report task execution result for health tracking."""
        import time as time_module

        self._task_count += 1
        if success:
            self._task_success_count += 1
        self._last_task_time = time_module.time()

    # --- ABSTRACT METHODS (Subclasses MUST implement these) ---

    async def setup(self):
        """Register subscriptions here."""
        pass

    async def lifecycle(self):
        """
        The Agent's internal 'Heartbeat'.
        Some agents react (Event-driven), others act (Loop-driven).
        """
        pass

    async def think(self, context: Any):
        """
        The AI Integration Slot.
        Override this with specific logic (LLM, Heuristic, etc).
        """
        pass

    async def execute_task(self, packet):
        """
        Synchronous task execution for Defense API.
        Subclasses (Prism, Chi) should override this.
        """

        # Default implementation - subclasses should override
        return ResultPacket(
            job_id=packet.id if hasattr(packet, "id") else "unknown",
            source_agent=self.name,
            status="SAFE",
            vulnerabilities=[],
            execution_time_ms=0,
            data={},
        )
