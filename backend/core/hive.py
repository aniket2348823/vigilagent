import asyncio
import logging
import json
import time
from typing import Callable, Dict, List, Any, Awaitable, Optional
from pydantic import BaseModel, Field
from enum import Enum
import uuid
from datetime import datetime
import collections

# --- 1. THE VOCABULARY (Strict Schemas) ---

class EventType(str, Enum):
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
    payload: Dict[str, Any] = {}

# --- 2. THE NERVOUS SYSTEM (Event Bus) ---

from backend.core.protocol import ModuleConfig, ResultPacket, Vulnerability
from backend.core.context import ScanContext
from backend.core.guard_layer import PromptInjectionBlocked, guard_layer
from backend.core.content_boundary import content_boundary
from backend.core.stdout_watchdog import watch_output
from backend.core.memory import memory_store
from backend.core.unified_knowledge_graph import knowledge_graph
from backend.core.task_manager import TaskManager
import collections

class EventBus:
    """
    The central message broker. 
    Decouples agents so they never talk directly.
    """
    def __init__(self):
        self.subscribers: Dict[EventType, List[Callable[[HiveEvent], Awaitable[None]]]] = {}
        self.scan_contexts: Dict[str, ScanContext] = {}
        self._context_tasks: Dict[str, asyncio.Task] = {}
        self._global_tasks = set()
        self.dead_letters: List[Dict[str, Any]] = []  # Dead Letter Queue
        self._max_dead_letters = 500  # Prevent unbounded DLQ growth
        self._task_manager = TaskManager("EventBus")


    def get_or_create_context(self, scan_id: str) -> ScanContext:
        if scan_id not in self.scan_contexts:
            ctx = ScanContext(scan_id=scan_id)
            self.scan_contexts[scan_id] = ctx
            # CRITICAL FIX 3: Single consumer per scan ensures causal A->B->C ordering
            task = asyncio.create_task(self._scan_event_loop(ctx))
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

    def _sanitize_event_payload(self, event: HiveEvent) -> Dict[str, Any]:
        attack_payload_events = {
            EventType.LIVE_ATTACK,
            EventType.JOB_ASSIGNED,
            EventType.JOB_COMPLETED,
            EventType.VULN_CANDIDATE,
            EventType.VULN_CONFIRMED,
        }
        payload_keys = {"payload", "generated_payloads", "payloads", "all_payloads"}

        def sanitize_value(value: Any, key: str = "") -> Any:
            if key in payload_keys and event.type in attack_payload_events:
                if isinstance(value, str):
                    return content_boundary.sanitize_control_tokens(value)[:4096]
                if isinstance(value, list):
                    return [sanitize_value(item, key) for item in value[:100]]
                if isinstance(value, dict):
                    return {k: sanitize_value(v, k) for k, v in value.items()}
                return value
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
                payload={"message": "Unsafe prompt-injection-like payload blocked before agent ingestion.", "reason": str(exc)},
            )
        except Exception as exc:
            logging.warning("[EventBus] Guard layer failed open for event %s: %s", event.id, exc)

        if event.type == EventType.JOB_COMPLETED:
            memory_store.remember_notification(event.scan_id, "Background job completed", event.payload)
        if event.type in {EventType.RECON_PACKET, EventType.RECON_COMPLETE, EventType.SCHEMA_DISCOVERED}:
            memory_store.remember_episode(event.scan_id, {
                "event_type": event.type.value,
                "source": event.source,
                "payload": event.payload,
            })
            if event.type == EventType.RECON_PACKET:
                try:
                    knowledge_graph.ingest_http_record(event.payload, scan_id=event.scan_id)
                except Exception as e:
                    logger.debug("[EventBus] ingest_http_record failed: %s", e)
        if event.type == EventType.VULN_CONFIRMED:
            knowledge_graph.ingest_finding(event.payload, scan_id=event.scan_id)

        if event.scan_id == "GLOBAL":
            if event.type in self.subscribers:
                for handler in self.subscribers[event.type]:
                    task = self._task_manager.create_task(
                        self._safe_execute(handler, event),
                        name=f"handler_{event.type}"
                    )
            return
            
        ctx = self.get_or_create_context(event.scan_id)

        # CRITICAL FIX 1: Exact-once deduplication window (FIFO)
        if not hasattr(ctx, "_recent_events_fifo"):
            ctx._recent_events_fifo = collections.deque(maxlen=1000)

        if event.id in ctx._recent_events:
            return  # Drop duplicate
            
        ctx._recent_events.add(event.id)
        ctx._recent_events_fifo.append(event.id)
        
        # Maintain Set Size (Oldest removal)
        if len(ctx._recent_events) > 1000:
            try:
                oldest = ctx._recent_events_fifo.popleft()
                ctx._recent_events.discard(oldest)
            except IndexError:
                pass  # Race: another coroutine evicted between len check and popleft

        # OpenClaw-style no-blackboard chronology: every scan-local event becomes
        # a linear transcript block before any agent consumes it.
        ctx.append_event(event)

        # Enqueue for causal execution
        await ctx.event_queue.put(event)


    async def _safe_execute(self, handler, event):
        try:
            await handler(event)
        except Exception as e:
            err_msg = str(e).encode('ascii', errors='replace').decode('ascii')
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
                "payload_summary": str(event.payload)[:200]
            }
            self.dead_letters.append(dead_entry)
            
            # Enforce DLQ size limit
            if len(self.dead_letters) > self._max_dead_letters:
                self.dead_letters = self.dead_letters[-self._max_dead_letters:]

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
                try: await task
                except asyncio.CancelledError: pass
            logging.info(f"🧹 Scan Context {scan_id} successfully evicted from Hive memory.")


class DistributedEventBus(EventBus):
    """
    XYTHERION DISTRIBUTED NERVOUS SYSTEM
    Role: Bridges local agent events to the global Redis cluster.
    """
    def __init__(self, redis_url: str):
        super().__init__()
        import redis.asyncio as aioredis
        self.redis_client = aioredis.from_url(redis_url, decode_responses=True)
        self.pubsub = self.redis_client.pubsub()
        self.is_running = False
        self._is_redis_online = None # Lazy check


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
            # We attempt to subscribe to the global channel
            await self.pubsub.subscribe("xytherion_events")
            self._task_manager.create_task(self._listen_loop(), name="redis_listener")
            logging.info("📡 Distributed Event Bus Online (Async).")
        except Exception as e:
            # V6-OMEGA HARDENING: If we can't subscribe, we stay in local-only mode
            self.is_running = False
            logging.warning(f"⚠️ [Hive] Redis subscribe failed: {e}. Event Bus staying local.")


    async def _listen_loop(self):
        """Listens for global events and injects them into the local hive (Fixed Async)."""
        try:
            async for message in self.pubsub.listen():
                if not self.is_running: break
                if message['type'] == 'message':
                    try:
                        event_data = json.loads(message['data'])
                        event = HiveEvent(**event_data)
                        
                        # Local Broadcast
                        await super().publish(event)
                    except Exception as e:
                        logging.error(f"[DistributedEventBus] Remote injection failed: {e}")
        except Exception as e:
            if self.is_running:
                logging.error(f"[DistributedEventBus] Listen loop crash: {e}")


    async def publish(self, event: HiveEvent):
        """Broadcasts local events to the global cluster and routes jobs with safety locking."""
        # 1. Local Broadcast (Memory-only sink always happens)
        await super().publish(event)
        
        # 2. Global Broadcast (Resilient Redis Attempt)
        try:
            event_json = event.model_dump_json()
            await self.redis_client.publish("xytherion_events", event_json)
            
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

class BaseAgent:
    """
    The template for all Hive Agents.
    Enforces a standard lifecycle: Wake -> Think -> Act.
    """
    def __init__(self, name: str, bus: EventBus):
        self.name = name
        self.bus = bus
        self.db = db_manager # Distributed Intelligence Backbone
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
            from backend.core.self_awareness_module import SelfAwarenessModule
            from backend.core.self_awareness_config import SelfAwarenessConfig

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
        await self.bus.publish(HiveEvent(
            type=EventType.AGENT_STATUS,
            source=self.name,
            payload={"status": "ONLINE"}
        ))

        # Start the internal thinking loop (if needed)
        task = asyncio.create_task(self.lifecycle())
        self._agent_tasks.add(task)
        task.add_done_callback(self._agent_tasks.discard)
        
        # Start health reporting loop
        health_task = asyncio.create_task(self._health_reporting_loop())
        self._agent_tasks.add(health_task)
        health_task.add_done_callback(self._agent_tasks.discard)

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

        for task in getattr(self, "_agent_tasks", []):
            task.cancel()
        if getattr(self, "_agent_tasks", []):
            await asyncio.gather(*self._agent_tasks, return_exceptions=True)
            
        logging.info(f"💤 {self.name} is OFFLINE.")
    
    async def _health_reporting_loop(self):
        """Report health metrics periodically."""
        import psutil
        import time as time_module
        
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
                success_rate = self._task_success_count / self._task_count if self._task_count > 0 else 1.0
                
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
                health_monitor.report_metrics(self.name, {
                    "idle_time_ms": idle_ms,
                    "idle": True,
                    "memory_mb": memory_mb,
                    "cpu_percent": cpu_percent,
                    "task_queue_depth": len(getattr(self, "_agent_tasks", []))
                })
                
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
        agent_class: Optional[str] = None,
        worker_specialty: Optional[str] = None,
        budget: int = 10,
        timeout: int = 30,
        tools: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
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
        from backend.core.protocol import ResultPacket, Vulnerability
        
        # Default implementation - subclasses should override
        return ResultPacket(
            job_id=packet.id if hasattr(packet, 'id') else "unknown",
            source_agent=self.name,
            status="SAFE",
            vulnerabilities=[],
            execution_time_ms=0,
            data={}
        )
