import logging
_logger = logging.getLogger(__name__)
"""
Vigilagent Delegation Manager (Architecture §5.5, §5.1.2, §29.13)
================================================================================
The control plane that replaces the flat EventBus as the *agent coordination*
model. The EventBus remains for UI/telemetry/audit (Architecture §5.5).

Pattern (Hermes delegate_tool → §29.13):
  - A parent agent spawns an isolated child agent with:
      * a restricted tool allowlist (blocked tools — delegation/clarify/memory —
        are always stripped, mirroring Hermes DELEGATE_BLOCKED_TOOLS),
      * its own IterationBudget (independent — cannot drain the parent §5),
      * an isolated context summary COPY (no unrestricted global memory §5),
      * a structured result contract (ResultPacket / ChildResult).
  - Delegation is bounded: a max subtree depth (Hermes max_spawn_depth) and a
    concurrency ceiling (Hermes max_concurrent_children) cap runaway fan-out.
  - When a MasterNode + Redis are available, the child task is enqueued onto the
    worker substrate (worker_queue:{id}) and the result awaited.
  - Otherwise delegation runs in-process.
  - Cancellation propagates to the child subtree, and lifecycle events are
    relayed to an optional telemetry hook (EventBus stays the telemetry plane).

Routing pattern (Architecture §5.1.2):
  Omega -> Master -> Worker pool -> Specialized agent/task -> Parsed result
        -> Master -> Omega/Graph
  Worker specialties (recon|browser|api|network|validation|forensics|reporting|
  skill|hybrid) are routable per ChildSpec.worker_specialty, with agent_class
  fallback routing.
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Any, ClassVar, Awaitable, Callable, Literal, AsyncGenerator

from backend.core.iteration_budget import IterationBudget, budget_config

logger = logging.getLogger("vigilagent.delegation")

ChildStatus = Literal[
    "completed", "failed", "budget_exhausted", "cancelled", "timeout", "rejected"
]

# The closed set of valid statuses, used to validate worker-returned packets so a
# malformed/untrusted result payload can't inject an unknown status.
_VALID_STATUSES: frozenset[str] = frozenset({
    "completed", "failed", "budget_exhausted", "cancelled", "timeout", "rejected",
})

# A child runner is any coroutine that takes a context dict + budget and returns
# a dict of findings/artifacts/summary. Specialized agents register builders.
ChildRunner = Callable[[dict, IterationBudget], Awaitable[dict]]

# An optional lifecycle hook for observability (Architecture §5.5: the EventBus
# stays the telemetry plane). Receives a flat dict; never affects control flow.
EventHook = Callable[[dict], None]

# ── Restricted tool allowlist (Hermes DELEGATE_BLOCKED_TOOLS → §29.13) ──────────
# Tools a child agent must NEVER receive. Prevents recursive delegation, user
# interaction, and writes to shared memory from leaking into an isolated child
# (Architecture §5 memory isolation + budget boundedness). Compared lowercased.
BLOCKED_CHILD_TOOLS: frozenset[str] = frozenset({
    "delegate", "delegate_task", "delegation",   # no recursive delegation
    "spawn", "spawn_many",
    "clarify", "ask_user", "ask",                 # no user interaction
    "memory", "global_memory", "write_memory",    # no writes to shared memory
    "approval_override", "approve",               # cannot self-approve
})

# ── Canonical worker specialties (Architecture §5.1.2) ──────────────────────────
WORKER_SPECIALTIES: frozenset[str] = frozenset({
    "recon", "browser", "api", "network",
    "validation", "forensics", "reporting", "skill", "hybrid",
})
_DEFAULT_SPECIALTY = "hybrid"

# Routing hints: substring of an agent_class -> worker specialty. Lets a spec
# that omits worker_specialty still route to the right pool (Architecture §5.1.2).
_AGENT_CLASS_SPECIALTY: dict[str, str] = {
    "recon": "recon",
    "browser": "browser",
    "api": "api",
    "network": "network",
    "validator": "validation",
    "validation": "validation",
    "forensic": "forensics",
    "report": "reporting",
    "skill": "skill",
}

# Bounded delegation defaults (Hermes MAX_DEPTH / max_concurrent_children).
DEFAULT_MAX_DEPTH = 3          # parent(0) -> child(1) -> ... bounded subtree
# Per-specialty concurrency limits
WORKER_SPECIALTY_LIMITS: Dict[str, int] = {
    "recon": 4, "browser": 2, "network": 6, "api": 4,
    "hybrid": 3, "validation": 4, "forensics": 2, "reporting": 2, "skill": 2,
}
DEFAULT_MAX_CONCURRENT = 4  # Fallback for unknown specialties


def sanitize_tools(tools: list[str] | None) -> list[str]:
    """Return a restricted allowlist: blocked tools stripped, duplicates removed,
    order preserved. A child can never receive delegation/clarify/memory tools
    (Architecture §5 memory isolation; Hermes ``_strip_blocked_tools``)."""
    seen: set[str] = set()
    clean: list[str] = []
    for t in tools or []:
        name = str(t).strip()
        if not name or name.lower() in BLOCKED_CHILD_TOOLS or name in seen:
            continue
        seen.add(name)
        clean.append(name)
    return clean


def normalize_specialty(specialty: str | None, agent_class: str = "") -> str:
    """Coerce a worker specialty to one of the canonical §5.1.2 values, routing
    by ``agent_class`` when unspecified and falling back to ``hybrid`` (Hermes
    ``_normalize_role`` silent-degrade pattern)."""
    s = (specialty or "").strip().lower()
    if s in WORKER_SPECIALTIES:
        return s
    cls = (agent_class or "").lower()
    for key, mapped in _AGENT_CLASS_SPECIALTY.items():
        if key in cls:
            return mapped
    if s:
        logger.warning("Unknown worker specialty %r; routing to '%s'", specialty, _DEFAULT_SPECIALTY)
    return _DEFAULT_SPECIALTY


@dataclass
class ChildSpec:
    """Specification for a delegated child agent (Architecture §5)."""

    agent_class: str                       # e.g. "ReconChild", "AttackChild"
    objective: str
    tools: list[str] = field(default_factory=list)   # tool allowlist (sanitized)
    budget: int = 50
    context: dict = field(default_factory=dict)       # isolated parent summary
    phase: str = ""
    timeout_s: int = 600
    worker_specialty: str = "hybrid"       # recon|browser|api|network|validation|...
    depth: int = 1                          # position in the delegation subtree

    def __post_init__(self) -> None:
        # Enforce the restricted allowlist + canonical specialty up front so every
        # downstream path (in-process, worker, serialization) sees a clean spec.
        self.tools = sanitize_tools(self.tools)
        self.worker_specialty = normalize_specialty(self.worker_specialty, self.agent_class)

    def to_task(self, scan_id: str, task_id: str) -> dict:
        """Serialize to a worker task packet for the Master substrate."""
        return {
            "task_id": task_id,
            "scan_id": scan_id,
            "agent_class": self.agent_class,
            "objective": self.objective,
            "phase": self.phase,
            "worker_requirements": {"type": self.worker_specialty},
            "config": {
                "tools": self.tools,
                "budget": self.budget,
                "context": self.context,
                "depth": self.depth,
            },
        }



    # Context sanitization: allowlist-based to prevent secret leakage
    SAFE_CONTEXT_KEYS = frozenset({
        "target", "target_url", "scope", "scope_policy",
        "scan_id", "phase", "strategy",
        "previous_findings", "entities", "endpoints", "services", "ports",
        "wordlist_path", "aggression_level", "method", "targets",
    })

    BLOCKED_CONTEXT_KEYS = frozenset({
        "api_keys", "tokens", "credentials", "secrets",
        "passwords", "private_keys", "session_cookies",
        "jwt_tokens", "auth_headers", "vault_tokens",
    })


    # Context sanitization: allowlist-based to prevent secret leakage
    SAFE_CONTEXT_KEYS = frozenset({
        "target", "target_url", "scope", "scope_policy",
        "scan_id", "phase", "strategy",
        "previous_findings", "entities", "endpoints", "services", "ports",
        "wordlist_path", "aggression_level", "method", "targets",
    })

    BLOCKED_CONTEXT_KEYS = frozenset({
        "api_keys", "tokens", "credentials", "secrets",
        "passwords", "private_keys", "session_cookies",
        "jwt_tokens", "auth_headers", "vault_tokens",
    })

    def sanitize_context(self) -> Dict:
        r"""Return only safe context keys for child workers."""
        if not self.context:
            return {}
        safe = {}
        for key, value in self.context.items():
            if key in self.SAFE_CONTEXT_KEYS and key not in self.BLOCKED_CONTEXT_KEYS:
                safe[key] = value
            elif key not in self.BLOCKED_CONTEXT_KEYS:
                _logger.debug("Dropping unknown context key '%s'", key)
        return safe
    def sanitize_context(self) -> Dict[str, Any]:
        """Return only safe context keys for child workers.

        Uses allowlist approach: only passes known-safe keys.
        """
        _logger = logging.getLogger(__name__)
        if not self.context:
            return {}
        safe = {}
        for key, value in self.context.items():
            if key in self.SAFE_CONTEXT_KEYS and key not in self.BLOCKED_CONTEXT_KEYS:
                safe[key] = value
            elif key not in self.SAFE_CONTEXT_KEYS and key not in self.BLOCKED_CONTEXT_KEYS:
                _logger.debug(
                    "Dropping unknown context key '%s' from child spec",
                    key,
                )
        return safe

class ChildResult:
    """Structured child-agent return object (Architecture §5, ResultPacket)."""

    child_id: str
    agent_class: str
    status: ChildStatus
    findings: list[dict] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    summary: str = ""
    budget_used: int = 0
    duration_ms: int = 0
    error: str = ""
    worker_specialty: str = "hybrid"        # which §5.1.2 pool handled the task
    depth: int = 1                           # position in the delegation subtree
    tools_allowed: list[str] = field(default_factory=list)  # restricted allowlist

    def to_dict(self) -> dict[str, Any]:
        return {
            "child_id": self.child_id,
            "agent_class": self.agent_class,
            "status": self.status,
            "findings": self.findings,
            "artifacts": self.artifacts,
            "summary": self.summary,
            "budget_used": self.budget_used,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "worker_specialty": self.worker_specialty,
            "depth": self.depth,
            "tools_allowed": self.tools_allowed,
        }

    @property
    def ok(self) -> bool:
        """True only for a cleanly completed child (Hermes status semantics)."""
        return self.status == "completed"


class DelegationManager:
    """Spawns budgeted, isolated child agents and returns structured results."""

    # Registry of in-process child runners keyed by agent_class.
    _runners: dict[str, ChildRunner] = {}

    def __init__(self, bus: Any = None, master: Any = None, *, scan_id: str = "GLOBAL",
                 max_depth: int = DEFAULT_MAX_DEPTH,
                 max_concurrent: int = DEFAULT_MAX_CONCURRENT,
                 depth: int = 0,
                 event_hook: EventHook | None = None) -> None:
        self.bus = bus
        self.master = master
        self.scan_id = scan_id
        self.max_depth = max(1, int(max_depth))
        self.depth = max(0, int(depth))             # this manager's tree depth
        self._event_hook = event_hook
        # Bound concurrent fan-out so a parent can't spawn an unbounded child swarm
        # (Architecture §5 budget boundedness; Hermes max_concurrent_children).
        self._sema = asyncio.Semaphore(max(1, int(max_concurrent)))
        self._specialty_semaphores: Dict[str, asyncio.Semaphore] = {}
        self._active: dict[str, asyncio.Task] = {}
        self.telemetry = {
            "spawned": 0,
            "completed": 0,
            "failed": 0,
            "timeouts": 0,
            "cancelled": 0,
            "budget_exhausted": 0,
            "rejected": 0,
        }

    # ── Observability hook (Architecture §5.5: EventBus stays telemetry plane) ──

    def _emit(self, event: str, **fields: Any) -> None:
        """Best-effort lifecycle event. Never affects control flow (Hermes
        DelegateEvent relay degrades silently when no sink is attached)."""
        hook = self._event_hook
        if hook is None:
            return
        try:
            hook({"event": event, "scan_id": self.scan_id, "depth": self.depth, **fields})
        except Exception:  # pragma: no cover - telemetry must never break control flow
            logger.debug("delegation event hook failed for %s", event, exc_info=True)

    # ── Runner registration (Architecture §5.1.2 worker specialties) ──────────

    @classmethod
    def register_runner(cls, agent_class: str, runner: ChildRunner) -> None:
        cls._runners[agent_class] = runner

    @classmethod
    def has_runner(cls, agent_class: str) -> bool:
        return agent_class in cls._runners

    # ── Spawning ──────────────────────────────────────────────────────────────

    async def spawn(self, spec: ChildSpec, parent_budget: IterationBudget | None = None) -> ChildResult:
        """Spawn a child agent. The child receives an INDEPENDENT budget so it can
        never drain the parent (Architecture §5 budget boundedness)."""
        child_id = f"{spec.agent_class}-{uuid.uuid4().hex[:8]}"

        # Depth bound: refuse to spawn beyond the configured subtree depth so a
        # runaway delegation chain can't recurse forever (Hermes max_spawn_depth).
        child_depth = self.depth + 1
        if child_depth > self.max_depth:
            self.telemetry["rejected"] += 1
            self._emit("delegate.rejected", child_id=child_id, agent_class=spec.agent_class,
                       reason="max_depth", depth=child_depth)
            return self._stamp(spec, ChildResult(
                child_id, spec.agent_class, "rejected",
                summary=f"delegation depth limit reached (depth={child_depth}, max={self.max_depth})",
            ), child_depth)
        spec.depth = child_depth

        if parent_budget is not None:
            child_budget = parent_budget.child(spec.budget, label=child_id)
        else:
            child_budget = IterationBudget(spec.budget, label=child_id)

        self.telemetry["spawned"] += 1
        started = time.time()
        self._emit("delegate.spawned", child_id=child_id, agent_class=spec.agent_class,
                   worker_specialty=spec.worker_specialty, depth=child_depth,
                   tools_allowed=list(spec.tools), budget=spec.budget)

        # Prefer the distributed substrate when available (Architecture §5.1.2).
        use_worker = self.master is not None and getattr(self.master, "redis_client", None) is not None

        # Bound concurrent fan-out (Hermes max_concurrent_children).
        async with self._sema:
            try:
                if use_worker:
                    coro = self._run_on_worker(spec, child_id, child_budget)
                else:
                    coro = self._run_in_process(spec, child_id, child_budget)

                task = asyncio.ensure_future(coro)
                self._active[child_id] = task
                result = await asyncio.wait_for(task, timeout=spec.timeout_s)
                result.duration_ms = int((time.time() - started) * 1000)
                self._stamp(spec, result, child_depth)
                self._tally(result.status)
                self._emit("delegate.completed", child_id=child_id, agent_class=spec.agent_class,
                           status=result.status, duration_ms=result.duration_ms,
                           budget_used=result.budget_used)
                return result
            except asyncio.TimeoutError:
                await self._cancel_child(child_id)
                self.telemetry["timeouts"] += 1
                self._emit("delegate.timeout", child_id=child_id, agent_class=spec.agent_class,
                           timeout_s=spec.timeout_s)
                return self._stamp(spec, ChildResult(
                    child_id, spec.agent_class, "timeout",
                    summary=f"child exceeded timeout {spec.timeout_s}s",
                    duration_ms=int((time.time() - started) * 1000)), child_depth)
            except asyncio.CancelledError:
                await self._cancel_child(child_id)
                self.telemetry["cancelled"] += 1
                self._emit("delegate.cancelled", child_id=child_id, agent_class=spec.agent_class)
                raise
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("Delegation error for %s: %s", child_id, exc)
                self.telemetry["failed"] += 1
                self._emit("delegate.failed", child_id=child_id, agent_class=spec.agent_class,
                           error=str(exc))
                return self._stamp(spec, ChildResult(
                    child_id, spec.agent_class, "failed", error=str(exc),
                    duration_ms=int((time.time() - started) * 1000)), child_depth)
            finally:
                self._active.pop(child_id, None)

    def _stamp(self, spec: ChildSpec, result: ChildResult, depth: int) -> ChildResult:
        """Copy routing/scope metadata from the spec onto the ResultPacket so the
        parent can trace which specialty/allowlist/depth produced the result."""
        result.worker_specialty = spec.worker_specialty
        result.depth = depth
        if not result.tools_allowed:
            result.tools_allowed = list(spec.tools)
        return result

    async def spawn_many(self, specs: list[ChildSpec],
                         parent_budget: IterationBudget | None = None) -> list[ChildResult]:
        """Spawn several children concurrently; ordered results (Architecture §29.3
        concurrent tool dispatch with ordered result collection)."""
        results = await asyncio.gather(
            *(self.spawn(spec, parent_budget) for spec in specs),
            return_exceptions=True,
        )
        normalized: list[ChildResult] = []
        for spec, res in zip(specs, results):
            if isinstance(res, ChildResult):
                normalized.append(res)
            else:
                normalized.append(ChildResult(
                    f"{spec.agent_class}-error", spec.agent_class, "failed", error=str(res)))
        return normalized

    # ── In-process execution ───────────────────────────────────────────────────

    async def _run_in_process(self, spec: ChildSpec, child_id: str,
                              budget: IterationBudget) -> ChildResult:
        runner = self._runners.get(spec.agent_class)
        if runner is None:
            return ChildResult(child_id, spec.agent_class, "failed",
                               error=f"no in-process runner registered for {spec.agent_class}")
        if budget.exhausted():
            return ChildResult(child_id, spec.agent_class, "budget_exhausted",
                               summary="child budget exhausted before start")
        # Isolated context: the child receives a COPY augmented with its scope
        # metadata, so it can never mutate the parent's live context dict and the
        # runner can self-restrict to the allowlist (Architecture §5 isolation).
        child_context = dict(spec.context)
        child_context.setdefault("scan_id", self.scan_id)
        child_context["_child_id"] = child_id
        child_context["_tools_allowed"] = list(spec.tools)
        child_context["_worker_specialty"] = spec.worker_specialty
        child_context["_depth"] = spec.depth
        try:
            out = await runner(child_context, budget) or {}
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return ChildResult(child_id, spec.agent_class, "failed", error=str(exc),
                               budget_used=budget.consumed)
        status: ChildStatus = "budget_exhausted" if budget.exhausted() and not out else "completed"
        return ChildResult(
            child_id=child_id,
            agent_class=spec.agent_class,
            status=status,
            findings=list(out.get("findings", [])),
            artifacts=list(out.get("artifacts", [])),
            summary=str(out.get("summary", "")),
            budget_used=budget.consumed,
        )

    # ── Distributed (worker) execution (Architecture §5.1.2) ─────────────────────

    async def _run_on_worker(self, spec: ChildSpec, child_id: str,
                             budget: IterationBudget) -> ChildResult:
        master = self.master
        task = spec.to_task(self.scan_id, child_id)
        result_key = f"delegation_result:{child_id}"
        try:
            await master.distribute_tasks([task])
        except Exception as exc:
            logger.warning("Worker distribute failed (%s); falling back in-process.", exc)
            return await self._run_in_process(spec, child_id, budget)

        # Await result key written by the worker (durable task lease §5.6).
        redis = master.redis_client
        deadline = time.time() + spec.timeout_s
        while time.time() < deadline:
            try:
                raw = await redis.get(result_key)
            except Exception as redis_exc:
                logger.debug(f"Delegation result key read failed: {redis_exc}")
                raw = None
        if raw:
                import json
                data = json.loads(raw)
                raw_status = str(data.get("status", "completed"))
                status: ChildStatus = (
                    raw_status if raw_status in _VALID_STATUSES else "completed"  # type: ignore[assignment]
                )
                return ChildResult(
                    child_id=child_id,
                    agent_class=spec.agent_class,
                    status=status,
                    findings=data.get("findings", []),
                    artifacts=data.get("artifacts", []),
                    summary=data.get("summary", ""),
                    budget_used=data.get("budget_used", 0),
                )
        await asyncio.sleep(1.0)
        return ChildResult(child_id, spec.agent_class, "timeout",
                           summary="worker result not received in time")

    # ── Cancellation (Architecture §5 interrupt propagation) ─────────────────────

    async def cancel_all(self) -> None:
        for child_id in list(self._active.keys()):
            await self._cancel_child(child_id)

    async def _cancel_child(self, child_id: str) -> None:
        task = self._active.get(child_id)
        if task and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass


    def _get_specialty_semaphore(self, specialty: str) -> asyncio.Semaphore:
        """Get or create a semaphore for a specific worker specialty."""
        if specialty not in self._specialty_semaphores:
            # Constants are module-level, accessible directly
            limit = WORKER_SPECIALTY_LIMITS.get(specialty, DEFAULT_MAX_CONCURRENT)
            self._specialty_semaphores[specialty] = asyncio.Semaphore(limit)
        return self._specialty_semaphores[specialty]

    async def spawn_streaming(
        self,
        spec: ChildSpec,
        parent_context: dict = None,
        progress_interval: float = 5.0,
    ) -> "AsyncGenerator[dict, None]":
        """Spawn a worker and stream progress updates.

        Yields dicts like:
            {"type": "PROGRESS", "data": {"status": "running"}}
            {"type": "COMPLETE", "data": {...result...}}
            {"type": "FAILED", "error": "..."}

        Only use for tasks >10 seconds (nmap, browser crawls, masscan).
        """
        task = asyncio.create_task(self.spawn(spec, parent_context))
        try:
            while not task.done():
                await asyncio.sleep(progress_interval)
                yield {"type": "PROGRESS", "data": {"status": "running"}}
            result = task.result()
            if result.status == "completed":
                yield {"type": "COMPLETE", "data": result.to_dict()}
            else:
                yield {"type": "FAILED", "error": result.error or "unknown"}
        except asyncio.CancelledError:
            task.cancel()
            yield {"type": "FAILED", "error": "parent cancelled"}
        finally:
            if not task.done():
                task.cancel()

    def _tally(self, status: ChildStatus) -> None:
        if status == "completed":
            self.telemetry["completed"] += 1
        elif status == "failed":
            self.telemetry["failed"] += 1
        elif status == "budget_exhausted":
            self.telemetry["budget_exhausted"] += 1
        elif status == "rejected":
            self.telemetry["rejected"] += 1
        elif status == "timeout":
            self.telemetry["timeouts"] += 1

    def get_telemetry(self) -> dict[str, Any]:
        return dict(self.telemetry)


def make_delegation_manager(bus: Any = None, master: Any = None,
                            scan_id: str = "GLOBAL", *,
                            max_depth: int = DEFAULT_MAX_DEPTH,
                            max_concurrent: int = DEFAULT_MAX_CONCURRENT,
                            depth: int = 0,
                            event_hook: EventHook | None = None) -> DelegationManager:
    return DelegationManager(bus=bus, master=master, scan_id=scan_id,
                             max_depth=max_depth, max_concurrent=max_concurrent,
                             depth=depth, event_hook=event_hook)
