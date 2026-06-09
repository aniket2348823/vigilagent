"""
Integration Coordinator — lightweight event router for deep system integration.

This module restores task 1.5 of the deep-system-integration spec: a coordinator
that wires LearningEngine, SkillLibrary, HealthMonitor, SelfHealingEngine and
BrowserOrchestrator behind the EventBus with:

  * Dependency injection (no module-globals reach inside).
  * Circuit-breaker isolation (optional ``circuitbreaker`` lib; graceful no-op
    fallback so this file imports cleanly even when the lib is absent).
  * Event batching to absorb storms (BROWSER_DISCOVERY).
  * Concurrency cap via semaphore (learning fan-out).
  * OpenTelemetry tracing via ``backend.core.tracing.trace_span`` (also a no-op
    when OTel is not installed / disabled).
  * Feature-flag guards so every handler is a no-op until the corresponding
    flag is turned on — safe default for Phase-1 checkpoint.

Architecture invariants honoured:
  * §29.13 non-blocking event loop — all handler bodies are async and the batch
    drain runs as a background task.
  * §11 two-LLM exclusivity — no LLM bindings live here.
  * §17 ≥2-signal evidence rule — coordinator does NOT confirm vulnerabilities;
    it only routes already-confirmed events to the learning pipeline.
  * §9 scope-is-law — coordinator carries no target/host data; targets travel
    inside event payloads and are validated by downstream components.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol

# Tracing — already optional inside backend.core.tracing
try:
    from backend.core.tracing import trace_span
except Exception:  # pragma: no cover - defensive: tracing is optional infra
    from contextlib import contextmanager

    @contextmanager
    def trace_span(name: str, attributes: Optional[dict] = None):  # type: ignore
        yield None

# Circuit breaker — OPTIONAL dependency. The design references the
# ``circuitbreaker`` PyPI package, but it is not pinned in
# backend/requirements.txt. Fall back to a transparent decorator so the module
# imports cleanly in environments that don't ship it. The local
# ``_LocalCircuitBreaker`` we build below still gives us trip-count metrics.
try:  # pragma: no cover - import-shape only
    from circuitbreaker import circuit as _ext_circuit  # type: ignore

    _CIRCUIT_BREAKER_LIB_AVAILABLE = True
except Exception:  # pragma: no cover
    _ext_circuit = None  # type: ignore
    _CIRCUIT_BREAKER_LIB_AVAILABLE = False

from backend.core.integration_config import IntegrationConfig, get_integration_config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocols (structural typing) — keep this file decoupled from concrete impls.
# ---------------------------------------------------------------------------
class _EventBusLike(Protocol):
    async def subscribe(self, event_type: str, handler: Callable[..., Awaitable[None]]) -> Any: ...
    async def publish(self, event_type: str, data: Any, **kwargs: Any) -> Any: ...


class _LearningEngineLike(Protocol):
    async def learn_from_browser_vulnerability(self, vuln_data: Dict, scan_id: str) -> Any: ...
    async def learn_framework_pattern(self, framework: Optional[str], routes: List[str]) -> Any: ...


class _SkillLibraryLike(Protocol):
    pass


class _HealthMonitorLike(Protocol):
    pass


class _HealingEngineLike(Protocol):
    pass


class _BrowserOrchestratorLike(Protocol):
    pass


# ---------------------------------------------------------------------------
# Local fail-safe circuit breaker (always available, even without the PyPI lib)
# ---------------------------------------------------------------------------
@dataclass
class _LocalCircuitBreaker:
    """Minimal in-process circuit breaker.

    Trips OPEN after ``failure_threshold`` consecutive failures and half-opens
    after ``recovery_timeout`` seconds. While OPEN, ``call`` raises
    ``CircuitOpen`` immediately so the caller can degrade gracefully.
    """

    name: str
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    _failures: int = 0
    _opened_at: Optional[float] = None
    _trips: int = 0

    class CircuitOpen(RuntimeError):
        pass

    def _now(self) -> float:
        return asyncio.get_event_loop().time()

    def _is_open(self) -> bool:
        if self._opened_at is None:
            return False
        if self._now() - self._opened_at >= self.recovery_timeout:
            # Half-open: allow next call through, reset state.
            self._opened_at = None
            self._failures = 0
            return False
        return True

    async def call(self, coro_func: Callable[[], Awaitable[Any]]) -> Any:
        if self._is_open():
            raise _LocalCircuitBreaker.CircuitOpen(f"circuit '{self.name}' OPEN")
        try:
            result = await coro_func()
        except Exception as exc:
            self._failures += 1
            logger.debug("[Coordinator] Handler failure: %s", exc)
            if self._failures >= self.failure_threshold:
                self._opened_at = self._now()
                self._trips += 1
                logger.warning(
                    "Circuit '%s' tripped open after %d consecutive failures",
                    self.name,
                    self._failures,
                )
            raise
        else:
            self._failures = 0
            return result

    @property
    def trips(self) -> int:
        return self._trips


# ---------------------------------------------------------------------------
# Lightweight event shim — accepts dicts OR objects with .data/.scan_id.
# ---------------------------------------------------------------------------
def _event_data(event: Any) -> Dict[str, Any]:
    if isinstance(event, dict):
        return event.get("data", event)
    return getattr(event, "data", {}) or {}


def _event_scan_id(event: Any, default: str = "unknown") -> str:
    if isinstance(event, dict):
        return str(event.get("scan_id", default))
    return str(getattr(event, "scan_id", default) or default)


# ---------------------------------------------------------------------------
# Coordinator
# ---------------------------------------------------------------------------
@dataclass
class _Metrics:
    events_processed: int = 0
    events_failed: int = 0
    events_skipped: int = 0
    batches_flushed: int = 0
    last_batch_size: int = 0


class IntegrationCoordinator:
    """Routes events between Evolution and Browser subsystems.

    All handlers are guarded by feature flags (``IntegrationConfig``). With the
    Phase-1 default of every flag OFF, every handler returns immediately and
    no downstream call is issued. This is the *safe default* required by the
    spec's gradual-rollout strategy.
    """

    def __init__(
        self,
        bus: _EventBusLike,
        learning_engine: _LearningEngineLike,
        skill_library: _SkillLibraryLike,
        health_monitor: _HealthMonitorLike,
        healing_engine: _HealingEngineLike,
        browser_orchestrator: _BrowserOrchestratorLike,
        config: Optional[IntegrationConfig] = None,
    ) -> None:
        self.bus = bus
        self.learning_engine = learning_engine
        self.skill_library = skill_library
        self.health_monitor = health_monitor
        self.healing_engine = healing_engine
        self.browser_orchestrator = browser_orchestrator
        self.config: IntegrationConfig = config or get_integration_config()

        # Event batching for BROWSER_DISCOVERY storms.
        self._discovery_batch: List[Dict[str, Any]] = []
        self._batch_lock = asyncio.Lock()
        self._batch_task: Optional[asyncio.Task] = None
        self._shutdown = False

        # Concurrency cap on learning fan-out.
        self._learning_semaphore = asyncio.Semaphore(
            max(1, self.config.max_concurrent_learning)
        )

        # Circuit breakers per dependency (always have local breakers; if the
        # external lib is present we still use the local ones so trip metrics
        # stay observable from one place).
        self._cb_vuln = _LocalCircuitBreaker(
            name="browser_vulnerability_learning",
            failure_threshold=self.config.circuit_breaker_threshold,
            recovery_timeout=float(self.config.circuit_breaker_timeout_s),
        )
        self._cb_discovery = _LocalCircuitBreaker(
            name="discovery_learning",
            failure_threshold=self.config.circuit_breaker_threshold,
            recovery_timeout=float(self.config.circuit_breaker_timeout_s),
        )

        self._metrics = _Metrics()
        self._initialized = False

    # ------------------------------------------------------------------ init
    async def initialize(self) -> None:
        """Subscribe to events and start the batch drainer."""
        if self._initialized:
            return
        with trace_span("integration_init"):
            try:
                await self.bus.subscribe("VULN_CONFIRMED", self._on_vulnerability)
                await self.bus.subscribe("BROWSER_DISCOVERY", self._on_discovery)
                await self.bus.subscribe("AGENT_FAILURE", self._on_failure)
            except Exception as e:  # pragma: no cover - defensive
                logger.warning("Coordinator subscribe partially failed: %s", e)

            self._batch_task = asyncio.create_task(
                self._drain_discovery_batches(), name="ic_batch_drain"
            )
            self._initialized = True

            logger.info(
                "IntegrationCoordinator initialized (browser_learning=%s, "
                "cross_healing=%s, forensic_learning=%s, intelligent_routing=%s)",
                self.config.enable_browser_learning,
                self.config.enable_cross_system_healing,
                self.config.enable_forensic_learning,
                self.config.enable_intelligent_routing,
            )

    # ------------------------------------------------------------ shutdown
    async def shutdown(self) -> None:
        """Cancel batch task, flush remainder."""
        self._shutdown = True
        if self._batch_task and not self._batch_task.done():
            self._batch_task.cancel()
            try:
                await self._batch_task
            except (asyncio.CancelledError, Exception):
                pass
        async with self._batch_lock:
            if self._discovery_batch:
                await self._flush_discovery_batch_locked()
        logger.info(
            "IntegrationCoordinator shutdown: processed=%d failed=%d skipped=%d batches=%d",
            self._metrics.events_processed,
            self._metrics.events_failed,
            self._metrics.events_skipped,
            self._metrics.batches_flushed,
        )

    # ----------------------------------------------------- public metrics
    def get_integration_metrics(self) -> Dict[str, Any]:
        """Snapshot for /api/integration/metrics."""
        processed = self._metrics.events_processed
        failed = self._metrics.events_failed
        return {
            "events_processed": processed,
            "events_failed": failed,
            "events_skipped": self._metrics.events_skipped,
            "failure_rate": (failed / processed) if processed else 0.0,
            "circuit_breaker_trips": self._cb_vuln.trips + self._cb_discovery.trips,
            "pending_discoveries": len(self._discovery_batch),
            "batches_flushed": self._metrics.batches_flushed,
            "last_batch_size": self._metrics.last_batch_size,
            "features_enabled": {
                "browser_learning": self.config.enable_browser_learning,
                "cross_system_healing": self.config.enable_cross_system_healing,
                "forensic_learning": self.config.enable_forensic_learning,
                "intelligent_routing": self.config.enable_intelligent_routing,
            },
            "circuit_breaker_lib_available": _CIRCUIT_BREAKER_LIB_AVAILABLE,
        }

    # ------------------------------------------------------- event handlers
    async def _on_vulnerability(self, event: Any) -> None:
        """VULN_CONFIRMED → learning_engine.learn_from_browser_vulnerability."""
        if not self.config.enable_browser_learning:
            self._metrics.events_skipped += 1
            return

        data = _event_data(event)
        scan_id = _event_scan_id(event)

        with trace_span(
            "handle_vulnerability",
            {"vuln.type": str(data.get("vuln_type")), "scan_id": scan_id},
        ):
            try:
                async def _do() -> None:
                    async with self._learning_semaphore:
                        await self.learning_engine.learn_from_browser_vulnerability(
                            data, scan_id
                        )

                await self._cb_vuln.call(_do)
                self._metrics.events_processed += 1
            except _LocalCircuitBreaker.CircuitOpen:
                # Breaker open → degrade silently, do NOT raise into the bus.
                self._metrics.events_skipped += 1
            except Exception as e:
                self._metrics.events_failed += 1
                logger.error(
                    "Vulnerability learning failed (scan_id=%s): %s",
                    scan_id,
                    e,
                    exc_info=True,
                )

    async def _on_discovery(self, event: Any) -> None:
        """BROWSER_DISCOVERY → buffer for batched learning."""
        if not self.config.enable_browser_learning:
            self._metrics.events_skipped += 1
            return

        data = _event_data(event)
        async with self._batch_lock:
            self._discovery_batch.append(data)
            if len(self._discovery_batch) >= self.config.event_batch_size:
                await self._flush_discovery_batch_locked()

    async def _on_failure(self, event: Any) -> None:
        """AGENT_FAILURE → forwarded to healing engine when cross-healing is on.

        Phase-1 default: feature flag OFF, so this is a no-op. The actual
        cross-system healing wiring lives in tasks 9.x.
        """
        if not self.config.enable_cross_system_healing:
            self._metrics.events_skipped += 1
            return
        # Intentionally minimal: full healing flow is owned by section 9.
        self._metrics.events_processed += 1

    # ------------------------------------------------------------- batching
    async def _drain_discovery_batches(self) -> None:
        timeout_s = max(0.05, self.config.event_batch_timeout_ms / 1000.0)
        try:
            while not self._shutdown:
                await asyncio.sleep(timeout_s)
                async with self._batch_lock:
                    if self._discovery_batch:
                        await self._flush_discovery_batch_locked()
        except asyncio.CancelledError:
            return

    async def _flush_discovery_batch_locked(self) -> None:
        """Caller holds ``self._batch_lock``."""
        if not self._discovery_batch:
            return
        batch = self._discovery_batch[:]
        self._discovery_batch.clear()
        self._metrics.last_batch_size = len(batch)

        with trace_span("flush_discovery_batch", {"batch.size": len(batch)}):
            try:
                async def _do() -> None:
                    tasks = [
                        self.learning_engine.learn_framework_pattern(
                            d.get("framework"), d.get("routes", []) or []
                        )
                        for d in batch
                    ]
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)

                await self._cb_discovery.call(_do)
                self._metrics.batches_flushed += 1
                self._metrics.events_processed += len(batch)
            except _LocalCircuitBreaker.CircuitOpen:
                self._metrics.events_skipped += len(batch)
            except Exception as e:
                self._metrics.events_failed += len(batch)
                logger.error("Discovery batch flush failed: %s", e, exc_info=True)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
# The dashboard endpoint at backend/api/endpoints/dashboard.py imports this
# symbol lazily inside a function and checks it for truthiness, so leaving it
# at None until lifespan calls ``init_integration_coordinator`` is safe.
integration_coordinator: Optional[IntegrationCoordinator] = None


def init_integration_coordinator(
    *,
    bus: _EventBusLike,
    learning_engine: _LearningEngineLike,
    skill_library: _SkillLibraryLike,
    health_monitor: _HealthMonitorLike,
    healing_engine: _HealingEngineLike,
    browser_orchestrator: _BrowserOrchestratorLike,
    config: Optional[IntegrationConfig] = None,
) -> IntegrationCoordinator:
    """Create + cache the module-level coordinator. Idempotent."""
    global integration_coordinator
    if integration_coordinator is None:
        integration_coordinator = IntegrationCoordinator(
            bus=bus,
            learning_engine=learning_engine,
            skill_library=skill_library,
            health_monitor=health_monitor,
            healing_engine=healing_engine,
            browser_orchestrator=browser_orchestrator,
            config=config,
        )
    return integration_coordinator


async def shutdown_integration_coordinator() -> None:
    global integration_coordinator
    if integration_coordinator is not None:
        await integration_coordinator.shutdown()
        integration_coordinator = None


__all__ = [
    "IntegrationCoordinator",
    "IntegrationConfig",
    "integration_coordinator",
    "init_integration_coordinator",
    "shutdown_integration_coordinator",
]
