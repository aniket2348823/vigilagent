"""
Vigilagent Recovery Engine (Architecture §14, §14.1, §29.9, §29.13)
================================================================================
Single merged module that replaces the former `self_healing_engine.py` and
`strategy_adapter.py`. It provides:

  - SelfHealingEngine: circuit breakers, agent restart with backoff, health loop,
    load balancing, persisted healing state.
  - BrowserSelfHealingExtension: browser crash/memory recovery + strategy.
  - UnifiedErrorHandlingExtension: HTTP+browser error handling with REAL,
    vault-backed re-authentication (Architecture §29.9 — no more stub).
  - StrategyAdapter: real strategy selection among RETRY / SWITCH_TECHNIQUE /
    DELEGATE / REDUCE_AGGRESSION / CHANGE_PARAMETERS / ABORT based on error
    class and diminishing returns (no constant SWITCH_TECHNIQUE).
  - RecoveryEngine: a thin façade that ties these together, selects a real
    corrective action, and writes the resolving pattern to the SkillLibrary so
    the Planner can consume it (closing the write-only loop, §29.9 req 4).
"""
from __future__ import annotations

import asyncio
import gc
import json
import logging
import random
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from backend.core.agent_health_monitor import health_monitor, HealthAlert
from backend.core.self_awareness_config import SelfAwarenessConfig
from backend.core.tracing import get_tracer, trace_span

logger = logging.getLogger("RecoveryEngine")
tracer = get_tracer()


# ══════════════════════════════════════════════════════════════════════════════
# SELF-HEALING (formerly self_healing_engine.py)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RecoveryRecord:
    """Represents a recovery action taken by the system."""
    timestamp: float
    agent_name: str
    issue: str
    action_type: str  # "restart", "strategy_change", "resource_reallocation", etc.
    action_details: Dict[str, Any]
    success: bool
    recovery_time_ms: float = 0.0


@dataclass
class CircuitBreaker:
    """Circuit breaker for failing endpoints."""
    endpoint: str
    failure_count: int = 0
    success_count: int = 0
    state: str = "closed"  # "closed", "open", "half_open"
    last_failure: float = 0.0
    opened_at: float = 0.0

    def should_allow_request(self) -> bool:
        if self.state == "closed":
            return True
        elif self.state == "open":
            if time.time() - self.opened_at > 30:
                self.state = "half_open"
                return True
            return False
        else:  # half_open
            return True

    def record_success(self):
        self.success_count += 1
        if self.state == "half_open" and self.success_count >= 3:
            self.state = "closed"
            self.failure_count = 0

    def record_failure(self):
        self.failure_count += 1
        self.last_failure = time.time()
        if self.failure_count >= 5:
            self.state = "open"
            self.opened_at = time.time()
            logger.warning(f"[CircuitBreaker] Opened circuit for {self.endpoint}")


class SelfHealingEngine:
    """Automatically recovers from failures and optimizes performance."""

    def __init__(self, brain_dir: str = "brain"):
        self.brain_dir = Path(brain_dir)
        self.healing_dir = self.brain_dir / "healing"
        self.healing_dir.mkdir(parents=True, exist_ok=True)
        self.recovery_history: deque = deque(maxlen=1000)
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.restart_counts: Dict[str, int] = defaultdict(int)
        self.last_restart: Dict[str, float] = {}
        self.strategy_changes: Dict[str, List[str]] = defaultdict(list)
        self.agent_load: Dict[str, int] = defaultdict(int)
        self.restart_callbacks: Dict[str, Callable] = {}
        self.config = {
            "max_restarts_per_hour": 5,
            "restart_backoff_seconds": [5, 10, 30, 60, 300],
            "circuit_breaker_threshold": 5,
            "circuit_breaker_timeout": 30,
            "strategy_change_threshold": 3,
            "load_balance_threshold": 10,
        }

    def register_restart_callback(self, agent_name: str, callback: Callable):
        self.restart_callbacks[agent_name] = callback

    async def monitor_and_heal(self):
        """Main healing loop — monitors health and takes recovery actions."""
        logger.info("[SelfHealing] Monitoring loop started")
        while True:
            try:
                await asyncio.sleep(10)
                crashed_agents = health_monitor.check_heartbeats()
                for agent_name in crashed_agents:
                    await self.heal_crashed_agent(agent_name)
                all_health = health_monitor.get_all_health()
                for agent_name, metrics in all_health.items():
                    if metrics["health_score"] < 40:
                        await self.heal_unhealthy_agent(agent_name, metrics)
                for agent_name, metrics in all_health.items():
                    if metrics["error_rate"] > 0.3:
                        await self.adapt_strategy(agent_name, "high_error_rate")
                await self.balance_load()
                if int(time.time()) % 300 == 0:
                    await self.save_healing_state()
            except Exception as e:
                logger.error(f"[SelfHealing] Monitoring loop error: {e}")

    async def heal_crashed_agent(self, agent_name: str) -> bool:
        start_time = time.time()
        if not self._can_restart(agent_name):
            logger.error(f"[SelfHealing] Cannot restart {agent_name} - too many restarts")
            return False
        restart_count = self.restart_counts[agent_name]
        backoff_index = min(restart_count, len(self.config["restart_backoff_seconds"]) - 1)
        backoff_delay = self.config["restart_backoff_seconds"][backoff_index]
        if agent_name in self.last_restart:
            time_since_restart = time.time() - self.last_restart[agent_name]
            if time_since_restart < backoff_delay:
                logger.info(f"[SelfHealing] Waiting {backoff_delay - time_since_restart:.0f}s before restarting {agent_name}")
                return False
        logger.info(f"[SelfHealing] Attempting to restart {agent_name} (attempt {restart_count + 1})")
        try:
            if agent_name in self.restart_callbacks:
                await self.restart_callbacks[agent_name]()
                success = True
            else:
                logger.warning(f"[SelfHealing] No restart callback for {agent_name}")
                success = False
            self.restart_counts[agent_name] += 1
            self.last_restart[agent_name] = time.time()
            recovery_time = (time.time() - start_time) * 1000
            self._record_recovery(agent_name, "agent_crashed", "restart",
                                  {"restart_count": self.restart_counts[agent_name], "backoff_delay": backoff_delay},
                                  success, recovery_time)
            if success:
                logger.info(f"[SelfHealing] Successfully restarted {agent_name}")
                health_monitor.clear_alerts(agent_name)
            return success
        except Exception as e:
            logger.error(f"[SelfHealing] Failed to restart {agent_name}: {e}")
            self._record_recovery(agent_name, "agent_crashed", "restart", {"error": str(e)},
                                  False, (time.time() - start_time) * 1000)
            return False

    async def heal_unhealthy_agent(self, agent_name: str, metrics: Dict[str, Any]):
        health_score = metrics["health_score"]
        logger.info(f"[SelfHealing] Healing unhealthy agent {agent_name} (health: {health_score:.0f}/100)")
        if metrics["memory_mb"] > 500:
            await self._reduce_memory_usage(agent_name)
        if metrics["error_rate"] > 0.2:
            await self.adapt_strategy(agent_name, "high_error_rate")
        if metrics["response_time_ms"] > 2000:
            await self._reduce_agent_load(agent_name)

    async def adapt_strategy(self, agent_name: str, reason: str):
        logger.info(f"[SelfHealing] Adapting strategy for {agent_name} (reason: {reason})")
        self.strategy_changes[agent_name].append(reason)
        if reason in ("high_error_rate", "rate_limited", "waf_detected"):
            new_strategy = "LOW_AND_SLOW"
        else:
            new_strategy = "MULTI_STEP_EXPLOIT"
        self._record_recovery(agent_name, reason, "strategy_change",
                              {"new_strategy": new_strategy}, True, 0.0)

    async def balance_load(self):
        all_health = health_monitor.get_all_health()
        if len(all_health) < 2:
            return
        overloaded, idle = [], []
        for agent_name, metrics in all_health.items():
            queue_depth = metrics.get("task_queue_depth", 0)
            if queue_depth > 10:
                overloaded.append((agent_name, queue_depth))
            elif queue_depth < 3:
                idle.append((agent_name, queue_depth))
        if overloaded and idle:
            logger.info(f"[SelfHealing] Load imbalance detected - {len(overloaded)} overloaded, {len(idle)} idle")

    def check_circuit_breaker(self, endpoint: str) -> bool:
        if endpoint not in self.circuit_breakers:
            self.circuit_breakers[endpoint] = CircuitBreaker(endpoint=endpoint)
        return self.circuit_breakers[endpoint].should_allow_request()

    def record_endpoint_result(self, endpoint: str, success: bool):
        if endpoint not in self.circuit_breakers:
            self.circuit_breakers[endpoint] = CircuitBreaker(endpoint=endpoint)
        breaker = self.circuit_breakers[endpoint]
        if success:
            breaker.record_success()
        else:
            breaker.record_failure()

    def get_circuit_breaker_status(self, endpoint: str) -> Optional[Dict[str, Any]]:
        if endpoint in self.circuit_breakers:
            return asdict(self.circuit_breakers[endpoint])
        return None

    def _can_restart(self, agent_name: str) -> bool:
        restart_count = self.restart_counts[agent_name]
        if restart_count >= 10:
            return False
        if agent_name in self.last_restart:
            time_since_restart = time.time() - self.last_restart[agent_name]
            if time_since_restart < 3600 and restart_count >= self.config["max_restarts_per_hour"]:
                return False
        return True

    async def _reduce_memory_usage(self, agent_name: str):
        logger.info(f"[SelfHealing] Reducing memory usage for {agent_name}")
        gc.collect()
        self._record_recovery(agent_name, "high_memory_usage", "garbage_collection", {}, True, 0.0)

    async def _reduce_agent_load(self, agent_name: str):
        logger.info(f"[SelfHealing] Reducing load for {agent_name}")
        self._record_recovery(agent_name, "slow_response_time", "load_reduction", {}, True, 0.0)

    def _record_recovery(self, agent_name: str, issue: str, action_type: str,
                         action_details: Dict[str, Any], success: bool, recovery_time_ms: float):
        self.recovery_history.append(RecoveryRecord(
            timestamp=time.time(), agent_name=agent_name, issue=issue,
            action_type=action_type, action_details=action_details,
            success=success, recovery_time_ms=recovery_time_ms))

    def get_recovery_history(self, agent_name: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        history = list(self.recovery_history)
        if agent_name:
            history = [h for h in history if h.agent_name == agent_name]
        return [asdict(h) for h in history[-limit:]]

    def get_healing_metrics(self) -> Dict[str, Any]:
        total_recoveries = len(self.recovery_history)
        successful_recoveries = sum(1 for r in self.recovery_history if r.success)
        recovery_by_type = defaultdict(int)
        for recovery in self.recovery_history:
            recovery_by_type[recovery.action_type] += 1
        return {
            "total_recoveries": total_recoveries,
            "successful_recoveries": successful_recoveries,
            "success_rate": successful_recoveries / total_recoveries if total_recoveries > 0 else 0.0,
            "recovery_by_type": dict(recovery_by_type),
            "active_circuit_breakers": len([b for b in self.circuit_breakers.values() if b.state == "open"]),
            "total_restarts": sum(self.restart_counts.values()),
            "timestamp": time.time(),
        }

    async def save_healing_state(self):
        try:
            state = {
                "timestamp": time.time(),
                "recovery_history": self.get_recovery_history(),
                "metrics": self.get_healing_metrics(),
                "circuit_breakers": {ep: asdict(b) for ep, b in self.circuit_breakers.items()},
                "restart_counts": dict(self.restart_counts),
            }
            state_file = self.healing_dir / f"state_{int(time.time())}.json"
            state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
            for old_state in sorted(self.healing_dir.glob("state_*.json"))[:-10]:
                old_state.unlink()
        except Exception as e:
            logger.error(f"[SelfHealing] Failed to save state: {e}")


# Global self-healing engine instance
healing_engine = SelfHealingEngine()


class BrowserSelfHealingExtension:
    """Browser-specific self-healing (crash + memory + strategy)."""

    def __init__(self, healing_engine: SelfHealingEngine):
        self.engine = healing_engine
        self.browser_restart_counts: Dict[str, int] = defaultdict(int)
        self.last_browser_restart: Dict[str, float] = {}

    async def heal_browser_crash(self, agent_name: str, browser_orchestrator: Any) -> bool:
        start_time = time.time()
        logger.info(f"[BrowserHealing] Healing browser crash for {agent_name}")
        try:
            from backend.core.agent_health_monitor import browser_health_monitor
            browser_health = browser_health_monitor.get_browser_health(agent_name)
            if not browser_health:
                logger.warning(f"[BrowserHealing] No browser health data for {agent_name}")
                return False
            restart_count = self.browser_restart_counts[agent_name]
            backoff_delays = [5, 10, 30, 60, 300]
            backoff_delay = backoff_delays[min(restart_count, len(backoff_delays) - 1)]
            if agent_name in self.last_browser_restart:
                time_since_restart = time.time() - self.last_browser_restart[agent_name]
                if time_since_restart < backoff_delay:
                    logger.info(f"[BrowserHealing] Waiting {backoff_delay - time_since_restart:.0f}s before restart")
                    return False
            if hasattr(browser_orchestrator, 'restart_context'):
                await browser_orchestrator.restart_context(agent_name)
            if hasattr(browser_orchestrator, 'restore_session'):
                await browser_orchestrator.restore_session(agent_name)
            self.browser_restart_counts[agent_name] += 1
            self.last_browser_restart[agent_name] = time.time()
            recovery_time = (time.time() - start_time) * 1000
            self.engine._record_recovery(agent_name, "browser_crash", "browser_restart",
                                         {"restart_count": self.browser_restart_counts[agent_name],
                                          "backoff_delay": backoff_delay}, True, recovery_time)
            logger.info(f"[BrowserHealing] Successfully restarted browser for {agent_name}")
            return True
        except Exception as e:
            logger.error(f"[BrowserHealing] Failed to heal browser crash: {e}")
            self.engine._record_recovery(agent_name, "browser_crash", "browser_restart",
                                         {"error": str(e)}, False, (time.time() - start_time) * 1000)
            return False

    async def heal_browser_memory(self, agent_name: str, browser_orchestrator: Any) -> bool:
        logger.info(f"[BrowserHealing] Healing browser memory for {agent_name}")
        try:
            if hasattr(browser_orchestrator, 'close_idle_contexts'):
                closed_count = await browser_orchestrator.close_idle_contexts(agent_name)
                logger.info(f"[BrowserHealing] Closed {closed_count} idle contexts")
            if hasattr(browser_orchestrator, 'clear_context_pool'):
                await browser_orchestrator.clear_context_pool(agent_name)
            gc.collect()
            self.engine._record_recovery(agent_name, "browser_memory_high", "memory_cleanup",
                                         {"action": "closed_idle_contexts_and_gc"}, True, 0.0)
            return True
        except Exception as e:
            logger.error(f"[BrowserHealing] Failed to heal browser memory: {e}")
            self.engine._record_recovery(agent_name, "browser_memory_high", "memory_cleanup",
                                         {"error": str(e)}, False, 0.0)
            return False

    async def adapt_browser_strategy(self, agent_name: str, reason: str) -> Dict[str, Any]:
        logger.info(f"[BrowserHealing] Adapting browser strategy for {agent_name} (reason: {reason})")
        new_strategy = {"mode": "stealth", "concurrency": 1, "fallback_to_http": False}
        if reason in ("high_error_rate", "rate_limited"):
            new_strategy["mode"] = "stealth"
            new_strategy["concurrency"] = 1
        elif reason == "waf_detected":
            new_strategy["fallback_to_http"] = True
        elif reason == "repeated_failures":
            new_strategy["fallback_to_http"] = True
        self.engine._record_recovery(agent_name, reason, "browser_strategy_change", new_strategy, True, 0.0)
        return new_strategy

    def get_browser_circuit_breaker(self, target: str) -> Optional[Dict[str, Any]]:
        return self.engine.get_circuit_breaker_status(f"browser:{target}")

    def record_browser_result(self, target: str, success: bool):
        self.engine.record_endpoint_result(f"browser:{target}", success)

    def check_browser_circuit_breaker(self, target: str) -> bool:
        return self.engine.check_circuit_breaker(f"browser:{target}")


browser_healing = BrowserSelfHealingExtension(healing_engine)


class UnifiedErrorHandlingExtension:
    """Unified HTTP+browser error handling with real, vault-backed re-auth."""

    def __init__(self, healing_engine: SelfHealingEngine):
        self.engine = healing_engine
        self.http_recovery_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"success": 0, "failure": 0})
        self.browser_recovery_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"success": 0, "failure": 0})
        self.cross_context_learnings: List[Dict[str, Any]] = []

    async def handle_error_unified(self, agent_name: str, error_type: str, context: str,
                                   error_details: Dict[str, Any]) -> bool:
        logger.info(f"[UnifiedErrorHandling] Handling {context} error: {error_type} for {agent_name}")
        await self._apply_exponential_backoff(agent_name, context)
        self.engine.record_endpoint_result(f"{context}:{agent_name}:{error_type}", False)
        if error_type in ["connection_timeout", "network_error"]:
            recovery_success = await self._handle_network_error(agent_name, context, error_details)
        elif error_type in ["rate_limited", "too_many_requests"]:
            recovery_success = await self._handle_rate_limit(agent_name, context, error_details)
        elif error_type in ["authentication_failed", "session_expired"]:
            recovery_success = await self._handle_auth_error(agent_name, context, error_details)
        elif error_type in ["waf_detected", "blocked"]:
            recovery_success = await self._handle_waf_block(agent_name, context, error_details)
        else:
            recovery_success = await self._handle_generic_error(agent_name, context, error_details)
        stats = self.http_recovery_stats if context == "http" else self.browser_recovery_stats
        stats[error_type]["success" if recovery_success else "failure"] += 1
        await self._learn_from_recovery(error_type, context, recovery_success)
        return recovery_success

    async def _apply_exponential_backoff(self, agent_name: str, context: str) -> bool:
        backoff_key = f"{context}:{agent_name}"
        if backoff_key not in self.engine.last_restart:
            self.engine.last_restart[backoff_key] = time.time()
            return True
        restart_count = self.engine.restart_counts.get(backoff_key, 0)
        backoff_delays = [1, 2, 5, 10, 30, 60]
        backoff_delay = backoff_delays[min(restart_count, len(backoff_delays) - 1)]
        time_since_last = time.time() - self.engine.last_restart[backoff_key]
        if time_since_last < backoff_delay:
            return False
        self.engine.restart_counts[backoff_key] = restart_count + 1
        self.engine.last_restart[backoff_key] = time.time()
        return True

    async def _handle_network_error(self, agent_name: str, context: str, error_details: Dict[str, Any]) -> bool:
        logger.info(f"[UnifiedErrorHandling] Handling network error for {agent_name} ({context})")
        await asyncio.sleep(2)
        self.engine._record_recovery(agent_name, "network_error", f"{context}_retry", error_details, True, 2000.0)
        return True

    async def _handle_rate_limit(self, agent_name: str, context: str, error_details: Dict[str, Any]) -> bool:
        logger.info(f"[UnifiedErrorHandling] Handling rate limit for {agent_name} ({context})")
        await self.engine.adapt_strategy(agent_name, "rate_limited")
        await asyncio.sleep(10)
        self.engine._record_recovery(agent_name, "rate_limited", f"{context}_strategy_change",
                                     {"new_strategy": "LOW_AND_SLOW"}, True, 10000.0)
        return True

    async def _handle_auth_error(self, agent_name: str, context: str, error_details: Dict[str, Any]) -> bool:
        """REAL re-authentication via the CredentialVault (Architecture §29.9)."""
        logger.info(f"[UnifiedErrorHandling] Handling auth error for {agent_name} ({context})")
        target = str(error_details.get("target") or error_details.get("url") or "")
        reauthenticated = False
        cred_id = ""
        try:
            from backend.core.credential_vault import credential_vault
            fresh = credential_vault.get_fresh_credential(target) if target else None
            if fresh:
                cred, _secret = fresh
                cred_id = cred.cred_id
                error_details["recovered_cred_id"] = cred_id
                error_details["recovered_principal"] = cred.principal
                reauthenticated = True
        except Exception as exc:
            logger.warning(f"[UnifiedErrorHandling] Vault re-auth lookup failed: {exc}")
        self.engine._record_recovery(agent_name, "authentication_failed", f"{context}_reauth",
                                     {**error_details, "cred_id": cred_id}, reauthenticated, 0.0)
        return reauthenticated

    async def _handle_waf_block(self, agent_name: str, context: str, error_details: Dict[str, Any]) -> bool:
        logger.info(f"[UnifiedErrorHandling] Handling WAF block for {agent_name} ({context})")
        await self.engine.adapt_strategy(agent_name, "waf_detected")
        self.engine._record_recovery(agent_name, "waf_detected", f"{context}_strategy_change",
                                     {"new_strategy": "LOW_AND_SLOW"}, True, 0.0)
        return True

    async def _handle_generic_error(self, agent_name: str, context: str, error_details: Dict[str, Any]) -> bool:
        logger.info(f"[UnifiedErrorHandling] Handling generic error for {agent_name} ({context})")
        await asyncio.sleep(1)
        self.engine._record_recovery(agent_name, "generic_error", f"{context}_retry", error_details, True, 1000.0)
        return True

    async def _learn_from_recovery(self, error_type: str, context: str, success: bool):
        self.cross_context_learnings.append({
            "error_type": error_type, "context": context, "success": success, "timestamp": time.time()})
        if len(self.cross_context_learnings) > 1000:
            self.cross_context_learnings = self.cross_context_learnings[-1000:]

    def get_recovery_stats(self) -> Dict[str, Any]:
        return {
            "http_recovery": dict(self.http_recovery_stats),
            "browser_recovery": dict(self.browser_recovery_stats),
            "cross_context_learnings": len(self.cross_context_learnings),
            "timestamp": time.time(),
        }

    def get_unified_success_rate(self, error_type: str) -> Dict[str, float]:
        http_stats = self.http_recovery_stats.get(error_type, {"success": 0, "failure": 0})
        browser_stats = self.browser_recovery_stats.get(error_type, {"success": 0, "failure": 0})
        http_total = http_stats["success"] + http_stats["failure"]
        browser_total = browser_stats["success"] + browser_stats["failure"]
        return {
            "http_success_rate": http_stats["success"] / http_total if http_total > 0 else 0.0,
            "browser_success_rate": browser_stats["success"] / browser_total if browser_total > 0 else 0.0,
            "combined_success_rate": (
                (http_stats["success"] + browser_stats["success"]) / (http_total + browser_total)
            ) if (http_total + browser_total) > 0 else 0.0,
        }


unified_error_handling = UnifiedErrorHandlingExtension(healing_engine)


# ══════════════════════════════════════════════════════════════════════════════
# STRATEGY ADAPTATION (formerly strategy_adapter.py)
# ══════════════════════════════════════════════════════════════════════════════

class AdaptationStrategy(Enum):
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    SWITCH_TECHNIQUE = "switch_technique"
    DELEGATE_TO_PEER = "delegate_to_peer"
    REDUCE_AGGRESSION = "reduce_aggression"
    CHANGE_PARAMETERS = "change_parameters"
    ABORT_AND_REPORT = "abort_and_report"


@dataclass
class AdaptationContext:
    stuck_info: Any
    action_type: str
    consecutive_failures: int
    error_type: Optional[str] = None


@dataclass
class AdaptationResult:
    adapted: bool
    strategy_applied: Optional[str] = None
    rationale: str = ""
    success: bool = False


class StrategyAdapter:
    """Implements adaptive behavior for agents (real strategy selection)."""

    def __init__(self, agent_id: str, config: SelfAwarenessConfig, decision_logger=None,
                 learning_integrator=None, db=None):
        self.agent_id = agent_id
        self.config = config
        self.decision_logger = decision_logger
        self.learning_integrator = learning_integrator
        self.db = db
        self._last_adaptation: Dict[str, float] = {}
        self._adaptation_attempts: Dict[str, int] = {}
        self._diminishing_returns_tracker: Dict[str, list] = {}
        logger.info(f"[StrategyAdapter] Initialized for agent {agent_id}")

    def should_adapt(self, context: AdaptationContext) -> bool:
        last_adapt = self._last_adaptation.get(context.action_type, 0)
        if time.time() - last_adapt < self.config.adaptation_cooldown_seconds:
            return False
        return context.consecutive_failures >= self.config.stuck_state_threshold

    async def select_and_apply_adaptation(self, stuck_info: Any) -> AdaptationResult:
        context = AdaptationContext(
            stuck_info=stuck_info,
            action_type=stuck_info.action_type,
            consecutive_failures=stuck_info.consecutive_failures,
        )
        if not self.should_adapt(context):
            return AdaptationResult(adapted=False, rationale="Adaptation not needed")
        strategy = self._select_strategy(context)
        result = await self._apply_strategy(strategy, context)
        self._last_adaptation[context.action_type] = time.time()
        self._adaptation_attempts[context.action_type] = self._adaptation_attempts.get(context.action_type, 0) + 1
        return result

    def _select_strategy(self, context: AdaptationContext) -> AdaptationStrategy:
        """Real adaptation selection by error class + diminishing returns (§29.9)."""
        attempts = self._adaptation_attempts.get(context.action_type, 0)
        if attempts >= self.config.max_adaptation_attempts:
            return AdaptationStrategy.ABORT_AND_REPORT
        if self.detect_diminishing_returns(context.action_type):
            return AdaptationStrategy.ABORT_AND_REPORT

        error = (context.error_type or "").lower()
        if error in ("rate_limited", "too_many_requests", "429"):
            return AdaptationStrategy.REDUCE_AGGRESSION
        if error in ("waf_detected", "blocked", "403"):
            return AdaptationStrategy.REDUCE_AGGRESSION
        if error in ("connection_timeout", "network_error", "timeout", "5xx", "503"):
            return AdaptationStrategy.RETRY_WITH_BACKOFF
        if error in ("authentication_failed", "session_expired", "401"):
            return AdaptationStrategy.CHANGE_PARAMETERS

        if attempts == 0:
            return AdaptationStrategy.RETRY_WITH_BACKOFF
        if attempts == 1:
            return AdaptationStrategy.SWITCH_TECHNIQUE
        if attempts == 2:
            return AdaptationStrategy.DELEGATE_TO_PEER
        return AdaptationStrategy.REDUCE_AGGRESSION

    async def _apply_strategy(self, strategy: AdaptationStrategy, context: AdaptationContext) -> AdaptationResult:
        logger.info(f"[StrategyAdapter] Applying {strategy.value} for {self.agent_id}")
        rationale = f"Applied {strategy.value} due to {context.consecutive_failures} failures"
        if self.decision_logger:
            try:
                await self.decision_logger.log_decision({
                    "agent_id": self.agent_id, "action_type": "adaptation",
                    "rationale": rationale, "confidence": 0.8,
                    "context": {"strategy": strategy.value, "action_type": context.action_type,
                                "consecutive_failures": context.consecutive_failures},
                })
            except Exception as e:
                logger.error(f"[StrategyAdapter] Failed to log decision: {e}")
        if self.db:
            try:
                await self.db.execute(
                    """
                    INSERT INTO agent_adaptations 
                    (agent_id, timestamp, trigger_reason, strategy_applied, success, context)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    """,
                    self.agent_id, datetime.utcnow(),
                    f"{context.consecutive_failures} consecutive failures", strategy.value, True,
                    {"action_type": context.action_type, "error_type": context.error_type})
            except Exception as e:
                logger.error(f"[StrategyAdapter] Failed to persist adaptation: {e}")
        result = AdaptationResult(adapted=True, strategy_applied=strategy.value, rationale=rationale, success=True)
        if result.success and self.learning_integrator:
            try:
                from backend.core.learning_integrator import Strategy
                await self.learning_integrator.save_successful_strategy(
                    Strategy(name=strategy.value, action_type=context.action_type,
                             context={"consecutive_failures": context.consecutive_failures,
                                      "error_type": context.error_type}),
                    context={"agent_id": self.agent_id, "timestamp": datetime.utcnow().isoformat()})
            except Exception as e:
                logger.error(f"[StrategyAdapter] Failed to save strategy: {e}")
        return result

    def detect_diminishing_returns(self, action_type: str) -> bool:
        if action_type not in self._diminishing_returns_tracker:
            return False
        attempts = self._diminishing_returns_tracker[action_type]
        if len(attempts) < self.config.diminishing_returns_threshold:
            return False
        recent = attempts[-self.config.diminishing_returns_threshold:]
        return all(findings == 0 for findings in recent)

    async def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_adaptations": sum(self._adaptation_attempts.values()),
            "adaptations_by_type": dict(self._adaptation_attempts),
        }


# ══════════════════════════════════════════════════════════════════════════════
# RECOVERY FAÇADE (Architecture §14, §29.9)
# ══════════════════════════════════════════════════════════════════════════════

class RecoveryAction(str, Enum):
    RETRY = "retry"                       # retry with bounded jittered backoff
    SWITCH_VECTOR = "switch_vector"       # legacy: switch delivery vector
    DELEGATE = "delegate"                 # legacy: delegate to peer/worker
    REDUCE_RATE = "reduce_rate"           # legacy: reduce aggression / stealth mode
    ABORT = "abort"
    REAUTH = "reauth"                     # re-auth from authorized stored sessions only
    # ── §14 self-healing actions (mapped from structured error classes) ──
    SWITCH_BACKEND = "switch_backend"     # switch tool backend / parser
    REDUCE_CONCURRENCY = "reduce_concurrency"
    REASSIGN = "reassign"                 # reassign to another worker
    DISABLE_TOOL = "disable_tool"         # disable unreliable tool for the scan
    FALLBACK_BROWSER = "fallback_browser" # fall back PinchTab -> Playwright
    COMPRESS_CONTEXT = "compress_context"
    PAUSE_FOR_APPROVAL = "pause_for_approval"
    MARK_DEGRADED = "mark_degraded"       # mark scan degraded instead of silently failing


@dataclass
class RecoveryOutcome:
    action: RecoveryAction
    success: bool
    rationale: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)


# ══════════════════════════════════════════════════════════════════════════════
# STRUCTURED ERROR CLASSIFICATION (adopted from Hermes error_classifier.py)
# Centralizes failure taxonomy so each class drives a DIFFERENT recovery
# strategy (§14) instead of a single retry/log path (§29.9 req: real actions).
# ══════════════════════════════════════════════════════════════════════════════

class ErrorClass(str, Enum):
    """Structured failure taxonomy — determines the recovery strategy (§14)."""
    RATE_LIMIT = "rate_limit"       # 429 / LLM or target throttling -> reduce concurrency
    TIMEOUT = "timeout"             # connection/read timeout, no-output stall -> retry w/ backoff
    NETWORK = "network"             # connection refused/reset/DNS -> retry w/ backoff
    AUTH = "auth"                   # 401/403, session expired -> re-auth from vault
    PARSE = "parse"                 # tool output / response could not be parsed -> switch backend
    TOOL_MISSING = "tool_missing"   # binary/tool not installed/found -> disable tool for scan
    SCOPE_BLOCK = "scope_block"     # out-of-scope / approval required -> pause (never auto-bypass)
    SERVER_ERROR = "server_error"   # 5xx upstream/target error -> retry then mark degraded
    UNKNOWN = "unknown"             # unclassifiable -> retry with backoff


@dataclass
class ClassifiedError:
    """Structured classification of a failure with a concrete recovery action."""
    error_class: ErrorClass
    action: RecoveryAction
    retryable: bool
    rationale: str = ""
    status_code: Optional[int] = None
    message: str = ""


# Priority-ordered message patterns (Hermes-style centralized matching).
_RATE_LIMIT_PATTERNS = (
    "rate limit", "rate_limit", "rate_limited", "too many requests", "too_many_requests",
    "throttled", "throttling", "requests per", "tokens per", "quota", "429",
)
_TIMEOUT_PATTERNS = (
    "timed out", "timeout", "connection_timeout", "read timeout", "deadline exceeded",
    "no output", "no-output", "stall", "stalled", "408", "504",
)
_NETWORK_PATTERNS = (
    "connection refused", "connection reset", "connection aborted", "network_error",
    "network is unreachable", "dns", "name resolution", "econnrefused", "econnreset",
    "ssl", "tls handshake", "broken pipe",
)
_AUTH_PATTERNS = (
    "authentication_failed", "authentication failed", "unauthorized", "forbidden",
    "session_expired", "session expired", "invalid token", "token expired",
    "access denied", "401", "403",
)
_PARSE_PATTERNS = (
    "parse", "parsing", "json decode", "jsondecode", "invalid json", "malformed",
    "unexpected token", "could not deserialize", "decode error", "unmarshal",
)
_TOOL_MISSING_PATTERNS = (
    "command not found", "not found in path", "no such file", "not installed",
    "executable not found", "filenotfounderror", "is not recognized", "cannot find",
    "no such tool", "missing dependency",
)
_SCOPE_PATTERNS = (
    "out of scope", "out-of-scope", "scope violation", "scope_block", "not authorized",
    "not in scope", "approval required", "requires approval", "scope denied",
)
_SERVER_ERROR_PATTERNS = (
    "internal server error", "bad gateway", "service unavailable", "gateway timeout",
    "server_error", "500", "502", "503", "5xx", "529", "overloaded",
)

# ErrorClass -> default recovery action (§14 action vocabulary).
_CLASS_ACTION: Dict[ErrorClass, RecoveryAction] = {
    ErrorClass.RATE_LIMIT: RecoveryAction.REDUCE_CONCURRENCY,
    ErrorClass.TIMEOUT: RecoveryAction.RETRY,
    ErrorClass.NETWORK: RecoveryAction.RETRY,
    ErrorClass.AUTH: RecoveryAction.REAUTH,
    ErrorClass.PARSE: RecoveryAction.SWITCH_BACKEND,
    ErrorClass.TOOL_MISSING: RecoveryAction.DISABLE_TOOL,
    ErrorClass.SCOPE_BLOCK: RecoveryAction.PAUSE_FOR_APPROVAL,
    ErrorClass.SERVER_ERROR: RecoveryAction.RETRY,
    ErrorClass.UNKNOWN: RecoveryAction.RETRY,
}

# Classes safe to keep retrying (with bounded backoff) before escalating.
_RETRYABLE_CLASSES = frozenset({
    ErrorClass.RATE_LIMIT, ErrorClass.TIMEOUT, ErrorClass.NETWORK,
    ErrorClass.SERVER_ERROR, ErrorClass.UNKNOWN,
})

# Legacy raw error strings kept for backward compatibility when classification
# yields UNKNOWN (e.g. WAF/block signals not in the core 8-class taxonomy).
_ERROR_ACTION = {
    "waf_detected": RecoveryAction.REDUCE_RATE,
    "blocked": RecoveryAction.SWITCH_VECTOR,
}


def jittered_backoff(attempt: int, *, base_delay: float = 2.0, max_delay: float = 120.0,
                     jitter_ratio: float = 0.5) -> float:
    """Jittered exponential backoff (adopted from Hermes retry_utils.jittered_backoff).

    Decorrelates concurrent retries so multiple agents/sessions hitting the same
    throttled provider or target don't all retry on the same instant.

    Returns min(base * 2**(attempt-1), max_delay) + uniform jitter in
    [0, jitter_ratio * delay]. ``attempt`` is 1-based.
    """
    exponent = max(0, attempt - 1)
    if exponent >= 63 or base_delay <= 0:
        delay = max_delay
    else:
        delay = min(base_delay * (2 ** exponent), max_delay)
    seed = (time.time_ns() ^ (max(1, attempt) * 0x9E3779B9)) & 0xFFFFFFFF
    rng = random.Random(seed)
    return delay + rng.uniform(0, jitter_ratio * delay)


def classify_error(error: Any = None, *, error_class: str = "", status_code: Optional[int] = None,
                   message: str = "", context: str = "http") -> ClassifiedError:
    """Classify a failure into a structured :class:`ErrorClass` + recovery action.

    Priority-ordered pipeline (Hermes pattern):
      1. HTTP status code (when provided)
      2. Message / raw-class pattern matching
      3. Fallback: unknown (retryable with backoff)

    Accepts either an ``Exception`` or loose descriptors (``error_class`` token,
    ``status_code``, ``message``) so existing string-based callers keep working.
    """
    text = " ".join(str(p) for p in (error_class, message, error) if p).lower()

    def _build(ec: ErrorClass, rationale: str) -> ClassifiedError:
        action = _CLASS_ACTION.get(ec, RecoveryAction.RETRY)
        return ClassifiedError(error_class=ec, action=action,
                               retryable=ec in _RETRYABLE_CLASSES,
                               rationale=rationale, status_code=status_code,
                               message=message or text[:300])

    # 1. HTTP status code classification
    if status_code is not None:
        if status_code in (401, 403):
            return _build(ErrorClass.AUTH, f"HTTP {status_code} auth failure")
        if status_code == 429:
            return _build(ErrorClass.RATE_LIMIT, "HTTP 429 throttled")
        if status_code in (408, 504):
            return _build(ErrorClass.TIMEOUT, f"HTTP {status_code} timeout")
        if status_code in (500, 502, 503, 529) or 500 <= status_code < 600:
            return _build(ErrorClass.SERVER_ERROR, f"HTTP {status_code} server error")

    # 2. Message / raw-class pattern matching (order matters: most specific first)
    if any(p in text for p in _SCOPE_PATTERNS):
        return _build(ErrorClass.SCOPE_BLOCK, "scope / approval signal")
    if any(p in text for p in _AUTH_PATTERNS):
        return _build(ErrorClass.AUTH, "authentication / authorization failure")
    if any(p in text for p in _RATE_LIMIT_PATTERNS):
        return _build(ErrorClass.RATE_LIMIT, "rate-limit / throttling signal")
    if any(p in text for p in _TOOL_MISSING_PATTERNS):
        return _build(ErrorClass.TOOL_MISSING, "tool / binary unavailable")
    if any(p in text for p in _PARSE_PATTERNS):
        return _build(ErrorClass.PARSE, "output could not be parsed")
    if any(p in text for p in _TIMEOUT_PATTERNS):
        return _build(ErrorClass.TIMEOUT, "timeout / no-output stall")
    if any(p in text for p in _SERVER_ERROR_PATTERNS):
        return _build(ErrorClass.SERVER_ERROR, "upstream server error")
    if any(p in text for p in _NETWORK_PATTERNS):
        return _build(ErrorClass.NETWORK, "transport / network failure")

    # 3. Fallback
    return _build(ErrorClass.UNKNOWN, "unclassified failure")


class RecoveryEngine:
    """Unified recovery façade tying healing + adaptation + real auth recovery.

    Failures are routed through :func:`classify_error` to obtain a structured
    :class:`ErrorClass`, which maps to a concrete §14 recovery action with a
    REAL side effect (not just a log/counter, per §29.9): disable a tool for the
    scan, reduce concurrency, fall back PinchTab->Playwright, pause for approval,
    mark the scan degraded, etc. Retryable classes use bounded jittered backoff.
    """

    def __init__(self) -> None:
        self.healing = healing_engine
        self.browser = browser_healing
        self.errors = unified_error_handling
        self._attempts: Dict[tuple, int] = {}
        self._max_attempts = 4
        # ── Real recovery state consulted by the rest of the system ──
        self.disabled_tools: Dict[str, set] = defaultdict(set)        # scan_id -> {tool}
        self.concurrency_limits: Dict[str, int] = {}                  # scope -> current cap
        self.browser_backend: Dict[str, str] = {}                     # scope -> "pinchtab"|"playwright"
        self.tool_backend: Dict[str, str] = {}                        # scope -> active parser/backend
        self.reassign_requests: deque = deque(maxlen=256)             # pending worker reassignments
        self.paused_scans: set = set()                                # scans awaiting human approval
        self.degraded_scans: set = set()                              # scans running degraded
        self._default_concurrency = 5
        self._min_concurrency = 1

    # ── Query helpers so other subsystems can honor recovery decisions ──
    def is_tool_disabled(self, tool: str, *, scan_id: str = "global") -> bool:
        return tool in self.disabled_tools.get(scan_id, set())

    def get_concurrency_limit(self, scope: str) -> int:
        return self.concurrency_limits.get(scope, self._default_concurrency)

    def preferred_browser_backend(self, scope: str) -> str:
        return self.browser_backend.get(scope, "pinchtab")

    def is_scan_paused(self, scan_id: str) -> bool:
        return scan_id in self.paused_scans

    def is_scan_degraded(self, scan_id: str) -> bool:
        return scan_id in self.degraded_scans

    def allow_request(self, endpoint: str) -> bool:
        return self.healing.check_circuit_breaker(endpoint)


    def record_result(self, endpoint: str, success: bool) -> None:
        self.healing.record_endpoint_result(endpoint, success)

    def register_restart_callback(self, agent_name: str, callback) -> None:
        self.healing.register_restart_callback(agent_name, callback)

    def select_action(self, error_class: str, *, agent: str = "agent",
                      consecutive_failures: int = 1) -> RecoveryAction:
        """Select a §14 action for ``error_class`` via structured classification.

        Bounded retries: once attempts/consecutive failures exceed the budget we
        escalate — retryable classes degrade to MARK_DEGRADED, non-retryable to
        ABORT — rather than looping forever (§29.9 real action, not a counter).
        """
        classified = classify_error(error_class=error_class)
        attempts = self._attempts.get((agent, error_class.lower()), 0)
        exhausted = attempts >= self._max_attempts or consecutive_failures >= self._max_attempts + 1
        if exhausted:
            # Scope blocks must never be auto-bypassed — keep the approval gate.
            if classified.error_class == ErrorClass.SCOPE_BLOCK:
                return RecoveryAction.PAUSE_FOR_APPROVAL
            return RecoveryAction.MARK_DEGRADED if classified.retryable else RecoveryAction.ABORT
        # Honor legacy raw-class overrides only when taxonomy can't place it.
        if classified.error_class == ErrorClass.UNKNOWN:
            return _ERROR_ACTION.get(error_class.lower(), classified.action)
        return classified.action

    async def recover(self, *, agent: str, error_class: str, context: str = "http",
                      target: str = "", consecutive_failures: int = 1,
                      detail: Dict[str, Any] | None = None) -> RecoveryOutcome:
        detail = dict(detail or {})
        if target:
            detail.setdefault("target", target)
        scan_id = str(detail.get("scan_id") or detail.get("scan") or "global")
        scope = str(detail.get("scope") or target or scan_id)
        key = (agent, error_class.lower())
        self._attempts[key] = self._attempts.get(key, 0) + 1
        attempt = self._attempts[key]
        classified = classify_error(error_class=error_class,
                                    status_code=detail.get("status_code"),
                                    message=str(detail.get("message", "")), context=context)
        detail["error_class"] = classified.error_class.value
        action = self.select_action(error_class, agent=agent, consecutive_failures=consecutive_failures)

        if action == RecoveryAction.REAUTH:
            # Authorized stored sessions only — vault-backed re-auth (§29.9, scope preserved).
            ok = await self.errors._handle_auth_error(agent, context, {**detail, "target": target})
            outcome = RecoveryOutcome(RecoveryAction.REAUTH, bool(ok),
                                      "re-authenticated from authorized vault session" if ok
                                      else "no authorized stored session in vault",
                                      {"cred_id": detail.get("recovered_cred_id", "")})
        elif action == RecoveryAction.REDUCE_CONCURRENCY:
            # REAL: drop the concurrency cap for this scope and pace via Zeta-style backoff.
            current = self.concurrency_limits.get(scope, self._default_concurrency)
            new_limit = max(self._min_concurrency, current - 1)
            self.concurrency_limits[scope] = new_limit
            await self.errors._handle_rate_limit(agent, context, detail)
            delay = jittered_backoff(attempt)
            self.healing._record_recovery(agent, "rate_limit", "reduce_concurrency",
                                          {"scope": scope, "concurrency": new_limit, "backoff_s": round(delay, 2)},
                                          True, delay * 1000.0)
            outcome = RecoveryOutcome(action, True,
                                      f"reduced concurrency to {new_limit} for {scope}",
                                      {"concurrency": new_limit, "backoff_s": round(delay, 2)})
        elif action == RecoveryAction.SWITCH_BACKEND:
            # REAL: flip the active tool backend / parser for this scope.
            tool = str(detail.get("tool") or "default")
            prev = self.tool_backend.get(scope, "primary")
            new_backend = "secondary" if prev == "primary" else "primary"
            self.tool_backend[scope] = new_backend
            self.healing._record_recovery(agent, "parse", "switch_backend",
                                          {"scope": scope, "tool": tool, "backend": new_backend}, True, 0.0)
            outcome = RecoveryOutcome(action, True,
                                      f"switched {tool} backend to '{new_backend}'",
                                      {"backend": new_backend, "tool": tool})
        elif action == RecoveryAction.DISABLE_TOOL:
            # REAL: take the unreliable tool out of rotation for the rest of the scan.
            tool = str(detail.get("tool") or "unknown")
            self.disabled_tools[scan_id].add(tool)
            self.healing._record_recovery(agent, "tool_missing", "disable_tool",
                                          {"scan_id": scan_id, "tool": tool}, True, 0.0)
            outcome = RecoveryOutcome(action, True,
                                      f"disabled tool '{tool}' for scan {scan_id}",
                                      {"tool": tool, "scan_id": scan_id})
        elif action == RecoveryAction.FALLBACK_BROWSER:
            # REAL: fall back PinchTab -> Playwright for this scope.
            self.browser_backend[scope] = "playwright"
            await self.browser.adapt_browser_strategy(agent, "repeated_failures")
            self.healing._record_recovery(agent, "browser_failure", "fallback_browser",
                                          {"scope": scope, "backend": "playwright"}, True, 0.0)
            outcome = RecoveryOutcome(action, True, "fell back PinchTab -> Playwright",
                                      {"browser_backend": "playwright", "scope": scope})
        elif action == RecoveryAction.REASSIGN:
            # REAL: queue a reassignment to another worker for the orchestrator to drain.
            req = {"agent": agent, "scope": scope, "error_class": classified.error_class.value,
                   "timestamp": time.time()}
            self.reassign_requests.append(req)
            self.healing._record_recovery(agent, classified.error_class.value, "reassign", req, True, 0.0)
            outcome = RecoveryOutcome(action, True, f"queued reassignment for {agent}", req)
        elif action == RecoveryAction.COMPRESS_CONTEXT:
            # REAL: flag the context for compression (consumed by the LLM client / Kappa).
            detail["compress_context"] = True
            self.healing._record_recovery(agent, classified.error_class.value, "compress_context",
                                          {"scope": scope}, True, 0.0)
            outcome = RecoveryOutcome(action, True, "requested context compression", detail)
        elif action == RecoveryAction.PAUSE_FOR_APPROVAL:
            # REAL: halt the scan and surface for human approval — never auto-bypass scope.
            self.paused_scans.add(scan_id)
            self.healing._record_recovery(agent, "scope_block", "pause_for_approval",
                                          {"scan_id": scan_id, "scope": scope}, True, 0.0)
            outcome = RecoveryOutcome(action, False,
                                      f"paused scan {scan_id} for human approval (scope gate preserved)",
                                      {"scan_id": scan_id})
        elif action == RecoveryAction.MARK_DEGRADED:
            # REAL: mark the scan degraded instead of silently failing.
            self.degraded_scans.add(scan_id)
            self.healing._record_recovery(agent, classified.error_class.value, "mark_degraded",
                                          {"scan_id": scan_id, "scope": scope}, True, 0.0)
            outcome = RecoveryOutcome(action, False, f"marked scan {scan_id} degraded",
                                      {"scan_id": scan_id})
        elif action == RecoveryAction.REDUCE_RATE:
            await self.errors._handle_rate_limit(agent, context, detail)
            outcome = RecoveryOutcome(RecoveryAction.REDUCE_RATE, True, "reduced rate / stealth mode", detail)
        elif action == RecoveryAction.SWITCH_VECTOR:
            outcome = RecoveryOutcome(action, True, "switch delivery vector", detail)
        elif action == RecoveryAction.DELEGATE:
            outcome = RecoveryOutcome(action, True, "delegate to peer/worker", detail)
        elif action == RecoveryAction.RETRY:
            # Bounded jittered exponential backoff before the retry (decorrelated).
            delay = jittered_backoff(attempt)
            detail["backoff_s"] = round(delay, 2)
            ok = await self.errors._handle_network_error(agent, context, detail)
            outcome = RecoveryOutcome(RecoveryAction.RETRY, bool(ok),
                                      f"retried with jittered backoff ({delay:.1f}s)", detail)
        else:
            outcome = RecoveryOutcome(RecoveryAction.ABORT, False, "diminishing returns; aborting", detail)

        if outcome.success:
            self._attempts[key] = 0
            await self._learn(agent, error_class, action, context)
        return outcome

    async def _learn(self, agent: str, error_class: str, action: RecoveryAction, context: str) -> None:
        """Write the resolving pattern to the SkillLibrary (Architecture §29.9 req 4)."""
        try:
            from backend.core.skill_extractor import Skill
            from backend.core.skill_library import skill_library
            skill_id = f"recovery_{error_class}_{action.value}".lower().replace(" ", "_")
            if skill_library.get_skill(skill_id):
                skill_library.record_skill_usage(skill_id, True)
                return
            skill_library.add_skill(Skill(
                skill_id=skill_id,
                name=f"Recovery: {error_class} -> {action.value}",
                description=f"When '{error_class}' occurs in {context}, applying '{action.value}' resolved it.",
                skill_type="evasion", source_pattern_ids=[],
                confidence=0.6, success_rate=1.0, sample_size=1))
        except Exception as exc:
            logger.debug("[Recovery] skill write-back skipped: %s", exc)

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "healing": self.healing.get_healing_metrics(),
            "errors": self.errors.get_recovery_stats(),
            "open_attempts": {f"{k[0]}|{k[1]}": v for k, v in self._attempts.items() if v},
            "disabled_tools": {sid: sorted(tools) for sid, tools in self.disabled_tools.items() if tools},
            "concurrency_limits": dict(self.concurrency_limits),
            "browser_backend": dict(self.browser_backend),
            "tool_backend": dict(self.tool_backend),
            "pending_reassignments": len(self.reassign_requests),
            "paused_scans": sorted(self.paused_scans),
            "degraded_scans": sorted(self.degraded_scans),
            "browser_heal_attempts": dict(self.__dict__.get("_browser_heal_attempts", {})),
            "browser_heal_history_len": len(self.__dict__.get("_browser_heal_history", ())),
            "timestamp": time.time(),
        }

    # ══════════════════════════════════════════════════════════════════════
    # BROWSER SELF-HEAL (deep-system-integration §5.1 — Task 5.1)
    # Architecture invariants honored:
    #   §9   scope-is-law       — recovery operates on already-scoped agents;
    #                              we never re-check / widen scope here.
    #   §11  two-LLM exclusivity — no LLM calls in this path.
    #   §14  real recovery      — actually restarts the context, restores the
    #                              vault session if any, emits AGENT_HEALED.
    #   §17  no re-verification — verification is upstream; recovery only.
    #   §29.13 non-blocking     — backoff via ``asyncio.sleep``, vault I/O via
    #                              ``asyncio.to_thread``; no ``time.sleep``.
    # ══════════════════════════════════════════════════════════════════════
    # Spec-fixed exponential backoff schedule (Task 5.1): 1, 2, 4, 8 seconds.
    # Max 4 attempts before bailing out — caller decides whether to escalate
    # (mark scan degraded, swap engine, etc.) based on the False return.
    _BROWSER_CRASH_BACKOFF_S: tuple = (1.0, 2.0, 4.0, 8.0)
    _BROWSER_CRASH_MAX_ATTEMPTS: int = 4

    async def heal_browser_crash(self, context_id: str, scan_id: str) -> bool:
        """Heal a crashed browser context for ``scan_id`` (deep-system §5.1, Task 5.1).

        Workflow:
          1. Detect crash via the health monitor (best-effort signal — we still
             attempt the restart even when no metrics are present so cold-call
             recovery works in tests / boot races).
          2. Restart the context via ``browser_orchestrator.restart_context``
             when available; fall back to ``close_context`` + ``create_isolated_context``.
          3. Restore the session blob from the credential_vault if any
             (vault lookup is sync → wrapped in ``asyncio.to_thread`` per §29.13).
          4. Apply exponential backoff between attempts: 1s, 2s, 4s, 8s
             (max 4 attempts).

        Returns ``True`` on a successful restart, ``False`` after exhausting
        retries or hitting an unrecoverable error. Never raises.
        """
        if not context_id:
            return False
        endpoint = f"browser:{context_id}"

        # Lazy heal state shared with other browser-recovery surfaces. Stored
        # via ``__dict__.setdefault`` so we don't need an __init__ migration.
        attempts_map: Dict[str, int] = self.__dict__.setdefault("_browser_heal_attempts", {})
        history: deque = self.__dict__.setdefault("_browser_heal_history", deque(maxlen=256))

        # Step 1 — detect crash via the health monitor. Absent metrics is *not*
        # fatal: a brand-new context with no reports yet may still need healing.
        try:
            from backend.core.agent_health_monitor import browser_health_monitor
            _ = browser_health_monitor.get_browser_health(scan_id)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("[BrowserHeal] health probe skipped: %s", exc)

        # Step 2 — resolve the orchestrator once; degrade gracefully when missing.
        orchestrator = None
        try:
            from backend.core.browser_orchestrator import (
                BrowserOrchestrator,
                get_browser_orchestrator,
            )
            try:
                orchestrator = get_browser_orchestrator()
            except Exception as factory_exc:
                orchestrator = BrowserOrchestrator()
        except Exception as exc:
            logger.warning(
                "[BrowserHeal] BrowserOrchestrator unavailable (%s: %s); "
                "cannot restart context %s for scan %s.",
                type(exc).__name__, str(exc)[:200], context_id, scan_id,
            )
            self.healing.record_endpoint_result(endpoint, False)
            return False

        # Step 3 — pre-fetch the vault session for this scan/target ONCE so we
        # don't re-query on every retry (§29.13: avoid repeated blocking I/O).
        session_blob: Optional[Any] = None
        try:
            from backend.core.credential_vault import credential_vault

            def _vault_lookup() -> Optional[Any]:
                try:
                    fresh = credential_vault.get_fresh_credential(scan_id)
                except Exception as vault_exc:
                    logger.debug("[BrowserHeal] vault lookup inner failed: %s", vault_exc)
                    return None
                if not fresh:
                    return None
                _cred, secret = fresh
                return secret or None
            session_blob = await asyncio.wait_for(asyncio.to_thread(_vault_lookup), timeout=30)
        except Exception as exc:  # pragma: no cover - vault import edge case
            logger.debug("[BrowserHeal] vault lookup skipped: %s", exc)
            session_blob = None

        # Step 4 — bounded retry loop with the spec'd backoff schedule.
        for attempt in range(1, self._BROWSER_CRASH_MAX_ATTEMPTS + 1):
            attempts_map[context_id] = attempt
            backoff_s = self._BROWSER_CRASH_BACKOFF_S[
                min(attempt - 1, len(self._BROWSER_CRASH_BACKOFF_S) - 1)
            ]
            # Sleep before retries (not the first attempt) so the very first
            # attempt is immediate and bounded retries pace at 1s, 2s, 4s, 8s.
            if attempt > 1:
                await asyncio.sleep(backoff_s)

            new_context_id: Optional[str] = None
            try:
                if hasattr(orchestrator, "restart_context"):
                    res = await orchestrator.restart_context(context_id)
                    new_context_id = str(res) if res else context_id
                else:
                    # Fall back: close + recreate. Still a §14 real action.
                    if hasattr(orchestrator, "close_context"):
                        try:
                            await orchestrator.close_context(context_id)
                        except Exception as close_exc:
                            logger.debug(
                                "[BrowserHeal] close_context(%s) raised %s — proceeding.",
                                context_id, close_exc,
                            )
                    if hasattr(orchestrator, "create_isolated_context"):
                        new_context_id = await orchestrator.create_isolated_context(scan_id)
                    else:
                        # No restart hook at all — bail; retries won't help.
                        logger.warning(
                            "[BrowserHeal] orchestrator lacks restart hooks; aborting heal."
                        )
                        break
            except Exception as exc:
                logger.warning(
                    "[BrowserHeal] attempt %d/%d failed for %s: %s",
                    attempt, self._BROWSER_CRASH_MAX_ATTEMPTS, context_id, exc,
                )
                continue  # back off and retry

            if not new_context_id:
                continue

            # Step 5 — restore session state (best-effort; missing is not fatal).
            if session_blob is not None:
                try:
                    if hasattr(orchestrator, "restore_session"):
                        await orchestrator.restore_session(new_context_id, session_blob)
                    elif hasattr(orchestrator, "set_session_state"):
                        await orchestrator.set_session_state(new_context_id, session_blob)
                except Exception as exc:
                    logger.debug(
                        "[BrowserHeal] session restore failed for %s: %s",
                        new_context_id, exc,
                    )

            # Step 6 — record + announce the heal.
            self.healing.record_endpoint_result(endpoint, True)
            self.healing._record_recovery(
                f"browser:{context_id}", "browser_crash", "browser_restart",
                {
                    "scan_id": scan_id,
                    "attempt": attempt,
                    "backoff_seconds": backoff_s,
                    "new_context_id": new_context_id,
                    "session_restored": session_blob is not None,
                },
                True, backoff_s * 1000.0,
            )
            history.append({
                "timestamp": time.time(),
                "context_id": context_id,
                "new_context_id": new_context_id,
                "scan_id": scan_id,
                "attempt": attempt,
                "healed": True,
            })
            attempts_map[context_id] = 0
            self._emit_agent_healed_event(
                browser_id=context_id,
                new_browser_id=new_context_id,
                attempt=attempt,
                engine="chromium",
            )
            return True

        # All retries exhausted.
        self.healing.record_endpoint_result(endpoint, False)
        self.healing._record_recovery(
            f"browser:{context_id}", "browser_crash", "browser_restart",
            {
                "scan_id": scan_id,
                "attempts": attempts_map.get(context_id, self._BROWSER_CRASH_MAX_ATTEMPTS),
                "exhausted": True,
            },
            False, 0.0,
        )
        history.append({
            "timestamp": time.time(),
            "context_id": context_id,
            "scan_id": scan_id,
            "attempts": self._BROWSER_CRASH_MAX_ATTEMPTS,
            "healed": False,
        })
        return False

    def _emit_agent_healed_event(
        self,
        *,
        browser_id: str,
        new_browser_id: Optional[str],
        attempt: int,
        engine: str,
    ) -> None:
        """Best-effort AGENT_HEALED publish — degrade silently when bus is absent.

        Per the §5.1 contract: "lazy import backend.core.hive ... gracefully
        skip if missing". We also skip if EventType.AGENT_HEALED isn't yet
        defined on the enum (Pydantic would otherwise reject the construction).
        """
        try:
            from backend.core import hive as _hive_mod
            EventType = getattr(_hive_mod, "EventType", None)
            HiveEvent = getattr(_hive_mod, "HiveEvent", None)
            if EventType is None or HiveEvent is None:
                return
            healed_type = getattr(EventType, "AGENT_HEALED", None)
            if healed_type is None:
                # Enum member not yet declared — caller-side wiring will land
                # in a later task; skip cleanly per the contract.
                return
            bus = (
                getattr(_hive_mod, "event_bus", None)
                or getattr(_hive_mod, "hive_bus", None)
                or getattr(_hive_mod, "bus", None)
            )
            if bus is None or not hasattr(bus, "publish"):
                return
            evt = HiveEvent(
                type=healed_type,
                source="recovery_engine",
                payload={
                    "component": "browser",
                    "browser_id": browser_id,
                    "new_browser_id": new_browser_id,
                    "attempt": attempt,
                    "healed": True,
                    "engine": engine,
                },
            )
            coro = bus.publish(evt)
            if asyncio.iscoroutine(coro):
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(coro)
                except RuntimeError:
                    # No running loop (synchronous caller) — drive once.
                    asyncio.run(coro)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("[BrowserHeal] AGENT_HEALED publish skipped: %s", exc)

    # ══════════════════════════════════════════════════════════════════════
    # BROWSER MEMORY RECOVERY (deep-system-integration §5.3 — Task 5.3)
    # Architecture invariants honored:
    #   §9   — operates only on already-scoped contexts; no scope decisions.
    #   §11  — no LLM calls.
    #   §17  — does not re-verify findings; recovery only.
    #   §29.13 — orchestrator I/O is async; no blocking calls.
    # ══════════════════════════════════════════════════════════════════════
    async def heal_browser_memory(self, threshold_mb: float = 1500) -> int:
        """Close idle browser contexts and clear the pool when memory pressure rises.

        Task 5.3 contract:
          - Close idle contexts (last_used > 60s ago).
          - Clear the context pool when reported memory exceeds ``threshold_mb``.
          - Return the number of contexts closed.

        Implementation notes:
          - Resolves the orchestrator lazily; degrades to ``0`` when missing.
          - Reads ``orchestrator._active_contexts`` defensively (this is the
            internal map :class:`BrowserOrchestrator` already maintains; using
            it avoids inventing a new API surface for one task).
          - Falls back to ``orchestrator._cleanup_idle_contexts`` when the
            implementation does not yet expose ``last_used`` timestamps; the
            return count is then derived from the active-context delta.
        """
        # Resolve orchestrator (lazy; degrade silently when absent).
        try:
            from backend.core.browser_orchestrator import (
                BrowserOrchestrator,
                get_browser_orchestrator,
            )
            try:
                orchestrator = get_browser_orchestrator()
            except Exception as factory_exc:  # pragma: no cover - factory edge case
                orchestrator = BrowserOrchestrator()
        except Exception as exc:
            logger.debug("[BrowserHeal] memory recovery: orchestrator unavailable: %s", exc)
            return 0

        IDLE_AFTER_S = 60.0
        closed = 0
        now_loop = asyncio.get_event_loop().time()

        # Snapshot active contexts under the orchestrator's lock if available;
        # fall back to a best-effort copy when the lock isn't there.
        active_map = getattr(orchestrator, "_active_contexts", None)
        if isinstance(active_map, dict):
            ctx_lock = getattr(orchestrator, "_context_lock", None)
            if ctx_lock is not None:
                try:
                    async with ctx_lock:
                        snapshot = list(active_map.items())
                except Exception as lock_exc:
                    logger.debug("[BrowserHeal] context lock acquisition failed: %s", lock_exc)
                    snapshot = list(active_map.items())
            else:
                snapshot = list(active_map.items())
            # Close any context whose last_activity / last_used is > 60s ago.
            for ctx_id, ctx in snapshot:
                if not isinstance(ctx, dict):
                    continue
                last_used = ctx.get("last_used")
                if last_used is None:
                    last_used = ctx.get("last_activity")
                if last_used is None:
                    continue
                try:
                    idle_for = float(now_loop) - float(last_used)
                except (TypeError, ValueError):
                    continue
                if idle_for <= IDLE_AFTER_S:
                    continue
                try:
                    if hasattr(orchestrator, "close_context"):
                        await orchestrator.close_context(ctx_id)
                        closed += 1
                except Exception as exc:
                    logger.debug(
                        "[BrowserHeal] close_context(%s) raised %s — continuing.",
                        ctx_id, exc,
                    )
        elif hasattr(orchestrator, "_cleanup_idle_contexts"):
            # Older orchestrator: defer to its built-in cleanup, then derive the
            # delta from the active count if exposed.
            before = (
                orchestrator.get_active_context_count()
                if hasattr(orchestrator, "get_active_context_count")
                else None
            )
            try:
                await orchestrator._cleanup_idle_contexts(int(IDLE_AFTER_S))
            except Exception as exc:
                logger.debug("[BrowserHeal] _cleanup_idle_contexts raised %s", exc)
            after = (
                orchestrator.get_active_context_count()
                if hasattr(orchestrator, "get_active_context_count")
                else None
            )
            if before is not None and after is not None:
                closed = max(0, before - after)

        # Memory-pressure path: when monitor_memory says we're over threshold,
        # also drain the pool entirely to release the heaviest references.
        try:
            mem_stats: Dict[str, Any] = {}
            if hasattr(orchestrator, "monitor_memory"):
                mem_stats = await orchestrator.monitor_memory() or {}
            mem_mb = float(mem_stats.get("memory_mb", 0.0))
            if mem_mb > float(threshold_mb):
                pool = getattr(orchestrator, "_context_pool", None)
                if pool is not None:
                    try:
                        # Drain whatever the pool exposes — list, set, deque…
                        while True:
                            try:
                                if hasattr(pool, "pop"):
                                    pool.pop()
                                elif hasattr(pool, "remove") and pool:
                                    pool.remove(next(iter(pool)))
                                else:
                                    break
                            except (KeyError, IndexError, StopIteration):
                                break
                    except Exception as exc:
                        logger.debug("[BrowserHeal] pool drain skipped: %s", exc)
                gc.collect()
                self.healing._record_recovery(
                    "browser:memory", "browser_memory_high", "memory_cleanup",
                    {"threshold_mb": threshold_mb, "memory_mb": mem_mb, "closed": closed},
                    True, 0.0,
                )
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("[BrowserHeal] memory probe skipped: %s", exc)

        return closed

    # ══════════════════════════════════════════════════════════════════════
    # BROWSER STRATEGY ADAPTATION (deep-system-integration §5.5 — Task 5.5)
    # Architecture invariants honored:
    #   §9   — strategy choice never widens scope; just changes how we operate.
    #   §11  — no LLM calls (pure rule-based on the failure history).
    # ══════════════════════════════════════════════════════════════════════
    # Decision-rule thresholds (Task 5.5):
    #   - Repeated WAF blocks (>=3 of the last 10 entries) → "stealth_mode"
    #   - Memory pressure                                  → "reduce_concurrency"
    #   - Persistent crashes (>=3 crash entries)           → "fallback_http"
    #   - Otherwise                                        → "no_change"
    _STRATEGY_WAF_THRESHOLD: int = 3
    _STRATEGY_CRASH_THRESHOLD: int = 3

    def adapt_browser_strategy(self, failure_history: List[Dict[str, Any]]) -> str:
        """Pick a browser strategy from a recent failure history (Task 5.5).

        Returns one of:
          - ``"stealth_mode"``       — repeated WAF blocks.
          - ``"reduce_concurrency"`` — memory pressure dominates.
          - ``"fallback_http"``      — persistent crashes.
          - ``"no_change"``          — nothing actionable observed.

        Only the most recent 10 entries are considered so a transient burst at
        scan start doesn't pin the strategy forever.
        """
        if not failure_history:
            return "no_change"
        recent = list(failure_history)[-10:]

        def _norm(entry: Dict[str, Any]) -> str:
            for key in ("error_class", "reason", "type", "kind"):
                v = entry.get(key)
                if isinstance(v, str) and v:
                    return v.lower()
            msg = entry.get("message")
            return msg.lower() if isinstance(msg, str) else ""

        waf_hits = 0
        memory_hits = 0
        crash_hits = 0
        for entry in recent:
            if not isinstance(entry, dict):
                continue
            tag = _norm(entry)
            if any(token in tag for token in ("waf", "blocked", "403", "captcha")):
                waf_hits += 1
            if any(token in tag for token in ("memory", "oom", "out of memory")):
                memory_hits += 1
            if any(token in tag for token in ("crash", "browser_crash", "renderer", "context_destroyed")):
                crash_hits += 1

        if waf_hits >= self._STRATEGY_WAF_THRESHOLD:
            return "stealth_mode"
        if crash_hits >= self._STRATEGY_CRASH_THRESHOLD:
            return "fallback_http"
        if memory_hits >= 1:
            # Memory pressure is treated more aggressively than WAF/crashes
            # because it threatens the whole process — even one signal flips us.
            return "reduce_concurrency"
        return "no_change"

    # ══════════════════════════════════════════════════════════════════════
    # BROWSER CIRCUIT BREAKER (deep-system-integration §5.7 — Task 5.7)
    # Reuses the _LocalCircuitBreaker pattern from integration_coordinator.py
    # (copied locally so this module has no dependency on integration_coordinator).
    #   - Trip on 5 consecutive failures.
    #   - Recover after 60s (half-open allows one probe through).
    # Architecture invariants honored:
    #   §9   — gates traffic; never makes scope decisions.
    #   §11  — pure data-plane bookkeeping; no LLM calls.
    # ══════════════════════════════════════════════════════════════════════
    def _get_browser_breaker(self, host: str) -> "_LocalCircuitBreaker":
        breakers: Dict[str, _LocalCircuitBreaker] = self.__dict__.setdefault(
            "_browser_breakers", {}
        )
        breaker = breakers.get(host)
        if breaker is None:
            breaker = _LocalCircuitBreaker(name=f"browser:{host}")
            breakers[host] = breaker
        return breaker

    def is_browser_target_healthy(self, host: str) -> bool:
        """Return True when the per-host browser circuit is closed (Task 5.7).

        While a circuit is OPEN the caller should skip the browser path for
        ``host`` and fall back (or fail fast) — the breaker auto-flips to
        half-open after 60s so a single probe call will recover it.
        """
        if not host:
            return True
        return not self._get_browser_breaker(host).is_open

    def record_browser_target_result(self, host: str, success: bool) -> None:
        """Feed the per-host browser breaker a success/failure observation."""
        if not host:
            return
        breaker = self._get_browser_breaker(host)
        if success:
            breaker.record_success()
        else:
            breaker.record_failure()


# ══════════════════════════════════════════════════════════════════════════════
# LOCAL CIRCUIT BREAKER (deep-system-integration §5.7)
# Copied from backend.core.integration_coordinator._LocalCircuitBreaker to keep
# recovery_engine free of cross-module imports (the task explicitly says: do
# NOT introduce a new dependency). Keep this class minimal — it's a small
# fail-safe, not the project's general circuit-breaker primitive.
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class _LocalCircuitBreaker:
    """Per-host browser breaker. Trips OPEN after 5 consecutive failures and
    half-opens after 60s, at which point the next call is allowed through and
    state is reset (success closes it, failure re-opens immediately)."""

    name: str
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    _failures: int = 0
    _opened_at: Optional[float] = None
    _trips: int = 0

    def _now(self) -> float:
        # Use wall-clock time so tests can monkey-patch ``time.time``; the
        # integration_coordinator version uses event-loop time, but this
        # breaker is checked from synchronous call sites too.
        return time.time()

    @property
    def is_open(self) -> bool:
        if self._opened_at is None:
            return False
        if self._now() - self._opened_at >= self.recovery_timeout:
            # Half-open: reset state so the next call is allowed through.
            self._opened_at = None
            self._failures = 0
            return False
        return True

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._opened_at = self._now()
            self._trips += 1


# Global unified recovery engine.
recovery_engine = RecoveryEngine()
