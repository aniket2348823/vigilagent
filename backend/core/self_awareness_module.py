"""
SELF-AWARENESS MODULE
Central coordinator for all self-awareness capabilities in agents.

This module:
1. Coordinates all self-awareness components
2. Provides unified interface for agents
3. Manages component lifecycle
4. Handles feature flag checks
5. Ensures graceful degradation on errors
"""

import logging
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from backend.core.feature_flags import get_feature_flags as _get_feature_flags
from backend.core.self_awareness_config import SelfAwarenessConfig

feature_flags = _get_feature_flags()
from backend.core.tracing import get_tracer, trace_span

if TYPE_CHECKING:
    from backend.core.hive import BaseAgent

logger = logging.getLogger("SelfAwarenessModule")
tracer = get_tracer()


# ============================================================================
# DATA STRUCTURES
# ============================================================================


class ActionType(StrEnum):
    """Types of actions agents can perform"""

    RECON = "recon"
    ATTACK = "attack"
    ANALYSIS = "analysis"
    DELEGATION = "delegation"
    COORDINATION = "coordination"
    LEARNING = "learning"


@dataclass
class Action:
    """Represents an action to be executed by an agent"""

    action_id: str
    action_type: ActionType
    target: str
    parameters: dict[str, Any]
    context: dict[str, Any]
    timestamp: float


@dataclass
class ActionResult:
    """Result of an action execution"""

    action_id: str
    success: bool
    data: dict[str, Any]
    error: str | None = None
    execution_time_ms: float = 0.0
    resource_usage: dict[str, Any] | None = None


@dataclass
class ActionDecision:
    """Decision about whether to execute an action"""

    should_execute: bool
    confidence: float  # 0.0 to 1.0
    rationale: str
    alternatives_considered: list = None

    def __post_init__(self):
        if self.alternatives_considered is None:
            self.alternatives_considered = []


@dataclass
class AdaptationResult:
    """Result of a strategy adaptation"""

    adapted: bool
    strategy_applied: str | None = None
    rationale: str = ""
    success: bool = False


@dataclass
class SelfAwarenessMetrics:
    """Current self-awareness metrics for an agent"""

    agent_id: str
    timestamp: float

    # Performance metrics
    success_rate: float = 0.0
    avg_response_time_ms: float = 0.0
    total_actions: int = 0

    # Capability metrics
    proficiency_scores: dict[str, float] = None
    avg_proficiency: float = 0.0

    # Adaptation metrics
    adaptations_count: int = 0
    stuck_state: bool = False

    # Resource metrics
    cpu_percent: float = 0.0
    memory_mb: float = 0.0

    # Overhead metrics
    introspection_overhead_percent: float = 0.0

    def __post_init__(self):
        if self.proficiency_scores is None:
            self.proficiency_scores = {}


# ============================================================================
# SELF-AWARENESS MODULE
# ============================================================================


class SelfAwarenessModule:
    """
    Central coordinator for all self-awareness capabilities.

    This module integrates:
    - Performance tracking
    - Capability assessment
    - Strategy adaptation
    - Decision logging
    - Coordination management
    - Learning integration
    """

    def __init__(self, agent: "BaseAgent", config: SelfAwarenessConfig | None = None):
        """
        Initialize self-awareness module.

        Args:
            agent: The agent this module is attached to
            config: Configuration for self-awareness features
        """
        self.agent = agent
        self.agent_id = agent.name
        self.config = config or SelfAwarenessConfig()

        # Component references (will be initialized lazily)
        self._performance_tracker = None
        self._capability_assessor = None
        self._strategy_adapter = None
        self._decision_logger = None
        self._coordination_manager = None
        self._learning_integrator = None

        # Overhead tracking
        self._introspection_start_time = 0.0
        self._total_introspection_time = 0.0
        self._total_execution_time = 0.0

        # Throttling state
        self._throttled = False
        self._throttle_until = 0.0

        # Initialization state
        self._initialized = False
        self._initialization_error = None

        logger.info(f"[SelfAwareness] Module created for agent {self.agent_id}")

    async def initialize(self):
        """
        Initialize all self-awareness components.
        Called during agent startup.
        """
        if self._initialized:
            return

        with trace_span("self_awareness.initialize", {"agent_id": self.agent_id}):
            try:
                # Check if self-awareness is enabled
                if not self._is_enabled():
                    logger.info(f"[SelfAwareness] Disabled for agent {self.agent_id}")
                    self._initialized = True
                    return

                logger.info(f"[SelfAwareness] Initializing for agent {self.agent_id}")

                # Initialize components based on feature flags
                if self.config.performance_tracking_enabled:
                    await self._init_performance_tracker()

                if self.config.capability_assessment_enabled:
                    await self._init_capability_assessor()

                if self.config.strategy_adaptation_enabled:
                    await self._init_strategy_adapter()

                if self.config.decision_logging_enabled:
                    await self._init_decision_logger()

                if self.config.coordination_enabled:
                    await self._init_coordination_manager()

                if self.config.learning_enabled:
                    await self._init_learning_integrator()

                self._initialized = True
                logger.info(f"[SelfAwareness] Initialization complete for agent {self.agent_id}")

            except Exception as e:
                self._initialization_error = str(e)
                logger.error(f"[SelfAwareness] Initialization failed for {self.agent_id}: {e}")
                # Don't raise - allow agent to continue without self-awareness

    async def _init_performance_tracker(self):
        """Initialize performance tracker component"""
        try:
            from backend.core.performance_tracker import PerformanceTracker

            self._performance_tracker = PerformanceTracker(agent_id=self.agent_id, config=self.config)
            logger.debug(f"[SelfAwareness] Performance tracker initialized for {self.agent_id}")
        except Exception as e:
            logger.warning(f"[SelfAwareness] Failed to initialize performance tracker: {e}")

    async def _init_capability_assessor(self):
        """Initialize capability assessor component"""
        try:
            from backend.core.capability_assessor import CapabilityAssessor

            self._capability_assessor = CapabilityAssessor(agent_id=self.agent_id, config=self.config)
            logger.debug(f"[SelfAwareness] Capability assessor initialized for {self.agent_id}")
        except Exception as e:
            logger.warning(f"[SelfAwareness] Failed to initialize capability assessor: {e}")

    async def _init_strategy_adapter(self):
        """Initialize strategy adapter component"""
        try:
            from backend.core.recovery_engine import StrategyAdapter

            self._strategy_adapter = StrategyAdapter(
                agent_id=self.agent_id,
                config=self.config,
                decision_logger=self._decision_logger,
                learning_integrator=self._learning_integrator,
                db=self.agent.db if hasattr(self.agent, "db") else None,
            )
            logger.debug(f"[SelfAwareness] Strategy adapter initialized for {self.agent_id}")
        except Exception as e:
            logger.warning(f"[SelfAwareness] Failed to initialize strategy adapter: {e}")

    async def _init_decision_logger(self):
        """Initialize decision logger component"""
        try:
            from backend.core.decision_logger import DecisionLogger

            self._decision_logger = DecisionLogger(agent_id=self.agent_id, config=self.config)
            logger.debug(f"[SelfAwareness] Decision logger initialized for {self.agent_id}")
        except Exception as e:
            logger.warning(f"[SelfAwareness] Failed to initialize decision logger: {e}")

    async def _init_coordination_manager(self):
        """Initialize coordination manager component"""
        try:
            from backend.core.coordination_manager import CoordinationManager

            self._coordination_manager = CoordinationManager(
                agent_id=self.agent_id, agent=self.agent, config=self.config
            )
            logger.debug(f"[SelfAwareness] Coordination manager initialized for {self.agent_id}")
        except Exception as e:
            logger.warning(f"[SelfAwareness] Failed to initialize coordination manager: {e}")

    async def _init_learning_integrator(self):
        """Initialize learning integrator component"""
        try:
            from backend.core.learning_integrator import LearningIntegrator

            self._learning_integrator = LearningIntegrator(
                agent_id=self.agent_id,
                config=self.config,
                capability_assessor=self._capability_assessor,
                hive=self.agent.bus if hasattr(self.agent, "bus") else None,
            )
            logger.debug(f"[SelfAwareness] Learning integrator initialized for {self.agent_id}")
        except Exception as e:
            logger.warning(f"[SelfAwareness] Failed to initialize learning integrator: {e}")

    def _is_enabled(self) -> bool:
        """Check if self-awareness is enabled for this agent"""
        if not self.config.enabled:
            return False

        # Check agent-specific feature flag
        agent_flag = f"self_awareness_{self.agent_id.lower()}"
        # CRITICAL FIX (#32/#38): Use is_feature_enabled() not is_enabled().
        # FeatureFlags only has is_feature_enabled(); is_enabled() would
        # raise AttributeError at runtime, silently breaking all self-awareness.
        _check = getattr(feature_flags, "is_feature_enabled", None) or getattr(feature_flags, "is_enabled", None)
        return _check(agent_flag) if _check else False

    def _start_introspection_timer(self):
        """Start timing introspection overhead"""
        self._introspection_start_time = time.time()

    def _stop_introspection_timer(self):
        """Stop timing introspection overhead and update metrics"""
        if self._introspection_start_time > 0:
            elapsed = time.time() - self._introspection_start_time
            self._total_introspection_time += elapsed
            self._introspection_start_time = 0.0

    def _check_overhead(self):
        """Check if introspection overhead exceeds threshold"""
        if self._total_execution_time == 0:
            return

        overhead_percent = (self._total_introspection_time / self._total_execution_time) * 100

        if overhead_percent > self.config.max_introspection_overhead_percent:
            logger.warning(
                f"[SelfAwareness] Overhead {overhead_percent:.1f}% exceeds threshold "
                f"{self.config.max_introspection_overhead_percent}% for {self.agent_id}"
            )
            self._throttle_introspection()

    def _throttle_introspection(self):
        """Temporarily throttle introspection to reduce overhead"""
        self._throttled = True
        self._throttle_until = time.time() + 60  # Throttle for 60 seconds
        logger.info(f"[SelfAwareness] Throttling introspection for {self.agent_id}")

    def _is_throttled(self) -> bool:
        """Check if introspection is currently throttled"""
        if not self._throttled:
            return False

        if time.time() > self._throttle_until:
            self._throttled = False
            logger.info(f"[SelfAwareness] Throttling ended for {self.agent_id}")
            return False

        return True

    async def before_action(self, action: Action, context: dict[str, Any]) -> ActionDecision:
        """
        Called before agent executes an action.

        This method:
        1. Assesses capability for the action
        2. Checks prerequisites
        3. Logs decision with rationale
        4. Returns decision about whether to execute

        Args:
            action: The action to be executed
            context: Current execution context

        Returns:
            ActionDecision with should_execute, confidence, rationale
        """
        # Start timing introspection
        self._start_introspection_timer()

        with trace_span(
            "self_awareness.before_action",
            {
                "agent_id": self.agent_id,
                "action_type": str(action.action_type) if hasattr(action, "action_type") else "unknown",
                "action_id": getattr(action, "action_id", "unknown"),
            },
        ) as span:
            try:
                # Check if enabled and initialized
                if not self._is_enabled() or not self._initialized:
                    return self._default_decision(action)

                # Check if throttled
                if self._is_throttled():
                    return self._default_decision(action)

                # Assess capability
                can_perform = True
                confidence = 0.7  # Default confidence
                rationale = f"Executing {action.action_type} action"

                if self._capability_assessor:
                    try:
                        skill = action.action_type.value
                        proficiency = await self._capability_assessor.get_proficiency(skill)
                        can_perform = proficiency >= self.config.min_proficiency_for_task
                        confidence = proficiency

                        if not can_perform:
                            rationale = f"Low proficiency ({proficiency:.2f}) for {skill}"

                        # Add proficiency to span
                        if span:
                            span.set_attribute("proficiency", proficiency)
                            span.set_attribute("can_perform", can_perform)
                    except Exception as e:
                        logger.error(f"[SelfAwareness] Capability assessment failed: {e}")

                # Log decision
                if self._decision_logger:
                    try:
                        await self._decision_logger.log_decision(
                            action=action, rationale=rationale, confidence=confidence, context=context
                        )
                    except Exception as e:
                        logger.error(f"[SelfAwareness] Decision logging failed: {e}")

                # Add decision to span
                if span:
                    span.set_attribute("confidence", confidence)
                    span.set_attribute("should_execute", can_perform)

                return ActionDecision(should_execute=can_perform, confidence=confidence, rationale=rationale)

            except Exception as e:
                logger.error(f"[SelfAwareness] before_action failed: {e}")
                if span:
                    span.record_exception(e)
                return self._default_decision(action)

            finally:
                self._stop_introspection_timer()

    async def after_action(self, action: Action, result: ActionResult) -> None:
        """
        Called after agent completes an action.

        This method:
        1. Records performance metrics
        2. Updates proficiency scores
        3. Checks for stuck states
        4. Triggers adaptation if needed
        5. Integrates learning

        Args:
            action: The action that was executed
            result: The result of the action
        """
        # Start timing introspection
        self._start_introspection_timer()

        # Update total execution time
        self._total_execution_time += result.execution_time_ms / 1000.0

        with trace_span(
            "self_awareness.after_action",
            {
                "agent_id": self.agent_id,
                "action_type": str(action.action_type) if hasattr(action, "action_type") else "unknown",
                "action_id": getattr(action, "action_id", "unknown"),
                "success": result.success,
                "execution_time_ms": result.execution_time_ms,
            },
        ) as span:
            try:
                # Check if enabled and initialized
                if not self._is_enabled() or not self._initialized:
                    return

                # Check if throttled
                if self._is_throttled():
                    return

                # Record performance
                if self._performance_tracker:
                    try:
                        await self._performance_tracker.record_action_end(action=action, result=result)
                    except Exception as e:
                        logger.error(f"[SelfAwareness] Performance recording failed: {e}")

                # Update proficiency
                if self._capability_assessor:
                    try:
                        skill = action.action_type.value
                        await self._capability_assessor.update_proficiency(
                            skill=skill, outcome=result.success, context=result.data
                        )
                    except Exception as e:
                        logger.error(f"[SelfAwareness] Proficiency update failed: {e}")

                # Check for stuck state and adapt
                if self._strategy_adapter and self._performance_tracker:
                    try:
                        stuck_info = await self._performance_tracker.detect_stuck_state()
                        if stuck_info:
                            logger.warning(
                                f"[SelfAwareness] Stuck state detected for {self.agent_id}: "
                                f"{stuck_info.consecutive_failures} failures"
                            )
                            if span:
                                span.set_attribute("stuck_state_detected", True)
                                span.set_attribute("consecutive_failures", stuck_info.consecutive_failures)
                            await self._trigger_adaptation(stuck_info)
                    except Exception as e:
                        logger.error(f"[SelfAwareness] Adaptation check failed: {e}")

                # Integrate learning
                if self._learning_integrator:
                    try:
                        await self._learning_integrator.learn_from_outcome(action=action, outcome=result)
                    except Exception as e:
                        logger.error(f"[SelfAwareness] Learning integration failed: {e}")

                # Check overhead
                self._check_overhead()

            except Exception as e:
                logger.error(f"[SelfAwareness] after_action failed: {e}")
                if span:
                    span.record_exception(e)

            finally:
                self._stop_introspection_timer()

    async def _trigger_adaptation(self, stuck_info: Any) -> AdaptationResult:
        """Trigger strategy adaptation when stuck"""
        if not self._strategy_adapter:
            return AdaptationResult(adapted=False, rationale="Strategy adapter not available")

        try:
            adaptation = await self._strategy_adapter.select_and_apply_adaptation(stuck_info=stuck_info)

            if adaptation.adapted:
                logger.info(f"[SelfAwareness] Applied adaptation for {self.agent_id}: {adaptation.strategy_applied}")

            return adaptation

        except Exception as e:
            logger.error(f"[SelfAwareness] Adaptation failed: {e}")
            return AdaptationResult(adapted=False, rationale=f"Adaptation error: {e}")

    def _default_decision(self, action: Action) -> ActionDecision:
        """Return default decision when self-awareness is unavailable"""
        return ActionDecision(
            should_execute=True,
            confidence=0.5,
            rationale="Self-awareness unavailable, proceeding with default behavior",
        )

    async def get_metrics(self) -> SelfAwarenessMetrics:
        """
        Get current self-awareness metrics.

        Returns:
            SelfAwarenessMetrics with current state
        """
        metrics = SelfAwarenessMetrics(agent_id=self.agent_id, timestamp=time.time())

        try:
            # Get performance metrics
            if self._performance_tracker:
                perf_metrics = await self._performance_tracker.get_metrics_summary()
                metrics.success_rate = perf_metrics.get("success_rate", 0.0)
                metrics.avg_response_time_ms = perf_metrics.get("avg_response_time_ms", 0.0)
                metrics.total_actions = perf_metrics.get("total_actions", 0)

            # Get proficiency scores
            if self._capability_assessor:
                skill_map = await self._capability_assessor.get_skill_map()
                metrics.proficiency_scores = skill_map
                if skill_map:
                    metrics.avg_proficiency = sum(skill_map.values()) / len(skill_map)

            # Get adaptation metrics
            if self._strategy_adapter:
                adapt_metrics = await self._strategy_adapter.get_metrics()
                metrics.adaptations_count = adapt_metrics.get("total_adaptations", 0)

            # Get stuck state
            if self._performance_tracker:
                stuck_info = await self._performance_tracker.detect_stuck_state()
                metrics.stuck_state = stuck_info is not None

            # Calculate overhead
            if self._total_execution_time > 0:
                metrics.introspection_overhead_percent = (
                    self._total_introspection_time / self._total_execution_time
                ) * 100

        except Exception as e:
            logger.error(f"[SelfAwareness] Failed to get metrics: {e}")

        return metrics

    def is_stuck(self) -> bool:
        """
        Check if agent is in stuck state.

        Returns:
            True if agent is stuck, False otherwise
        """
        try:
            if not self._performance_tracker:
                return False

            # This is a synchronous wrapper - actual check is async
            # For now, return False and rely on after_action to detect stuck states
            return False

        except Exception as e:
            logger.error(f"[SelfAwareness] Stuck state check failed: {e}")
            return False

    async def adapt_strategy(self) -> AdaptationResult:
        """
        Manually trigger strategic adaptation.

        Returns:
            AdaptationResult with adaptation details
        """
        try:
            if not self._strategy_adapter:
                return AdaptationResult(adapted=False, rationale="Strategy adapter not available")

            # Get stuck state info
            stuck_info = None
            if self._performance_tracker:
                stuck_info = await self._performance_tracker.detect_stuck_state()

            if not stuck_info:
                return AdaptationResult(adapted=False, rationale="No stuck state detected")

            return await self._trigger_adaptation(stuck_info)

        except Exception as e:
            logger.error(f"[SelfAwareness] Manual adaptation failed: {e}")
            return AdaptationResult(adapted=False, rationale=f"Adaptation error: {e}")

    async def shutdown(self):
        """Shutdown self-awareness module and cleanup resources"""
        try:
            logger.info(f"[SelfAwareness] Shutting down for agent {self.agent_id}")

            # Flush any pending data
            if self._performance_tracker:
                await self._performance_tracker.flush()

            if self._decision_logger:
                await self._decision_logger.flush()

            logger.info(f"[SelfAwareness] Shutdown complete for agent {self.agent_id}")

        except Exception as e:
            logger.error(f"[SelfAwareness] Shutdown error: {e}")


# ============================================================================
# SELF-AWARE AGENT MIXIN
# ============================================================================


class SelfAwareAgentMixin:
    """
    Mixin that adds self-awareness capabilities to agents.

    Usage:
        class AlphaAgent(BaseAgent, SelfAwareAgentMixin):
            pass
    """

    def __init__(self, *args, **kwargs):
        """Initialize self-awareness for the agent"""
        super().__init__(*args, **kwargs)

        # Initialize self-awareness module
        self.self_awareness: SelfAwarenessModule | None = None

        # Check if self-awareness should be enabled
        if self._should_enable_self_awareness():
            self._init_self_awareness()

    def _should_enable_self_awareness(self) -> bool:
        """Check if self-awareness should be enabled for this agent"""
        # CRITICAL FIX (#38): Use is_feature_enabled() not is_enabled().
        # FeatureFlags only has is_feature_enabled(); is_enabled() would
        # raise AttributeError at runtime, silently breaking self-awareness.
        _check = getattr(feature_flags, "is_feature_enabled", None) or getattr(feature_flags, "is_enabled", None)
        if not (_check and _check("self_awareness_enabled")):
            return False

        # Check agent-specific feature flag
        agent_flag = f"self_awareness_{self.name.lower()}"
        return _check(agent_flag)

    def _init_self_awareness(self):
        """Initialize self-awareness module"""
        try:
            config = SelfAwarenessConfig()
            self.self_awareness = SelfAwarenessModule(agent=self, config=config)
            logger.info(f"[SelfAwareAgent] Self-awareness enabled for {self.name}")
        except Exception as e:
            logger.error(f"[SelfAwareAgent] Failed to initialize self-awareness: {e}")
            self.self_awareness = None

    async def execute_with_awareness(self, action: Action, context: dict[str, Any]) -> ActionResult:
        """
        Execute action with full self-awareness.

        This method wraps action execution with:
        - Pre-execution capability assessment
        - Decision logging
        - Performance tracking
        - Post-execution learning
        - Adaptation triggering

        Args:
            action: The action to execute
            context: Execution context

        Returns:
            ActionResult with execution outcome
        """
        # Initialize self-awareness if needed
        if self.self_awareness and not self.self_awareness._initialized:
            await self.self_awareness.initialize()

        # Pre-execution: assess and decide
        decision = ActionDecision(should_execute=True, confidence=0.5, rationale="Default")
        if self.self_awareness:
            try:
                decision = await self.self_awareness.before_action(action, context)
            except Exception as e:
                logger.error(f"[SelfAwareAgent] before_action failed: {e}")

        # Check if we should execute
        if not decision.should_execute:
            return ActionResult(
                action_id=action.action_id,
                success=False,
                data={"skipped": True, "reason": decision.rationale},
                execution_time_ms=0.0,
            )

        # Execute the action
        start_time = time.time()
        result = await self._execute_action_impl(action, context)
        result.execution_time_ms = (time.time() - start_time) * 1000.0

        # Post-execution: learn and adapt
        if self.self_awareness:
            try:
                await self.self_awareness.after_action(action, result)
            except Exception as e:
                logger.error(f"[SelfAwareAgent] after_action failed: {e}")

        return result

    async def _execute_action_impl(self, action: Action, context: dict[str, Any]) -> ActionResult:
        """
        Actual action execution implementation.
        Subclasses should override this method.
        """
        # Default implementation - subclasses should override
        return ActionResult(action_id=action.action_id, success=True, data={"message": "Action executed"})
