"""
LEARNING INTEGRATOR
Updates agent knowledge based on outcomes.

This integrator:
1. Learns from action outcomes
2. Saves successful strategies
3. Marks failed approaches
4. Shares learning via Hive
5. Applies shared learning from peers
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from backend.core.learning_engine import learning_engine
from backend.core.self_awareness_config import SelfAwarenessConfig
from backend.core.tracing import get_tracer

logger = logging.getLogger("LearningIntegrator")
tracer = get_tracer()


@dataclass
class Strategy:
    """Represents a successful strategy"""

    name: str
    action_type: str
    context: dict[str, Any]
    success_count: int = 1
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


@dataclass
class FailedApproach:
    """Represents a failed approach to avoid"""

    approach_type: str
    context: dict[str, Any]
    failure_count: int = 1
    first_failure: datetime = None
    last_failure: datetime = None

    def __post_init__(self):
        if self.first_failure is None:
            self.first_failure = datetime.utcnow()
        if self.last_failure is None:
            self.last_failure = datetime.utcnow()


@dataclass
class Learning:
    """Represents shared learning data"""

    agent_id: str
    learning_type: str  # "strategy" or "failed_approach"
    data: dict[str, Any]
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


_MAX_STRATEGIES = 500
_MAX_FAILED_APPROACHES = 200


class LearningIntegrator:
    """Integrates learning from action outcomes"""

    def __init__(self, agent_id: str, config: SelfAwarenessConfig, capability_assessor=None, hive=None):
        self.agent_id = agent_id
        self.config = config
        self.learning_engine = learning_engine
        self.capability_assessor = capability_assessor
        self.hive = hive

        # Track strategies and failed approaches
        self.successful_strategies: dict[str, Strategy] = {}
        self.failed_approaches: dict[str, FailedApproach] = {}

        logger.info(f"[LearningIntegrator] Initialized for agent {agent_id}")

    async def learn_from_outcome(self, action: Any, outcome: Any):
        """Learn from action outcome"""
        try:
            # Extract learning data
            if outcome.success:
                await self._learn_success(action, outcome)
            else:
                await self._learn_failure(action, outcome)
        except Exception as e:
            logger.error(f"[LearningIntegrator] Learning failed: {e}")

    async def _learn_success(self, action: Any, outcome: Any):
        """Learn from successful action"""
        logger.debug(f"[LearningIntegrator] Learning from success: {action}")

        # Update proficiency if capability assessor is available
        if self.capability_assessor:
            action_type = getattr(action, "type", str(action))
            await self.capability_assessor.update_proficiency(action_type, True, {})

    async def _learn_failure(self, action: Any, outcome: Any):
        """Learn from failed action"""
        logger.debug(f"[LearningIntegrator] Learning from failure: {action}")

        # Update proficiency if capability assessor is available
        if self.capability_assessor:
            action_type = getattr(action, "type", str(action))
            await self.capability_assessor.update_proficiency(action_type, False, {})

    async def save_successful_strategy(self, strategy: Strategy, context: dict[str, Any]):
        """Save successful strategy to skill library

        Args:
            strategy: The successful strategy
            context: Context metadata for the strategy
        """
        try:
            strategy_key = f"{strategy.action_type}:{strategy.name}"

            if strategy_key in self.successful_strategies:
                # Increment success count
                self.successful_strategies[strategy_key].success_count += 1
            else:
                # Evict oldest entry if at capacity
                if len(self.successful_strategies) >= _MAX_STRATEGIES:
                    oldest_key = min(
                        self.successful_strategies, key=lambda k: self.successful_strategies[k].success_count
                    )
                    del self.successful_strategies[oldest_key]
                # Add new strategy
                self.successful_strategies[strategy_key] = strategy

            # Save to skill library via learning engine
            await self.learning_engine.record_outcome(action_type=strategy.action_type, outcome=True, context=context)

            # Share learning via Hive if enabled
            if self.config.learning_enabled and self.hive:
                await self.share_learning(
                    Learning(
                        agent_id=self.agent_id,
                        learning_type="strategy",
                        data={
                            "strategy_name": strategy.name,
                            "action_type": strategy.action_type,
                            "context": context,
                            "success_count": strategy.success_count,
                        },
                    )
                )

            logger.info(f"[LearningIntegrator] Saved successful strategy: {strategy_key}")

        except Exception as e:
            logger.error(f"[LearningIntegrator] Failed to save strategy: {e}")

    async def mark_failed_approach(self, approach: FailedApproach, context: dict[str, Any]):
        """Mark approach as ineffective to prevent future repetition

        Args:
            approach: The failed approach
            context: Context metadata for the failure
        """
        try:
            approach_key = f"{approach.approach_type}"

            if approach_key in self.failed_approaches:
                # Increment failure count and update timestamp
                self.failed_approaches[approach_key].failure_count += 1
                self.failed_approaches[approach_key].last_failure = datetime.utcnow()
            else:
                # Evict oldest entry if at capacity
                if len(self.failed_approaches) >= _MAX_FAILED_APPROACHES:
                    oldest_key = min(self.failed_approaches, key=lambda k: self.failed_approaches[k].failure_count)
                    del self.failed_approaches[oldest_key]
                # Add new failed approach
                self.failed_approaches[approach_key] = approach

            # Record in learning engine
            await self.learning_engine.record_outcome(
                action_type=approach.approach_type, outcome=False, context=context
            )

            # Share learning via Hive if enabled
            if self.config.learning_enabled and self.hive:
                await self.share_learning(
                    Learning(
                        agent_id=self.agent_id,
                        learning_type="failed_approach",
                        data={
                            "approach_type": approach.approach_type,
                            "context": context,
                            "failure_count": approach.failure_count,
                        },
                    )
                )

            logger.info(
                f"[LearningIntegrator] Marked failed approach: {approach_key} (failures: {approach.failure_count})"
            )

        except Exception as e:
            logger.error(f"[LearningIntegrator] Failed to mark approach: {e}")

    async def share_learning(self, learning: Learning):
        """Share learning with other agents via Hive

        Args:
            learning: The learning data to share
        """
        try:
            if not self.hive:
                logger.warning("[LearningIntegrator] Hive not available for sharing")
                return

            from backend.core.hive import EventType, HiveEvent

            # Broadcast learning via Hive
            await self.hive.publish(
                HiveEvent(
                    type=EventType.PATTERN_LEARNED,
                    source=self.agent_id,
                    payload={
                        "learning_type": learning.learning_type,
                        "data": learning.data,
                        "timestamp": learning.timestamp.isoformat(),
                    },
                )
            )

            logger.debug(f"[LearningIntegrator] Shared learning: {learning.learning_type}")

        except Exception as e:
            logger.error(f"[LearningIntegrator] Failed to share learning: {e}")

    async def apply_shared_learning(self, learning: Learning):
        """Apply learning shared by another agent

        Args:
            learning: The learning data from another agent
        """
        try:
            if learning.agent_id == self.agent_id:
                # Don't apply our own learning
                return

            if learning.learning_type == "strategy":
                # Apply successful strategy
                data = learning.data
                strategy = Strategy(
                    name=data.get("strategy_name", "unknown"),
                    action_type=data.get("action_type", "unknown"),
                    context=data.get("context", {}),
                    success_count=data.get("success_count", 1),
                )

                strategy_key = f"{strategy.action_type}:{strategy.name}"
                if strategy_key not in self.successful_strategies:
                    self.successful_strategies[strategy_key] = strategy
                    logger.info(f"[LearningIntegrator] Applied shared strategy: {strategy_key}")

            elif learning.learning_type == "failed_approach":
                # Apply failed approach
                data = learning.data
                approach = FailedApproach(
                    approach_type=data.get("approach_type", "unknown"),
                    context=data.get("context", {}),
                    failure_count=data.get("failure_count", 1),
                )

                approach_key = approach.approach_type
                if approach_key not in self.failed_approaches:
                    self.failed_approaches[approach_key] = approach
                    logger.info(f"[LearningIntegrator] Applied shared failed approach: {approach_key}")

        except Exception as e:
            logger.error(f"[LearningIntegrator] Failed to apply shared learning: {e}")

    def get_successful_strategies(self) -> dict[str, Strategy]:
        """Get all successful strategies"""
        return self.successful_strategies.copy()

    def get_failed_approaches(self) -> dict[str, FailedApproach]:
        """Get all failed approaches"""
        return self.failed_approaches.copy()

    def should_avoid_approach(self, approach_type: str, context: dict[str, Any]) -> bool:
        """Check if an approach should be avoided based on past failures

        Args:
            approach_type: The type of approach to check
            context: Current context

        Returns:
            True if approach should be avoided, False otherwise
        """
        if approach_type in self.failed_approaches:
            approach = self.failed_approaches[approach_type]
            # Use config threshold instead of hardcoded 3
            threshold = self.config.stuck_state_threshold
            if approach.failure_count >= threshold:
                logger.debug(
                    f"[LearningIntegrator] Avoiding approach {approach_type} (failed {approach.failure_count} times)"
                )
                return True
        return False

    # ── READ PATH (Architecture §6.8, §29.9) ──────────────────────────────────
    # The integrator must not be write-only. These methods deliver learned
    # recommendations OUT to agents/planner before they form a plan.

    def get_recommendations(
        self,
        *,
        target_url: str | None = None,
        vuln_class: str | None = None,
        action_type: str | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        """Return a consolidated recommendation bundle for planning.

        Pulls from: (1) the SkillLibrary recommendations, (2) locally-learned
        successful strategies, and (3) approaches to avoid. Agents call this
        before planning so learning is actually consumed (Architecture §29.9).
        """
        skill_recs: list[dict] = []
        try:
            from backend.core.skill_library import skill_library

            skill_recs = skill_library.get_recommendations(
                target_url=target_url,
                vuln_class=vuln_class,
                skill_type=action_type,
                limit=limit,
            )
        except Exception as exc:
            logger.debug(f"[LearningIntegrator] skill recs unavailable: {exc}")

        strategies = [
            {"name": s.name, "action_type": s.action_type, "success_count": s.success_count}
            for s in sorted(self.successful_strategies.values(), key=lambda x: x.success_count, reverse=True)[:limit]
        ]
        avoid = [
            {"approach_type": a.approach_type, "failure_count": a.failure_count}
            for a in self.failed_approaches.values()
            if a.failure_count >= 3
        ]
        return {
            "skills": skill_recs,
            "successful_strategies": strategies,
            "avoid": avoid,
        }

    def recommend_strategies(self, action_type: str, limit: int = 5) -> list[Strategy]:
        """Return learned successful strategies for a given action type."""
        matches = [s for s in self.successful_strategies.values() if s.action_type == action_type]
        matches.sort(key=lambda s: s.success_count, reverse=True)
        return matches[:limit]
