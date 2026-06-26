"""
Self-Awareness Configuration

This module provides configuration for self-awareness capabilities in agents.
It integrates with the existing feature flag system to enable gradual rollout
and per-agent configuration.
"""

import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SelfAwarenessConfig:
    """
    Configuration for self-awareness features.

    This configuration controls all aspects of agent self-awareness including
    performance tracking, capability assessment, strategy adaptation, decision
    logging, coordination, and learning.
    """

    # ========================================================================
    # FEATURE FLAGS
    # ========================================================================

    # Master switch for all self-awareness features
    enabled: bool = False

    # Individual component flags
    performance_tracking_enabled: bool = True
    capability_assessment_enabled: bool = True
    strategy_adaptation_enabled: bool = True
    decision_logging_enabled: bool = True
    coordination_enabled: bool = True
    learning_enabled: bool = True

    # ========================================================================
    # PERFORMANCE THRESHOLDS
    # ========================================================================

    # Number of consecutive failures before stuck state detection
    stuck_state_threshold: int = 3

    # Number of attempts with no new findings before diminishing returns
    diminishing_returns_threshold: int = 3

    # Maximum introspection overhead as percentage of total execution time
    max_introspection_overhead_percent: float = 5.0

    # ========================================================================
    # PROFICIENCY SETTINGS
    # ========================================================================

    # Initial proficiency score for new skills (0.0-1.0)
    initial_proficiency: float = 0.5

    # Minimum proficiency required to perform a task (0.0-1.0)
    min_proficiency_for_task: float = 0.5

    # Learning rate for proficiency updates (0.0-1.0)
    proficiency_learning_rate: float = 0.1

    # ========================================================================
    # ADAPTATION SETTINGS
    # ========================================================================

    # Cooldown period between adaptations (seconds)
    adaptation_cooldown_seconds: int = 60

    # Maximum number of adaptation attempts before giving up
    max_adaptation_attempts: int = 3

    # ========================================================================
    # PERFORMANCE SETTINGS
    # ========================================================================

    # Interval for batching metrics writes to database (seconds)
    metrics_batch_interval_seconds: int = 30

    # Retention period for metrics data (days)
    metrics_retention_days: int = 90

    # ========================================================================
    # COORDINATION SETTINGS
    # ========================================================================

    # Enable task delegation to other agents
    delegation_enabled: bool = True

    # Interval for broadcasting agent status (seconds)
    broadcast_interval_seconds: int = 10

    # ========================================================================
    # AGENT-SPECIFIC OVERRIDES
    # ========================================================================

    # Per-agent configuration overrides
    agent_overrides: dict[str, dict[str, any]] = field(default_factory=dict)

    @classmethod
    def from_env(cls, agent_id: str | None = None) -> "SelfAwarenessConfig":
        """
        Load configuration from environment variables.

        Args:
            agent_id: Optional agent ID for agent-specific configuration

        Returns:
            SelfAwarenessConfig instance
        """
        config = cls(
            # Feature flags
            enabled=cls._get_bool_env("SELF_AWARENESS_ENABLED", False),
            performance_tracking_enabled=cls._get_bool_env("SELF_AWARENESS_PERFORMANCE_TRACKING", True),
            capability_assessment_enabled=cls._get_bool_env("SELF_AWARENESS_CAPABILITY_ASSESSMENT", True),
            strategy_adaptation_enabled=cls._get_bool_env("SELF_AWARENESS_STRATEGY_ADAPTATION", True),
            decision_logging_enabled=cls._get_bool_env("SELF_AWARENESS_DECISION_LOGGING", True),
            coordination_enabled=cls._get_bool_env("SELF_AWARENESS_COORDINATION", True),
            learning_enabled=cls._get_bool_env("SELF_AWARENESS_LEARNING", True),
            # Performance thresholds
            stuck_state_threshold=cls._get_int_env("SELF_AWARENESS_STUCK_THRESHOLD", 3),
            diminishing_returns_threshold=cls._get_int_env("SELF_AWARENESS_DIMINISHING_RETURNS_THRESHOLD", 3),
            max_introspection_overhead_percent=cls._get_float_env("SELF_AWARENESS_MAX_OVERHEAD_PCT", 5.0),
            # Proficiency settings
            initial_proficiency=cls._get_float_env("SELF_AWARENESS_INITIAL_PROFICIENCY", 0.5),
            min_proficiency_for_task=cls._get_float_env("SELF_AWARENESS_MIN_PROFICIENCY", 0.5),
            proficiency_learning_rate=cls._get_float_env("SELF_AWARENESS_LEARNING_RATE", 0.1),
            # Adaptation settings
            adaptation_cooldown_seconds=cls._get_int_env("SELF_AWARENESS_ADAPTATION_COOLDOWN", 60),
            max_adaptation_attempts=cls._get_int_env("SELF_AWARENESS_MAX_ADAPTATION_ATTEMPTS", 3),
            # Performance settings
            metrics_batch_interval_seconds=cls._get_int_env("SELF_AWARENESS_METRICS_BATCH_INTERVAL", 30),
            metrics_retention_days=cls._get_int_env("SELF_AWARENESS_METRICS_RETENTION_DAYS", 90),
            # Coordination settings
            delegation_enabled=cls._get_bool_env("SELF_AWARENESS_DELEGATION_ENABLED", True),
            broadcast_interval_seconds=cls._get_int_env("SELF_AWARENESS_BROADCAST_INTERVAL", 10),
        )

        # Apply agent-specific overrides if agent_id provided
        if agent_id:
            config._apply_agent_overrides(agent_id)

        return config

    def _apply_agent_overrides(self, agent_id: str):
        """Apply agent-specific configuration overrides"""
        # Check for agent-specific enabled flag
        agent_enabled_key = f"SELF_AWARENESS_ENABLED_{agent_id.upper()}"
        if os.getenv(agent_enabled_key):
            self.enabled = self._get_bool_env(agent_enabled_key, self.enabled)

        # Store agent-specific overrides
        if agent_id not in self.agent_overrides:
            self.agent_overrides[agent_id] = {}

    @staticmethod
    def _get_bool_env(key: str, default: bool) -> bool:
        """Get boolean from environment variable"""
        value = os.getenv(key, str(default)).lower()
        return value in ("true", "1", "yes", "on")

    @staticmethod
    def _get_int_env(key: str, default: int) -> int:
        """Get integer from environment variable"""
        try:
            return int(os.getenv(key, str(default)))
        except ValueError:
            logger.warning(f"Invalid integer for {key}, using default {default}")
            return default

    @staticmethod
    def _get_float_env(key: str, default: float) -> float:
        """Get float from environment variable"""
        try:
            return float(os.getenv(key, str(default)))
        except ValueError:
            logger.warning(f"Invalid float for {key}, using default {default}")
            return default

    def is_component_enabled(self, component: str) -> bool:
        """
        Check if a specific self-awareness component is enabled.

        Args:
            component: Component name (performance_tracking, capability_assessment, etc.)

        Returns:
            True if component is enabled
        """
        if not self.enabled:
            return False

        component_map = {
            "performance_tracking": self.performance_tracking_enabled,
            "capability_assessment": self.capability_assessment_enabled,
            "strategy_adaptation": self.strategy_adaptation_enabled,
            "decision_logging": self.decision_logging_enabled,
            "coordination": self.coordination_enabled,
            "learning": self.learning_enabled,
        }

        return component_map.get(component, False)

    def to_dict(self) -> dict:
        """Convert configuration to dictionary"""
        return {
            "enabled": self.enabled,
            "components": {
                "performance_tracking": self.performance_tracking_enabled,
                "capability_assessment": self.capability_assessment_enabled,
                "strategy_adaptation": self.strategy_adaptation_enabled,
                "decision_logging": self.decision_logging_enabled,
                "coordination": self.coordination_enabled,
                "learning": self.learning_enabled,
            },
            "thresholds": {
                "stuck_state": self.stuck_state_threshold,
                "diminishing_returns": self.diminishing_returns_threshold,
                "max_overhead_percent": self.max_introspection_overhead_percent,
            },
            "proficiency": {
                "initial": self.initial_proficiency,
                "min_for_task": self.min_proficiency_for_task,
                "learning_rate": self.proficiency_learning_rate,
            },
            "adaptation": {
                "cooldown_seconds": self.adaptation_cooldown_seconds,
                "max_attempts": self.max_adaptation_attempts,
            },
            "performance": {
                "batch_interval_seconds": self.metrics_batch_interval_seconds,
                "retention_days": self.metrics_retention_days,
            },
            "coordination": {
                "delegation_enabled": self.delegation_enabled,
                "broadcast_interval_seconds": self.broadcast_interval_seconds,
            },
        }

    def validate(self) -> bool:
        """
        Validate configuration values.

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        # Validate proficiency values are in [0.0, 1.0]
        if not (0.0 <= self.initial_proficiency <= 1.0):
            raise ValueError(f"initial_proficiency must be in [0.0, 1.0], got {self.initial_proficiency}")

        if not (0.0 <= self.min_proficiency_for_task <= 1.0):
            raise ValueError(f"min_proficiency_for_task must be in [0.0, 1.0], got {self.min_proficiency_for_task}")

        if not (0.0 <= self.proficiency_learning_rate <= 1.0):
            raise ValueError(f"proficiency_learning_rate must be in [0.0, 1.0], got {self.proficiency_learning_rate}")

        # Validate overhead percentage
        if not (0.0 <= self.max_introspection_overhead_percent <= 100.0):
            raise ValueError(
                f"max_introspection_overhead_percent must be in [0.0, 100.0], got {self.max_introspection_overhead_percent}"
            )

        # Validate positive integers
        if self.stuck_state_threshold < 1:
            raise ValueError(f"stuck_state_threshold must be >= 1, got {self.stuck_state_threshold}")

        if self.diminishing_returns_threshold < 1:
            raise ValueError(f"diminishing_returns_threshold must be >= 1, got {self.diminishing_returns_threshold}")

        if self.adaptation_cooldown_seconds < 0:
            raise ValueError(f"adaptation_cooldown_seconds must be >= 0, got {self.adaptation_cooldown_seconds}")

        if self.max_adaptation_attempts < 1:
            raise ValueError(f"max_adaptation_attempts must be >= 1, got {self.max_adaptation_attempts}")

        if self.metrics_batch_interval_seconds < 1:
            raise ValueError(f"metrics_batch_interval_seconds must be >= 1, got {self.metrics_batch_interval_seconds}")

        if self.metrics_retention_days < 1:
            raise ValueError(f"metrics_retention_days must be >= 1, got {self.metrics_retention_days}")

        if self.broadcast_interval_seconds < 1:
            raise ValueError(f"broadcast_interval_seconds must be >= 1, got {self.broadcast_interval_seconds}")

        return True


# ============================================================================
# ENVIRONMENT-SPECIFIC CONFIGURATIONS
# ============================================================================

# Development configuration - faster feedback, shorter retention
DEVELOPMENT_CONFIG = SelfAwarenessConfig(
    enabled=True,
    metrics_batch_interval_seconds=10,  # Faster feedback
    metrics_retention_days=7,
    broadcast_interval_seconds=5,
)

# Staging configuration - production-like settings
STAGING_CONFIG = SelfAwarenessConfig(
    enabled=True,
    metrics_batch_interval_seconds=30,
    metrics_retention_days=30,
    broadcast_interval_seconds=10,
)

# Production configuration - conservative defaults, disabled by default
PRODUCTION_CONFIG = SelfAwarenessConfig(
    enabled=False,  # Start disabled for safety
    metrics_batch_interval_seconds=30,
    metrics_retention_days=90,
    broadcast_interval_seconds=10,
    max_introspection_overhead_percent=5.0,
)


# ============================================================================
# GLOBAL CONFIGURATION INSTANCE
# ============================================================================

_global_config: SelfAwarenessConfig | None = None


def get_self_awareness_config(agent_id: str | None = None) -> SelfAwarenessConfig:
    """
    Get global self-awareness configuration instance.

    Args:
        agent_id: Optional agent ID for agent-specific configuration

    Returns:
        SelfAwarenessConfig instance
    """
    global _global_config

    if _global_config is None:
        # Load from environment variables (which include per-agent overrides)
        _global_config = SelfAwarenessConfig.from_env(agent_id)

        # Validate configuration
        try:
            _global_config.validate()
            env = os.getenv("ENVIRONMENT", "development").lower()
            logger.info(f"Self-awareness configuration loaded for {env} environment")
        except ValueError as e:
            logger.error(f"Invalid self-awareness configuration: {e}")
            raise

    # MEDIUM FIX (#42): Apply per-agent overrides even when returning the
    # cached global config. Without this, the second agent_id is silently
    # ignored — all agents get the first agent's config.
    if agent_id:
        _global_config._apply_agent_overrides(agent_id)

    return _global_config


def reload_self_awareness_config(agent_id: str | None = None) -> SelfAwarenessConfig:
    """
    Reload configuration from environment (for hot-reload).

    Args:
        agent_id: Optional agent ID for agent-specific configuration

    Returns:
        SelfAwarenessConfig instance
    """
    global _global_config
    _global_config = None
    return get_self_awareness_config(agent_id)
