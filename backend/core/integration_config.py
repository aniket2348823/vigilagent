"""
Integration Configuration and Feature Flags

This module provides configuration and feature flags for the deep system integration
between Agent Evolution and OpenClaw browser automation.

Design Principles:
- Feature flags for gradual rollout
- Environment-based configuration
- Hot-reloadable settings
- Backward compatibility

Loading order (highest priority last):
  1. Hardcoded class defaults
  2. ``config/integration.yaml`` (if present)
  3. Environment variables (12-factor override for prod)
"""

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:  # PyYAML is already a transitive dep used elsewhere in backend.core
    import yaml  # type: ignore
except Exception as _yaml_exc:  # pragma: no cover - graceful degradation
    logger.debug("PyYAML not available: %s", _yaml_exc)
    yaml = None  # type: ignore

# Repo-relative default location for the integration YAML. Resolved lazily so
# the import has no side-effects (matches §29.13 — no I/O on import).
_DEFAULT_YAML_PATH = Path(__file__).resolve().parents[2] / "config" / "integration.yaml"


@dataclass
class IntegrationConfig:
    """Configuration for deep system integration features"""

    # Feature flags
    enable_browser_learning: bool = False
    enable_cross_system_healing: bool = False
    enable_forensic_learning: bool = False
    enable_intelligent_routing: bool = False

    # Rollout-bucket flags (config/integration.yaml is the source of truth in dev).
    # These mirror the spec tasks 3.8 / 5.11 / 7.8 / 9.10 / 11.8 / 13.11.
    enable_skill_library_v2: bool = False
    enable_browser_health_monitoring: bool = False
    enable_self_healing: bool = False
    enable_unified_graph: bool = False

    # Gradual rollout percentages (0-100)
    browser_learning_rollout_pct: int = 0
    cross_healing_rollout_pct: int = 0
    forensic_learning_rollout_pct: int = 0
    intelligent_routing_rollout_pct: int = 0

    # Per-feature rollout cohorts driven by the YAML
    skill_library_rollout_pct: int = 0
    health_monitoring_rollout_pct: int = 0
    self_healing_rollout_pct: int = 0
    unified_graph_rollout_pct: int = 0
    routing_forensics_rollout_pct: int = 0

    # Event batching configuration
    event_batch_size: int = 10
    event_batch_timeout_ms: int = 1000

    # Concurrency limits
    max_concurrent_learning: int = 5
    max_concurrent_healing: int = 3

    # Circuit breaker settings
    circuit_breaker_enabled: bool = True
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout_s: int = 60

    # Distributed locking
    lock_ttl_seconds: int = 300
    lock_retry_attempts: int = 3
    lock_retry_delay_ms: int = 100

    # Caching
    cache_enabled: bool = True
    cache_ttl_seconds: int = 3600
    cache_max_size: int = 10000

    # Performance limits
    skill_search_timeout_ms: int = 50
    learning_timeout_ms: int = 5000
    healing_timeout_ms: int = 10000

    # Observability
    tracing_enabled: bool = True
    tracing_sample_rate: float = 1.0
    metrics_enabled: bool = True

    @classmethod
    def from_env(cls) -> "IntegrationConfig":
        """
        Load configuration from environment variables

        Environment variables:
            ENABLE_BROWSER_LEARNING: Enable browser learning (true/false)
            BROWSER_LEARNING_ROLLOUT_PCT: Rollout percentage (0-100)
            ENABLE_CROSS_HEALING: Enable cross-system healing (true/false)
            ENABLE_FORENSIC_LEARNING: Enable forensic learning (true/false)
            ENABLE_INTELLIGENT_ROUTING: Enable intelligent routing (true/false)

            EVENT_BATCH_SIZE: Event batch size (default: 10)
            EVENT_BATCH_TIMEOUT_MS: Event batch timeout (default: 1000)

            MAX_CONCURRENT_LEARNING: Max concurrent learning operations (default: 5)
            MAX_CONCURRENT_HEALING: Max concurrent healing operations (default: 3)

            CIRCUIT_BREAKER_ENABLED: Enable circuit breakers (true/false)
            CIRCUIT_BREAKER_THRESHOLD: Failure threshold (default: 5)
            CIRCUIT_BREAKER_TIMEOUT_S: Recovery timeout (default: 60)

            TRACING_ENABLED: Enable distributed tracing (true/false)
            TRACING_SAMPLE_RATE: Tracing sample rate (0.0-1.0)

        Returns:
            IntegrationConfig instance with values from environment
        """

        def get_bool(key: str, default: bool) -> bool:
            """Get boolean from environment"""
            value = os.getenv(key, str(default)).lower()
            return value in ("true", "1", "yes", "on")

        def get_int(key: str, default: int) -> int:
            """Get integer from environment"""
            try:
                return int(os.getenv(key, str(default)))
            except ValueError:
                logger.warning(f"Invalid integer for {key}, using default: {default}")
                return default

        def get_float(key: str, default: float) -> float:
            """Get float from environment"""
            try:
                return float(os.getenv(key, str(default)))
            except ValueError:
                logger.warning(f"Invalid float for {key}, using default: {default}")
                return default

        config = cls(
            # Feature flags
            enable_browser_learning=get_bool("ENABLE_BROWSER_LEARNING", False),
            enable_cross_system_healing=get_bool("ENABLE_CROSS_HEALING", False),
            enable_forensic_learning=get_bool("ENABLE_FORENSIC_LEARNING", False),
            enable_intelligent_routing=get_bool("ENABLE_INTELLIGENT_ROUTING", False),
            # Rollout-bucket feature flags (mirror config/integration.yaml).
            enable_skill_library_v2=get_bool("ENABLE_SKILL_LIBRARY_V2", False),
            enable_browser_health_monitoring=get_bool("ENABLE_BROWSER_HEALTH_MONITORING", False),
            enable_self_healing=get_bool("ENABLE_SELF_HEALING", False),
            enable_unified_graph=get_bool("ENABLE_UNIFIED_GRAPH", False),
            # Rollout percentages
            browser_learning_rollout_pct=get_int("BROWSER_LEARNING_ROLLOUT_PCT", 0),
            cross_healing_rollout_pct=get_int("CROSS_HEALING_ROLLOUT_PCT", 0),
            forensic_learning_rollout_pct=get_int("FORENSIC_LEARNING_ROLLOUT_PCT", 0),
            intelligent_routing_rollout_pct=get_int("INTELLIGENT_ROUTING_ROLLOUT_PCT", 0),
            # Per-feature rollout cohorts (tasks 3.8 / 5.11 / 7.8 / 9.10 / 11.8 / 13.11)
            skill_library_rollout_pct=get_int("SKILL_LIBRARY_ROLLOUT_PCT", 0),
            health_monitoring_rollout_pct=get_int("HEALTH_MONITORING_ROLLOUT_PCT", 0),
            self_healing_rollout_pct=get_int("SELF_HEALING_ROLLOUT_PCT", 0),
            unified_graph_rollout_pct=get_int("UNIFIED_GRAPH_ROLLOUT_PCT", 0),
            routing_forensics_rollout_pct=get_int("ROUTING_FORENSICS_ROLLOUT_PCT", 0),
            # Event batching
            event_batch_size=get_int("EVENT_BATCH_SIZE", 10),
            event_batch_timeout_ms=get_int("EVENT_BATCH_TIMEOUT_MS", 1000),
            # Concurrency
            max_concurrent_learning=get_int("MAX_CONCURRENT_LEARNING", 5),
            max_concurrent_healing=get_int("MAX_CONCURRENT_HEALING", 3),
            # Circuit breaker
            circuit_breaker_enabled=get_bool("CIRCUIT_BREAKER_ENABLED", True),
            circuit_breaker_threshold=get_int("CIRCUIT_BREAKER_THRESHOLD", 5),
            circuit_breaker_timeout_s=get_int("CIRCUIT_BREAKER_TIMEOUT_S", 60),
            # Distributed locking
            lock_ttl_seconds=get_int("LOCK_TTL_SECONDS", 300),
            lock_retry_attempts=get_int("LOCK_RETRY_ATTEMPTS", 3),
            lock_retry_delay_ms=get_int("LOCK_RETRY_DELAY_MS", 100),
            # Caching
            cache_enabled=get_bool("CACHE_ENABLED", True),
            cache_ttl_seconds=get_int("CACHE_TTL_SECONDS", 3600),
            cache_max_size=get_int("CACHE_MAX_SIZE", 10000),
            # Performance
            skill_search_timeout_ms=get_int("SKILL_SEARCH_TIMEOUT_MS", 50),
            learning_timeout_ms=get_int("LEARNING_TIMEOUT_MS", 5000),
            healing_timeout_ms=get_int("HEALING_TIMEOUT_MS", 10000),
            # Observability
            tracing_enabled=get_bool("TRACING_ENABLED", True),
            tracing_sample_rate=get_float("TRACING_SAMPLE_RATE", 1.0),
            metrics_enabled=get_bool("METRICS_ENABLED", True),
        )

        logger.info(
            "Integration configuration loaded",
            extra={
                "browser_learning_enabled": config.enable_browser_learning,
                "browser_learning_rollout": config.browser_learning_rollout_pct,
                "cross_healing_enabled": config.enable_cross_system_healing,
                "forensic_learning_enabled": config.enable_forensic_learning,
                "intelligent_routing_enabled": config.enable_intelligent_routing,
            },
        )

        return config

    @classmethod
    def from_yaml(
        cls,
        path: Path | None = None,
        *,
        env_overrides: bool = True,
    ) -> "IntegrationConfig":
        """Load configuration from ``config/integration.yaml``.

        Resolution order (last-write-wins on each field):
          1. Hardcoded class defaults
          2. YAML values under the top-level ``integration:`` key (if file exists)
          3. Environment variables (only when ``env_overrides=True``)

        The YAML loader is fail-soft: a missing file, missing PyYAML, or a parse
        error all degrade to env+defaults rather than raising. This keeps the
        backend importable in stripped-down CI containers.

        Mapping (yaml key → dataclass field):
          enable_browser_learning            → enable_browser_learning
          browser_learning_rollout_pct       → browser_learning_rollout_pct
          enable_skill_library_v2            → enable_skill_library_v2
          skill_library_rollout_pct          → skill_library_rollout_pct
          enable_browser_health_monitoring   → enable_browser_health_monitoring
          health_monitoring_rollout_pct      → health_monitoring_rollout_pct
          enable_self_healing                → enable_self_healing
          self_healing_rollout_pct           → self_healing_rollout_pct
          enable_unified_graph               → enable_unified_graph
          unified_graph_rollout_pct          → unified_graph_rollout_pct
          enable_intelligent_routing         → enable_intelligent_routing
          enable_forensic_learning           → enable_forensic_learning
          routing_forensics_rollout_pct      → routing_forensics_rollout_pct
          event_batch_size / event_batch_timeout_ms / max_concurrent_learning /
          circuit_breaker_threshold / circuit_breaker_timeout_s — passed through.
        """
        yaml_path: Path = Path(path) if path is not None else _DEFAULT_YAML_PATH
        yaml_data: dict[str, Any] = {}

        if yaml is not None and yaml_path.exists():
            try:
                raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
                if isinstance(raw, dict):
                    section = raw.get("integration", raw)
                    if isinstance(section, dict):
                        yaml_data = section
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "Failed to parse %s (%s); falling back to env+defaults",
                    yaml_path,
                    exc,
                )

        # Start from env (which already merges defaults+env), then layer YAML on top
        # so explicit yaml entries win over defaults but env still wins overall when
        # env_overrides=True. To achieve that order we instead build from defaults,
        # apply YAML, and then re-apply env on top.
        base = cls()  # defaults

        # --- Layer YAML values ---
        cls._apply_mapping(base, yaml_data)

        # --- Layer env values (if requested) ---
        if env_overrides:
            env_cfg = cls.from_env()
            cls._apply_env_overrides(base, env_cfg)

        logger.info(
            "Integration configuration loaded from yaml=%s (env_overrides=%s)",
            yaml_path if yaml_path.exists() else "(missing)",
            env_overrides,
        )
        return base

    # ------------------------------------------------------------------
    # YAML / env merging helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _apply_mapping(target: "IntegrationConfig", data: Mapping[str, Any]) -> None:
        """Copy supported fields from ``data`` into ``target`` in-place."""
        for key, value in data.items():
            if not hasattr(target, key):
                # Unknown keys are silently ignored — keeps the YAML schema
                # forward-compatible without raising on stale dev configs.
                continue
            try:
                # Preserve dataclass field types where it matters (rollout pct
                # must be int, flags must be bool). YAML already gives us
                # native Python types so a direct assign is safe; we coerce
                # ints/bools for robustness.
                current = getattr(target, key)
                if isinstance(current, bool):
                    setattr(target, key, bool(value))
                elif isinstance(current, int):
                    setattr(target, key, int(value))
                elif isinstance(current, float):
                    setattr(target, key, float(value))
                else:
                    setattr(target, key, value)
            except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
                logger.warning("Skipping invalid YAML value for %s=%r (%s)", key, value, exc)

    @staticmethod
    def _apply_env_overrides(target: "IntegrationConfig", env_cfg: "IntegrationConfig") -> None:
        """Re-apply env-derived values that differ from the dataclass defaults.

        We can't simply copy every field from ``env_cfg`` (that would clobber
        YAML values with default-zero env reads). Instead we copy only those
        fields whose env-derived value differs from the dataclass default,
        which is exactly the set of env vars the operator actually set.
        """
        defaults = IntegrationConfig()
        for f in target.__dataclass_fields__:
            env_val = getattr(env_cfg, f)
            default_val = getattr(defaults, f)
            if env_val != default_val:
                setattr(target, f, env_val)

    def should_enable_for_scan(self, scan_id: str, feature: str) -> bool:
        """
        Determine if feature should be enabled for this scan (gradual rollout)

        Uses consistent hashing based on scan_id to ensure same scan always
        gets same decision (important for A/B testing and debugging).

        Args:
            scan_id: Unique scan identifier
            feature: Feature name ("browser_learning", "cross_healing", etc.)

        Returns:
            True if feature should be enabled for this scan
        """
        feature_map = {
            "browser_learning": (self.enable_browser_learning, self.browser_learning_rollout_pct),
            "cross_healing": (self.enable_cross_system_healing, self.cross_healing_rollout_pct),
            "forensic_learning": (self.enable_forensic_learning, self.forensic_learning_rollout_pct),
            "intelligent_routing": (self.enable_intelligent_routing, self.intelligent_routing_rollout_pct),
        }

        if feature not in feature_map:
            logger.warning(f"Unknown feature: {feature}")
            return False

        enabled, rollout_pct = feature_map[feature]

        # Feature must be enabled globally
        if not enabled:
            return False

        # 100% rollout - always enable
        if rollout_pct >= 100:
            return True

        # 0% rollout - never enable
        if rollout_pct <= 0:
            return False

        # Gradual rollout - use consistent hashing
        # This ensures same scan_id always gets same result
        # HIGH-71: Use deterministic hash (hash() is randomized per-process)
        import hashlib as _hl

        scan_hash = int.from_bytes(_hl.sha256(scan_id.encode()).digest()[:4], "big") % 100
        return scan_hash < rollout_pct

    def get_feature_status(self) -> dict[str, dict[str, any]]:
        """
        Get status of all features

        Returns:
            Dictionary with feature status information
        """
        return {
            "browser_learning": {
                "enabled": self.enable_browser_learning,
                "rollout_pct": self.browser_learning_rollout_pct,
                "fully_rolled_out": self.browser_learning_rollout_pct >= 100,
            },
            "cross_healing": {
                "enabled": self.enable_cross_system_healing,
                "rollout_pct": self.cross_healing_rollout_pct,
                "fully_rolled_out": self.cross_healing_rollout_pct >= 100,
            },
            "forensic_learning": {
                "enabled": self.enable_forensic_learning,
                "rollout_pct": self.forensic_learning_rollout_pct,
                "fully_rolled_out": self.forensic_learning_rollout_pct >= 100,
            },
            "intelligent_routing": {
                "enabled": self.enable_intelligent_routing,
                "rollout_pct": self.intelligent_routing_rollout_pct,
                "fully_rolled_out": self.intelligent_routing_rollout_pct >= 100,
            },
        }

    def validate(self) -> bool:
        """
        Validate configuration values

        Returns:
            True if configuration is valid

        Raises:
            ValueError: If configuration is invalid
        """
        # Validate rollout percentages
        for pct_name in [
            "browser_learning_rollout_pct",
            "cross_healing_rollout_pct",
            "forensic_learning_rollout_pct",
            "intelligent_routing_rollout_pct",
            "skill_library_rollout_pct",
            "health_monitoring_rollout_pct",
            "self_healing_rollout_pct",
            "unified_graph_rollout_pct",
            "routing_forensics_rollout_pct",
        ]:
            pct = getattr(self, pct_name)
            if not 0 <= pct <= 100:
                raise ValueError(f"{pct_name} must be between 0 and 100, got {pct}")

        # Validate positive integers
        for int_name in [
            "event_batch_size",
            "max_concurrent_learning",
            "max_concurrent_healing",
            "circuit_breaker_threshold",
            "circuit_breaker_timeout_s",
        ]:
            value = getattr(self, int_name)
            if value <= 0:
                raise ValueError(f"{int_name} must be positive, got {value}")

        # Validate tracing sample rate
        if not 0.0 <= self.tracing_sample_rate <= 1.0:
            raise ValueError(f"tracing_sample_rate must be between 0.0 and 1.0, got {self.tracing_sample_rate}")

        return True


# Global configuration instance (loaded from environment)
_config: IntegrationConfig | None = None


def get_integration_config() -> IntegrationConfig:
    """
    Get global integration configuration

    Loads from YAML (config/integration.yaml) on first call, falling back to
    env+defaults when the file is missing. Subsequent calls return the cached
    instance. Call ``reload_integration_config()`` to refresh.

    Returns:
        IntegrationConfig instance
    """
    global _config
    if _config is None:
        _config = IntegrationConfig.from_yaml() if _DEFAULT_YAML_PATH.exists() else IntegrationConfig.from_env()
        _config.validate()
    return _config


def reload_integration_config() -> IntegrationConfig:
    """
    Reload configuration from YAML/environment

    Useful for hot-reloading configuration without restart.

    Returns:
        New IntegrationConfig instance
    """
    global _config
    _config = IntegrationConfig.from_yaml() if _DEFAULT_YAML_PATH.exists() else IntegrationConfig.from_env()
    _config.validate()
    logger.info("Integration configuration reloaded")
    return _config
