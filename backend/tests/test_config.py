"""
Tests for configuration management.
"""

import pytest
import os
from backend.core.config import ConfigManager, GlobalSettings, RedisConfig


class TestConfigManager:
    """Tests for ConfigManager."""

    def test_singleton_pattern(self):
        """Test that ConfigManager is a singleton."""
        config1 = ConfigManager()
        config2 = ConfigManager()
        assert config1 is config2

    def test_redis_config_defaults(self):
        """Test RedisConfig defaults."""
        config = RedisConfig()
        assert config.url.startswith("redis://")
        assert config.max_connections == 10
        assert config.socket_timeout == 5

    def test_global_settings_defaults(self):
        """Test GlobalSettings has required attributes."""
        settings = GlobalSettings()
        assert hasattr(settings, "PROJECT_ROOT")
        assert hasattr(settings, "SUPABASE_URL")
        assert hasattr(settings, "REDIS_URL")


class TestEnvironmentVariables:
    """Tests for environment variable handling."""

    def test_vigil_env_fallback(self):
        """Test that vigil_env falls back to VULAGENT_ prefix."""
        from backend.core.config import vigil_env
        
        # Set legacy env var
        os.environ["VULAGENT_TEST_VAR"] = "legacy_value"
        
        try:
            result = vigil_env("TEST_VAR", "default")
            assert result == "legacy_value"
        finally:
            del os.environ["VULAGENT_TEST_VAR"]

    def test_vigil_env_new_format(self):
        """Test that vigil_env reads VIGILAGENT_ prefix."""
        os.environ["VIGILAGENT_TEST_VAR"] = "new_value"
        
        try:
            from backend.core.config import vigil_env
            result = vigil_env("TEST_VAR", "default")
            assert result == "new_value"
        finally:
            del os.environ["VIGILAGENT_TEST_VAR"]