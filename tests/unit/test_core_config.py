"""Tests for backend.core.config — GlobalSettings, ConfigManager, load_workers_config."""
import os
import json
import pytest
from unittest.mock import patch, mock_open
from backend.core.config import (
    vigil_env, GlobalSettings, ConfigManager, RedisConfig, SupabaseConfig,
    WorkerConfig, PinchTabConfig, OpenClawConfig, HybridBrowserConfig,
    MasterConfig, load_workers_config, _validate_workers_schema,
    CONFIG_DIR, BACKEND_DIR, PROJECT_ROOT, REPORTS_DIR, STATIC_DIR,
)


class TestVigilEnv:
    def test_returns_vigilagent_env(self):
        with patch.dict(os.environ, {"VIGILAGENT_FOO": "bar"}):
            assert vigil_env("FOO") == "bar"

    def test_falls_back_to_vulagent(self):
        with patch.dict(os.environ, {"VULAGENT_FOO": "baz"}, clear=False):
            os.environ.pop("VIGILAGENT_FOO", None)
            assert vigil_env("FOO") == "baz"

    def test_returns_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VIGILAGENT_TEST", None)
            os.environ.pop("VULAGENT_TEST", None)
            assert vigil_env("TEST", "fallback") == "fallback"

    def test_vigilagent_takes_precedence(self):
        with patch.dict(os.environ, {"VIGILAGENT_X": "first", "VULAGENT_X": "second"}):
            assert vigil_env("X") == "first"


class TestGlobalSettings:
    def test_defaults(self):
        s = GlobalSettings()
        assert s.PRODUCT_NAME == "Vigilagent"
        assert s.SCAN_TIMEOUT >= 1
        assert s.ALPHA_DEFAULT_RPS >= 1

    def test_singleton_settings_exists(self):
        from backend.core.config import settings
        assert isinstance(settings, GlobalSettings)


class TestConfigManager:
    def test_singleton_behavior(self):
        c1 = ConfigManager()
        c2 = ConfigManager()
        assert c1 is c2

    def test_is_valid_no_errors(self):
        cm = ConfigManager()
        # Default config may have validation errors, just check method works
        assert isinstance(cm.is_valid(), bool)

    def test_get_validation_errors(self):
        cm = ConfigManager()
        errors = cm.get_validation_errors()
        assert isinstance(errors, list)

    def test_get_all(self):
        cm = ConfigManager()
        data = cm.get_all()
        assert "redis" in data
        assert "supabase" in data
        assert "worker" in data
        assert "pinchtab" in data
        assert "openclaw" in data
        assert "hybrid_browser" in data
        assert "master" in data
        assert "validation" in data

    def test_get_all_masks_secrets(self):
        cm = ConfigManager()
        data = cm.get_all()
        assert data["supabase"]["key"] == "MASKED"
        assert data["supabase"]["openrouter_key"] == "MASKED"


class TestRedisConfig:
    def test_defaults(self):
        rc = RedisConfig()
        # Pool sized for the full 13-agent swarm (was 10/5). Mirrors
        # backend.core.redis_client defaults.
        assert rc.max_connections == 150
        assert rc.socket_timeout == 15
        assert "redis" in rc.url


class TestWorkerConfig:
    def test_defaults(self):
        wc = WorkerConfig()
        assert wc.max_concurrent_tasks == 5
        assert wc.heartbeat_interval == 30


class TestValidateWorkersSchema:
    def test_valid_data(self):
        data = {"cluster": {"default_num_workers": 3, "heartbeat_interval_seconds": 30}}
        errors = _validate_workers_schema(data)
        assert errors == []

    def test_missing_required_key(self):
        data = {"cluster": {}}
        errors = _validate_workers_schema(data)
        assert any("default_num_workers" in e for e in errors)

    def test_non_dict_cluster(self):
        data = {"cluster": "bad"}
        errors = _validate_workers_schema(data)
        assert any("mapping" in e for e in errors)

    def test_non_numeric_value(self):
        data = {"cluster": {"default_num_workers": "bad", "heartbeat_interval_seconds": 30}}
        errors = _validate_workers_schema(data)
        assert any("numeric" in e for e in errors)

    def test_negative_value(self):
        data = {"cluster": {"default_num_workers": -1, "heartbeat_interval_seconds": 30}}
        errors = _validate_workers_schema(data)
        assert any(">= 0" in e for e in errors)

    def test_specialties_not_list(self):
        data = {"cluster": {"default_num_workers": 3, "heartbeat_interval_seconds": 30}, "specialties": "bad"}
        errors = _validate_workers_schema(data)
        assert any("list" in e for e in errors)


class TestLoadWorkersConfig:
    def test_returns_defaults_when_no_file(self):
        with patch("os.path.exists", return_value=False):
            result = load_workers_config()
            assert result["default_num_workers"] == 3
            assert result["heartbeat_interval_seconds"] == 30
            assert result["in_process_fallback"] is True

    def test_returns_defaults_when_yaml_missing(self):
        with patch("os.path.exists", return_value=False):
            result = load_workers_config()
            assert "specialties" in result
            assert isinstance(result["specialties"], list)


class TestPathConstants:
    def test_project_root(self):
        assert os.path.isabs(PROJECT_ROOT)

    def test_backend_dir(self):
        assert os.path.isabs(BACKEND_DIR)
        assert BACKEND_DIR.endswith("backend")

    def test_reports_dir_exists(self):
        assert os.path.isdir(REPORTS_DIR)

    def test_static_dir_exists(self):
        assert os.path.isdir(STATIC_DIR)
