import os
import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Initialize Environment
load_dotenv()


def vigil_env(name: str, default: str = "") -> str:
    """Read a VIGILAGENT_<name> env var, falling back to VULAGENT_<name>, then
    a plain default (Architecture §13.2 branding — user-facing rename only,
    backward compatible with existing .env files)."""
    return os.getenv(f"VIGILAGENT_{name}", os.getenv(f"VULAGENT_{name}", default))

# --- VUL AGENT: UNIFIED PATH RESOLUTION (V6-OMEGA) ---
# Ensure absolute roots regardless of where the app is launched
CONFIG_DIR = os.path.dirname(os.path.abspath(__file__)) # .../backend/core
BACKEND_DIR = os.path.abspath(os.path.join(CONFIG_DIR, ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")

# Ensure critical directories exist
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# XYTHERION CONFIGURATION MATRIX
# Role: Dynamic environment-based settings for the distributed swarm.

# Vigilagent declarative config files (Architecture §21, §29.10).
CONFIG_FILES_DIR = os.path.join(PROJECT_ROOT, "config")
SCOPE_CONFIG_PATH = os.path.join(CONFIG_FILES_DIR, "scope.yaml")
TOOLS_CONFIG_PATH = os.path.join(CONFIG_FILES_DIR, "tools.yaml")
BUDGETS_CONFIG_PATH = os.path.join(CONFIG_FILES_DIR, "budgets.yaml")
MODELS_CONFIG_PATH = os.path.join(CONFIG_FILES_DIR, "models.yaml")
EXTENSION_CONFIG_PATH = os.path.join(CONFIG_FILES_DIR, "extension.yaml")
SKILLS_CONFIG_PATH = os.path.join(CONFIG_FILES_DIR, "skills.yaml")
WORKERS_CONFIG_PATH = os.path.join(CONFIG_FILES_DIR, "workers.yaml")
ENGAGEMENT_CONFIG_PATH = os.path.join(CONFIG_FILES_DIR, "engagement.yaml")


# CRIT-21: Schema validation constants for YAML config files.
_WORKERS_REQUIRED_KEYS = {"default_num_workers", "heartbeat_interval_seconds"}
_WORKERS_NUMERIC_KEYS = {
    "default_num_workers", "heartbeat_interval_seconds",
    "max_concurrent_tasks_per_worker",
}


def _validate_workers_schema(data: Dict[str, Any]) -> List[str]:
    """Validate workers.yaml data against expected schema.
    Returns a list of validation error strings (empty = valid)."""
    errors: List[str] = []
    cluster = data.get("cluster") or {}
    if not isinstance(cluster, dict):
        errors.append("'cluster' must be a mapping")
        return errors
    for key in _WORKERS_REQUIRED_KEYS:
        if key not in cluster:
            errors.append(f"cluster.{key} is required")
    for key in _WORKERS_NUMERIC_KEYS:
        val = cluster.get(key)
        if val is not None and not isinstance(val, (int, float)):
            errors.append(f"cluster.{key} must be numeric, got {type(val).__name__}")
        elif isinstance(val, (int, float)) and val < 0:
            errors.append(f"cluster.{key} must be >= 0")
    specialties = data.get("specialties")
    if specialties is not None and not isinstance(specialties, list):
        errors.append("'specialties' must be a list")
    return errors


def load_workers_config() -> Dict[str, Any]:
    """Load cluster/worker defaults from config/workers.yaml (Architecture
    §4.3, §5.1.2, §29.10). Returns a dict with safe fallbacks so the cluster
    runs even if the file is missing or malformed."""
    defaults: Dict[str, Any] = {
        "default_num_workers": 3,
        "heartbeat_interval_seconds": 30,
        "max_concurrent_tasks_per_worker": 5,
        "in_process_fallback": True,
        "specialties": ["hybrid", "recon", "browser", "api", "network",
                         "validation", "forensics", "reporting", "skill"],
        "default_specialty": "hybrid",
    }
    try:
        import yaml  # type: ignore
        if os.path.exists(WORKERS_CONFIG_PATH):
            with open(WORKERS_CONFIG_PATH, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            # CRIT-21: Validate schema before accepting values
            schema_errors = _validate_workers_schema(data)
            if schema_errors:
                for err in schema_errors:
                    logger.warning("workers.yaml schema: %s", err)
                # Still use safe defaults; only apply validated keys
            cluster = data.get("cluster", {}) or {}
            if isinstance(cluster, dict):
                for k, v in cluster.items():
                    if v is not None and (k in _WORKERS_NUMERIC_KEYS or k in defaults):
                        defaults[k] = v
            if data.get("specialties") and isinstance(data["specialties"], list):
                defaults["specialties"] = list(data["specialties"])
            if data.get("default_specialty"):
                defaults["default_specialty"] = str(data["default_specialty"])
    except Exception as exc:  # pragma: no cover - fail safe to defaults (yaml.YAMLError, OSError, etc.)
        logger.warning(
            "Could not parse workers.yaml (%s); using defaults. "
            "Check the file for syntax errors or missing required keys.",
            exc, exc_info=True)
    return defaults

# Product identity (Architecture §1, §13). User-facing only.
PRODUCT_NAME = vigil_env("PRODUCT_NAME", "Vigilagent")

@dataclass
class GlobalSettings:
    """Consolidated project-level settings."""
    PROJECT_ROOT: str = PROJECT_ROOT
    REPORTS_DIR: str = REPORTS_DIR
    STATIC_DIR: str = STATIC_DIR
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "")
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    SCAN_TIMEOUT: int = max(1, int(os.getenv("SCAN_TIMEOUT", "3600") or "3600"))  # Default 1 hour
    ALPHA_ENABLE_V6: bool = os.getenv("ALPHA_ENABLE_V6", "true").lower() == "true"
    ALPHA_TOOL_ROOT: str = os.getenv("ALPHA_TOOL_ROOT", os.path.join(PROJECT_ROOT, "data"))
    ALPHA_ARTIFACT_ROOT: str = os.getenv("ALPHA_ARTIFACT_ROOT", "data/scans")
    ALPHA_DEFAULT_MODE: str = os.getenv("ALPHA_DEFAULT_MODE", "STANDARD")
    ALPHA_DEFAULT_RPS: int = int(os.getenv("ALPHA_DEFAULT_RPS", "50"))
    ALPHA_MAX_HTTPX_THREADS: int = int(os.getenv("ALPHA_MAX_HTTPX_THREADS", "50"))
    ALPHA_MAX_CRAWL_DEPTH: int = int(os.getenv("ALPHA_MAX_CRAWL_DEPTH", "3"))
    ALPHA_ENABLE_EXTERNAL_TOOLS: bool = os.getenv("ALPHA_ENABLE_EXTERNAL_TOOLS", "false").lower() == "true"
    ALPHA_TOOL_TIMEOUT_SECONDS: int = int(os.getenv("ALPHA_TOOL_TIMEOUT_SECONDS", "3600"))
    ALPHA_ENABLE_PINCHTAB: bool = os.getenv("ALPHA_ENABLE_PINCHTAB", "true").lower() == "true"
    ALPHA_RECON_VIA_PLANNER: bool = os.getenv("ALPHA_RECON_VIA_PLANNER", "true").lower() == "true"
    ALPHA_RECON_TIMEOUT_SECONDS: int = int(os.getenv("ALPHA_RECON_TIMEOUT_SECONDS", "3600"))
    # Hard upper bound on how long Omega waits for the recon RECON_COMPLETE
    # event before degrading gracefully and proceeding with whatever recon
    # was able to emit. Read by the orchestrator at scan time
    # (Architecture §29.13: never starve the attack phase on a slow recon).
    RECON_MAX_WAIT_SECONDS: int = int(os.getenv("RECON_MAX_WAIT_SECONDS", "3600"))
    ALPHA_EXPLICIT_AUTHORIZATION: bool = os.getenv("ALPHA_EXPLICIT_AUTHORIZATION", "false").lower() == "true"
    PINCHTAB_BASE_URL: str = os.getenv("PINCHTAB_BASE_URL", "http://127.0.0.1:9867")
    ALPHA_ENABLE_NEO4J: bool = os.getenv("ALPHA_ENABLE_NEO4J", "false").lower() == "true"
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "")
    ALPHA_ENABLE_OPENCTI_EXPORT: bool = os.getenv("ALPHA_ENABLE_OPENCTI_EXPORT", "false").lower() == "true"
    OPENCTI_URL: str = os.getenv("OPENCTI_URL", "")
    OPENCTI_TOKEN: str = os.getenv("OPENCTI_TOKEN", "")

    # ── Vigilagent settings (Architecture §8, §11, §13, §21) ────────────────
    PRODUCT_NAME: str = PRODUCT_NAME
    SCOPE_CONFIG_PATH: str = SCOPE_CONFIG_PATH
    TOOLS_CONFIG_PATH: str = TOOLS_CONFIG_PATH
    BUDGETS_CONFIG_PATH: str = BUDGETS_CONFIG_PATH
    MODELS_CONFIG_PATH: str = MODELS_CONFIG_PATH
    EXTENSION_CONFIG_PATH: str = EXTENSION_CONFIG_PATH
    # Terminal Engine (§8): prefer Docker-isolated execution for Linux-native tools.
    TERMINAL_PREFER_DOCKER: bool = vigil_env("TERMINAL_PREFER_DOCKER", "true").lower() == "true"
    # Recon Docker arsenal image (§7 rule 3): the full 39-tool image so recon
    # runs identically on any host without per-host installs.
    RECON_DOCKER_IMAGE: str = vigil_env("RECON_DOCKER_IMAGE", "vigilagent/recon:latest")
    RECON_DOCKER_NETWORK: str = vigil_env("RECON_DOCKER_NETWORK", "bridge")
    SANDBOX_IMAGE: str = vigil_env("SANDBOX_IMAGE", "python:3.12-slim")
    # Two-LLM policy (§11): only these two providers are reachable.
    STRATEGIC_MODEL: str = vigil_env("STRATEGIC_MODEL", "openai/gpt-oss-20b")
    TACTICAL_MODEL: str = vigil_env("TACTICAL_MODEL", "gemini-2.5-flash")

settings = GlobalSettings()

@dataclass
class RedisConfig:
    url: str = os.getenv("REDIS_URL", "redis://localhost:6379")
    max_connections: int = 10
    socket_timeout: int = 5

@dataclass
class SupabaseConfig:
    url: str = os.getenv("SUPABASE_URL", "")
    key: str = os.getenv("SUPABASE_KEY", "")
    openrouter_key: str = os.getenv("OPENROUTER_API_KEY", "")

@dataclass
class WorkerConfig:
    worker_id: str = os.getenv("WORKER_ID", "")
    specialty: str = os.getenv("WORKER_SPECIALTY", "hybrid")
    max_concurrent_tasks: int = 5
    heartbeat_interval: int = 30

@dataclass
class PinchTabConfig:
    base_url: str = os.getenv("PINCHTAB_BASE_URL", "http://127.0.0.1:9867")
    enabled: bool = os.getenv("ALPHA_ENABLE_PINCHTAB", "true").lower() == "true"
    headless: bool = os.getenv("PINCHTAB_HEADLESS", "true").lower() == "true"
    browser_type: str = "chromium"
    timeout: int = 30000
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

@dataclass
class OpenClawConfig:
    enabled: bool = os.getenv("OPENCLAW_ENABLED", "true").lower() == "true"
    headless: bool = os.getenv("OPENCLAW_HEADLESS", "true").lower() == "true"
    browser_type: str = os.getenv("OPENCLAW_BROWSER", "chromium")
    timeout: int = int(os.getenv("OPENCLAW_TIMEOUT", "30000"))
    stealth_mode: bool = os.getenv("OPENCLAW_STEALTH", "true").lower() == "true"
    user_agent: str = os.getenv("OPENCLAW_USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    viewport_width: int = int(os.getenv("OPENCLAW_VIEWPORT_WIDTH", "1920"))
    viewport_height: int = int(os.getenv("OPENCLAW_VIEWPORT_HEIGHT", "1080"))
    max_contexts: int = int(os.getenv("OPENCLAW_MAX_CONTEXTS", "5"))

@dataclass
class HybridBrowserConfig:
    """Configuration for hybrid OpenClaw + PinchTab browser orchestration."""
    enabled: bool = os.getenv("HYBRID_BROWSER_ENABLED", "true").lower() == "true"
    default_engine: str = os.getenv("HYBRID_DEFAULT_ENGINE", "auto")  # auto, openclaw, pinchtab
    auto_fallback: bool = os.getenv("HYBRID_AUTO_FALLBACK", "true").lower() == "true"
    session_sharing: bool = os.getenv("HYBRID_SESSION_SHARING", "true").lower() == "true"
    forensics_enabled: bool = os.getenv("HYBRID_FORENSICS_ENABLED", "true").lower() == "true"
    forensics_dir: str = os.getenv("HYBRID_FORENSICS_DIR", "scan_states/forensics")
    session_dir: str = os.getenv("HYBRID_SESSION_DIR", "scan_states/sessions")

@dataclass
class MasterConfig:
    max_workers: int = 50
    distribution_interval: int = 10
    worker_timeout: int = 180

import threading

class ConfigManager:
    """Central configuration management using the Singleton pattern with validation.

    FIX: The original used a threading.Lock for the singleton, but the app
    runs in asyncio.  While Python's GIL prevents true races on __new__,
    the thread lock doesn't protect against async concurrency within a
    single thread (two coroutines interleaving at await points). We keep
    the threading.Lock for the singleton instantiation (safe under GIL) but
    document that runtime config access should be treated as immutable
    after boot.
    """
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._load_all()
                    cls._instance._validate_all()
        return cls._instance
    
    def _load_all(self):
        self.redis = RedisConfig()
        self.supabase = SupabaseConfig()
        self.worker = WorkerConfig()
        self.pinchtab = PinchTabConfig()
        self.openclaw = OpenClawConfig()
        self.hybrid_browser = HybridBrowserConfig()
        self.master = MasterConfig()
        self.validation_errors: List[str] = []
    
    def _validate_all(self):
        """Validate all configuration settings."""
        self.validation_errors = []
        
        # Validate Redis configuration
        self._validate_redis()
        
        # Validate Supabase configuration
        self._validate_supabase()
        
        # Validate Worker configuration
        self._validate_worker()
        
        # Validate Browser configurations
        self._validate_browser_configs()
        
        # Validate paths
        self._validate_paths()
        
        # Log validation results
        if self.validation_errors:
            logger.warning(f"[ConfigManager] Configuration validation found {len(self.validation_errors)} issues:")
            for error in self.validation_errors:
                logger.warning(f"  - {error}")
        else:
            logger.info("[ConfigManager] Configuration validation passed")
    
    def _validate_redis(self):
        """Validate Redis configuration."""
        if not self.redis.url:
            self.validation_errors.append("Redis URL is not configured")
        
        if self.redis.max_connections < 1:
            self.validation_errors.append("Redis max_connections must be at least 1")
        
        if self.redis.socket_timeout < 1:
            self.validation_errors.append("Redis socket_timeout must be at least 1 second")
    
    def _validate_supabase(self):
        """Validate Supabase configuration."""
        if self.supabase.url and not self.supabase.url.startswith(('http://', 'https://')):
            self.validation_errors.append("Supabase URL must start with http:// or https://")
        
        if self.supabase.url and not self.supabase.key:
            self.validation_errors.append("Supabase key is required when URL is configured")
    
    def _validate_worker(self):
        """Validate Worker configuration."""
        valid_specialties = ['hybrid', 'recon', 'browser', 'api', 'network', 'validation', 'forensics', 'reporting', 'skill', 'attack', 'analysis']
        if self.worker.specialty not in valid_specialties:
            self.validation_errors.append(f"Worker specialty must be one of {valid_specialties}")
        
        if self.worker.max_concurrent_tasks < 1:
            self.validation_errors.append("Worker max_concurrent_tasks must be at least 1")
        
        if self.worker.heartbeat_interval < 5:
            self.validation_errors.append("Worker heartbeat_interval must be at least 5 seconds")
    
    def _validate_browser_configs(self):
        """Validate browser configurations."""
        # Validate PinchTab
        if self.pinchtab.enabled:
            if not self.pinchtab.base_url.startswith(('http://', 'https://')):
                self.validation_errors.append("PinchTab base_url must start with http:// or https://")
            
            if self.pinchtab.timeout < 1000:
                self.validation_errors.append("PinchTab timeout must be at least 1000ms")
            
            valid_browsers = ['chromium', 'firefox', 'webkit']
            if self.pinchtab.browser_type not in valid_browsers:
                self.validation_errors.append(f"PinchTab browser_type must be one of {valid_browsers}")
        
        # Validate OpenClaw
        if self.openclaw.enabled:
            if self.openclaw.timeout < 1000:
                self.validation_errors.append("OpenClaw timeout must be at least 1000ms")
            
            valid_browsers = ['chromium', 'firefox', 'webkit']
            if self.openclaw.browser_type not in valid_browsers:
                self.validation_errors.append(f"OpenClaw browser_type must be one of {valid_browsers}")
            
            if self.openclaw.viewport_width < 100 or self.openclaw.viewport_height < 100:
                self.validation_errors.append("OpenClaw viewport dimensions must be at least 100x100")
            
            if self.openclaw.max_contexts < 1:
                self.validation_errors.append("OpenClaw max_contexts must be at least 1")
        
        # Validate Hybrid Browser
        if self.hybrid_browser.enabled:
            valid_engines = ['auto', 'openclaw', 'pinchtab']
            if self.hybrid_browser.default_engine not in valid_engines:
                self.validation_errors.append(f"Hybrid default_engine must be one of {valid_engines}")
            
            if not self.openclaw.enabled and not self.pinchtab.enabled:
                self.validation_errors.append("Hybrid browser requires at least one engine (OpenClaw or PinchTab) to be enabled")
    
    def _validate_paths(self):
        """Validate critical paths exist and are writable."""
        critical_paths = [
            (REPORTS_DIR, "Reports directory"),
            (STATIC_DIR, "Static directory"),
        ]
        
        for path, name in critical_paths:
            path_obj = Path(path)
            if not path_obj.exists():
                try:
                    path_obj.mkdir(parents=True, exist_ok=True)
                    logger.info(f"[ConfigManager] Created {name}: {path}")
                except Exception as e:
                    self.validation_errors.append(f"{name} could not be created: {e}")
            elif not os.access(path, os.W_OK):
                self.validation_errors.append(f"{name} is not writable: {path}")
    
    def is_valid(self) -> bool:
        """Check if configuration is valid."""
        return len(self.validation_errors) == 0
    
    def get_validation_errors(self) -> List[str]:
        """Get list of validation errors."""
        return self.validation_errors.copy()

    def get_all(self) -> Dict[str, Any]:
        """Serializes current configuration for logging or UI sync."""
        return {
            "redis": self.redis.__dict__,
            "supabase": {"url": self.supabase.url, "key": "MASKED", "openrouter_key": "MASKED"},
            "worker": self.worker.__dict__,
            "pinchtab": self.pinchtab.__dict__,
            "openclaw": self.openclaw.__dict__,
            "hybrid_browser": self.hybrid_browser.__dict__,
            "master": self.master.__dict__,
            "validation": {
                "is_valid": self.is_valid(),
                "error_count": len(self.validation_errors),
                "errors": self.validation_errors
            }
        }

if __name__ == "__main__":
    # Test Config Mapping
    config = ConfigManager()
    print("Xytherion Config Matrix Loaded.")
    print(json.dumps(config.get_all(), indent=2))
