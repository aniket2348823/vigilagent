"""
Centralized Error Types (Architecture security hardening)
================================================================================
Defines a hierarchy of application-specific exceptions for consistent error
handling across the Vigilagent system. Replaces ad-hoc string-based errors.
"""

from __future__ import annotations


class VigilagentError(Exception):
    """Base exception for all Vigilagent errors."""

    def __init__(self, message: str, code: str = "UNKNOWN", details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


class ScopeViolation(VigilagentError):
    """Raised when an action falls outside the authorized engagement scope."""

    def __init__(self, message: str, target: str = "", action: str = "", **kwargs):
        super().__init__(message, code="SCOPE_VIOLATION", details={"target": target, "action": action, **kwargs})
        self.target = target
        self.action = action


class AuthenticationError(VigilagentError):
    """Raised when authentication fails."""

    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(message, code="AUTH_FAILED", **kwargs)


class AuthorizationError(VigilagentError):
    """Raised when authorization fails."""

    def __init__(self, message: str = "Authorization denied", required_permission: str = "", **kwargs):
        super().__init__(message, code="AUTH_DENIED", details={"required": required_permission, **kwargs})


class RateLimitError(VigilagentError):
    """Raised when rate limit is exceeded."""

    def __init__(self, message: str = "Rate limit exceeded", retry_after: int = 60, **kwargs):
        super().__init__(message, code="RATE_LIMITED", details={"retry_after": retry_after, **kwargs})
        self.retry_after = retry_after


class ToolExecutionError(VigilagentError):
    """Raised when a tool execution fails."""

    def __init__(self, message: str, tool_name: str = "", exit_code: int = -1, **kwargs):
        super().__init__(message, code="TOOL_FAILED", details={"tool": tool_name, "exit_code": exit_code, **kwargs})
        self.tool_name = tool_name
        self.exit_code = exit_code


class SkillError(VigilagentError):
    """Raised when skill loading/execution fails."""

    def __init__(self, message: str, skill_id: str = "", **kwargs):
        super().__init__(message, code="SKILL_ERROR", details={"skill_id": skill_id, **kwargs})
        self.skill_id = skill_id


class MemoryProviderError(VigilagentError):
    """Raised when memory operations fail."""

    def __init__(self, message: str, provider: str = "", **kwargs):
        super().__init__(message, code="MEMORY_ERROR", details={"provider": provider, **kwargs})
        self.provider = provider


class LLMError(VigilagentError):
    """Raised when LLM operations fail."""

    def __init__(self, message: str, provider: str = "", model: str = "", **kwargs):
        super().__init__(message, code="LLM_ERROR", details={"provider": provider, "model": model, **kwargs})
        self.provider = provider
        self.model = model


class ConfigurationError(VigilagentError):
    """Raised when configuration is invalid or missing."""

    def __init__(self, message: str, config_key: str = "", **kwargs):
        super().__init__(message, code="CONFIG_ERROR", details={"key": config_key, **kwargs})
        self.config_key = config_key


class IntegrityError(VigilagentError):
    """Raised when data integrity checks fail (HMAC, checksums)."""

    def __init__(self, message: str, data_type: str = "", **kwargs):
        super().__init__(message, code="INTEGRITY_ERROR", details={"data_type": data_type, **kwargs})
        self.data_type = data_type
