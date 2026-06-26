"""
Vigilagent Scope Policy (Architecture §2.1, §9, §10, §29.2)
================================================================================
"Scope is law." Every network request, browser action, command execution, tool
run, and extension-captured event must pass scope validation before execution
or ingestion.

This is the single authorization authority for the HTTP client, browser
orchestrator, exploit/validation engines, recon Terminal Engine, and the
extension bridge.

Scope model (Architecture §10):
  - allowed_hosts / allowed_cidrs / allowed_url_globs
  - denied_hosts / denied_url_globs
  - allowed_ports
  - engagement window [starts_at, ends_at]
  - authorization master switch (none => passive/recon only)
  - max_rps / max_concurrency
  - extension capture allowlist
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from collections.abc import Iterable

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

logger = logging.getLogger("vigilagent.scope")

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SCOPE_FILE = _PROJECT_ROOT / "config" / "scope.yaml"


class ScopeViolation(PermissionError):
    """Raised when an action targets an out-of-scope resource."""


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except Exception as exc:
        logger.warning("Could not parse scope datetime: %s: %s", value, exc)
        return None


@dataclass
class ScopePolicy:
    allowed_hosts: set[str] = field(default_factory=set)
    allowed_cidrs: list[str] = field(default_factory=list)
    allowed_url_globs: list[str] = field(default_factory=list)
    denied_hosts: set[str] = field(default_factory=set)
    denied_url_globs: list[str] = field(default_factory=list)
    allowed_ports: set[int] = field(default_factory=set)
    allow_private_networks: bool = False

    # Engagement governance (Architecture §9, §10)
    engagement_name: str = "default"
    authorization: str = "none"  # "none" => passive/recon only; "explicit" => active allowed
    window_start: datetime | None = None
    window_end: datetime | None = None

    # Limits (Architecture §10)
    max_rps: int = 25
    max_concurrency: int = 8
    max_runtime_minutes: int = 120

    # Extension capture allowlist (Architecture §19)
    extension_capture_allowlist: set[str] = field(default_factory=set)

    # ── Construction ─────────────────────────────────────────────────────────

    @classmethod
    def from_target(cls, target_url: str | None = None, extra_hosts: Iterable[str] = ()) -> ScopePolicy:
        """Build scope from a single target URL.

        SECURITY: Defaults to passive/recon-only mode (authorization="none").
        Active testing requires explicit authorization via scope.yaml or
        ALPHA_EXPLICIT_AUTHORIZATION=true environment variable.
        """
        hosts = {host.lower() for host in extra_hosts if host}
        if target_url:
            parsed = urlparse(target_url)
            if parsed.hostname:
                hosts.add(parsed.hostname.lower())

        # SECURITY: Default to passive mode unless explicitly authorized
        import os

        auth_mode = "none"
        if os.getenv("ALPHA_EXPLICIT_AUTHORIZATION", "false").lower() == "true":
            auth_mode = "explicit"

        return cls(allowed_hosts=hosts, authorization=auth_mode)

    @classmethod
    def from_yaml(cls, path: str | Path | None = None) -> ScopePolicy:
        """Load the declarative engagement scope from config/scope.yaml."""
        cfg_path = Path(path) if path else _SCOPE_FILE
        if yaml is None or not cfg_path.exists():
            logger.info("No scope.yaml found; starting in passive/recon-only mode.")
            return cls(authorization="none")
        try:
            data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            logger.error("Failed to parse scope.yaml (%s); defaulting to passive.", exc)
            return cls(authorization="none")

        engagement = data.get("engagement", {}) or {}
        scope = data.get("scope", {}) or {}
        limits = data.get("limits", {}) or {}

        return cls(
            allowed_hosts={h.lower() for h in scope.get("allowed_hosts", []) or []},
            allowed_cidrs=list(scope.get("allowed_cidrs", []) or []),
            allowed_url_globs=list(scope.get("allowed_url_globs", []) or []),
            denied_hosts={h.lower() for h in scope.get("denied_hosts", []) or []},
            denied_url_globs=list(scope.get("denied_url_globs", []) or []),
            allowed_ports={int(p) for p in scope.get("allowed_ports", []) or []},
            allow_private_networks=bool(scope.get("allow_private_networks", False)),
            extension_capture_allowlist=set(scope.get("extension_capture_allowlist", []) or []),
            engagement_name=str(engagement.get("name", "default")),
            authorization=str(engagement.get("authorization", "none")).lower(),
            window_start=_parse_iso(engagement.get("starts_at")),
            window_end=_parse_iso(engagement.get("ends_at")),
            max_rps=int(limits.get("max_rps", 25)),
            max_concurrency=int(limits.get("max_concurrency", 8)),
            max_runtime_minutes=int(limits.get("max_runtime_minutes", 120)),
        )

    # ── Authorization state (Architecture §9) ─────────────────────────────────

    def is_authorized(self, *, now: datetime | None = None) -> bool:
        """True only when active testing is explicitly authorized AND the
        current time is within the engagement window."""
        if self.authorization != "explicit":
            return False
        return self.within_window(now=now)

    def within_window(self, *, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        if self.window_start and now < self.window_start:
            return False
        return not (self.window_end and now > self.window_end)

    # ── Decisions ──────────────────────────────────────────────────────────────

    def allows(self, url: str) -> bool:
        parsed = urlparse(url if "://" in url else f"//{url}", scheme="")
        host = (parsed.hostname or "").lower()
        normalized = url.lower()
        if not host:
            return False

        # Denylists take precedence.
        if host in self.denied_hosts:
            return False
        if any(fnmatch(normalized, pattern.lower()) for pattern in self.denied_url_globs):
            return False

        # Port restriction (only when a port is present and a list is configured).
        if self.allowed_ports and parsed.port is not None and parsed.port not in self.allowed_ports:
            return False

        host_allowed = self._host_in_scope(host)
        glob_allowed = not self.allowed_url_globs or any(
            fnmatch(normalized, pattern.lower()) for pattern in self.allowed_url_globs
        )

        # If any allowlist is configured, the target must satisfy it.
        if (self.allowed_hosts or self.allowed_cidrs) and not host_allowed:
            return False
        if self.allowed_url_globs and not glob_allowed:
            return False

        # Private networks blocked unless explicitly allowed or explicitly listed.
        if not self.allow_private_networks and _is_private_like(host):
            return host in self.allowed_hosts or self._cidr_match(host)

        # MED-13: With no allowlist at all, deny by default (safe-by-default).
        # Previously this returned True, allowing any public host.
        if not (self.allowed_hosts or self.allowed_cidrs or self.allowed_url_globs):
            return False

        return host_allowed or glob_allowed

    def _host_in_scope(self, host: str) -> bool:
        if host in self.allowed_hosts:
            return True
        # Wildcard host entries (e.g. "*.acme.com").
        if any("*" in h and fnmatch(host, h) for h in self.allowed_hosts):
            return True
        return self._cidr_match(host)

    def _cidr_match(self, host: str) -> bool:
        if not self.allowed_cidrs:
            return False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        for cidr in self.allowed_cidrs:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def assert_allowed(self, url: str, *, action: str = "request") -> None:
        """Raise ScopeViolation if the URL is out of scope, or if an active
        action is attempted without authorization (Architecture §9, §29.14)."""
        active_actions = {"exploit", "validate", "attack", "intrusive"}
        if action in active_actions and not self.is_authorized():
            raise ScopeViolation(
                f"Blocked {action}: engagement not authorized or outside window (authorization={self.authorization})"
            )
        if not self.allows(url):
            raise ScopeViolation(f"Blocked out-of-scope {action}: {url}")

    def allows_extension_capture(self, capture_type: str) -> bool:
        """Whether the extension bridge may ingest this data class (§19)."""
        if not self.extension_capture_allowlist:
            return False
        return capture_type in self.extension_capture_allowlist

    def to_dict(self) -> dict:
        return {
            "engagement_name": self.engagement_name,
            "authorization": self.authorization,
            "authorized_now": self.is_authorized(),
            "window_start": self.window_start.isoformat() if self.window_start else None,
            "window_end": self.window_end.isoformat() if self.window_end else None,
            "allowed_hosts": sorted(self.allowed_hosts),
            "allowed_cidrs": list(self.allowed_cidrs),
            "allowed_url_globs": list(self.allowed_url_globs),
            "denied_url_globs": list(self.denied_url_globs),
            "allow_private_networks": self.allow_private_networks,
            "max_rps": self.max_rps,
            "max_concurrency": self.max_concurrency,
        }


def _is_private_like(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


# Global guard. Loads engagement scope from config/scope.yaml when present,
# otherwise starts in safe passive/recon-only mode.
scope_guard = ScopePolicy.from_yaml()

# Backward-compatible alias (FIX)
ScopeGuard = ScopePolicy
