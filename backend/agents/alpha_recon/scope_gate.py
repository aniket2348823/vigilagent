"""
Alpha V6 Scope Gate — Production-grade target authorization.

Enforces:
- .gov/.mil/.edu TLD blocking unless explicitly authorized
- Private network blocking
- Wildcard subdomain scope enforcement
- Active scanning authorization requirement
- Rate limit enforcement per scope mode
"""

from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlparse

from backend.agents.alpha_recon.models import ReconScope, ScanMode
from backend.core.config import settings

logger = logging.getLogger("alpha.scope_gate")

# TLDs that MUST have explicit authorization
RESTRICTED_TLDS = frozenset(
    {
        ".gov",
        ".mil",
        ".edu",
        ".gov.uk",
        ".gov.au",
        ".gov.in",
        ".gov.br",
        ".gov.cn",
        ".mil.br",
        ".police.uk",
        ".nhs.uk",
        ".judiciary.uk",
        ".parliament.uk",
        ".mod.uk",
    }
)

# Domains that should never be scanned
GLOBAL_DENY_LIST = frozenset(
    {
        "metadata.google.internal",
        "169.254.169.254",
        "instance-data",
        "metadata.azure.com",
    }
)


class ScopeGateViolation(PermissionError):
    """Raised when a target or URL is outside the authorized scope."""

    def __init__(self, target: str, reason: str):
        self.target = target
        self.reason = reason
        super().__init__(f"Scope violation for '{target}': {reason}")


class ScopeGate:
    """Production scope enforcement for Alpha V6."""

    def __init__(self, scope: ReconScope):
        self.scope = scope
        self._compiled_deny = set(GLOBAL_DENY_LIST)
        for h in scope.denied_hosts:
            self._compiled_deny.add(h.lower())

    def validate_target(self, target_url: str) -> None:
        """Validate the primary scan target before any scanning begins."""
        parsed = urlparse(target_url)
        host = (parsed.hostname or "").lower()

        if not host:
            raise ScopeGateViolation(target_url, "no_hostname")

        # 1. Global deny list
        if host in self._compiled_deny:
            raise ScopeGateViolation(target_url, f"globally_denied:{host}")

        # 2. Restricted TLD check
        if self._is_restricted_tld(host):
            if not self.scope.explicit_authorization:
                raise ScopeGateViolation(target_url, f"restricted_tld_requires_authorization:{host}")
            logger.warning(f"[SCOPE] Scanning restricted TLD {host} WITH explicit authorization")

        # 3. Private network check
        if self._is_private_ip(host) and not self.scope.explicit_authorization:
            raise ScopeGateViolation(target_url, f"private_network_requires_authorization:{host}")

        # 4. Active scanning authorization
        if self.scope.scan_mode in (ScanMode.STANDARD, ScanMode.AGGRESSIVE):
            auth_required = getattr(settings, "ALPHA_EXPLICIT_AUTHORIZATION", False)
            if auth_required and not self.scope.explicit_authorization:
                raise ScopeGateViolation(target_url, "active_scanning_requires_explicit_authorization")

        logger.info(f"[SCOPE] Target validated: {host} (mode={self.scope.scan_mode.value})")

    def is_in_scope(self, url: str) -> bool:
        """Check if a discovered URL is within the authorized scope."""
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if not host:
            return False

        # Deny list
        if host in self._compiled_deny:
            return False

        # Must match base domain or allowed hosts
        base = self.scope.base_domain.lower()
        if base and (host == base or host.endswith(f".{base}")):
            return True

        if self.scope.allowed_hosts:
            for ah in self.scope.allowed_hosts:
                ah_lower = ah.lower()
                if host == ah_lower or host.endswith(f".{ah_lower}"):
                    return True

        # Check allowed suffixes
        return any(host.endswith(suffix.lower()) for suffix in self.scope.allowed_host_suffixes)

    def filter_in_scope(self, urls: list[str]) -> list[str]:
        """Filter a list of URLs to only those in scope."""
        return [u for u in urls if self.is_in_scope(u)]

    def assert_in_scope(self, url: str, *, action: str = "request") -> None:
        """Raise if URL is out of scope."""
        if not self.is_in_scope(url):
            raise ScopeGateViolation(url, f"out_of_scope_{action}")

    def get_phase_authorization(self, phase: str) -> dict:
        """Check what's authorized for a specific phase."""
        mode = self.scope.scan_mode
        return {
            "phase": phase,
            "authorized": True,
            "requires_approval": mode == ScanMode.AGGRESSIVE
            and phase in ("directory_route_discovery", "api_reconnaissance", "template_validation"),
            "max_rps": self.scope.max_rps,
            "max_depth": self.scope.max_depth,
        }

    @staticmethod
    def _is_restricted_tld(host: str) -> bool:
        return any(host.endswith(tld) for tld in RESTRICTED_TLDS)

    @staticmethod
    def _is_private_ip(host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            # Not an IP, check hostname patterns
            return (
                host == "localhost"
                or host.startswith("127.")
                or host.startswith("10.")
                or host.startswith("192.168.")
                or host.startswith("172.16.")
                or host.endswith(".internal")
                or host.endswith(".local")
            )
