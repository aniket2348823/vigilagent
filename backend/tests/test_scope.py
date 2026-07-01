"""
Tests for scope validation.
"""

import pytest
from backend.core.scope import ScopePolicy, ScopeViolation


class TestScopePolicy:
    """Tests for ScopePolicy class."""

    def test_allows_localhost_when_configured(self):
        """Test that localhost is allowed when in scope."""
        policy = ScopePolicy(
            allowed_hosts={"localhost", "127.0.0.1"},
            authorization="explicit",
        )
        assert policy.allows("http://localhost:8080") is True
        assert policy.allows("http://127.0.0.1:8080") is True

    def test_denies_unknown_host(self):
        """Test that unknown hosts are denied."""
        policy = ScopePolicy(
            allowed_hosts={"localhost"},
            authorization="explicit",
        )
        assert policy.allows("http://example.com") is False

    def test_denies_when_not_authorized(self):
        """Test that active actions are denied when not authorized."""
        policy = ScopePolicy(
            allowed_hosts={"localhost"},
            authorization="none",
        )
        with pytest.raises(ScopeViolation):
            policy.assert_allowed("http://localhost:8080", action="exploit")

    def test_allows_when_authorized(self):
        """Test that active actions are allowed when authorized."""
        policy = ScopePolicy(
            allowed_hosts={"localhost"},
            authorization="explicit",
        )
        # Should not raise
        policy.assert_allowed("http://localhost:8080", action="exploit")

    def test_denied_url_globs(self):
        """Test that denied URL globs are respected."""
        policy = ScopePolicy(
            allowed_hosts={"localhost"},
            authorization="explicit",
            denied_url_globs=["*://*/logout*"],
        )
        assert policy.allows("http://localhost/logout") is False
        assert policy.allows("http://localhost/login") is True

    def test_cidr_matching(self):
        """Test CIDR matching for allowed networks."""
        policy = ScopePolicy(
            allowed_cidrs=["10.0.0.0/8"],
            authorization="explicit",
        )
        assert policy.allows("http://10.0.0.1") is True
        assert policy.allows("http://192.168.1.1") is False

    def test_port_restriction(self):
        """Test port restriction when configured."""
        policy = ScopePolicy(
            allowed_hosts={"localhost"},
            allowed_ports={8080, 8000},
            authorization="explicit",
        )
        assert policy.allows("http://localhost:8080") is True
        assert policy.allows("http://localhost:3000") is False

    def test_private_networks_blocked_by_default(self):
        """Test that private networks are blocked unless explicitly allowed."""
        policy = ScopePolicy(
            allowed_hosts={"10.0.0.1"},
            allow_private_networks=False,
            authorization="explicit",
        )
        assert policy.allows("http://10.0.0.1") is True  # Explicitly allowed
        assert policy.allows("http://192.168.1.1") is False  # Not in allowed_hosts


class TestScopeViolation:
    """Tests for ScopeViolation exception."""

    def test_inherits_from_permission_error(self):
        """Test that ScopeViolation inherits from PermissionError."""
        assert issubclass(ScopeViolation, PermissionError)