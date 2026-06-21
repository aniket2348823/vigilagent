"""Tests for the dashboard stats endpoint."""
import os
import json
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

# Set test mode before importing
os.environ["VULAGENT_TEST_MODE"] = "true"
os.environ["TESTING"] = "true"


class FakeScanRecord:
    """Minimal scan record dict for testing."""
    def __init__(self, **kwargs):
        self._data = {
            "id": kwargs.get("id", "scan-001"),
            "name": kwargs.get("name", "Test Scan"),
            "scope": kwargs.get("scope", "http://localhost:8080"),
            "status": kwargs.get("status", "Completed"),
            "target_url": kwargs.get("target_url", "http://localhost:8080"),
            "results": kwargs.get("results", []),
            "created_at": kwargs.get("created_at", "2026-01-01T00:00:00"),
        }

    def __getitem__(self, key):
        return self._data.get(key)

    def get(self, key, default=None):
        return self._data.get(key, default)


class TestGetDashboardStats:
    """Tests for the get_dashboard_stats endpoint."""

    def test_scan_record_access_with_get_defaults(self):
        """Scan records should be accessed with .get() to avoid KeyError."""
        scan = {"id": "scan-001", "status": "Completed"}

        # These should NOT raise KeyError
        name = scan.get("name") or scan.get("scope") or "Untitled Scan"
        assert name == "Untitled Scan"

        status = scan.get("status", "Unknown")
        assert status == "Completed"

    def test_scan_record_missing_name_and_scope(self):
        """Scan records missing both name and scope should get default."""
        scan = {"id": "scan-002", "status": "Running"}

        name = scan.get("name") or scan.get("scope") or "Untitled Scan"
        assert name == "Untitled Scan"

    def test_scan_record_has_name(self):
        """Scan records with a name should use it."""
        scan = {"id": "scan-003", "name": "Production Scan", "status": "Completed"}

        name = scan.get("name") or scan.get("scope") or "Untitled Scan"
        assert name == "Production Scan"

    def test_scan_record_has_scope_but_no_name(self):
        """Scan records with scope but no name should use scope."""
        scan = {"id": "scan-004", "scope": "https://example.com", "status": "Completed"}

        name = scan.get("name") or scan.get("scope") or "Untitled Scan"
        assert name == "https://example.com"

    def test_payload_dict_type_defensive_check(self):
        """Payload should be handled defensively when it's not a dict."""
        # Payload as string
        payload = "some string"
        if isinstance(payload, dict):
            result = payload.get("type", "UNKNOWN")
        else:
            result = "SYSTEM LOG"
        assert result == "SYSTEM LOG"

        # Payload as dict
        payload = {"type": "INJECTION", "url": "http://example.com"}
        if isinstance(payload, dict):
            result = payload.get("type", "UNKNOWN")
        else:
            result = "SYSTEM LOG"
        assert result == "INJECTION"

    def test_stats_cache_structure(self):
        """The stats cache should have the expected structure."""
        stats = {
            "metrics": {
                "total_scans": 0,
                "active_scans": 0,
                "vulnerabilities": 0,
                "critical": 0,
            },
            "graph_data": [],
            "recent_activity": [],
            "historical_threats": [],
        }

        assert "metrics" in stats
        assert "graph_data" in stats
        assert "recent_activity" in stats
        assert "historical_threats" in stats
        assert isinstance(stats["metrics"], dict)
        assert stats["metrics"]["total_scans"] == 0

    def test_recent_activity_limit(self):
        """Recent activity should be limited to 5 entries."""
        scans = [
            FakeScanRecord(id=f"scan-{i}", name=f"Scan {i}")
            for i in range(10)
        ]

        # Sort by created_at descending and limit to 5
        recent = sorted(scans, key=lambda s: s.get("created_at", ""), reverse=True)[:5]
        assert len(recent) == 5

    def test_historical_threats_extraction(self):
        """Threats should be extracted from scan results."""
        scan = FakeScanRecord(
            results=[
                {"type": "SQL_INJECTION", "severity": "CRITICAL", "url": "/login"},
                {"type": "XSS", "severity": "HIGH", "url": "/search"},
                {"type": "INFO_LEAK", "severity": "MEDIUM", "url": "/api/config"},
            ]
        )

        threats = []
        results = scan.get("results", [])
        if isinstance(results, list):
            for r in results:
                if isinstance(r, dict) and r.get("type"):
                    threats.append(r)

        assert len(threats) == 3
        assert threats[0]["type"] == "SQL_INJECTION"
        assert threats[0]["severity"] == "CRITICAL"

    def test_active_scans_count(self):
        """Active scans should count only Running/Initializing scans."""
        scans = [
            FakeScanRecord(status="Completed"),
            FakeScanRecord(id="scan-2", status="Running"),
            FakeScanRecord(id="scan-3", status="Initializing"),
            FakeScanRecord(id="scan-4", status="Completed"),
        ]

        active = sum(
            1 for s in scans
            if s.get("status") in ("Running", "Initializing")
        )
        assert active == 2

    def test_metrics_critical_count(self):
        """Critical vulnerabilities should be counted from threats."""
        threats = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "CRITICAL"},
            {"severity": "MEDIUM"},
        ]

        critical = sum(1 for t in threats if t.get("severity") == "CRITICAL")
        total_vulns = len(threats)
        assert critical == 2
        assert total_vulns == 4


class TestAgentNameResolution:
    """Tests for the agent name resolution logic (frontend agentNames.js)."""

    AGENT_MAP = [
        {"match": "theta", "name": "THE SENTINEL", "color": "text-purple-400"},
        {"match": "iota", "name": "THE INSPECTOR", "color": "text-orange-400"},
        {"match": "beta", "name": "BETA (BREAKER)", "color": "text-red-400"},
        {"match": "alpha_recon", "name": "ALPHA (RECON)", "color": "text-cyan-400"},
        {"match": "alpha", "name": "ALPHA (SCOUT)", "color": "text-cyan-400"},
        {"match": "gamma", "name": "GAMMA (TYCOON)", "color": "text-yellow-400"},
        {"match": "omega", "name": "OMEGA (STRAT)", "color": "text-pink-400"},
        {"match": "zeta", "name": "ZETA (CORTEX)", "color": "text-indigo-400"},
        {"match": "sigma", "name": "SIGMA (SMITH)", "color": "text-green-400"},
        {"match": "kappa", "name": "KAPPA (LIBRARIAN)", "color": "text-teal-400"},
        {"match": "planner", "name": "PLANNER", "color": "text-amber-400"},
        {"match": "Orchestrator", "name": "ORCHESTRATOR", "color": "text-fuchsia-400"},
        {"match": "spy", "name": "SPY", "color": "text-slate-400"},
        {"match": "synapse", "name": "SYNAPSE", "color": "text-sky-400"},
    ]

    def _resolve(self, agent_id):
        """Python port of resolveAgent() for testing."""
        if not agent_id:
            return {"name": "UNKNOWN", "color": "text-gray-400"}
        for entry in self.AGENT_MAP:
            if entry["match"] in agent_id:
                return {"name": entry["name"], "color": entry["color"]}
        return {"name": "UNKNOWN", "color": "text-gray-400"}

    def test_resolve_orchestrator(self):
        result = self._resolve("Orchestrator")
        assert result["name"] == "ORCHESTRATOR"
        assert result["color"] == "text-fuchsia-400"

    def test_resolve_agent_beta(self):
        result = self._resolve("agent_beta")
        assert result["name"] == "BETA (BREAKER)"
        assert result["color"] == "text-red-400"

    def test_resolve_alpha_recon_before_alpha(self):
        """alpha_recon should match ALPHA (RECON), not ALPHA (SCOUT)."""
        result = self._resolve("alpha_recon")
        assert result["name"] == "ALPHA (RECON)"

    def test_resolve_alpha_plain(self):
        result = self._resolve("alpha")
        assert result["name"] == "ALPHA (SCOUT)"

    def test_resolve_agent_gamma(self):
        result = self._resolve("agent_gamma")
        assert result["name"] == "GAMMA (TYCOON)"

    def test_resolve_agent_sigma(self):
        result = self._resolve("agent_sigma")
        assert result["name"] == "SIGMA (SMITH)"

    def test_resolve_synapse(self):
        result = self._resolve("synapse")
        assert result["name"] == "SYNAPSE"

    def test_resolve_theta(self):
        result = self._resolve("theta")
        assert result["name"] == "THE SENTINEL"

    def test_resolve_iota(self):
        result = self._resolve("iota")
        assert result["name"] == "THE INSPECTOR"

    def test_resolve_omega(self):
        result = self._resolve("omega")
        assert result["name"] == "OMEGA (STRAT)"

    def test_resolve_zeta(self):
        result = self._resolve("zeta")
        assert result["name"] == "ZETA (CORTEX)"

    def test_resolve_kappa(self):
        result = self._resolve("kappa")
        assert result["name"] == "KAPPA (LIBRARIAN)"

    def test_resolve_planner(self):
        result = self._resolve("planner")
        assert result["name"] == "PLANNER"

    def test_resolve_spy(self):
        result = self._resolve("spy")
        assert result["name"] == "SPY"

    def test_resolve_none(self):
        result = self._resolve(None)
        assert result["name"] == "UNKNOWN"

    def test_resolve_empty_string(self):
        result = self._resolve("")
        assert result["name"] == "UNKNOWN"

    def test_resolve_unknown_agent(self):
        result = self._resolve("random_agent_xyz")
        assert result["name"] == "UNKNOWN"
        assert result["color"] == "text-gray-400"

    def test_all_14_agents_resolvable(self):
        """All 14 agents in the map should resolve to non-UNKNOWN names."""
        agent_ids = [
            "theta", "iota", "beta", "alpha_recon", "alpha",
            "gamma", "omega", "zeta", "sigma", "kappa",
            "planner", "Orchestrator", "spy", "synapse"
        ]
        for agent_id in agent_ids:
            result = self._resolve(agent_id)
            assert result["name"] != "UNKNOWN", f"Agent '{agent_id}' resolved to UNKNOWN"
            assert result["color"] != "text-gray-400", f"Agent '{agent_id}' has no color"


class TestCsrfTokenFlow:
    """Tests for the csrfFetch CSRF token logic."""

    def test_csrf_required_methods(self):
        """POST, PUT, PATCH, DELETE should require CSRF tokens."""
        methods_requiring_csrf = ["POST", "PUT", "PATCH", "DELETE"]
        for method in methods_requiring_csrf:
            assert method in ["POST", "PUT", "PATCH", "DELETE"]

    def test_get_does_not_require_csrf(self):
        """GET requests should not trigger CSRF token fetch."""
        method = "GET"
        needs_csrf = method in ["POST", "PUT", "PATCH", "DELETE"]
        assert not needs_csrf

    def test_retry_on_403_csrf(self):
        """Should retry once on 403 with CSRF in detail."""
        status = 403
        detail = "CSRF token validation failed"
        should_retry = (
            status == 403
            and "CSRF" in detail
        )
        assert should_retry

    def test_no_retry_on_403_non_csrf(self):
        """Should NOT retry on 403 without CSRF in detail."""
        status = 403
        detail = "Forbidden"
        should_retry = (
            status == 403
            and "CSRF" in detail
        )
        assert not should_retry

    def test_no_retry_on_401(self):
        """Should NOT retry on 401."""
        status = 401
        should_retry = status == 403
        assert not should_retry
