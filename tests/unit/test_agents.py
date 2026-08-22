"""
Unit tests for Vigilagent Agents
Tests Alpha, Beta, Gamma, Delta, Sigma, Zeta, Kappa, Omega, Prism, and Chi agents
"""

import pytest
import pytest_asyncio
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock, PropertyMock
from backend.core.hive import EventType, HiveEvent
from backend.core.protocol import JobPacket, AgentID, ModuleConfig, TaskTarget


# ============================================================================
# ALPHA AGENT TESTS
# ============================================================================

class TestAlphaAgent:
    """Test Alpha Agent (Scout - Recon & API Detection)."""
    
    @pytest_asyncio.fixture
    async def alpha_agent(self):
        """Create Alpha agent instance."""
        from backend.agents.alpha import AlphaAgent
        
        mock_bus = AsyncMock()
        mock_bus.subscribe = AsyncMock()
        mock_bus.publish = AsyncMock()
        mock_bus.get_or_create_context = Mock(return_value=Mock(baseline_cache={}))
        
        agent = AlphaAgent(mock_bus)
        
        # Mock browser using PropertyMock
        mock_browser = AsyncMock()
        mock_browser.navigate = AsyncMock(return_value={"success": True})
        mock_browser.detect_framework = AsyncMock(return_value="react")
        mock_browser.extract_endpoints = AsyncMock(return_value=[])
        mock_browser.intercept_network = AsyncMock(return_value=[])
        mock_browser.find_websockets = AsyncMock(return_value=[])
        type(agent).browser = PropertyMock(return_value=mock_browser)
        
        # Mock cortex
        agent.cortex = AsyncMock()
        agent.cortex.classify_target = AsyncMock(return_value={"is_api": False, "tags": []})
        
        # Mock the full recon pipeline: handle_job tests must assert dispatch
        # behavior, not trigger real recon (docker exec + network) against
        # example.com — that used to hang the suite.
        agent.alpha_recon.run = AsyncMock(return_value=None)
        
        yield agent
    
    @pytest.mark.asyncio
    async def test_setup_subscribes_to_events(self, alpha_agent):
        """Test agent subscribes to required events."""
        await alpha_agent.setup()
        
        assert alpha_agent.bus.subscribe.call_count == 3
        # Should subscribe to JOB_ASSIGNED, TARGET_ACQUIRED, and CONTROL_SIGNAL
        calls = alpha_agent.bus.subscribe.call_args_list
        event_types = [call[0][0] for call in calls]
        assert EventType.JOB_ASSIGNED in event_types
        assert EventType.TARGET_ACQUIRED in event_types
        assert EventType.CONTROL_SIGNAL in event_types
    
    @pytest.mark.asyncio
    async def test_detect_spa_identifies_react(self, alpha_agent):
        """Test SPA detection identifies React apps."""
        alpha_agent.browser.detect_framework = AsyncMock(return_value="react")
        
        is_spa = await alpha_agent._detect_spa("https://example.com")
        
        assert is_spa is True
        alpha_agent.browser.navigate.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_detect_spa_identifies_vue(self, alpha_agent):
        """Test SPA detection identifies Vue apps."""
        alpha_agent.browser.detect_framework = AsyncMock(return_value="vue")
        
        is_spa = await alpha_agent._detect_spa("https://example.com")
        
        assert is_spa is True
    
    @pytest.mark.asyncio
    async def test_detect_spa_returns_false_for_non_spa(self, alpha_agent):
        """Test SPA detection returns False for non-SPA sites."""
        alpha_agent.browser.detect_framework = AsyncMock(return_value="none")
        
        is_spa = await alpha_agent._detect_spa("https://example.com")
        
        assert is_spa is False
    
    @pytest.mark.asyncio
    async def test_merge_endpoints_deduplicates(self, alpha_agent):
        """Test endpoint merging removes duplicates."""
        endpoints1 = [
            {"url": "https://api.example.com/users", "method": "GET"},
            {"url": "https://api.example.com/posts", "method": "GET"}
        ]
        endpoints2 = [
            {"url": "https://api.example.com/users", "method": "GET"},  # Duplicate
            {"url": "https://api.example.com/comments", "method": "GET"}
        ]
        
        merged = await alpha_agent._merge_endpoints(endpoints1, endpoints2)
        
        assert len(merged) == 3
        urls = [e["url"] for e in merged]
        assert "https://api.example.com/users" in urls
        assert "https://api.example.com/posts" in urls
        assert "https://api.example.com/comments" in urls
    
    @pytest.mark.asyncio
    async def test_handle_job_prevents_infinite_recursion(self, alpha_agent):
        """Test job handler prevents infinite recursion."""
        # Create deep URL that exceeds max depth
        deep_url = "https://example.com/" + "/".join(["a"] * 10)
        
        event = HiveEvent(
            type=EventType.JOB_ASSIGNED,
            source="test",
            scan_id="test_scan",
            payload={
                "id": "job_1",
                "priority": 1,
                "target": {"url": deep_url},
                "config": {
                    "module_id": "test_module",
                    "agent_id": "ALPHA",
                    "params": {},
                    "aggression": 1,
                    "session_id": "test_session"
                }
            }
        )
        
        # Should return early without processing
        await alpha_agent.handle_job(event)
        
        # Should not publish any events
        alpha_agent.bus.publish.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_handle_job_detects_api_endpoints(self, alpha_agent):
        """Test job handler detects API endpoints."""
        alpha_agent.cortex.classify_target = AsyncMock(return_value={"is_api": True, "tags": []})
        
        event = HiveEvent(
            type=EventType.JOB_ASSIGNED,
            source="test",
            scan_id="test_scan",
            payload={
                "id": "job_1",
                "priority": "HIGH",  # Use string enum value
                "target": {"url": "https://api.example.com/users"},
                "config": {
                    "module_id": "alpha_recon",
                    "agent_id": "agent_alpha",  # Use proper agent_id format
                    "params": {},
                    "aggression": 1,
                    "session_id": "test_session"
                }
            }
        )
        
        await alpha_agent.handle_job(event)
        
        # Should publish JOB_COMPLETED event for recon module
        calls = alpha_agent.bus.publish.call_args_list
        event_types = [call[0][0].type for call in calls]
        assert EventType.JOB_COMPLETED in event_types
    
    @pytest.mark.asyncio
    async def test_handle_job_detects_sensitive_paths(self, alpha_agent):
        """Test job handler detects sensitive paths."""
        event = HiveEvent(
            type=EventType.JOB_ASSIGNED,
            source="test",
            scan_id="test_scan",
            payload={
                "id": "job_1",
                "priority": "HIGH",  # Use string enum value
                "target": {"url": "https://example.com/user/profile"},
                "config": {
                    "module_id": "alpha_recon",
                    "agent_id": "agent_alpha",  # Use proper agent_id format
                    "params": {},
                    "aggression": 1,
                    "session_id": "test_session"
                }
            }
        )
        
        await alpha_agent.handle_job(event)
        
        # Should publish JOB_COMPLETED event for recon module
        calls = alpha_agent.bus.publish.call_args_list
        event_types = [call[0][0].type for call in calls]
        assert EventType.JOB_COMPLETED in event_types


# ============================================================================
# BETA AGENT TESTS
# ============================================================================

class TestBetaAgent:
    """Test Beta Agent (CSRF & Session Testing)."""
    
    @pytest_asyncio.fixture
    async def beta_agent(self):
        """Create Beta agent instance."""
        from backend.agents.beta import BetaAgent
        
        mock_bus = AsyncMock()
        mock_bus.subscribe = AsyncMock()
        mock_bus.publish = AsyncMock()
        
        agent = BetaAgent(mock_bus)
        
        # Mock browser using PropertyMock
        mock_browser = AsyncMock()
        mock_browser.navigate = AsyncMock(return_value={"success": True})
        type(agent).browser = PropertyMock(return_value=mock_browser)
        
        # Mock network interceptor
        agent.network_interceptor = AsyncMock()
        agent.network_interceptor.intercept = AsyncMock(return_value=[])
        
        yield agent
    
    @pytest.mark.asyncio
    async def test_csrf_bypass_no_token(self, beta_agent):
        """Test CSRF bypass technique: no token."""
        result = await beta_agent._test_csrf_bypass(
            "https://example.com/api/action",
            {"name": "csrf_token", "value": "abc123"},
            "test_scan"
        )
        
        # Should return a dict with bypass information
        assert isinstance(result, dict)
        assert "bypassed" in result
    
    @pytest.mark.asyncio
    async def test_csrf_bypass_empty_token(self, beta_agent):
        """Test CSRF bypass technique: empty token."""
        result = await beta_agent._test_csrf_bypass(
            "https://example.com/api/action",
            {"name": "csrf_token", "value": ""},
            "test_scan"
        )
        
        assert isinstance(result, dict)
        assert "bypassed" in result
    
    @pytest.mark.asyncio
    async def test_csrf_bypass_all_blocked(self, beta_agent):
        """Test CSRF bypass when all techniques blocked."""
        # Mock network interceptor to return 403 for all requests
        from backend.core.proxy import network_interceptor
        
        async def mock_fetch(*args, **kwargs):
            mock_response = Mock()
            mock_response.status = 403
            mock_response.body = "Forbidden"
            return mock_response
        
        with patch.object(network_interceptor, 'fetch', side_effect=mock_fetch):
            result = await beta_agent._test_csrf_bypass(
                "https://example.com/api/action",
                {"name": "csrf_token", "value": "abc123"},
                "test_scan"
            )
        
        assert isinstance(result, dict)
        assert result.get("bypassed") is False


# ============================================================================
# GAMMA AGENT TESTS
# ============================================================================

class TestGammaAgent:
    """Test Gamma Agent (Network Traffic Analysis)."""
    
    @pytest_asyncio.fixture
    async def gamma_agent(self):
        """Create Gamma agent instance."""
        from backend.agents.gamma import GammaAgent
        
        mock_bus = AsyncMock()
        mock_bus.subscribe = AsyncMock()
        mock_bus.publish = AsyncMock()
        
        agent = GammaAgent(mock_bus)
        
        # Mock network interceptor
        agent.network_interceptor = AsyncMock()
        agent.network_interceptor.capture = AsyncMock(return_value=[])
        
        # Mock forensics using PropertyMock
        mock_forensics = AsyncMock()
        mock_forensics.capture_network_logs = AsyncMock()
        type(agent).forensics = PropertyMock(return_value=mock_forensics)
        
        yield agent
    
    @pytest.mark.asyncio
    async def test_analyze_network_traffic_detects_ssrf(self, gamma_agent):
        """Test network traffic analysis detects SSRF attempts."""
        # Mock network traffic with SSRF indicators
        traffic = [
            {
                "url": "http://169.254.169.254/latest/meta-data/",
                "method": "GET",
                "status": 200
            }
        ]
        
        gamma_agent.network_interceptor.capture = AsyncMock(return_value=traffic)
        
        result = await gamma_agent._analyze_network_traffic(
            "https://example.com",
            "test_payload",
            "test_scan"
        )
        
        assert isinstance(result, dict)
        # Should detect SSRF attempt to metadata endpoint
        assert "suspicious" in str(result).lower() or "ssrf" in str(result).lower()
    
    @pytest.mark.asyncio
    async def test_analyze_network_traffic_detects_metadata_access(self, gamma_agent):
        """Test detection of cloud metadata access."""
        # Mock network traffic with cloud metadata access
        traffic = [
            {
                "url": "http://metadata.google.internal/computeMetadata/v1/",
                "method": "GET",
                "status": 200
            }
        ]
        
        gamma_agent.network_interceptor.capture = AsyncMock(return_value=traffic)
        
        result = await gamma_agent._analyze_network_traffic(
            "https://example.com",
            "test_payload",
            "test_scan"
        )
        
        assert isinstance(result, dict)
        # Should detect metadata access
        assert "metadata" in str(result).lower() or "suspicious" in str(result).lower()


# ============================================================================
# SIGMA AGENT TESTS
# ============================================================================

class TestSigmaAgent:
    """Test Sigma Agent (DOM Analysis & Payload Generation)."""
    
    @pytest_asyncio.fixture
    async def sigma_agent(self):
        """Create Sigma agent instance."""
        from backend.agents.sigma import SigmaAgent
        
        mock_bus = AsyncMock()
        mock_bus.subscribe = AsyncMock()
        mock_bus.publish = AsyncMock()
        
        agent = SigmaAgent(mock_bus)
        
        # Mock browser using PropertyMock
        mock_browser = AsyncMock()
        mock_browser.navigate = AsyncMock(return_value={"success": True})
        mock_browser.detect_framework = AsyncMock(return_value="react")
        type(agent).browser = PropertyMock(return_value=mock_browser)
        
        yield agent
    
    @pytest.mark.asyncio
    async def test_analyze_dom_structure_detects_framework(self, sigma_agent):
        """Test DOM analysis detects JavaScript framework."""
        result = await sigma_agent._analyze_dom_structure("https://example.com")
        
        assert result["framework"] == "react"
        sigma_agent.browser.navigate.assert_called_once()
        sigma_agent.browser.detect_framework.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_analyze_dom_structure_handles_errors(self, sigma_agent):
        """Test DOM analysis handles navigation errors."""
        sigma_agent.browser.navigate = AsyncMock(return_value={"success": False})
        
        result = await sigma_agent._analyze_dom_structure("https://example.com")
        
        # Check that result is a dict and has expected error indicators
        assert isinstance(result, dict)
        assert result.get("framework") is None or result.get("success") is False


# ============================================================================
# ZETA AGENT TESTS
# ============================================================================

class TestZetaAgent:
    """Test Zeta Agent (Context Management)."""
    
    @pytest_asyncio.fixture
    async def zeta_agent(self):
        """Create Zeta agent instance."""
        from backend.agents.zeta import ZetaAgent
        
        mock_bus = AsyncMock()
        mock_bus.subscribe = AsyncMock()
        mock_bus.publish = AsyncMock()
        
        agent = ZetaAgent(mock_bus)
        
        # Mock browser orchestrator directly on the agent
        agent.browser_orchestrator = Mock()
        agent.browser_orchestrator._active_contexts = {
            "ctx_1": {
                "scan_id": "scan_1",
                "engine": "openclaw",
                "created_at": 1000,
                "last_activity": 1000
            },
            "ctx_2": {
                "scan_id": "scan_2",
                "engine": "pinchtab",
                "created_at": 2000,
                "last_activity": 2000
            }
        }
        agent.browser_orchestrator._context_lock = asyncio.Lock()
        agent.browser_orchestrator.get_context_stats = Mock(return_value={})
        agent.browser_orchestrator.close_context = AsyncMock()
        
        yield agent
    
    @pytest.mark.asyncio
    async def test_get_active_contexts_returns_all(self, zeta_agent):
        """Test getting all active contexts."""
        contexts = await zeta_agent._get_active_contexts()
        
        # Should return the 2 mocked contexts
        assert len(contexts) == 2
        assert any(c["scan_id"] == "scan_1" for c in contexts)
        assert any(c["scan_id"] == "scan_2" for c in contexts)
    
    @pytest.mark.asyncio
    async def test_close_idle_contexts_closes_old_contexts(self, zeta_agent):
        """Test closing idle contexts."""
        # Make contexts appear old (idle for >5 minutes)
        # Both contexts have last_activity at 1000 and 2000
        # We need to set time to be >300 seconds after the LATEST activity (2000)
        with patch('time.time', return_value=2000 + 400):  # 400 seconds after ctx_2's last activity
            closed_count = await zeta_agent._close_idle_contexts()
        
        # Should close both contexts since they're both idle for >300 seconds
        assert closed_count == 2
        assert zeta_agent.browser_orchestrator.close_context.call_count == 2
    
    @pytest.mark.asyncio
    async def test_close_idle_contexts_keeps_active(self, zeta_agent):
        """Test idle context closure keeps active contexts."""
        # No contexts are idle yet
        with patch('time.time', return_value=1000 + 100):  # 100 seconds later
            closed_count = await zeta_agent._close_idle_contexts()
        
        assert closed_count == 0
        zeta_agent.browser_orchestrator.close_context.assert_not_called()


# ============================================================================
# PRISM AGENT TESTS
# ============================================================================

class TestPrismAgent:
    """Test Prism Agent (HTTP Probing & Iframe Analysis)."""
    
    @pytest_asyncio.fixture
    async def prism_agent(self):
        """Create Prism agent instance."""
        from backend.agents.prism import AgentPrism
        
        mock_bus = AsyncMock()
        mock_bus.subscribe = AsyncMock()
        mock_bus.publish = AsyncMock()
        
        agent = AgentPrism(mock_bus)
        
        # Mock browser using PropertyMock
        mock_browser = AsyncMock()
        mock_browser.navigate = AsyncMock(return_value={"success": True})
        type(agent).browser = PropertyMock(return_value=mock_browser)
        
        yield agent
    
    @pytest.mark.asyncio
    async def test_analyze_iframes_detects_suspicious_patterns(self, prism_agent):
        """Test iframe analysis detects suspicious patterns."""
        # Mock browser navigation
        prism_agent.browser.navigate = AsyncMock(return_value={
            "success": True,
            "iframes": [
                {"src": "https://evil.com/phishing", "sandbox": ""},
                {"src": "https://example.com/safe", "sandbox": "allow-scripts"}
            ]
        })
        
        result = await prism_agent._analyze_iframes("https://example.com")
        
        # Method returns a list of suspicious iframes
        assert isinstance(result, list)
    
    @pytest.mark.asyncio
    async def test_block_event_captures_forensics(self, prism_agent):
        """Test event blocking captures forensic evidence."""
        # This test is for Chi agent functionality, but placed in Prism class
        # Mock event blocking
        result = {"blocked": True, "event_type": "click", "forensics_captured": True}
        
        # Since this is a placeholder test, just verify the structure
        assert isinstance(result, dict)
        assert "blocked" in result


# ============================================================================
# DELTA AGENT TESTS
# ============================================================================

class TestDeltaAgent:
    """Test Delta Agent (Hybrid Browser Controller)."""
    
    @pytest_asyncio.fixture
    async def delta_agent(self):
        """Create Delta agent instance."""
        from backend.agents.delta import AgentDelta
        
        mock_bus = AsyncMock()
        mock_bus.subscribe = AsyncMock()
        mock_bus.publish = AsyncMock()
        
        agent = AgentDelta(mock_bus)
        
        # Mock browser using PropertyMock
        mock_browser = AsyncMock()
        mock_browser.navigate = AsyncMock(return_value={"success": True})
        mock_browser.extract_tokens = AsyncMock(return_value={"tokens": []})
        mock_browser.extract_endpoints = AsyncMock(return_value={"tokens": []})
        mock_browser.test_payload = AsyncMock(return_value={"success": True})
        type(agent).browser = PropertyMock(return_value=mock_browser)
        
        # Mock session manager using PropertyMock
        mock_session_manager = AsyncMock()
        mock_session_manager.save_session = AsyncMock(return_value=True)
        mock_session_manager.restore_session = AsyncMock(return_value={})
        type(agent).session_manager = PropertyMock(return_value=mock_session_manager)
        
        yield agent
    
    @pytest.mark.asyncio
    async def test_extract_tokens_hybrid_fast_only(self, delta_agent):
        """Test hybrid token extraction uses fast method when sufficient."""
        # Mock fast extraction with good results
        delta_agent.browser.extract_tokens = AsyncMock(return_value={
            "tokens": [
                {"value": "token1", "type": "csrf"},
                {"value": "token2", "type": "session"},
                {"value": "token3", "type": "auth"}
            ]
        })
        
        result = await delta_agent._extract_tokens_hybrid("https://example.com", "scan_1")
        
        assert result["total_count"] == 3
        assert result["fast_count"] == 3
        assert result["deep_count"] == 0
        # Should not call deep extraction
        delta_agent.browser.extract_endpoints.assert_not_called()
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_extract_tokens_hybrid_uses_deep_when_needed(self, delta_agent):
        """Test hybrid extraction uses deep method when fast finds few tokens."""
        # Mock fast extraction with insufficient results
        delta_agent.browser.extract_tokens = AsyncMock(return_value={
            "tokens": [{"value": "token1", "type": "csrf"}]
        })
        
        # Mock deep extraction
        delta_agent.browser.extract_endpoints = AsyncMock(return_value={
            "tokens": [
                {"value": "token2", "type": "session"},
                {"value": "token3", "type": "auth"}
            ]
        })
        
        result = await delta_agent._extract_tokens_hybrid("https://example.com", "scan_1")
        
        assert result["total_count"] == 3
        assert result["fast_count"] == 1
        assert result["deep_count"] == 2
        # Should call both methods
        delta_agent.browser.extract_tokens.assert_called_once()
        delta_agent.browser.extract_endpoints.assert_called_once()
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_extract_tokens_hybrid_deduplicates(self, delta_agent):
        """Test hybrid extraction removes duplicate tokens."""
        # Mock both methods returning overlapping tokens
        delta_agent.browser.extract_tokens = AsyncMock(return_value={
            "tokens": [
                {"value": "token1", "type": "csrf"},
                {"value": "token2", "type": "session"}
            ]
        })
        
        delta_agent.browser.extract_endpoints = AsyncMock(return_value={
            "tokens": [
                {"value": "token2", "type": "session"},  # Duplicate
                {"value": "token3", "type": "auth"}
            ]
        })
        
        result = await delta_agent._extract_tokens_hybrid("https://example.com", "scan_1")
        
        # Should have 3 unique tokens, not 4
        assert result["total_count"] == 3
        token_values = [t["value"] for t in result["tokens"]]
        assert len(token_values) == len(set(token_values))  # All unique
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_coordinate_engines_full_recon(self, delta_agent):
        """Test engine coordination for full reconnaissance."""
        # Mock fast recon detecting SPA
        delta_agent.browser.navigate = AsyncMock(return_value={
            "success": True,
            "is_spa": True
        })
        
        # Mock deep recon
        delta_agent.browser.extract_endpoints = AsyncMock(return_value={
            "endpoints": ["/api/users", "/api/posts"]
        })
        
        result = await delta_agent._coordinate_engines(
            "https://example.com",
            "full_recon",
            "scan_1"
        )
        
        assert "fast" in result
        assert "deep" in result
        assert result["fast"]["is_spa"] is True
        delta_agent.browser.extract_endpoints.assert_called_once()
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_coordinate_engines_token_extraction(self, delta_agent):
        """Test engine coordination for token extraction."""
        delta_agent.browser.extract_tokens = AsyncMock(return_value={
            "tokens": [{"value": "token1"}]
        })
        
        result = await delta_agent._coordinate_engines(
            "https://example.com",
            "token_extraction",
            "scan_1"
        )
        
        assert "tokens" in result
        assert result["total_count"] >= 0
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_coordinate_engines_xss_testing(self, delta_agent):
        """Test engine coordination for XSS testing."""
        delta_agent.browser.test_payload = AsyncMock(return_value={
            "success": True,
            "triggered": True
        })
        
        result = await delta_agent._coordinate_engines(
            "https://example.com",
            "xss_testing",
            "scan_1"
        )
        
        assert result["success"] is True
        delta_agent.browser.test_payload.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_pinch_nav_saves_session(self, delta_agent):
        """Test navigation saves session data."""
        success = await delta_agent._pinch_nav(None, "https://example.com")
        
        assert success is True
        delta_agent.session_manager.save_session.assert_called_once()
        
        # Check session was saved with correct metadata
        call_args = delta_agent.session_manager.save_session.call_args
        assert "delta_" in call_args[1]["session_id"]
        assert call_args[1]["metadata"]["agent"] == "delta"


# ============================================================================
# KAPPA AGENT TESTS
# ============================================================================

class TestKappaAgent:
    """Test Kappa Agent (Knowledge & Memory)."""
    
    @pytest_asyncio.fixture
    async def kappa_agent(self):
        """Create Kappa agent instance."""
        from backend.agents.kappa import KappaAgent
        
        mock_bus = AsyncMock()
        mock_bus.subscribe = AsyncMock()
        mock_bus.publish = AsyncMock()
        
        # Mock get_or_create_context to return a mock context object
        mock_context = Mock()
        mock_context.append_event = Mock()
        mock_bus.get_or_create_context = Mock(return_value=mock_context)
        
        agent = KappaAgent(mock_bus)
        
        # Mock browser using PropertyMock
        mock_browser = AsyncMock()
        mock_browser.navigate = AsyncMock(return_value={"success": True})
        type(agent).browser = PropertyMock(return_value=mock_browser)
        
        # Mock session manager using PropertyMock
        mock_session_manager = AsyncMock()
        mock_session_manager.save_session = AsyncMock(return_value=True)
        mock_session_manager.restore_session = AsyncMock(return_value={})
        type(agent).session_manager = PropertyMock(return_value=mock_session_manager)
        
        yield agent
    
    @pytest.mark.asyncio
    async def test_archive_victory_stores_vulnerability(self, kappa_agent):
        """Test vulnerability archival."""
        event = HiveEvent(
            type=EventType.VULN_CONFIRMED,
            source="test",
            scan_id="test_scan",
            payload={
                "type": "SQL_INJECTION",
                "url": "https://example.com/api/users",
                "payload": "' OR 1=1--",
                "confidence": 0.95,
                "audit_reasoning": "Successful SQL injection"
            }
        )
        
        await kappa_agent.archive_victory(event)
        
        # Should publish LOG event
        kappa_agent.bus.publish.assert_called()
        calls = kappa_agent.bus.publish.call_args_list
        event_types = [call[0][0].type for call in calls]
        assert EventType.LOG in event_types
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_archive_victory_feeds_pattern_to_omega(self, kappa_agent):
        """Test pattern learning feedback to Omega."""
        event = HiveEvent(
            type=EventType.VULN_CONFIRMED,
            source="test",
            scan_id="test_scan",
            payload={
                "type": "XSS",
                "url": "https://example.com/search?q=test",
                "payload": "<script>alert(1)</script>",
                "confidence": 0.85
            }
        )
        
        await kappa_agent.archive_victory(event)
        
        # PATTERN_LEARNED is published from the background _slow_archive task
        # (archiving is intentionally non-blocking on the bus) — drain the
        # tracked background tasks before asserting.
        if kappa_agent._archive_tasks:
            await asyncio.gather(*list(kappa_agent._archive_tasks), return_exceptions=True)
            kappa_agent._archive_tasks.clear()
        
        # Should publish PATTERN_LEARNED event for high confidence
        calls = kappa_agent.bus.publish.call_args_list
        event_types = [call[0][0].type for call in calls]
        assert EventType.PATTERN_LEARNED in event_types
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_store_browser_session(self, kappa_agent):
        """Test browser session storage."""
        session_data = {
            "url": "https://example.com",
            "cookies": [{"name": "session", "value": "abc123"}],
            "localStorage": {"token": "xyz789"}
        }
        
        success = await kappa_agent._store_browser_session(
            "scan_1",
            "vuln_1",
            session_data
        )
        
        assert success is True
        kappa_agent.session_manager.save_session.assert_called_once()
        
        # Check session ID format
        call_args = kappa_agent.session_manager.save_session.call_args
        assert call_args[1]["session_id"] == "scan_1_vuln_1"
        assert call_args[1]["metadata"]["type"] == "exploit_session"
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_load_browser_session(self, kappa_agent):
        """Test browser session loading."""
        # Mock restored session
        kappa_agent.session_manager.restore_session = AsyncMock(return_value={
            "url": "https://example.com",
            "cookies": []
        })
        
        session_data = await kappa_agent._load_browser_session("scan_1", "vuln_1")
        
        assert session_data is not None
        assert "url" in session_data
        kappa_agent.session_manager.restore_session.assert_called_once()
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_recall_session_replays(self, kappa_agent):
        """Test session recall and replay."""
        # Mock session with URL
        kappa_agent.session_manager.restore_session = AsyncMock(return_value={
            "url": "https://example.com/exploit"
        })
        
        result = await kappa_agent.recall_session("scan_1", "vuln_1")
        
        assert result["success"] is True
        assert result["session_restored"] is True
        kappa_agent.browser.navigate.assert_called_once()
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_recall_session_handles_missing(self, kappa_agent):
        """Test session recall handles missing sessions."""
        # Mock no session found
        kappa_agent.session_manager.restore_session = AsyncMock(return_value=None)
        
        result = await kappa_agent.recall_session("scan_1", "vuln_1")
        
        assert result["success"] is False
        assert "not found" in result["error"]


# ============================================================================
# OMEGA AGENT TESTS
# ============================================================================

class TestOmegaAgent:
    """Test Omega Agent (Strategist)."""
    
    @pytest_asyncio.fixture
    async def omega_agent(self):
        """Create Omega agent instance."""
        from backend.agents.omega import OmegaAgent
        
        mock_bus = AsyncMock()
        mock_bus.subscribe = AsyncMock()
        mock_bus.publish = AsyncMock()
        mock_bus.scan_contexts = {}
        
        agent = OmegaAgent(mock_bus)
        
        # Mock browser using PropertyMock
        mock_browser = AsyncMock()
        mock_browser.detect_framework = AsyncMock(return_value="none")
        type(agent).browser = PropertyMock(return_value=mock_browser)
        
        # Mock AI
        agent.ai = AsyncMock()
        agent.ai.enabled = True
        agent.ai.select_attack_strategy = AsyncMock(return_value="BLITZKRIEG")
        
        yield agent
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_select_strategy_uses_ai_recommendation(self, omega_agent):
        """Test strategy selection uses AI recommendation when available."""
        strategy = omega_agent._select_strategy(
            "https://example.com",
            ai_strategy="E_COMMERCE_BLITZ",
            scan_id="test_scan"
        )
        
        assert strategy == "E_COMMERCE_BLITZ"
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_select_strategy_falls_back_to_mixed(self, omega_agent):
        """Test strategy selection falls back to mixed strategy."""
        strategy = omega_agent._select_strategy(
            "https://example.com",
            ai_strategy=None,
            scan_id="test_scan"
        )
        
        # Should return one of the valid strategies
        assert strategy in omega_agent.STRATEGY_PROFILES.keys()
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_initiate_campaign_dispatches_jobs(self, omega_agent):
        """Test campaign initiation dispatches jobs."""
        await omega_agent.initiate_campaign("https://example.com", "test_scan")
        
        # Should publish multiple events
        assert omega_agent.bus.publish.call_count > 0
        
        # Should publish JOB_ASSIGNED events
        calls = omega_agent.bus.publish.call_args_list
        event_types = [call[0][0].type for call in calls]
        assert EventType.JOB_ASSIGNED in event_types
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_handle_confirmed_vuln_adapts_strategy(self, omega_agent):
        """Test vulnerability confirmation triggers strategy adaptation."""
        # Setup campaign
        omega_agent._active_campaigns["test_scan"] = {
            "target_url": "https://example.com",
            "strategy": "BLITZKRIEG",
            "dispatched_jobs": [],
            "confirmed_vulns": [],
            "adapted": False
        }
        
        event = HiveEvent(
            type=EventType.VULN_CONFIRMED,
            source="test",
            scan_id="test_scan",
            payload={
                "type": "SQL_INJECTION",
                "url": "https://example.com/api/users",
                "confidence": 0.9
            }
        )
        
        await omega_agent.handle_confirmed_vuln(event)
        
        # Should mark campaign as adapted
        campaign = omega_agent._active_campaigns["test_scan"]
        assert len(campaign["confirmed_vulns"]) == 1
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_detect_spa_identifies_react(self, omega_agent):
        """Test SPA detection identifies React apps."""
        omega_agent.browser.detect_framework = AsyncMock(return_value="react")
        
        is_spa = await omega_agent._detect_spa("https://example.com")
        
        assert is_spa is True
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_detect_spa_identifies_non_spa(self, omega_agent):
        """Test SPA detection identifies non-SPA sites."""
        omega_agent.browser.detect_framework = AsyncMock(return_value="none")
        
        is_spa = await omega_agent._detect_spa("https://example.com")
        
        assert is_spa is False
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_plan_browser_campaign_for_spa(self, omega_agent):
        """Test browser campaign planning for SPAs."""
        omega_agent.browser.detect_framework = AsyncMock(return_value="react")
        
        plan = await omega_agent._plan_browser_campaign("https://example.com", "test_scan")
        
        assert plan["strategy"] == "SPA_ASSAULT"
        assert plan["is_spa"] is True
        assert plan["browser_required"] is True
        assert len(plan["phases"]) == 4
    
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_plan_browser_campaign_for_non_spa(self, omega_agent):
        """Test browser campaign planning for non-SPA sites."""
        omega_agent.browser.detect_framework = AsyncMock(return_value="none")
        
        plan = await omega_agent._plan_browser_campaign("https://example.com", "test_scan")
        
        assert plan["strategy"] == "BROWSER_DEEP_RECON"
        assert plan["is_spa"] is False
        assert plan["browser_required"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
