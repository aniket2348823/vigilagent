"""
BrowserEnabledAgent: Base class for agents with browser capabilities.

Consolidates browser initialization and provides common browser methods.
"""

import logging

from backend.core.browser_optimization import get_optimized_browser
from backend.core.browser_orchestrator import BrowserOrchestrator
from backend.core.forensic_collector import ForensicCollector
from backend.core.hive import BaseAgent
from backend.core.hybrid_session_manager import HybridSessionManager

logger = logging.getLogger("BrowserAgent")


class BrowserEnabledAgent(BaseAgent):
    """
    Base class for agents with browser automation capabilities.

    Provides:
    - Unified browser orchestrator
    - Session management
    - Forensic evidence collection
    - Common browser operations

    Usage:
        class MyAgent(BrowserEnabledAgent):
            def __init__(self, bus):
                super().__init__("my_agent", bus)
                # Agent-specific initialization
    """

    def __init__(self, name: str, bus):
        super().__init__(name, bus)

        # Browser components (initialized lazily)
        self._browser = None
        self._session_manager = None
        self._forensics = None
        self._browser_initialized = False

    @property
    def browser(self) -> BrowserOrchestrator:
        """Get browser orchestrator (lazy initialization)."""
        if self._browser is None:
            # Use optimized singleton instance
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                self._browser = loop.run_until_complete(get_optimized_browser())
            except Exception as e:
                import logging

                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to get optimized browser, using fallback: {e}")
                # Fallback to regular instance
                self._browser = BrowserOrchestrator()
        return self._browser

    @property
    def session_manager(self) -> HybridSessionManager:
        """Get session manager (lazy initialization)."""
        if self._session_manager is None:
            self._session_manager = HybridSessionManager()
        return self._session_manager

    @property
    def forensics(self) -> ForensicCollector:
        """Get forensic collector (lazy initialization)."""
        if self._forensics is None:
            self._forensics = ForensicCollector()
        return self._forensics

    async def ensure_browser_initialized(self):
        """Ensure browser components are initialized."""
        if not self._browser_initialized:
            if self._browser is None:
                self._browser = await get_optimized_browser()
            else:
                await self._browser.initialize()
            self._browser_initialized = True
            logger.info(f"[{self.name}] Browser capabilities initialized")

    async def navigate_browser(self, url: str, stealth: bool = False, scan_id: str = None):
        """Navigate to URL using browser."""
        await self.ensure_browser_initialized()
        return await self.browser.navigate(url, stealth=stealth, scan_id=scan_id)

    async def extract_endpoints_browser(self, url: str, deep: bool = False, scan_id: str = None):
        """Extract endpoints using browser."""
        await self.ensure_browser_initialized()
        return await self.browser.extract_endpoints(url, deep=deep, scan_id=scan_id)

    async def test_payload_browser(self, url: str, payload: str, scan_id: str = None):
        """Test payload in browser context."""
        await self.ensure_browser_initialized()
        return await self.browser.test_payload(url, payload, scan_id=scan_id)

    async def detect_framework_browser(self, url: str):
        """Detect JavaScript framework."""
        await self.ensure_browser_initialized()

        # Use cached detection if available
        from backend.core.browser_optimization import OptimizedBrowserOrchestrator

        return await OptimizedBrowserOrchestrator.detect_framework_cached(url)

    async def capture_evidence(self, scan_id: str, label: str = "evidence"):
        """Capture forensic evidence (screenshot + DOM)."""
        await self.ensure_browser_initialized()

        # Capture screenshot
        screenshot = await self.browser.capture_screenshot(scan_id, label)

        # Capture DOM
        dom = await self.browser.capture_dom(scan_id, label)

        return {"screenshot": screenshot, "dom": dom}

    async def save_browser_session(self, scan_id: str, session_data: dict):
        """Save browser session for later replay."""
        await self.session_manager.save_session(session_id=scan_id, engine="openclaw", session_data=session_data)

    async def restore_browser_session(self, scan_id: str):
        """Restore browser session."""
        return await self.session_manager.restore_session(scan_id, "openclaw")

    async def cleanup_browser(self):
        """Cleanup browser resources."""
        # Context pool handles cleanup automatically
        logger.info(f"[{self.name}] Browser cleanup complete")


class BrowserMixin:
    """
    Mixin for adding browser capabilities to existing agents.

    Usage:
        class MyAgent(BaseAgent, BrowserMixin):
            def __init__(self, bus):
                BaseAgent.__init__(self, "my_agent", bus)
                BrowserMixin.__init__(self)
    """

    def __init__(self):
        self._browser = None
        self._session_manager = None
        self._forensics = None

    @property
    def browser(self) -> BrowserOrchestrator:
        """Get browser orchestrator."""
        if self._browser is None:
            import asyncio

            try:
                loop = asyncio.get_event_loop()
                self._browser = loop.run_until_complete(get_optimized_browser())
            except Exception as e:
                import logging

                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to get optimized browser, using fallback: {e}")
                self._browser = BrowserOrchestrator()
        return self._browser

    @property
    def session_manager(self) -> HybridSessionManager:
        """Get session manager."""
        if self._session_manager is None:
            self._session_manager = HybridSessionManager()
        return self._session_manager

    @property
    def forensics(self) -> ForensicCollector:
        """Get forensic collector."""
        if self._forensics is None:
            self._forensics = ForensicCollector()
        return self._forensics


class ForensicMixin:
    """
    Mixin for forensic evidence collection.

    Provides common methods for capturing and bundling evidence.
    """

    async def capture_exploit_evidence(self, scan_id: str, context, label: str):
        """Capture comprehensive exploit evidence."""
        if not hasattr(self, "forensics"):
            from backend.core.forensic_collector import ForensicCollector

            self.forensics = ForensicCollector()

        # Capture screenshot
        await self.forensics.capture_screenshot(
            scan_id=scan_id, context=context, engine="openclaw", label=f"{label}_screenshot"
        )

        # Capture DOM snapshot
        await self.forensics.capture_dom_snapshot(
            scan_id=scan_id, context=context, engine="openclaw", label=f"{label}_dom"
        )

        # Capture console logs
        await self.forensics.capture_console_log(
            scan_id=scan_id, context=context, engine="openclaw", label=f"{label}_console"
        )

        # Capture network log
        await self.forensics.capture_network_log(
            scan_id=scan_id, context=context, engine="openclaw", label=f"{label}_network"
        )

        logger.info(f"[ForensicMixin] Captured comprehensive evidence for {label}")

    async def bundle_scan_evidence(self, scan_id: str, vuln_id: str):
        """Bundle all evidence for a vulnerability."""
        if not hasattr(self, "forensics"):
            from backend.core.forensic_collector import ForensicCollector

            self.forensics = ForensicCollector()

        bundle_path = await self.forensics.bundle_evidence(scan_id, vuln_id)
        logger.info(f"[ForensicMixin] Evidence bundled: {bundle_path}")
        return bundle_path
