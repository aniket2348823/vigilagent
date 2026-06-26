"""
Compatibility shim for browser_orchestrator.py
Re-exports from browser_engine.py (Scrappling) for backward compatibility.
"""

from backend.core.browser_engine import (
    BrowserEngine,
    BrowserOrchestrator,
    OpenClawEngine,
    PinchTabClient,
    PinchTabEngine,
    PinchTabInstance,
    ScrapplingEngine,
    get_browser_orchestrator,
)
from backend.core.browser_engine import (
    ScrapplingUnavailable as BrowserUnavailable,
)

# Re-export all public API
__all__ = [
    "BrowserEngine",
    "BrowserOrchestrator",
    "BrowserUnavailable",
    "OpenClawEngine",
    "PinchTabEngine",
    "PinchTabInstance",
    "PinchTabClient",
    "get_browser_orchestrator",
    "ScrapplingEngine",
]
