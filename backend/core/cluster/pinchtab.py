"""
Compatibility shim for cluster/pinchtab.py
Re-exports from browser_engine.py (Scrappling) for backward compatibility.
"""

from backend.core.browser_engine import (
    ScrapplingFuzzer as PinchTabInstance,
)

# Re-export
__all__ = [
    "PinchTabInstance",
]
