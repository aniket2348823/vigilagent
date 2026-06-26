"""
BACKWARD-COMPATIBLE RE-EXPORT SHIM
===================================
The canonical BaseAgent lives in backend.core.hive.
BaseArsenalModule has been extracted to backend.core.arsenal_base.

This file re-exports BaseArsenalModule so existing module imports
(from backend.core.base import BaseArsenalModule) continue to work.
"""

from backend.core.arsenal_base import BaseArsenalModule  # noqa: F401

# NOTE: The BaseAgent class that was here has been REMOVED.
# All agents should import BaseAgent from backend.core.hive instead.
# If you were importing BaseAgent from here, update your import to:
#   from backend.core.hive import BaseAgent
