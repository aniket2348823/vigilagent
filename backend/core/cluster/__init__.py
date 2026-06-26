"""
Backend Cluster Package — Extracted from orchestrator.py god-object.

Provides clean imports for the three cluster components:
  - PinchTabInstance: Isolated browser execution for DOM fuzzing
  - MasterNode: Central coordinator for distributed work
  - WorkerNode: Distributed task executor with module dispatch
"""

from backend.core.cluster.master import MasterNode
from backend.core.cluster.pinchtab import PinchTabInstance
from backend.core.cluster.worker import WorkerNode

__all__ = ["PinchTabInstance", "MasterNode", "WorkerNode"]
