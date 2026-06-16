"""
COORDINATION MANAGER
Facilitates inter-agent communication and task delegation.

This manager:
1. Broadcasts agent status via Hive
2. Delegates tasks to capable agents
3. Manages meta-awareness (Omega only)
4. Handles assistance requests
5. Selects best agent for tasks
"""

import logging
import time
from typing import Dict, Any, Optional, TYPE_CHECKING
from dataclasses import dataclass
from enum import Enum

from backend.core.self_awareness_config import SelfAwarenessConfig
from backend.core.hive import EventType, HiveEvent
from backend.core.tracing import get_tracer, trace_span

if TYPE_CHECKING:
    from backend.core.hive import BaseAgent

logger = logging.getLogger("CoordinationManager")
tracer = get_tracer()


class HiveMessageType(Enum):
    """Types of Hive messages for coordination"""
    STATUS_UPDATE = "status_update"
    CAPABILITY_BROADCAST = "capability_broadcast"
    TASK_DELEGATION = "task_delegation"
    ASSISTANCE_REQUEST = "assistance_request"
    LEARNING_SHARE = "learning_share"


@dataclass
class DelegationResult:
    """Result of task delegation"""
    delegated: bool
    target_agent: Optional[str] = None
    rationale: str = ""


class CoordinationManager:
    """Manages inter-agent coordination"""
    
    def __init__(
        self,
        agent_id: str,
        agent: 'BaseAgent',
        config: SelfAwarenessConfig
    ):
        self.agent_id = agent_id
        self.agent = agent
        self.config = config
        self._meta_awareness: Dict[str, Dict[str, Any]] = {}
        self._meta_awareness_max = 50  # HIGH-41: bound size to prevent memory leak
        
        logger.info(f"[CoordinationManager] Initialized for agent {agent_id}")
    
    async def broadcast_status(self, status: Dict[str, Any]):
        """Broadcast agent status to Hive"""
        try:
            event = HiveEvent(
                type=EventType.AGENT_STATUS,
                source=self.agent_id,
                payload={
                    "message_type": HiveMessageType.STATUS_UPDATE.value,
                    "status": status
                }
            )
            
            await self.agent.bus.publish(event)
            
            logger.debug(f"[CoordinationManager] Broadcasted status for {self.agent_id}")
        except Exception as e:
            logger.error(f"[CoordinationManager] Failed to broadcast status: {e}")
    
    async def delegate_task(
        self,
        task: Any,
        target_agent: Optional[str] = None
    ) -> DelegationResult:
        """Delegate task to another agent"""
        if not target_agent:
            target_agent = await self.select_best_agent(task)
        
        if not target_agent:
            return DelegationResult(
                delegated=False,
                rationale="No suitable agent found"
            )
        
        try:
            event = HiveEvent(
                type=EventType.JOB_ASSIGNED,
                source=self.agent_id,
                payload={
                    "message_type": HiveMessageType.TASK_DELEGATION.value,
                    "task": task,
                    "target_agent": target_agent
                }
            )
            
            await self.agent.bus.publish(event)
            
            return DelegationResult(
                delegated=True,
                target_agent=target_agent,
                rationale=f"Delegated to {target_agent}"
            )
        except Exception as e:
            logger.error(f"[CoordinationManager] Delegation failed: {e}")
            return DelegationResult(delegated=False, rationale=str(e))
    
    async def select_best_agent(self, task: Any) -> Optional[str]:
        """Select best agent for task based on proficiency"""
        # Simplified implementation - would query proficiency scores
        return None
    
    def update_meta_awareness(self, agent_id: str, capabilities: Dict[str, Any]):
        """Update meta-awareness (Omega only)"""
        if self.agent_id.lower() != "omega":
            return
        
        # HIGH-41: Stamp with timestamp for correct age-based eviction
        capabilities["_updated_at"] = time.time()
        self._meta_awareness[agent_id] = capabilities
        # HIGH-41: Evict oldest entry when capacity exceeded.
        # Use insertion-order (Python 3.7+ dict) + timestamp to ensure
        # the truly oldest entry is evicted, not an arbitrary one.
        if len(self._meta_awareness) > self._meta_awareness_max:
            # Find entry with oldest _updated_at timestamp
            oldest_key = min(
                self._meta_awareness,
                key=lambda k: self._meta_awareness[k].get("_updated_at", 0),
            )
            del self._meta_awareness[oldest_key]
        logger.debug(f"[CoordinationManager] Updated meta-awareness for {agent_id}")
    
    async def request_assistance(
        self,
        problem: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Request assistance from peer agents
        
        Args:
            problem: Description of the problem needing assistance
            
        Returns:
            Assistance response from peers
        """
        try:
            event = HiveEvent(
                type=EventType.AGENT_STATUS,
                source=self.agent_id,
                payload={
                    "message_type": HiveMessageType.ASSISTANCE_REQUEST.value,
                    "problem": problem,
                    "requesting_agent": self.agent_id
                }
            )
            
            await self.agent.bus.publish(event)
            
            logger.info(f"[CoordinationManager] Requested assistance for {self.agent_id}")
            
            return {
                "requested": True,
                "problem": problem,
                "timestamp": event.timestamp.isoformat()
            }
            
        except Exception as e:
            logger.error(f"[CoordinationManager] Failed to request assistance: {e}")
            return {
                "requested": False,
                "error": str(e)
            }
    
    async def handle_assistance_response(
        self,
        response: Dict[str, Any]
    ):
        """Handle assistance response from peers
        
        Args:
            response: Assistance response from another agent
        """
        try:
            responding_agent = response.get("agent_id")
            solution = response.get("solution")
            
            logger.info(f"[CoordinationManager] Received assistance from {responding_agent}")
            
            # Apply the suggested solution
            # This would integrate with the agent's execution logic
            
        except Exception as e:
            logger.error(f"[CoordinationManager] Failed to handle assistance response: {e}")
    
    def get_meta_awareness(self) -> Dict[str, Dict[str, Any]]:
        """Get current meta-awareness state (Omega only)
        
        Returns:
            Dictionary of agent capabilities
        """
        if self.agent_id.lower() != "omega":
            return {}
        
        return self._meta_awareness.copy()
