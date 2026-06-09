"""CognitiveRouter: Centralized event-to-agent routing.

WHY: Currently, each agent subscribes to events directly via the EventBus.
This works but makes routing implicit - you have to read every agent's
setup() method to understand who handles what.

CognitiveRouter makes routing explicit and centralized. It decides which
agent(s) handle each event type, supporting multi-agent routing (one
event -> multiple agents).

This is an ADDITION to the existing subscriber model, not a replacement.
Existing agent subscriptions continue to work. The router provides
centralized visibility for debugging and future migration.
"""

import logging
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from backend.core.hive import BaseAgent, EventType, HiveEvent

logger = logging.getLogger(__name__)


class CognitiveRouter:
    """Centralized event-to-agent routing.

    Provides explicit, testable routing logic that can be queried
    without subscribing to the EventBus.

    USAGE:
        router = CognitiveRouter(agents)
        targets = router.route_event(event)
        for agent in targets:
            await agent.handle_event(event)
    """

    # Multi-agent routing table: one event -> potentially multiple agents
    ROUTING_TABLE = {
        # Lifecycle
        "TARGET_ACQUIRED": ["alpha", "omega"],  # Recon + strategy
        "SCAN_COMPLETED": ["omega", "kappa"],  # Learning + archival

        # Recon
        "RECON_PACKET": ["alpha", "omega"],  # Analysis + strategy update
        "JOB_ASSIGNED": ["alpha", "sigma", "beta", "delta"],  # Dispatch to correct handler

        # Vulnerability pipeline
        "VULN_CANDIDATE": ["gamma"],  # Audit/verify
        "VULN_CONFIRMED": ["sigma", "kappa"],  # Exploit + archive
        "VULN_FALSE_POSITIVE": ["kappa"],  # Archive for learning

        # Attack
        "LIVE_ATTACK": ["beta"],  # Execute attack
        "JOB_COMPLETED": ["sigma", "beta", "delta"],  # Process results

        # Governance
        "CONTROL_SIGNAL": ["zeta"],  # Throttle/resume

        # Intelligence
        "LEARNING_EVENT": ["kappa"],  # Knowledge archival
        "SKILL_LEARNED": ["kappa"],  # Skill extraction
    }

    def __init__(self, agents: Dict[str, "BaseAgent"]):
        """Initialize with agent registry.

        Args:
            agents: Dict mapping agent_name -> agent instance.
                    E.g., {"alpha": alpha_agent, "sigma": sigma_agent, ...}
        """
        self.agents = agents
        self._routing_stats: Dict[str, int] = {}  # Track routing decisions

    def route_event(self, event: "HiveEvent") -> List["BaseAgent"]:
        """Route an event to the appropriate agent(s).

        Returns a list because one event may need multiple agents:
        - RECON_PACKET -> Alpha (analysis) + Omega (strategy update)
        - VULN_CONFIRMED -> Sigma (exploit) + Kappa (archive)

        If an agent name in the routing table doesn't exist in self.agents,
        it's silently skipped (no crash).
        """
        event_type = event.type if hasattr(event, 'type') else str(event.type)
        agent_names = self.ROUTING_TABLE.get(event_type, [])

        targets = []
        for name in agent_names:
            if name in self.agents:
                targets.append(self.agents[name])
            else:
                logger.debug("Router: agent '%s' not found for event %s", name, event_type)

        # Track stats for debugging
        key = f"{event_type}:{len(targets)}"
        self._routing_stats[key] = self._routing_stats.get(key, 0) + 1

        return targets

    def get_routing_for_event(self, event_type: str) -> List[str]:
        """Query which agents handle a given event type.

        Useful for debugging and documentation.
        """
        return list(self.ROUTING_TABLE.get(event_type, []))

    def get_all_routes(self) -> Dict[str, List[str]]:
        """Return the full routing table."""
        return dict(self.ROUTING_TABLE)

    def get_stats(self) -> Dict[str, int]:
        """Return routing statistics for debugging."""
        return dict(self._routing_stats)
