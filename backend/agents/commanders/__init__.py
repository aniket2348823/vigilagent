"""
Vigilagent Commander Agents (Architecture §5)
================================================================================
Budgeted commander agents that own a domain of the campaign and delegate bounded
work to specialized children/workers through the DelegationManager.

  NetworkServiceCommander - port/service/TLS assessment (L4/L6/L7, §29.7)

This module also registers in-process child runners with the DelegationManager
(Architecture §5.1.2) so commanders can spawn bounded network-assessment tasks.
"""

import logging

from backend.agents.commanders.network_commander import NetworkServiceCommander

logger = logging.getLogger(__name__)

__all__ = ["NetworkServiceCommander"]


def _register_child_runners() -> None:
    """Register delegation child runners (Architecture §5.1.2 worker specialties)."""
    try:
        from backend.core.delegation_manager import DelegationManager
        from backend.core.iteration_budget import IterationBudget
    except Exception as e:
        import logging

        logging.debug(f"Commander child runner registration import failed: {e}")
        return

    if DelegationManager.has_runner("NetworkChild"):
        return

    async def _network_child(context: dict, budget: IterationBudget) -> dict:
        """worker.network specialty (Architecture §5.1.2): bounded host assessment."""
        host = context.get("host") or context.get("target")
        scan_id = context.get("scan_id", "GLOBAL")
        if not host:
            return {"summary": "no host in context", "findings": []}
        bus = context.get("bus")
        if bus is not None:
            commander = NetworkServiceCommander(bus)
        else:
            # Headless delegation: construct without a bus.
            from backend.core.scope import scope_guard
            from backend.core.terminal_engine import terminal_engine
            from backend.core.unified_knowledge_graph import unified_knowledge_graph

            commander = NetworkServiceCommander.__new__(NetworkServiceCommander)
            commander.name = "agent_network_commander"
            commander.scope = scope_guard
            commander.terminal = terminal_engine
            commander.graph = unified_knowledge_graph
            commander.bus = None
        results = await commander.assess_host(host, scan_id, budget=budget)
        findings = [{"type": "OPEN_SERVICE", **s} for s in results.get("services", [])]
        return {
            "findings": findings,
            "artifacts": [],
            "summary": f"{len(results.get('ports', []))} ports, {len(results.get('services', []))} services on {host}",
        }

    DelegationManager.register_runner("NetworkChild", _network_child)


_register_child_runners()
