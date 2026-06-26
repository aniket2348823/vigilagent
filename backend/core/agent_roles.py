"""
Backend mirror of ``src/lib/agentNames.js`` display labels.

The frontend Live Monitor renders broadcast payloads with both ``agent`` (the
internal id, e.g. ``agent_alpha``) and a human-readable role label. To keep the
two sides consistent without making the UI depend on the exact id list, the
orchestrator stamps every outgoing live-event payload with an ``agent_role``
sibling computed here.

Stays intentionally tiny — no I/O, no logging, no lookups beyond a dict.
"""

from __future__ import annotations

AGENT_ROLES: dict[str, str] = {
    "agent_alpha": "Recon Scout",
    "agent_beta": "Attack Breaker",
    "agent_gamma": "Forensic Analyst",
    "agent_omega": "Campaign Strategist",
    "agent_sigma": "Payload Smith",
    "agent_kappa": "Memory Librarian",
    "agent_zeta": "Governance Governor",
    "agent_delta": "Hybrid Controller",
    "agent_prism": "Defense Sentinel",
    "agent_chi": "Inspector",
    "agent_planner": "Mission Planner",
    "Orchestrator": "Hive Orchestrator",
}


def _humanize(agent_id: str) -> str:
    """Best-effort title-case fallback for unknown agent ids.

    ``agent_alpha_recon`` -> ``Alpha Recon``;
    ``Orchestrator`` -> ``Orchestrator``.
    """
    if not agent_id:
        return "Unknown"
    cleaned = agent_id
    if cleaned.startswith("agent_"):
        cleaned = cleaned[len("agent_") :]
    cleaned = cleaned.replace("_", " ").replace("-", " ").strip()
    return cleaned.title() if cleaned else agent_id


def role_for(agent_id: str) -> str:
    """Resolve an agent id to its display role.

    Direct hits in :data:`AGENT_ROLES` win. If the id contains a known stem
    (``"agent_alpha_recon"`` -> matches ``"agent_alpha"``) the longest stem
    wins. Otherwise we humanize the id so the frontend never sees ``"None"``.
    """
    if not agent_id:
        return "Unknown"
    if agent_id in AGENT_ROLES:
        return AGENT_ROLES[agent_id]
    # Substring fallback (sorted longest-first so ``agent_alpha_recon``
    # prefers ``agent_alpha`` over a hypothetical shorter match).
    for stem in sorted(AGENT_ROLES.keys(), key=len, reverse=True):
        if stem and stem in agent_id:
            return AGENT_ROLES[stem]
    return _humanize(agent_id)


def stamp(payload: dict, agent_field: str = "agent", role_field: str = "agent_role") -> dict:
    """Mutate ``payload`` in place to add ``agent_role`` if ``agent`` is set.

    Returns the same payload for fluent use. Safe to call on payloads that
    already carry an ``agent_role`` (existing value is preserved).
    """
    if not isinstance(payload, dict):
        return payload
    if role_field in payload and payload[role_field]:
        return payload
    agent_id = payload.get(agent_field)
    if agent_id:
        payload[role_field] = role_for(str(agent_id))
    return payload
