"""Alpha Recon — Unified Reconnaissance Spine (Architecture §5.1.1).

The single recon runtime spine for Agent Alpha (`backend/agents/alpha.py`).
The former separate `alpha_v6` package has been renamed to `alpha_recon`; it is
part of the one Alpha family — there is no separate "V6" path.

Exports:
    AlphaOrchestrator            — the unified recon orchestrator (spine)
    AlphaUnifiedReconCommander   — canonical unified name (Architecture §24 step 8)
    AlphaV6ReconOrchestrator     — alias (backward compat)
    AlphaV6DeepOrchestrator      — alias (backward compat)
    recon_router                 — FastAPI router for recon API
"""

__all__ = [
    "AlphaOrchestrator",
    "AlphaUnifiedReconCommander",
    "AlphaV6ReconOrchestrator",
    "AlphaV6DeepOrchestrator",
    "recon_router",
]


def __getattr__(name: str):
    if name in (
        "AlphaOrchestrator",
        "AlphaUnifiedReconCommander",
        "AlphaV6ReconOrchestrator",
        "AlphaV6DeepOrchestrator",
    ):
        from backend.agents.alpha_recon.alpha_orchestrator import AlphaOrchestrator

        return AlphaOrchestrator
    if name == "recon_router":
        from backend.agents.alpha_recon.api_routes import router

        return router
    raise AttributeError(name)
