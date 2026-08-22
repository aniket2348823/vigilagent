from __future__ import annotations

import time as _time

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.core.approval import approval_store
from backend.core.telemetry import telemetry
from backend.core.tool_executor import tool_executor
from backend.core.tool_registry import tool_registry
from backend.core.unified_knowledge_graph import knowledge_graph

router = APIRouter(prefix="/runtime", tags=["runtime"])


class ToolRunRequest(BaseModel):
    tool_name: str
    args: dict = Field(default_factory=dict)
    scan_id: str = "GLOBAL"
    agent: str = "api"
    approval_id: str | None = None


@router.get("/tools")
async def list_tools():
    return {"tools": tool_registry.schemas()}


@router.post("/tools/run")
async def run_tool(payload: ToolRunRequest):
    result = await tool_executor.execute(
        payload.tool_name,
        payload.args,
        scan_id=payload.scan_id,
        agent=payload.agent,
        approval_id=payload.approval_id,
    )
    return result.__dict__


@router.get("/approvals")
async def list_approvals(scan_id: str | None = None):
    return {"approvals": [ticket.__dict__ for ticket in approval_store.pending(scan_id)]}


@router.post("/approvals/{approval_id}/approve")
async def approve(approval_id: str):
    try:
        return approval_store.approve(approval_id).__dict__
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown approval id")


@router.post("/approvals/{approval_id}/deny")
async def deny(approval_id: str):
    try:
        return approval_store.deny(approval_id).__dict__
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown approval id")


@router.get("/graph")
async def graph_stats():
    return knowledge_graph.stats()


@router.get("/telemetry")
async def recent_telemetry(limit: int = 100):
    return {"spans": telemetry.recent(limit)}


@router.get("/self-improvement")
async def self_improvement_audit(limit: int = 50):
    """Auditable agent-evolution changes + routing weights (Architecture §13.4, §15.1)."""
    from backend.core.self_improvement_engine import self_improvement_engine

    return {
        "stats": self_improvement_engine.stats(),
        "audit": self_improvement_engine.get_audit(limit=limit),
        "profiles": {a: p.to_dict() for a, p in self_improvement_engine.profiles.items()},
    }


@router.get("/scope")
async def scope_status():
    """Current engagement scope + authorization state (Architecture §9, §10)."""
    from backend.core.scope import scope_guard

    return scope_guard.to_dict()


@router.get("/terminal")
async def terminal_status():
    """Governed Terminal Engine telemetry (Architecture §8)."""
    from backend.core.terminal_engine import terminal_engine

    return terminal_engine.get_telemetry()


@router.get("/recovery")
async def recovery_status():
    """Recovery engine metrics: healing + error recovery (Architecture §14)."""
    from backend.core.recovery_engine import recovery_engine

    return recovery_engine.get_metrics()


@router.get("/health")
async def runtime_health() -> dict:
    """Live runtime status for the Live Monitor sidebar.

    Polled by the frontend every ~10s. Returns:

      * ``browser`` — output of ``BrowserOrchestrator.health_check()``
        (engine status + remediation hints if anything is offline).
      * ``active_scans`` — count of scans currently in
        Initializing/Running/Finalizing.
      * ``total_scans`` — lifetime scan count from the StateManager.
      * ``agents`` — system health summary
        (total/active agents, avg health score, alert counts).
      * ``alerts`` — most recent 20 alerts, newest last.

    The endpoint is best-effort: any individual subsystem error degrades
    that field to a structured ``error`` payload instead of failing the
    whole call. The Live Monitor must always render *something*.
    """
    from backend.core.agent_health_monitor import health_monitor
    from backend.core.browser_orchestrator import get_browser_orchestrator
    from backend.core.state import stats_db_manager

    # Browser health (best-effort). The frontend polls this every ~10s, but
    # health_check() probes each engine live (OpenClaw spins a Playwright
    # context). Cache the probe briefly so polling never pays that cost.
    _bcache_key = "runtime_browser_health"
    _now = _time.monotonic()
    if _now - getattr(runtime_health, "_bhealth_ts", 0.0) > 10.0:
        try:
            _bhealth = await get_browser_orchestrator().health_check()
            runtime_health._bhealth = _bhealth
            runtime_health._bhealth_ts = _now
        except Exception as exc:
            _bhealth = {
                "openclaw": "unavailable",
                "pinchtab": "unavailable",
                "error": f"{type(exc).__name__}: {exc}",
            }
    else:
        _bhealth = getattr(runtime_health, "_bhealth", None) or {
            "openclaw": "unavailable",
            "pinchtab": "unavailable",
        }
    browser_health = _bhealth

    # Scan counters from the StateManager. ``get_stats()`` returns the
    # live dict; we copy out only what the sidebar needs to keep the
    # response small.
    try:
        stats = stats_db_manager.get_stats()
        active_scans = int(stats.get("active_scans", 0))
        total_scans = int(stats.get("total_scans", 0))
    except Exception as exc:
        active_scans = 0
        total_scans = 0
        scan_error = f"{type(exc).__name__}: {exc}"
    else:
        scan_error = None

    # Agent health summary + most recent alerts.
    try:
        agents_summary = health_monitor.get_system_health_summary()
        recent_alerts = health_monitor.get_alerts(limit=20)
    except Exception as exc:
        agents_summary = {"error": f"{type(exc).__name__}: {exc}"}
        recent_alerts = []

    response = {
        "browser": browser_health,
        "active_scans": active_scans,
        "total_scans": total_scans,
        "agents": agents_summary,
        "alerts": recent_alerts,
    }
    if scan_error:
        response["scan_error"] = scan_error
    return response
