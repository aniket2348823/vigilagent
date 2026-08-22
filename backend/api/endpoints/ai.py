import logging
from typing import Any

from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel

from backend.ai.cortex import get_cortex_engine

# Initialize Router
router = APIRouter()


class MutationRequest(BaseModel):
    url: str
    method: str
    headers: dict[str, str] = {}
    body: Any | None = {}
    velocity: int | None = 50
    # New Config Fields matching Frontend
    interception_filters: list[str] | None = []
    logic_vectors: list[dict[str, Any]] | None = []


@router.post("/mutate")
async def generate_mutations(payload: MutationRequest):
    """
    Trigger AI Payload suggestions manually.
    """
    base_request = {"url": payload.url, "method": payload.method, "body": payload.body}
    brain = get_cortex_engine()
    variants = await brain.synthesize_payloads(base_request)
    return {"status": "success", "variants": variants}


@router.post("/autonomous/engage")
async def engage_autonomous(payload: MutationRequest, background_tasks: BackgroundTasks):
    """
    Full Auto Mode: Bootstraps the Hive Mind.
    """
    scan_id = "HIVE-" + payload.url.replace("https://", "").replace("http://", "")[:10]

    # Pass full payload to the Hive Orchestrator (imported lazily — the
    # orchestrator chain loads ~6s of agent modules; only pay it on demand).
    from backend.core.orchestrator import HiveOrchestrator

    background_tasks.add_task(HiveOrchestrator.bootstrap_hive, payload.model_dump(), scan_id)

    return {"status": "launched", "message": "Hive Mind Swarm Activated", "scan_id": scan_id}


@router.get("/status")
async def get_ai_status():
    """
    Returns AI Core health, LLM metrics, and fallback state.
    """
    brain = get_cortex_engine()
    # Defensive access to telemetry
    telemetry = brain._telemetry if hasattr(brain, "_telemetry") else {}
    nvidia = getattr(brain, "_nvidia", None)
    nvidia_strategic = getattr(brain, "_nvidia_strategic", None)

    return {
        "core_status": {
            "gi5": "online" if getattr(brain, "_gi5_available", False) else "error",
            "nvidia_tactical": "active" if getattr(nvidia, "is_available", False) else "disabled",
            "nvidia_strategic": "active" if getattr(nvidia_strategic, "is_available", False) else "disabled",
        },
        "llm_calls": telemetry.get("llm_calls", 0),
        "circuit_breaker_trips": telemetry.get("circuit_breaker_trips", 0),
        "circuit_breaker_tripped": telemetry.get("circuit_breaker_trips", 0) > 0,
        "agent_capabilities": ["singularity", "recon", "attack", "defense"],
        "fallback": "Gemini" if getattr(brain, "_gemini", None) and getattr(brain._gemini, "is_available", False) else "GI5_only",
    }


# ──────────────────────────────────────────────────────────────────────
#  CORTEX CACHE MANAGEMENT ENDPOINTS
# ──────────────────────────────────────────────────────────────────────


@router.get("/health")
async def cortex_health():
    """Return cortex cache stats, circuit breaker state, and Redis connectivity."""
    try:
        from backend.ai.cortex import get_cortex_engine

        # Try to get a cached instance or create a minimal one
        cortex = get_cortex_engine()
        stats = cortex.get_cache_stats()
        return {"status": "ok", "cache": stats}
    except Exception as e:
        logging.warning(f"CORTEX cache invalidation failed: {e}")
        return {"status": "error", "error": str(e)}


@router.post("/cache/invalidate")
async def cortex_cache_invalidate(
    scan_id: str = None,
    pattern: str = None,
):
    """Invalidate LLM response cache entries by scan_id or pattern."""
    try:
        from backend.ai.cortex import get_cortex_engine

        cortex = get_cortex_engine()
        evicted, redis_flush_error = await cortex.invalidate_cache(scan_id=scan_id, pattern=pattern)
        result = {
            "status": "ok",
            "evicted_in_memory": evicted,
            "scan_id": scan_id,
            "pattern": pattern,
        }
        if redis_flush_error:
            result["redis_flush_error"] = redis_flush_error
        return result
    except Exception as e:
        logging.warning(f"CORTEX cache invalidation failed: {e}")
        return {"status": "error", "error": str(e)}


@router.get("/metrics")
async def cortex_metrics():
    """Return Prometheus-compatible metrics for cortex engine."""
    try:
        cortex = get_cortex_engine()
        return cortex.get_metrics()
    except Exception as e:
        logging.warning(f"CORTEX metrics failed: {e}")
        return {"error": str(e)}
