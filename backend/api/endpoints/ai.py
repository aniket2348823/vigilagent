import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import os
from backend.ai.cortex import get_cortex_engine
from backend.core.orchestrator import HiveOrchestrator

# Initialize Router
router = APIRouter()

class MutationRequest(BaseModel):
    url: str
    method: str
    headers: Dict[str, str] = {}
    body: Optional[Any] = {} 
    velocity: Optional[int] = 50
    # New Config Fields matching Frontend
    interception_filters: Optional[List[str]] = [] 
    logic_vectors: Optional[List[Dict[str, Any]]] = []

@router.post("/mutate")
async def generate_mutations(payload: MutationRequest):
    """
    Trigger AI Payload suggestions manually.
    """
    base_request = {
        "url": payload.url,
        "method": payload.method,
        "body": payload.body
    }
    if os.getenv("VULAGENT_TEST_MODE", "false").lower() == "true":
        seed = str(payload.body)[:80]
        return {
            "status": "success",
            "variants": [
                {"type": "sqli", "payload": "' OR '1'='1", "target": payload.url},
                {"type": "sqli", "payload": "admin'--", "target": payload.url},
                {"type": "auth", "payload": {"username": "admin", "password": "admin"}, "target": payload.url},
                {"type": "idor", "payload": {"id": 0}, "target": payload.url},
                {"type": "xss", "payload": "<script>alert(1)</script>", "target": payload.url},
                {"type": "json", "payload": {"$ne": seed}, "target": payload.url},
                {"type": "logic", "payload": {"role": "admin"}, "target": payload.url},
                {"type": "rate_limit", "payload": {"burst": payload.velocity}, "target": payload.url},
            ],
        }
    brain = get_cortex_engine()
    variants = await brain.synthesize_payloads(base_request)
    return {"status": "success", "variants": variants}

@router.post("/autonomous/engage")
async def engage_autonomous(payload: MutationRequest, background_tasks: BackgroundTasks):
    """
    Full Auto Mode: Bootstraps the Hive Mind.
    """
    scan_id = "HIVE-" + payload.url.replace("https://", "").replace("http://", "")[:10]
    
    # Pass full payload to the Hive Orchestrator
    background_tasks.add_task(HiveOrchestrator.bootstrap_hive, payload.model_dump(), scan_id)
    
    return {
        "status": "launched", 
        "message": "Hive Mind Swarm Activated",
        "scan_id": scan_id 
    }

@router.get("/status")
async def get_ai_status():
    """
    Returns AI Core health, LLM metrics, and fallback state.
    """
    brain = get_cortex_engine()
    # Defensive access to telemetry
    telemetry = brain._telemetry if hasattr(brain, "_telemetry") else {}
    nvidia = getattr(brain, "_nvidia", None)
    openrouter = getattr(brain, "_openrouter", None)
    
    return {
        "core_status": {
            "gi5": "online" if getattr(brain, "_gi5_available", False) else "error",
            "ollama": "standby",
            "openrouter": "active" if getattr(openrouter, "is_available", False) else "disabled",
            "nvidia": "active" if getattr(nvidia, "is_available", False) else "dummy_key"
        },
        "llm_calls": telemetry.get("llm_calls", 0),
        "circuit_breaker_trips": telemetry.get("circuit_breaker_trips", 0),
        "circuit_breaker_tripped": telemetry.get("circuit_breaker_trips", 0) > 0,
        "agent_capabilities": ["singularity", "recon", "attack", "defense"],
        "fallback": "OpenRouter" if getattr(brain, "_gi5_available", False) else "GI5_only"
    }


# ──────────────────────────────────────────────────────────────────────
#  CORTEX CACHE MANAGEMENT ENDPOINTS
# ──────────────────────────────────────────────────────────────────────

@router.get("/health")
async def cortex_health():
    """Return cortex cache stats, circuit breaker state, and Redis connectivity."""
    try:
        from backend.ai.cortex import Cortex, get_cortex_engine
        import asyncio
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
        from backend.ai.cortex import Cortex, get_cortex_engine
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
