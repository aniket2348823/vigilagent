import asyncio
import logging
import time
import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request

from backend.core.rate_limiter import rate_limit
from backend.core.state import stats_db_manager
from backend.core.url_validator import validate_url
from backend.schemas.payloads import AttackPayload

logger = logging.getLogger(__name__)

router = APIRouter()


def validate_target_url(url: str, allow_private: bool = True):
    """Validate an attack target URL for SSRF safety.

    Thin wrapper over the centralized SSRF validator so callers (and tests)
    have a single, intention-revealing entry point at the API boundary.
    Returns a ``(is_valid, reason)`` tuple.
    """
    return validate_url(url, allow_private=allow_private)


# --- INPUT VALIDATION: URL ALLOWLIST ---
_active_scan_targets: dict[str, float] = {}
_active_scan_targets_lock = asyncio.Lock()


@router.post("/fire")
@rate_limit("/api/attack/fire")
async def fire_attack(request: Request, payload: AttackPayload, background_tasks: BackgroundTasks):
    """
    Triggers the Vigilagent Singularity Swarm.
    Replaces legacy Gatekeeper Engine.
    """
    # INPUT VALIDATION: Reject out-of-scope targets using centralized validator
    is_valid, reason = validate_url(payload.target_url, allow_private=True)
    if not is_valid:
        status = 422 if "scheme" in reason.lower() or "malformed" in reason.lower() else 403
        raise HTTPException(status_code=status, detail=f"Target URL rejected: {reason}")

    lock_key = f"{payload.method.upper()}:{payload.target_url.lower()}"
    now = time.time()
    async with _active_scan_targets_lock:
        expired = [key for key, until in _active_scan_targets.items() if until < now]
        for key in expired:
            _active_scan_targets.pop(key, None)
        if lock_key in _active_scan_targets:
            raise HTTPException(status_code=429, detail="A scan for this target is already running.")
        _active_scan_targets[lock_key] = now + max(int(payload.duration or 10), 10)

    scan_id = str(uuid.uuid4())

    import json

    parsed_body = {}
    if payload.body:
        try:
            parsed_body = json.loads(payload.body)
        except Exception as exc:
            import logging as _log

            _log.debug(f"Attack payload JSON parse fallback: {exc}")
            parsed_body = payload.body  # Fallback if not JSON string

    target_config = {
        "url": payload.target_url,
        "method": payload.method,
        "headers": payload.headers,
        "payload": parsed_body,
        "velocity": payload.velocity,
        "concurrency": payload.concurrency,  # Performance Bound
        "rps": payload.rps,  # Requests Per Second Bound
        "modules": payload.modules,
        "filters": payload.filters,
        "duration": payload.duration,
    }

    # 1.5 Initialize distributed DB layer
    from backend.core.database import db_manager

    await db_manager.initialize()

    # We do a minimal placeholder here to ensure immediate UI feedback
    # 2. Initial DB Registration (Sync)
    # Use Manager to ensure persistence to disk immediately
    start_time = datetime.now()
    scan_record = {
        "id": scan_id,
        "status": "Initializing",
        "name": target_config["url"],
        "scope": target_config["url"],
        "modules": target_config["modules"] if target_config["modules"] else ["Singularity V5"],
        "timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "results": [],
    }
    # [FATAL BUG FIX: V6-OMEGA] register_scan is an async def and MUST be awaited
    await stats_db_manager.register_scan(scan_record)

    # 3. Launch The Hive (Background Task)
    # The Orchestrator manages the entire lifecycle (Agents, EventBus, Reporting)
    async def run_scan_and_release():
        try:
            from backend.core.orchestrator import HiveOrchestrator  # deferred: heavy import

            await HiveOrchestrator.bootstrap_hive(target_config, scan_id)
        finally:
            async with _active_scan_targets_lock:
                _active_scan_targets.pop(lock_key, None)

    background_tasks.add_task(run_scan_and_release)

    # 4. Immediate Response
    return {
        "status": "Swarm Online",
        "scan_id": scan_id,
        "message": "The Singularity has been unleashed. Monitor the 'Live Graph' for real-time telemetry.",
    }


# --- PROBLEM 13 FIX: Attack Replay Mechanism ---


@router.post("/replay/{vuln_id}")
@rate_limit()
async def replay_attack(request: Request, vuln_id: str, background_tasks: BackgroundTasks):
    """
    Re-run a specific attack against a confirmed vulnerability to verify if a fix was applied.
    Avoids re-running the entire scan.
    """
    import time

    vuln = await stats_db_manager.find_vulnerability(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="vulnerability not found")

    replay_config = {
        "url": vuln.get("url", ""),
        "method": vuln.get("method", "GET"),
        "headers": vuln.get("headers", {}),
        "payload": vuln.get("payload", ""),
        "modules": [vuln.get("attack_type", vuln.get("type", ""))],
        "velocity": 5,
        "concurrency": 1,
        "rps": 10,
        "filters": [],
        "duration": 60,
    }

    replay_scan_id = f"replay_{vuln_id[:8]}_{int(time.time())}"

    # Register the replay scan
    start_time = datetime.now()
    replay_record = {
        "id": replay_scan_id,
        "status": "Initializing",
        "name": f"REPLAY: {vuln.get('type', 'Unknown')} @ {vuln.get('url', 'Unknown')}",
        "scope": replay_config["url"],
        "modules": replay_config["modules"],
        "timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "results": [],
        "replay_of": vuln_id,
    }
    await stats_db_manager.register_scan(replay_record)

    # Launch replay in background (HiveOrchestrator imported lazily — heavy chain)
    from backend.core.orchestrator import HiveOrchestrator

    background_tasks.add_task(HiveOrchestrator.bootstrap_hive, replay_config, replay_scan_id)

    return {
        "status": "Replay initiated",
        "replay_scan_id": replay_scan_id,
        "original_vuln_id": vuln_id,
        "target": replay_config["url"],
        "module": replay_config["modules"],
    }


@router.get("/vectors")
async def get_attack_vectors():
    """List available attack vectors and modules."""
    vectors = [
        {"id": "tech_sqli", "name": "SQL Injection", "type": "tech", "severity": "critical"},
        {"id": "tech_xss", "name": "Cross-Site Scripting", "type": "tech", "severity": "high"},
        {"id": "tech_ssti", "name": "Server-Side Template Injection", "type": "tech", "severity": "critical"},
        {"id": "tech_cmdi", "name": "Command Injection", "type": "tech", "severity": "critical"},
        {"id": "tech_jwt", "name": "JWT Token Attacks", "type": "tech", "severity": "high"},
        {"id": "tech_auth_bypass", "name": "Authentication Bypass", "type": "tech", "severity": "critical"},
        {"id": "logic_tycoon", "name": "Financial Logic Manipulation", "type": "logic", "severity": "high"},
        {"id": "logic_doppelganger", "name": "IDOR/Session Manipulation", "type": "logic", "severity": "high"},
        {"id": "logic_skipper", "name": "Auth Flow Bypass", "type": "logic", "severity": "medium"},
        {"id": "logic_chronomancer", "name": "Race Condition/Timing", "type": "logic", "severity": "medium"},
        {"id": "logic_escalator", "name": "Privilege Escalation", "type": "logic", "severity": "high"},
        {"id": "recon_nuclei", "name": "Nuclei Templates", "type": "recon", "severity": "critical"},
        {"id": "recon_httpx", "name": "HTTP Fingerprinting", "type": "recon", "severity": "medium"},
    ]
    return {"vectors": vectors, "total": len(vectors)}
