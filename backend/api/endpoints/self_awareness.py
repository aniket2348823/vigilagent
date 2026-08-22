"""
SELF-AWARENESS API ENDPOINTS
REST API endpoints for self-awareness metrics and monitoring.

Provides endpoints for:
- Performance metrics
- Proficiency scores
- Decision logs
- Coordination status
- Audit trails
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from backend.core.rate_limiter import rate_limit
from backend.core.tracing import get_tracer, trace_span

router = APIRouter()
logger = logging.getLogger("SelfAwarenessAPI")
tracer = get_tracer()


# ============================================================================
# ROOT SUMMARY (Architecture §15, §22 — GET /api/self-awareness)
# ============================================================================


@router.get("")
@router.get("/")
@router.get("/status")
@rate_limit()
async def get_self_awareness_summary():
    """Self-awareness summary (Architecture §15 outputs, §22 API surface).

    Returns the capability map / health snapshot: agent + tool reliability,
    staged self-improvement changes, and recommended next action. Degrades
    gracefully when subsystems are unavailable so the endpoint always answers.
    """
    summary: dict = {
        "product": "Vigilagent",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "capability_map": {},
        "self_improvement": {},
        "skills": {},
        "recommended_next_action": "idle",
    }
    # Agent/tool reliability + staged improvements (Architecture §13.4, §15.1).
    try:
        from backend.core.self_improvement_engine import self_improvement_engine

        summary["self_improvement"] = self_improvement_engine.stats()
        summary["capability_map"] = {
            aid: {
                "routing_weight": p.routing_weight,
                "success_rate": p.success_rate,
                "false_positive_rate": p.false_positive_rate,
            }
            for aid, p in self_improvement_engine.profiles.items()
        }
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("self-improvement stats unavailable: %s", exc)
    # Skill catalog coverage (Architecture §5.3).
    try:
        from backend.skills.catalog import skill_catalog

        summary["skills"] = skill_catalog.stats()
    except Exception as exc:  # pragma: no cover
        logger.debug("skill stats unavailable: %s", exc)
    return JSONResponse(content=summary)


# ============================================================================
# PERFORMANCE METRICS ENDPOINTS
# ============================================================================


@router.get("/agents/{agent_id}/performance")
@rate_limit()
async def get_agent_performance(
    agent_id: str, window_minutes: int = Query(60, ge=1, le=1440, description="Time window in minutes")
):
    """
    Get performance metrics for a specific agent.

    Returns:
    - Success rates
    - Resource usage (CPU, memory, API calls)
    - Response times
    - Stuck state indicators

    Query params:
    - window_minutes: Time window for metrics (default: 60, max: 1440)
    """
    with trace_span(
        "api.self_awareness.get_agent_performance", {"agent_id": agent_id, "window_minutes": window_minutes}
    ):
        try:
            from backend.core.hive import hive

            # Get agent from hive
            agent = hive.get_agent(agent_id)

            if not agent:
                return JSONResponse(status_code=404, content={"error": f"Agent {agent_id} not found"})

            # Check if agent has self-awareness enabled
            if not hasattr(agent, "self_awareness") or not agent.self_awareness:
                return JSONResponse(
                    status_code=200,
                    content={
                        "agent_id": agent_id,
                        "self_awareness_enabled": False,
                        "message": "Self-awareness not enabled for this agent",
                    },
                )

            # Get performance metrics
            performance_tracker = agent.self_awareness.performance_tracker
            metrics = await performance_tracker.get_metrics_summary()

            # Get resource usage
            resource_usage = performance_tracker.get_resource_usage()

            # Check stuck state
            stuck_info = await performance_tracker.detect_stuck_state()

            return JSONResponse(
                content={
                    "success": True,
                    "agent_id": agent_id,
                    "self_awareness_enabled": True,
                    "window_minutes": window_minutes,
                    "metrics": metrics,
                    "resource_usage": {
                        "cpu_percent": resource_usage.cpu_percent,
                        "memory_mb": resource_usage.memory_mb,
                        "api_calls_per_minute": resource_usage.api_calls_per_minute,
                        "timestamp": resource_usage.timestamp,
                    },
                    "stuck_state": {
                        "is_stuck": stuck_info is not None,
                        "action_type": stuck_info.action_type if stuck_info else None,
                        "consecutive_failures": stuck_info.consecutive_failures if stuck_info else 0,
                        "first_failure_time": stuck_info.first_failure_time.isoformat() if stuck_info else None,
                        "last_failure_time": stuck_info.last_failure_time.isoformat() if stuck_info else None,
                    }
                    if stuck_info
                    else None,
                }
            )

        except Exception as e:
            logger.error(f"Failed to get performance metrics for {agent_id}: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/agents/metrics/summary")
@rate_limit()
async def get_all_agents_metrics_summary():
    """
    Get performance metrics summary for all agents with self-awareness enabled.

    Returns aggregated metrics across all agents:
    - Total actions
    - Average success rates
    - Resource usage
    - Stuck agents
    """
    with trace_span("api.self_awareness.get_all_agents_metrics_summary"):
        try:
            from backend.core.hive import hive

            all_agents = hive.get_all_agents()

            summary = {
                "timestamp": datetime.utcnow().isoformat(),
                "total_agents": len(all_agents),
                "self_aware_agents": 0,
                "agents": [],
                "aggregated": {
                    "total_actions": 0,
                    "total_successful": 0,
                    "total_failed": 0,
                    "avg_success_rate": 0.0,
                    "stuck_agents": 0,
                },
            }

            total_success_rate = 0.0

            for agent in all_agents:
                if not hasattr(agent, "self_awareness") or not agent.self_awareness:
                    continue

                summary["self_aware_agents"] += 1

                # Get metrics for this agent
                performance_tracker = agent.self_awareness.performance_tracker
                metrics = await performance_tracker.get_metrics_summary()

                # Check stuck state
                stuck_info = await performance_tracker.detect_stuck_state()

                agent_summary = {
                    "agent_id": agent.agent_id,
                    "total_actions": metrics.get("total_actions", 0),
                    "success_rate": metrics.get("success_rate", 0.0),
                    "is_stuck": stuck_info is not None,
                }

                summary["agents"].append(agent_summary)

                # Aggregate
                summary["aggregated"]["total_actions"] += metrics.get("total_actions", 0)
                summary["aggregated"]["total_successful"] += metrics.get("successful_actions", 0)
                summary["aggregated"]["total_failed"] += metrics.get("failed_actions", 0)
                total_success_rate += metrics.get("success_rate", 0.0)

                if stuck_info:
                    summary["aggregated"]["stuck_agents"] += 1

            # Calculate average success rate
            if summary["self_aware_agents"] > 0:
                summary["aggregated"]["avg_success_rate"] = total_success_rate / summary["self_aware_agents"]

            return JSONResponse(content=summary)

        except Exception as e:
            logger.error(f"Failed to get metrics summary: {e}")
            return JSONResponse(status_code=500, content={"error": str(e)})


# ============================================================================
# PROFICIENCY ENDPOINTS
# ============================================================================


@router.get("/agents/{agent_id}/proficiency")
@rate_limit()
async def get_agent_proficiency(agent_id: str, skill: str | None = Query(None, description="Filter by specific skill")):
    """
    Get proficiency scores for a specific agent.

    Returns:
    - Skill proficiency map (0.0 to 1.0)
    - Attempt counts
    - Success counts

    Query params:
    - skill: Optional filter for specific skill
    """
    try:
        from backend.core.hive import hive

        # Get agent from hive
        agent = hive.get_agent(agent_id)

        if not agent:
            return JSONResponse(status_code=404, content={"error": f"Agent {agent_id} not found"})

        # Check if agent has self-awareness enabled
        if not hasattr(agent, "self_awareness") or not agent.self_awareness:
            return JSONResponse(
                status_code=200,
                content={
                    "agent_id": agent_id,
                    "self_awareness_enabled": False,
                    "message": "Self-awareness not enabled for this agent",
                },
            )

        capability_assessor = agent.self_awareness.capability_assessor

        if skill:
            # Get proficiency for specific skill
            proficiency = await capability_assessor.get_proficiency(skill)

            return JSONResponse(
                content={"success": True, "agent_id": agent_id, "skill": skill, "proficiency": proficiency}
            )
        else:
            # Get all proficiency scores
            skill_map = await capability_assessor.get_skill_map()

            return JSONResponse(
                content={"success": True, "agent_id": agent_id, "skills": skill_map, "total_skills": len(skill_map)}
            )

    except Exception as e:
        logger.error(f"Failed to get proficiency for {agent_id}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


# ============================================================================
# DECISION LOG ENDPOINTS
# ============================================================================


@router.get("/agents/{agent_id}/decisions")
@rate_limit()
async def get_agent_decisions(
    agent_id: str,
    action_type: str | None = Query(None, description="Filter by action type"),
    start_time: str | None = Query(None, description="Start time (ISO format)"),
    end_time: str | None = Query(None, description="End time (ISO format)"),
    min_confidence: float | None = Query(None, ge=0.0, le=1.0, description="Minimum confidence"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
):
    """
    Get decision logs for a specific agent.

    Returns:
    - Decision history with rationale
    - Confidence levels
    - Alternatives considered
    - Context information

    Query params:
    - action_type: Filter by action type
    - start_time: Filter by start time (ISO format)
    - end_time: Filter by end time (ISO format)
    - min_confidence: Minimum confidence threshold
    - limit: Maximum number of results (default: 100, max: 1000)
    """
    try:
        from backend.core.hive import hive

        # Get agent from hive
        agent = hive.get_agent(agent_id)

        if not agent:
            return JSONResponse(status_code=404, content={"error": f"Agent {agent_id} not found"})

        # Check if agent has self-awareness enabled
        if not hasattr(agent, "self_awareness") or not agent.self_awareness:
            return JSONResponse(
                status_code=200,
                content={
                    "agent_id": agent_id,
                    "self_awareness_enabled": False,
                    "decisions": [],
                    "message": "Self-awareness not enabled for this agent",
                },
            )

        decision_logger = agent.self_awareness.decision_logger

        # Parse datetime filters
        start_dt = datetime.fromisoformat(start_time) if start_time else None
        end_dt = datetime.fromisoformat(end_time) if end_time else None

        # Query decisions
        decisions = await decision_logger.query_decisions(
            agent_id=agent_id,
            action_type=action_type,
            start_time=start_dt,
            end_time=end_dt,
            min_confidence=min_confidence,
            limit=limit,
        )

        # Convert to dict
        decisions_data = []
        for decision in decisions:
            decisions_data.append(
                {
                    "decision_id": decision.decision_id,
                    "agent_id": decision.agent_id,
                    "timestamp": decision.timestamp.isoformat(),
                    "action_type": decision.action_type,
                    "rationale": decision.rationale,
                    "confidence": decision.confidence,
                    "alternatives_considered": decision.alternatives_considered,
                    "context": decision.context,
                    "finding_id": decision.finding_id,
                }
            )

        return JSONResponse(
            content={
                "success": True,
                "agent_id": agent_id,
                "decisions": decisions_data,
                "total_count": len(decisions_data),
                "filters": {
                    "action_type": action_type,
                    "start_time": start_time,
                    "end_time": end_time,
                    "min_confidence": min_confidence,
                    "limit": limit,
                },
            }
        )

    except Exception as e:
        logger.error(f"Failed to get decisions for {agent_id}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/findings/{finding_id}/audit-trail")
@rate_limit()
async def get_finding_audit_trail(finding_id: str):
    """
    Get complete audit trail for a finding.

    Returns the complete decision chain that led to the finding,
    including all intermediate decisions and rationale.

    Path params:
    - finding_id: The finding ID to get audit trail for
    """
    try:
        from backend.core.hive import hive

        # Get all agents to search for decisions
        all_agents = hive.get_all_agents()

        all_decisions = []

        for agent in all_agents:
            if not hasattr(agent, "self_awareness") or not agent.self_awareness:
                continue

            decision_logger = agent.self_awareness.decision_logger

            # Get decision chain for this finding
            decisions = await decision_logger.get_decision_chain(finding_id)

            for decision in decisions:
                all_decisions.append(
                    {
                        "decision_id": decision.decision_id,
                        "agent_id": decision.agent_id,
                        "timestamp": decision.timestamp.isoformat(),
                        "action_type": decision.action_type,
                        "rationale": decision.rationale,
                        "confidence": decision.confidence,
                        "alternatives_considered": decision.alternatives_considered,
                        "context": decision.context,
                    }
                )

        # Sort by timestamp
        all_decisions.sort(key=lambda d: d["timestamp"])

        return JSONResponse(
            content={
                "success": True,
                "finding_id": finding_id,
                "audit_trail": all_decisions,
                "total_decisions": len(all_decisions),
            }
        )

    except Exception as e:
        logger.error(f"Failed to get audit trail for finding {finding_id}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


# ============================================================================
# COORDINATION STATUS ENDPOINTS
# ============================================================================


@router.get("/agents/coordination/status")
@rate_limit()
async def get_coordination_status():
    """
    Get coordination status for all agents.

    Returns:
    - Agent availability
    - Delegation history
    - Meta-awareness state (Omega)
    - Assistance requests
    """
    try:
        from backend.core.hive import hive

        all_agents = hive.get_all_agents()

        status = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_agents": len(all_agents),
            "self_aware_agents": 0,
            "agents": [],
            "meta_awareness": None,
        }

        for agent in all_agents:
            if not hasattr(agent, "self_awareness") or not agent.self_awareness:
                continue

            status["self_aware_agents"] += 1

            coordination_manager = agent.self_awareness.coordination_manager

            agent_status = {
                "agent_id": agent.agent_id,
                "available": True,  # Would check actual availability
                "capabilities": {},
            }

            # Get proficiency scores as capabilities
            capability_assessor = agent.self_awareness.capability_assessor
            skill_map = await capability_assessor.get_skill_map()
            agent_status["capabilities"] = skill_map

            status["agents"].append(agent_status)

            # Get meta-awareness from Omega
            if agent.agent_id.lower() == "omega":
                meta_awareness = coordination_manager.get_meta_awareness()
                status["meta_awareness"] = meta_awareness

        return JSONResponse(content=status)

    except Exception as e:
        logger.error(f"Failed to get coordination status: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/agents/{agent_id}/delegations")
@rate_limit()
async def get_agent_delegations(agent_id: str, limit: int = Query(50, ge=1, le=500, description="Maximum results")):
    """
    Get delegation history for a specific agent.

    Returns:
    - Tasks delegated by this agent
    - Tasks delegated to this agent
    - Delegation rationale

    Query params:
    - limit: Maximum number of results (default: 50, max: 500)
    """
    try:
        from backend.core.hive import hive

        # Get agent from hive
        agent = hive.get_agent(agent_id)

        if not agent:
            return JSONResponse(status_code=404, content={"error": f"Agent {agent_id} not found"})

        # Check if agent has self-awareness enabled
        if not hasattr(agent, "self_awareness") or not agent.self_awareness:
            return JSONResponse(
                status_code=200,
                content={
                    "agent_id": agent_id,
                    "self_awareness_enabled": False,
                    "delegations": [],
                    "message": "Self-awareness not enabled for this agent",
                },
            )

        # Query delegation decisions from decision logger
        decision_logger = agent.self_awareness.decision_logger

        decisions = await decision_logger.query_decisions(agent_id=agent_id, action_type="DELEGATE_TASK", limit=limit)

        delegations = []
        for decision in decisions:
            delegations.append(
                {
                    "decision_id": decision.decision_id,
                    "timestamp": decision.timestamp.isoformat(),
                    "rationale": decision.rationale,
                    "confidence": decision.confidence,
                    "target_agent": decision.context.get("target_agent"),
                    "task_type": decision.context.get("task_type"),
                }
            )

        return JSONResponse(
            content={"success": True, "agent_id": agent_id, "delegations": delegations, "total_count": len(delegations)}
        )

    except Exception as e:
        logger.error(f"Failed to get delegations for {agent_id}: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


# ============================================================================
# OMEGA META-AWARENESS ENDPOINT
# ============================================================================


@router.get("/agents/omega/meta-awareness")
@rate_limit()
async def get_omega_meta_awareness():
    """
    Get Omega's meta-awareness of all agent states.

    Returns comprehensive view of:
    - All agent capabilities
    - Proficiency levels
    - Current states
    - Resource availability

    Only available when Omega agent has self-awareness enabled.
    """
    try:
        from backend.core.hive import hive

        # Get Omega agent
        omega = hive.get_agent("omega")

        if not omega:
            return JSONResponse(status_code=404, content={"error": "Omega agent not found"})

        # Check if Omega has self-awareness enabled
        if not hasattr(omega, "self_awareness") or not omega.self_awareness:
            return JSONResponse(
                status_code=200,
                content={
                    "agent_id": "omega",
                    "self_awareness_enabled": False,
                    "message": "Self-awareness not enabled for Omega",
                },
            )

        coordination_manager = omega.self_awareness.coordination_manager
        meta_awareness = coordination_manager.get_meta_awareness()

        return JSONResponse(
            content={
                "success": True,
                "agent_id": "omega",
                "timestamp": datetime.utcnow().isoformat(),
                "meta_awareness": meta_awareness,
                "tracked_agents": len(meta_awareness),
            }
        )

    except Exception as e:
        logger.error(f"Failed to get Omega meta-awareness: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
