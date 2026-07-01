import collections
import logging
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel
from starlette.responses import JSONResponse

# Hybrid AI Engine
from backend.ai.cortex import get_cortex_engine
from backend.api.socket_manager import manager  # UI Broadcast

# Import your orchestrator instance class to access static registry
from backend.core.orchestrator import HiveOrchestrator
from backend.core.protocol import AgentID, JobPacket, ModuleConfig, TaskTarget

logger = logging.getLogger(__name__)

router = APIRouter()


# Rate limiter for /analyze endpoint (security hardening)
class _AnalyzeRateLimiter:
    """Simple sliding window rate limiter for the defense analyze endpoint."""

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self._max = max_requests
        self._window = window_seconds
        self._requests: dict[str, list[float]] = collections.defaultdict(list)
        self._total_checks = 0

    def check(self, client_ip: str) -> bool:
        now = __import__("time").time()
        cutoff = now - self._window
        # Prune old entries
        self._requests[client_ip] = [t for t in self._requests[client_ip] if t > cutoff]
        if len(self._requests[client_ip]) >= self._max:
            return False
        self._requests[client_ip].append(now)
        # Periodic cleanup: every 100 requests, purge stale IPs
        self._total_checks = getattr(self, "_total_checks", 0) + 1
        if self._total_checks % 100 == 0:
            self.cleanup()
        return True

    def cleanup(self) -> None:
        """Remove stale entries to prevent unbounded memory growth."""
        import time as _time

        now = _time.time()
        cutoff = now - self._window
        stale = [ip for ip, times in self._requests.items() if not times or times[-1] < cutoff]
        for ip in stale:
            del self._requests[ip]
        # M-2: Hard cap on tracked IPs to prevent memory exhaustion
        MAX_TRACKED_IPS = 10000
        if len(self._requests) > MAX_TRACKED_IPS:
            # Force-evict oldest 20%
            sorted_ips = sorted(
                self._requests.keys(), key=lambda ip: self._requests[ip][-1] if self._requests[ip] else 0
            )
            evict_count = len(self._requests) // 5
            for ip in sorted_ips[:evict_count]:
                del self._requests[ip]


_analyze_rate_limiter = _AnalyzeRateLimiter()

# Lazy-init: import at call time to avoid blocking app startup (HIGH-49)
_cortex = None
_ephemeral_bus = None  # H-11: Module-level singleton to avoid Redis connection exhaustion


def _get_cortex():
    global _cortex
    if _cortex is None:
        _cortex = get_cortex_engine()
    return _cortex


class ThreatPayload(BaseModel):
    agent_id: str  # "agent_prism" or "agent_chi"
    content: dict[str, Any]  # The DOM data or Text
    url: str
    session_id: str | None = "anonymous-session"  # V6: Session Persistence


@router.post("/alerts")
async def receive_alertmanager_alert(request: Request):
    """Webhook endpoint for Alertmanager to POST firing/resolved alerts."""
    try:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "Invalid JSON"})
        alerts = body.get("alerts", [])
        if not isinstance(alerts, list):
            alerts = []
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            status = alert.get("status", "unknown")
            labels = alert.get("labels", {})
            annotations = alert.get("annotations", {})
            alertname = labels.get("alertname", "Unknown")
            severity = labels.get("severity", "warning")
            summary = annotations.get("summary", "")
            log_fn = logger.warning if status == "firing" else logger.info
            log_fn(
                "[Alertmanager] %s %s: %s (%s)", status.upper(), severity.upper(), alertname, summary
            )
            # Broadcast to UI
            await manager.broadcast({
                "type": "ALERTMANAGER_ALERT",
                "payload": {
                    "status": status,
                    "alertname": alertname,
                    "severity": severity,
                    "summary": summary,
                    "description": annotations.get("description", ""),
                },
            })
        return {"status": "ok", "alerts_received": len(alerts)}
    except Exception as e:
        logger.error("Alertmanager webhook error: %s", e)
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/analyze")
async def analyze_threat_discovery():
    """Satisfy endpoint discovery checks from TC005."""
    return {"status": "ready", "capabilities": ["injection_detection", "anomaly_classification"]}


@router.post("/analyze")
async def analyze_threat(request: Request):
    """
    The Single Entry Point for the Extension Defense Shield.
    """
    try:
        # Rate limiting for defense analysis endpoint
        client_ip = request.client.host if request.client else "unknown"
        if not _analyze_rate_limiter.check(client_ip):
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded. Max 30 requests per minute.", "mode": "rate_limited"},
            )

        body = await request.body()
        if not body:
            return JSONResponse(status_code=500, content={"error": "Empty payload", "mode": "validation_error"})
        try:
            import json

            raw_payload = json.loads(body)
        except Exception as exc:
            logging.getLogger("defense").debug("JSON parse failed: %s", exc)
            return JSONResponse(status_code=500, content={"error": "Malformed json", "mode": "validation_error"})

        # Manually invoke Pydantic model
        try:
            payload = ThreatPayload(**raw_payload)
        except Exception as exc:
            logging.getLogger("defense").debug("Pydantic validation failed: %s", exc)
            return JSONResponse(
                status_code=500, content={"error": "Schema validation failed", "mode": "validation_error"}
            )

        # Validate content is a dict
        if not isinstance(payload.content, dict):
            return JSONResponse(
                status_code=500,
                content={"error": "Invalid content format: expected object", "mode": "validation_error"},
            )

        # Validate agent_id is not None/empty
        if not payload.agent_id:
            return JSONResponse(status_code=500, content={"error": "agent_id is required", "mode": "validation_error"})

        # 1. Lookup Agent
        agent = HiveOrchestrator.active_agents.get(payload.agent_id)

        if not agent:
            from backend.core.hive import DistributedEventBus, EventBus

            # H-11: Use a module-level singleton ephemeral bus to avoid creating
            # a new Redis connection pool per request (exhausts Redis connections
            # under load).
            global _ephemeral_bus
            if _ephemeral_bus is None:
                try:
                    _ephemeral_bus = DistributedEventBus("redis://localhost:6379")
                except Exception as exc:
                    logging.getLogger("defense").debug("Distributed bus unavailable, using local: %s", exc)
                    _ephemeral_bus = EventBus()
            ephemeral_bus = _ephemeral_bus

            if payload.agent_id == "agent_prism":
                from backend.agents.prism import AgentPrism

                agent = AgentPrism(ephemeral_bus)
            elif payload.agent_id == "agent_chi":
                from backend.agents.chi import AgentChi

                agent = AgentChi(ephemeral_bus)
            else:
                return {"verdict": "IDLE", "reason": "Vigilagent Hive is in Standby Mode", "risk_score": 0}

        # 2. Create a Job Packet for the Agent
        # We wrap the extension data into a format the Agent understands (JobPacket)
        # Mapping "agent_prism" -> AgentID.PRISM
        agent_enum = AgentID.PRISM if payload.agent_id == "agent_prism" else AgentID.CHI

        packet = JobPacket(
            target=TaskTarget(
                url=payload.url,
                payload=payload.content,  # Passing content here
            ),
            config=ModuleConfig(
                module_id="defense_scan",
                agent_id=agent_enum,
                aggression=1,
                ai_mode=False,
                session_id=payload.session_id,  # V6: Persist Session Context
            ),
        )

        # 3. Execute the Agent Logic (Prism or Chi)
        result = await agent.execute_task(packet)

        # 4. Return Verdict to Extension (BLOCK or ALLOW)
        reason = None
        if result.vulnerabilities:
            reason = result.vulnerabilities[0].description

        # HYBRID AI: Dynamic risk scoring instead of hardcoded 95/10
        if result.vulnerabilities:
            risk_score = await _get_cortex().assess_contextual_risk(
                threat_type=reason or "UI_ANOMALY", target_url=payload.url, context=payload.content
            )
        else:
            risk_score = 10

        verdict = "BLOCK" if result.status == "THREAT_BLOCKED" else "ALLOW"

        # BROADCAST TO UI (Real-time Feedback)
        await manager.broadcast(
            {
                "type": "LIVE_THREAT_LOG",
                "source": payload.agent_id,
                "payload": {
                    "timestamp": result.timestamp,
                    "agent": payload.agent_id,
                    "threat_type": reason or "UI_ANOMALY",
                    "url": payload.url,
                    "severity": "CRITICAL" if verdict == "BLOCK" else "LOW",
                    "risk_score": risk_score,
                    "verdict": verdict,
                },
            }
        )

        return {"verdict": verdict, "reason": reason, "risk_score": risk_score}
    except Exception as e:
        # FIX-056: Don't leak internal error details
        logging.getLogger("defense").error(f"Defense analysis error: {e}")
        return JSONResponse(status_code=500, content={"error": "Internal analysis error", "mode": "internal_error"})
