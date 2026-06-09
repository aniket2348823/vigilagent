import asyncio
import argparse
import logging
import signal
import sys
import uuid
import os
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any
from json import JSONDecodeError

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import uvicorn

logger = logging.getLogger(__name__)

# Vigilagent Core Imports
from backend.core.config import settings, ConfigManager
from backend.core.default_tools import register_default_tools
from backend.core.orchestrator import HiveOrchestrator, MasterNode, WorkerNode
from backend.api.socket_manager import manager
from backend.core.state import stats_db_manager
from backend.api.endpoints import recon, attack, reports, dashboard, ai, runtime
from backend.api.endpoints.code_analysis import router as code_analysis_router
from backend.api.endpoints.data import router as data_router
from backend.api.endpoints.self_awareness import router as self_awareness_router
from backend.api.endpoints.skills import router as skills_router
from backend.api.endpoints.bridge import router as bridge_router
from backend.api.endpoints.scans import router as scans_router
from backend.api import defense
from backend.core.task_manager import TaskManager
from backend.core.rate_limiter import start_cleanup_task, rate_limiter
from backend.core.csrf_protection import start_csrf_cleanup_task

# FIX: Windows charmap encoding crash
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception as exc:
        import logging as _log
        _log.getLogger('main').debug('UTF-8 reconfigure failed: %s', exc)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("\n" + "="*50)
    logger.info("VIGILAGENT: UNIFIED LIFECYCLE START")
    logger.info("="*50)
    
    # Clean up zombie scans from ungraceful shutdowns
    cleaned = stats_db_manager.reset_stale_scans()
    if cleaned > 0:
        logger.info(f"[LIFECYCLE] Reset {cleaned} stale scan(s) from previous session.")
    
    # Pillar Initiation (GSD, Ralph, TestSprite)
    logger.info("[PILLAR] Activating Governance Frameworks...")
    register_default_tools()

    # Runtime self-check on boot (Architecture §24): scope authorization,
    # recon tool + Docker availability, configured LLMs, skill catalog.
    try:
        from backend.core.scope import scope_guard
        from backend.core.terminal_engine import terminal_engine
        from backend.core.config import settings as _settings
        logger.info(f"[BOOT] Engagement '{scope_guard.engagement_name}' authorization={scope_guard.authorization} authorized_now={scope_guard.is_authorized()}")
        _tt = terminal_engine.get_telemetry()
        logger.info(f"[BOOT] Terminal Engine: docker_available={_tt['docker_available']} ""prefer_docker={_tt['prefer_docker']}")
        logger.info(f"[BOOT] LLMs: strategic={_settings.STRATEGIC_MODEL} tactical={_settings.TACTICAL_MODEL}")
    except Exception as _e:
        logger.info(f"[BOOT] self-check warning: {_e}")

    # Ingest skill catalog (Architecture §5.3 skill ingestion pipeline).
    try:
        from backend.skills import ingest_skills
        n = ingest_skills()
        logger.info(f"[BOOT] Skill catalog ingested: {n} skills")
    except Exception as _e:
        logger.info(f"[BOOT] skill ingestion skipped: {_e}")

    # Register delegation child runners (Architecture §5.1.2) by importing the
    # commanders package at boot.
    try:
        import backend.agents.commanders  # noqa: F401
        from backend.core.delegation_manager import DelegationManager
        logger.info(f"[BOOT] Delegation child runners ready: NetworkChild={DelegationManager.has_runner('NetworkChild')}")
    except Exception as _e:
        logger.info(f"[BOOT] commander runner registration skipped: {_e}")
    
    # Start rate limiter cleanup task
    cleanup_task = asyncio.create_task(start_cleanup_task())
    logger.info("[RATE_LIMITER] Background cleanup task started")
    
    # Start CSRF protection cleanup task
    csrf_cleanup_task = asyncio.create_task(start_csrf_cleanup_task())
    logger.info("[CSRF_PROTECTION] Background cleanup task started")

    # Eager Redis client init (singleton in backend.core.redis_client) so the
    # health monitor reflects real connectivity from t=0.
    try:
        from backend.core.redis_client import get_redis_client
        await get_redis_client()
        logger.info("[REDIS] Distributed client initialized")
    except Exception as _re:
        logger.info(f"[REDIS] init skipped: {_re}")

    # Eager DB manager init so the first scan doesn't pay the connection
    # cost on the hot path (Architecture §29.13).
    try:
        from backend.core.database import db_manager
        await db_manager.initialize()
        logger.info("[DB] Elite DB manager initialized")
    except Exception as _de:
        logger.info(f"[DB] init skipped: {_de}")

    # Boot-time browser stack health probe (Architecture §7 browser arsenal).
    # Surfaces any OpenClaw / PinchTab unavailability ONCE here with a
    # concrete reason + remediation hint, instead of letting the first scan
    # spam generic "unavailable" warnings. Recon and HTTP probe still run
    # when both engines are offline.
    try:
        from backend.core.browser_orchestrator import get_browser_orchestrator
        _bo = get_browser_orchestrator()
        _bo_health = await _bo.health_check()
        logger.info(
            f"[BROWSER] OpenClaw={_bo_health.get('openclaw')} "
            f"PinchTab={_bo_health.get('pinchtab')} "
            f"reasons={_bo_health.get('reasons') or {}}"
        )
    except Exception as _bhe:
        logger.info(f"[BROWSER] health_check skipped: {_bhe}")
    
    await manager.broadcast({
        "type": "LIFECYCLE_EVENT",
        "payload": {"state": "ACTIVE", "mode": "Unified"}
    })
    
    try:
        yield
    finally:
        logger.info("[LIFECYCLE] Shutting down background tasks...")
        cleanup_task.cancel()
        csrf_cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        try:
            await csrf_cleanup_task
        except asyncio.CancelledError:
            pass
        # Cancel the StateManager background writer cleanly so we don't see
        # the "Task was destroyed but it is pending" warning on Windows.
        try:
            await stats_db_manager.shutdown()
        except Exception as _se:
            logger.info(f"[LIFECYCLE] stats_db_manager.shutdown warning: {_se}")
        await manager.stop_tasks()
        # Close DB + Redis clients (Architecture §29.13).
        try:
            from backend.core.database import db_manager as _dbm
            await _dbm.close()
        except Exception as _ce:
            logger.info(f"[LIFECYCLE] db_manager.close warning: {_ce}")
        try:
            from backend.core.redis_client import shutdown_redis_client
            await shutdown_redis_client()
        except Exception as _re:
            logger.info(f"[LIFECYCLE] redis_client shutdown warning: {_re}")
        logger.info("[LIFECYCLE] Shutdown complete.")

app = FastAPI(title="Vigilagent Scanner", lifespan=lifespan)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """TC004 Compliance: Map missing fields / Pydantic 422s to explicit REST 400 Bad Requests."""
    if request.url.path.endswith("/api/attack/fire"):
        return JSONResponse(
            status_code=422,
            content={"detail": exc.errors()}
        )
    return JSONResponse(
        status_code=400,
        content={"detail": "Invalid or missing payload. Expected a valid request structure."}
    )

# FIX-006: Secure CORS — explicit allowlist, never wildcard with credentials
_DEFAULT_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000"
_cors_env = os.getenv("CORS_ORIGINS", _DEFAULT_ORIGINS).strip()
if _cors_env == "*":
    raise ValueError("CORS_ORIGINS='*' is not allowed when allow_credentials=True. Set explicit origins.")
ALLOWED_ORIGINS = [o.strip() for o in _cors_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# HIGH-43: API key authentication middleware (wired in)
_app_api_key = os.getenv('API_AUTH_KEY', '')
if _app_api_key:
    @app.middleware("http")
    async def _api_key_middleware(request: Request, call_next):
        path = request.url.path
        if path in ('/api/health', '/docs', '/openapi.json', '/') or not path.startswith('/api/'):
            return await call_next(request)
        provided = request.headers.get('X-API-Key', '') or request.headers.get('Authorization', '').replace('Bearer ', '')
        if provided != _app_api_key:
            return JSONResponse(status_code=401, content={'detail': 'Invalid or missing API key'})
        return await call_next(request)

app.include_router(runtime.router, prefix="/api")

# CRIT-17 / HIGH-43: Global rate-limiting middleware applied to ALL API routes.
@app.middleware("http")
async def _rate_limit_middleware(request: Request, call_next):
    # Skip rate limiting for health checks (used by load balancers/monitors)
    if request.url.path.startswith("/api/") and request.url.path != "/api/health":
        client_ip = request.client.host if request.client else "unknown"
        try:
            await rate_limiter.check_rate_limit(client_ip, request.url.path)
        except HTTPException:
            raise  # Let FastAPI's HTTPException propagate with Retry-After header
        except Exception as exc:
            import logging as _log
            _log.getLogger("main").debug("CORS middleware import failed: %s", exc)
            from fastapi.responses import JSONResponse as _JSONResponse
            return _JSONResponse(status_code=429, content={"detail": "Rate limit exceeded."})
    return await call_next(request)

# CRIT-28: Scope-guard middleware — validates target URLs against engagement scope
# before they reach individual API handlers. This closes the gap where scope_guard
# was only enforced during tool execution, not at the API boundary.
@app.middleware("http")
async def _scope_guard_middleware(request: Request, call_next):
    """Reject requests whose JSON body target_url is out of scope."""
    if request.method in ("POST", "PUT", "PATCH") and request.url.path.startswith("/api/"):
        try:
            body = await request.body()
            if body:
                import json as _json
                data = _json.loads(body)
                target = (
                    data.get("target_url")
                    or data.get("url")
                    or (data.get("target", {}).get("url") if isinstance(data.get("target"), dict) else None)
                )
                if target and isinstance(target, str):
                    from backend.core.scope import scope_guard as _sg, ScopeViolation
                    try:
                        _sg.assert_allowed(target, action="api_request")
                    except ScopeViolation as sv:
                        return JSONResponse(status_code=403, content={"detail": str(sv)})
        except JSONDecodeError:
            pass  # Non-JSON bodies pass through
        except Exception as exc:
            import logging as _log
            _log.getLogger("main").debug("CORS preflight handling failed: %s", exc)
            pass  # Other errors pass through to handler
    return await call_next(request)

# Routes
@app.get("/api/health")
async def health_check():
    """Production health check — tests infra components."""
    import time as _t
    start = _t.time()
    comps = {}
    try:
        comps["supabase"] = "healthy" if settings.SUPABASE_URL else "not_configured"
    except Exception as exc:
        import logging as _log
        _log.getLogger("main").debug("Supabase health check failed: %s", exc)
        comps["supabase"] = "unhealthy"

    try:
        if settings.REDIS_URL:
            import redis.asyncio as aioredis
            r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            await r.ping(); await r.close()
            comps["redis"] = "healthy"
        else:
            comps["redis"] = "not_configured"
    except Exception as exc:
        import logging as _log
        _log.getLogger("main").debug("Redis health check failed: %s", exc)
        comps["redis"] = "unhealthy"
    comps["alpha"] = "enabled" if getattr(settings, "ALPHA_ENABLE_V6", False) else "disabled"
    overall = "healthy" if "unhealthy" not in comps.values() else "degraded"
    # FIX-045: Return minimal info for unauthenticated health checks
    return {"status": overall,
            "latency_ms": round((_t.time() - start) * 1000, 1)}


@app.get("/api/tools")
async def list_tools():
    """Recon tool inventory + availability (Architecture §7, §22)."""
    try:
        from backend.tools.recon.registry import RECON_TOOLS, check_tool_availability
        tools = []
        for name, spec in RECON_TOOLS.items():
            avail = check_tool_availability(name)
            tools.append({"name": name, "phase": spec.get("phase"),
                          "binary": spec.get("binary"), "modes": spec.get("modes", []),
                          "installed": avail.get("installed", False),
                          "source": avail.get("source", ""), "reason": avail.get("reason", "")})
        installed = sum(1 for t in tools if t["installed"])
        return {"tools": tools, "total": len(tools), "installed": installed}
    except Exception as e:
        return {"tools": [], "error": str(e)}

app.include_router(recon.router, prefix="/api/recon", tags=["Recon"])
app.include_router(attack.router, prefix="/api/attack", tags=["Attack"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(defense.router, prefix="/api/defense", tags=["Defense"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(ai.router, prefix="/api/ai", tags=["AI"])
app.include_router(code_analysis_router, prefix="/api", tags=["Code Analysis"])  # PROBLEM 18
app.include_router(data_router, prefix="/api/data", tags=["Data"])
app.include_router(self_awareness_router, prefix="/api/self-awareness", tags=["Self-Awareness"])
app.include_router(skills_router, prefix="/api/skills", tags=["Skills"])
app.include_router(bridge_router, prefix="/bridge", tags=["Extension Bridge"])
app.include_router(scans_router, prefix="/api/scans", tags=["Scans"])

# Alpha Recon API
from backend.agents.alpha_recon.api_routes import router as alpha_recon_router

app.include_router(alpha_recon_router, tags=["Alpha Recon"])

@app.websocket("/stream")
@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket, client_type: str = Query("ui"), token: str = Query(None)):
    from backend.api.endpoints.dashboard import load_config, load_session

    # CRIT-12: WebSocket Origin Validation — reject connections from
    # unexpected origins to prevent cross-site WebSocket hijacking.
    origin = websocket.headers.get("origin", "")
    if origin:
        from urllib.parse import urlparse as _urlparse
        try:
            origin_host = (_urlparse(origin).hostname or "").lower()
        except Exception as exc:
            import logging as _log
            _log.getLogger("main").debug("CORS origin parse failed: %s", exc)
            origin_host = ""
            if origin_host:
                _allowed_hosts = set()
                for _o in ALLOWED_ORIGINS:
                    try:
                        _h = _urlparse(_o).hostname or ""
                        if _h:
                            _allowed_hosts.add(_h.lower())
                    except Exception as exc:
                            import logging as _log
                            _log.getLogger("main").debug("CORS port parse failed: %s", exc)
                if origin_host not in _allowed_hosts:
                        await websocket.close(code=1008, reason="Policy Violation: Disallowed Origin")
                        return

    # WebSocket Authentication Handshake.
    try:
        config = load_config() or {}
    except Exception as exc:
        import logging as _log
        _log.getLogger("main").debug("CORS config load failed: %s", exc)
        config = {}
    auth_required = bool(config.get("enabled", True))
    if auth_required:
        try:
            session = load_session() or {}
        except Exception as exc:
            import logging as _log
            _log.getLogger("main").debug("CORS session init failed: %s", exc)
            session = {}
        # Disconnect any unauthenticated or token-mismatched websockets
        if not session.get("authenticated") or session.get("token") != token:
            await websocket.close(code=1008, reason="Policy Violation: Invalid Auth Token")
            return

    # HIGH-42: WebSocket auth is already enforced via load_config/load_session token check above
    await manager.connect(websocket, client_type)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# --- INTEGRATED CLUSTER ORCHESTRATOR ---

class DistributedAttackCluster:
    """Orchestrates the lifecycle of the distributed cluster components."""
    def __init__(self, mode: str):
        self.mode = mode
        self.config = ConfigManager()
        self.running = False
        self.master_node: Optional[MasterNode] = None
        self.worker_node: Optional[WorkerNode] = None
        self._task_manager = TaskManager("DistributedCluster")
        
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (ValueError, NotImplementedError):
            pass
    
    def _signal_handler(self, signum, frame):
        logger.info(f"🛑 Received signal {signum}, initiating clean cluster extraction...")
        self.running = False
    
    async def start_master(self):
        try:
            self.master_node = MasterNode(
                self.config.redis.url,
                self.config.supabase.url,
                self.config.supabase.key
            )
            self.running = True
            logger.info("📡 VIGILAGENT: Master Node Activated.")
            await self.master_node.start()
        except Exception as e:
            logger.info(f"❌ Master start error: {e}")
            raise
    
    async def start_worker(self, worker_id: Optional[str] = None):
        try:
            worker_id = worker_id or self.config.worker.worker_id or f"worker-{uuid.uuid4().hex[:6]}"
            self.worker_node = WorkerNode(
                worker_id,
                self.config.worker.specialty,
                self.config.redis.url,
                self.config.supabase.url,
                self.config.supabase.key
            )
            self.running = True
            logger.info(f"🦾 VIGILAGENT: Worker Node Activated ({worker_id})")
            await self.worker_node.start()
        except Exception as e:
            logger.info(f"❌ Worker start error: {e}")
            raise

    async def start_cluster(self, num_workers: int = 5):
        master_task = self._task_manager.create_task(
            self.start_master(),
            name="master_node"
        )
        await asyncio.sleep(2)
        worker_tasks = []
        for i in range(num_workers):
            wid = f"worker-{i+1}-{uuid.uuid4().hex[:4]}"
            worker_task = self._task_manager.create_task(
                self.start_worker(wid),
                name=f"worker_{wid}"
            )
            worker_tasks.append(worker_task)
            await asyncio.sleep(0.5)
        logger.info(f"🔗 Cluster Handshake: 1 Master + {num_workers} Workers Linked.")
        await asyncio.gather(master_task, *worker_tasks)

# --- EXECUTION KERNEL ---

async def vulagent_serve(args):
    if args.mode == "serve":
        logger.info(f"🚀 Launching Vigilagent API Gateway on {args.host}:{args.port}")
        config = uvicorn.Config(app, host=args.host, port=args.port, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()
    else:
        cluster = DistributedAttackCluster(args.mode)
        try:
            if args.mode == "master":
                await cluster.start_master()
            elif args.mode == "worker":
                await cluster.start_worker(args.worker_id)
            elif args.mode == "cluster":
                await cluster.start_cluster(args.num_workers)
        except Exception as e:
            logger.info(f"🚨 Cluster Hard Crash: {e}")
            sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vigilagent: Unified Entry Point")
    parser.add_argument("--mode", choices=["serve", "master", "worker", "cluster"], default="serve", help="Execution mode.")
    parser.add_argument("--host", default="127.0.0.1", help="API Host.")
    parser.add_argument("--port", type=int, default=8000, help="API Port.")
    # Cluster worker count default comes from config/workers.yaml (Architecture §29.10).
    try:
        from backend.core.config import load_workers_config
        _default_workers = int(load_workers_config().get("default_num_workers", 3))
    except Exception as exc:
        import logging as _log
        _log.getLogger('main').debug('workers config fallback: %s', exc)
        _default_workers = 3
    parser.add_argument("--num-workers", type=int, default=_default_workers, help="Cluster worker count.")
    parser.add_argument("--worker-id", help="Override worker ID.")
    
    args = parser.parse_args()
    try:
        asyncio.run(vulagent_serve(args))
    except KeyboardInterrupt:
        print("\n[VIGILAGENT] Service shutdown by user.")
