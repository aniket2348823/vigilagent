"""
XYTHERION EXECUTION NODE (WORKER NODE)
Role: Distributed task executor with browser automation, module dispatch, and heartbeat.
Extracted from orchestrator.py for clean architecture.
"""

import asyncio
import importlib
import json
import logging
import uuid
from datetime import datetime

import aiohttp
import psutil

from backend.core.cluster.pinchtab import PinchTabInstance
from backend.core.hive import DistributedEventBus, EventType, HiveEvent
from backend.core.stdout_watchdog import watch_output
from backend.core.task_manager import TaskManager

logger = logging.getLogger("WorkerNode")


class WorkerNode:
    """XYTHERION EXECUTION NODE (WORKER NODE)"""

    def __init__(self, worker_id: str, specialty: str, redis_url: str, supabase_url: str, supabase_key: str):
        self.id = worker_id
        self.specialty = specialty
        self.redis_client = None  # Initialized lazily in start() via centralized pool
        # Supabase is OPTIONAL — keep working with Redis-only when missing
        # (Architecture §29.13: never block the cluster on a slow/down DB).
        self.supabase = None
        if supabase_url and supabase_key:
            try:
                from supabase import Client, create_client  # noqa: F401

                self.supabase = create_client(supabase_url, supabase_key)
            except Exception as exc:
                logger.warning(
                    "WorkerNode[%s]: Supabase init failed (%s) — running without persistent task ledger.",
                    worker_id,
                    exc,
                )
                self.supabase = None
        self.pinchtab = PinchTabInstance(worker_id, 9867 + hash(worker_id) % 1000)
        self.bus = DistributedEventBus(redis_url)
        self.running = False
        self._task_manager = TaskManager("WorkerNode")

    async def start(self):
        self.running = True
        from backend.core.redis_client import get_redis_client

        rc = await get_redis_client()
        self.redis_client = rc.client
        # Publisher-only bus: the worker consumes jobs via brpop on its own
        # queue, and only EMITS VULN_CONFIRMED / JOB_COMPLETED. Subscribing
        # here added a phantom peer (NUMSUB=2) in single-process installs,
        # re-enabling the Redis round-trip + duplicate events.
        await self.bus.start(listen=False)
        if self.specialty in ["browser", "hybrid"]:
            await self.pinchtab.start()
        self._task_manager.create_task(self.send_heartbeat(), name="heartbeat")
        try:
            while self.running:
                if psutil.virtual_memory().percent > 85.0:
                    await asyncio.sleep(5)
                    continue
                try:
                    task_data = await self.redis_client.brpop(f"worker_queue:{self.id}", timeout=5)
                except Exception as exc:
                    logger.debug("Worker[%s] brpop error: %s", self.id, exc)
                    await asyncio.sleep(1)
                    continue
                if not task_data:
                    continue
                try:
                    task = json.loads(task_data[1])
                except Exception as exc:
                    logger.warning("Worker[%s] dropped malformed task: %s", self.id, exc)
                    continue
                # Specialty mismatch — bounce back to pending queue gracefully
                # rather than failing the task (Architecture §4.3).
                required = (task.get("worker_requirements") or {}).get("type")
                if required and required not in (self.specialty, "hybrid"):
                    try:
                        await self.redis_client.lpush("pending_tasks", json.dumps(task))
                    except Exception as e:
                        logger.debug("Worker[%s] re-queue lpush failed: %s", self.id, e)
                    logger.debug(
                        "Worker[%s] re-queued task %s (needs %s, have %s)",
                        self.id,
                        task.get("task_id"),
                        required,
                        self.specialty,
                    )
                    continue
                self._task_manager.create_task(self.execute_task(task), name=f"task_{task.get('task_id', 'unknown')}")
        except asyncio.CancelledError:
            pass
        finally:
            await self.shutdown()

    async def shutdown(self):
        if not self.running:
            return
        self.running = False
        await self._task_manager.cancel_all()
        await self.pinchtab.stop()
        try:
            await self.redis_client.hdel("workers", self.id)
        except Exception as e:
            logger.debug("Worker[%s] shutdown cleanup failed: %s", self.id, e)

    async def send_heartbeat(self):
        # Heartbeat with backoff on Redis errors so we don't busy-spin
        # when the cache flips offline (Architecture §29.13).
        while self.running:
            try:
                heartbeat = {"id": self.id, "last_heartbeat": datetime.now().isoformat(), "status": "active"}
                await self.redis_client.hset("workers", self.id, json.dumps(heartbeat))
            except Exception as exc:
                logger.debug("Worker heartbeat error: %s", exc)
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                break

    async def execute_task(self, task: dict):
        tid = task.get("task_id", str(uuid.uuid4()))
        scan_id = task.get("scan_id", "GLOBAL")
        # HIGH-08: Validate task config structure before use
        task_config = task.get("config", {}) or {}
        if not isinstance(task_config, dict):
            logger.warning("[Worker] Invalid task config type: %s", type(task_config).__name__)
            return
        module_id = task_config.get("module_id")
        agent_class = task.get("agent_class")

        # Delegation task path (Architecture §5.1.2): a child-agent packet from
        # the DelegationManager. Run the registered in-process child runner and
        # write the structured result to the delegation_result key the manager
        # is awaiting.
        if agent_class and not module_id:
            await self._execute_delegation_task(task, tid, scan_id, agent_class)
            return

        try:
            await self.update_task_status(tid, "RUNNING")

            if not module_id:
                raise ValueError("No module_id provided in task config")

            # Map internal module IDs to actual python paths
            module_map = {
                "logic_tycoon": ("backend.modules.logic.tycoon", "TheTycoon"),
                "logic_escalator": ("backend.modules.logic.escalator", "TheEscalator"),
                "logic_skipper": ("backend.modules.logic.skipper", "TheSkipper"),
                "logic_doppelganger": ("backend.modules.logic.doppelganger", "Doppelganger"),
                "logic_chronomancer": ("backend.modules.logic.chronomancer", "Chronomancer"),
                "tech_sqli": ("backend.modules.tech.sqli", "SQLInjectionProbe"),
                "tech_jwt": ("backend.modules.tech.jwt", "JWTTokenCracker"),
                "tech_fuzzer": ("backend.modules.tech.fuzzer", "APIFuzzer"),
                "tech_auth_bypass": ("backend.modules.tech.auth_bypass", "AuthBypassTester"),
            }

            if module_id not in module_map:
                raise ValueError(f"Unknown module_id: {module_id}")
            path, class_name = module_map[module_id]
            module_pkg = importlib.import_module(path)
            module_class = getattr(module_pkg, class_name)
            instance = module_class()

            from backend.core.protocol import JobPacket

            # FIX-019: Validate task data before constructing JobPacket
            if not isinstance(task, dict) or not task.get("target"):
                raise ValueError("Invalid task: missing 'target' field")
                packet = JobPacket(**task)

                # 1. Generate Payloads
                targets = await instance.generate_payloads(packet)

                # 2. Real-Time Execution
                interactions = []
                from backend.api.socket_manager import publish_request_event
                from backend.core.content_boundary import content_boundary
                from backend.core.proxy import network_interceptor

                async with aiohttp.ClientSession() as session:
                    for t in targets:
                        await publish_request_event(
                            {
                                "timestamp": datetime.now().strftime("%H:%M:%S"),
                                "method": t.method,
                                "endpoint": t.url,
                                "payload": str(t.payload)[:50],
                                "agent": self.id,
                                "result": "EXECUTING",
                            },
                            scan_id=scan_id,
                        )

                        datetime.now()
                        try:
                            response = await network_interceptor.fetch(
                                t.method, t.url, session=session, json=t.payload, headers=t.headers, timeout=10
                            )
                            text = content_boundary.wrap_http_response(
                                response.status, response.headers, response.body, response.url
                            )
                            watched = await watch_output(text)
                            text = watched.content
                            latency = response.elapsed_ms
                            interactions.append((t, text))

                            await publish_request_event(
                                {
                                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                                    "method": t.method,
                                    "endpoint": t.url,
                                    "payload": str(t.payload)[:50],
                                    "status": response.status,
                                    "latency": latency,
                                    "agent": self.id,
                                    "result": "OK" if response.status < 400 else "ERROR",
                                },
                                scan_id=scan_id,
                            )
                        except Exception as e:
                            interactions.append((t, f"Error: {str(e)}"))

                # 3. Analyze Responses
                vulns = await instance.analyze_responses(interactions, packet)

                # 4. Report findings
                for v in vulns:
                    await self.bus.publish(
                        HiveEvent(
                            type=EventType.VULN_CONFIRMED,
                            source=f"worker:{self.id}",
                            scan_id=scan_id,
                            payload=v.model_dump(),
                        )
                    )

            await self.update_task_status(tid, "COMPLETED")
            await self.bus.publish(
                HiveEvent(
                    type=EventType.JOB_COMPLETED,
                    source=f"worker:{self.id}",
                    payload={"job_id": tid, "status": "SUCCESS"},
                )
            )

        except Exception as e:
            logger.error(f"Worker Task Error [{tid}]: {e}")
            await self.update_task_status(tid, "FAILED")

    async def _execute_delegation_task(self, task: dict, tid: str, scan_id: str, agent_class: str):
        """Run a delegated child-agent task and publish its structured result
        (Architecture §5.1.2). Result is written to delegation_result:{tid} which
        the DelegationManager polls."""
        import json

        from backend.core.delegation_manager import DelegationManager
        from backend.core.iteration_budget import IterationBudget

        cfg = task.get("config", {}) or {}
        budget = IterationBudget(int(cfg.get("budget", 50)), label=f"worker:{tid}")
        context = cfg.get("context", {})
        result = {"status": "failed", "findings": [], "artifacts": [], "summary": "", "budget_used": 0}
        try:
            await self.update_task_status(tid, "RUNNING")
            # FIX-011: Validate agent_class against explicit allowlist before execution
            allowed_runner_classes = {k for k in DelegationManager._runners}
            if agent_class not in allowed_runner_classes:
                result["summary"] = f"agent_class '{agent_class}' not in allowlist"
                await self.update_task_status(tid, "FAILED")
                return
            runner = DelegationManager._runners.get(agent_class)
            if runner is None:
                result["summary"] = f"no in-process runner for {agent_class}"
            else:
                out = await runner(context, budget) or {}
                result.update(
                    {
                        "status": "completed",
                        "findings": list(out.get("findings", [])),
                        "artifacts": list(out.get("artifacts", [])),
                        "summary": str(out.get("summary", "")),
                        "budget_used": budget.consumed,
                    }
                )
            await self.update_task_status(tid, "COMPLETED")
        except Exception as e:
            logger.error(f"Worker delegation task error [{tid}]: {e}")
            result["summary"] = str(e)
            await self.update_task_status(tid, "FAILED")
        finally:
            try:
                await self.redis_client.set(f"delegation_result:{tid}", json.dumps(result), ex=900)
            except Exception as e:
                logger.debug("Worker[%s] delegation_result write failed: %s", self.id, e)

    async def update_task_status(self, tid: str, status: str):
        # Persistent ledger update is best-effort. Worker keeps moving even
        # when Supabase is offline (Architecture §29.13).
        if self.supabase is None:
            return
        try:
            await asyncio.wait_for(
                asyncio.to_thread(
                    lambda: (
                        self.supabase.table("task_assignments")
                        .update({"status": status, "updated_at": datetime.now().isoformat()})
                        .eq("task_id", tid)
                        .execute()
                    )
                ),
                timeout=30,
            )
        except Exception as exc:
            logger.debug("Worker[%s] update_task_status skipped: %s", self.id, exc)
