"""
XYTHERION COMMAND MATRIX (MASTER NODE)
Role: Central task coordination and worker management for the distributed cluster.
Extracted from orchestrator.py for clean architecture.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any

from backend.core.database import db_manager
from backend.core.task_manager import TaskManager
from backend.core.unified_knowledge_graph import GraphEngine

logger = logging.getLogger("MasterNode")


class MasterNode:
    """XYTHERION COMMAND MATRIX (MASTER NODE)"""

    def __init__(self, redis_url: str, supabase_url: str, supabase_key: str):
        self.redis_client = None  # Initialized lazily in start() via centralized pool
        self.supabase = None  # Optional — populated below if creds provided.
        if supabase_url and supabase_key:
            try:
                from supabase import Client, create_client  # noqa: F401

                self.supabase = create_client(supabase_url, supabase_key)
            except Exception as exc:
                logger.warning(
                    "MasterNode: Supabase init failed (%s) — running without "
                    "persistent task ledger; cluster keeps coordinating via "
                    "Redis alone.",
                    exc,
                )
                self.supabase = None
        else:
            logger.info("MasterNode: Supabase creds not configured — running in Redis-only mode (Architecture §29.13).")
        self.workers: dict[str, dict[str, Any]] = {}
        self.attack_graph = GraphEngine()
        self._task_manager = TaskManager("MasterNode")
        self.active = False

    async def start(self):
        self.active = True
        from backend.core.redis_client import get_redis_client

        rc = await get_redis_client()
        self.redis_client = rc.client
        await self._discover_swarm()
        self._task_manager.create_task(self.monitor_workers(), name="worker_monitor")
        try:
            while self.active:
                try:
                    task_data = await self.redis_client.brpop("pending_tasks", timeout=5)
                    if task_data:
                        task = json.loads(task_data[1])
                        await self.distribute_tasks([task])
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.debug("MasterNode loop error: %s", exc)
                    await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await self.shutdown()

    async def shutdown(self):
        """Clean shutdown: stop the monitor task and clean up Redis registry."""
        if not self.active:
            return
        self.active = False
        try:
            await self._task_manager.cancel_all()
        except Exception as e:
            logger.debug("MasterNode task cancel failed: %s", e)
        # NOTE: Don't close redis_client here — it's the shared centralized pool client.
        # Remove our worker registry entries (specific field names, not wildcards).
        try:
            if self.workers:
                await self.redis_client.hdel("workers", *self.workers.keys())
        except Exception as e:
            logger.debug("MasterNode shutdown cleanup failed: %s", e)

    async def _discover_swarm(self):
        try:
            raw_workers = await self.redis_client.hgetall("workers")
            for worker_id, data in raw_workers.items():
                self.workers[worker_id] = json.loads(data)
        except Exception as e:
            logger.debug("MasterNode swarm discovery failed: %s", e)

    async def register_worker(self, worker_id: str, specialty: str, capabilities: list[str]):
        worker_info = {
            "id": worker_id,
            "specialty": specialty,
            "capabilities": capabilities,
            "status": "active",
            "last_heartbeat": datetime.now().isoformat(),
            "current_tasks": [],
        }
        self.workers[worker_id] = worker_info
        await self.redis_client.hset("workers", worker_id, json.dumps(worker_info))

    def select_optimal_worker(self, task: dict) -> str | None:
        required_type = task.get("worker_requirements", {}).get("type", "hybrid")
        eligible_workers = [
            wid
            for wid, w in self.workers.items()
            if (w["specialty"] in [required_type, "hybrid"]) and w["status"] == "active"
        ]
        if not eligible_workers:
            return None
        return min(eligible_workers, key=lambda w: len(self.workers[w].get("current_tasks", [])))

    async def distribute_tasks(self, tasks: list[dict]):
        for task in tasks:
            worker_id = self.select_optimal_worker(task)
            if worker_id:
                await self.redis_client.lpush(f"worker_queue:{worker_id}", json.dumps(task))
                self.workers[worker_id].setdefault("current_tasks", []).append(task["task_id"])
                # Best-effort persistence to Supabase. Cluster MUST keep
                # coordinating even if the persistent ledger is offline
                # (Architecture §29.13: Redis is the source of truth for
                # live coordination; Supabase is the durable replica).
                try:
                    await db_manager.initialize()
                    if db_manager.supabase is not None:
                        await db_manager._run_sync(
                            lambda: (
                                db_manager.supabase.table("distributed_tasks")
                                .insert(
                                    {
                                        "scan_id": task.get("scan_id", "GLOBAL"),
                                        "task_id": task["task_id"],
                                        "worker_id": worker_id,
                                        "status": "RUNNING",
                                        "locked_by": worker_id,
                                        "lock_time": datetime.now().isoformat(),
                                    }
                                )
                                .execute()
                            )
                        )
                except Exception as exc:
                    logger.debug("Supabase task ledger write skipped: %s", exc)

    async def monitor_workers(self):
        # Backoff loop — never busy-spin (Architecture §29.13).
        try:
            while self.active:
                await asyncio.sleep(60)
                now = datetime.now()
                for wid, w in list(self.workers.items()):
                    try:
                        last = datetime.fromisoformat(w["last_heartbeat"])
                    except Exception as exc:
                        logger.debug("MasterNode heartbeat parse failed for %s: %s", wid, exc)
                        continue
                    if now - last > timedelta(minutes=3):
                        w["status"] = "inactive"
                        await self.reassign_worker_tasks(wid)
        except asyncio.CancelledError:
            return

    async def reassign_worker_tasks(self, failed_worker_id: str):
        worker = self.workers.get(failed_worker_id)
        if not worker:
            return
        for tid in worker.get("current_tasks", []):
            await self.redis_client.lpush("pending_tasks", json.dumps({"task_id": tid, "retry": True}))
        worker["current_tasks"] = []
