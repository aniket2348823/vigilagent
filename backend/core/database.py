import asyncio
import contextlib
import logging
import time as _time
from datetime import UTC, datetime
from typing import Any

import redis.asyncio as aioredis
from supabase import Client, create_client

from backend.core.config import settings

logger = logging.getLogger("ELITE-DB")


class EliteDBManager:
    """
    The Single Source of Truth Manager for Vigilagent.
    Coordinates distributed state across Supabase (Persistence) and Redis (Hot Cache/Locking).
    """

    def __init__(self):
        self.supabase_url = settings.SUPABASE_URL
        self.supabase_key = settings.SUPABASE_KEY
        self.redis_url = settings.REDIS_URL

        self.supabase: Client | None = None
        self.redis: aioredis.Redis | None = None
        self._initialized = False
        # Fallback in-process lock when Redis is unavailable for dedup
        self._vuln_lock = asyncio.Lock()
        # Circuit breaker for Supabase: after consecutive failures, pause
        # retries to avoid hammering an unreachable endpoint.
        self._supabase_failures = 0
        self._supabase_circuit_open = False
        self._supabase_circuit_open_until: float = 0.0

    async def initialize(self):
        """Lazy initialization of cloud/cache connections.

        FIX: Never silently eat the error and leave callers with a partially
        initialized manager.  If Supabase fails we still mark _initialized
        so callers don't spin forever, but we log at WARNING so operators
        can see the problem in production (previously logged at DEBUG).

        Circuit breaker: after 3 consecutive initialization failures for
        Supabase or Redis, the corresponding connection is marked as
        unavailable for 120s to avoid hammering an unreachable endpoint.
        """
        if self._initialized:
            return

        try:
            # 1. Supabase Initialization
            if self.supabase_url and self.supabase_key:
                try:
                    self.supabase = create_client(self.supabase_url, self.supabase_key)
                    self._supabase_record_success()
                    logger.info("ELITE-DB: Supabase Connection Active ✓")
                except Exception as sup_e:
                    self._supabase_record_failure()
                    logger.warning("ELITE-DB: Supabase init failed: %s", sup_e)
                    self.supabase = None

            # 2. Redis Initialization
            if self.redis_url:
                try:
                    temp_redis = aioredis.from_url(self.redis_url, decode_responses=True)
                    await temp_redis.ping()
                    self.redis = temp_redis
                    logger.info("ELITE-DB: Redis Distributed Cache Active ✓")
                except Exception as redis_e:
                    logger.warning("ELITE-DB: Redis unavailable, falling back to local caching. (%s)", redis_e)
                    self.redis = None

            self._initialized = True
        except Exception as e:
            # Always mark initialized so callers don't retry indefinitely;
            # callers that need the DB will get None/error from individual
            # methods which is safer than a silent infinite retry loop.
            logger.error("ELITE-DB Initialization Failed: %s", e, exc_info=True)
            self._initialized = True

    async def _run_sync(self, fn, *args, _timeout: float = 30.0, **kwargs):
        """Run a blocking call (e.g. supabase-py's HTTPS .execute()) on a worker
        thread so it cannot stall the event loop. The Supabase client is
        synchronous; without this, every recon entity/toolcall upsert blocks
        the entire hive (Sigma/Beta/Gamma response times spiral, the
        recon-complete handoff misses its deadline). Architecture §29.13:
        execution must not block the orchestrator.

        HIGH-03: Wrapped with ``asyncio.wait_for`` so a stalled thread
        cannot hang the event loop indefinitely.

        Circuit breaker: after _CB_FAILURE_THRESHOLD consecutive failures,
        the method short-circuits for _CB_COOLDOWN_SECONDS to avoid
        hammering an unreachable Supabase endpoint. Timeouts are recorded
        at DEBUG level only (a slow but connected query shouldn't trip
        the breaker)."""
        if not self._supabase_available():
            raise ConnectionError("Supabase circuit breaker open — retries paused")
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(fn, *args, **kwargs),
                timeout=_timeout,
            )
            self._supabase_record_success()
            return result
        except TimeoutError:
            # FIX: Timeouts don't count toward the circuit breaker threshold.
            # A slow but connected Supabase query shouldn't trip the breaker.
            # Log at DEBUG so operators can still see timeout patterns.
            logger.debug("_run_sync timed out after %.1fs (not counting toward circuit breaker)", _timeout)
            raise
        except Exception:
            self._supabase_record_failure()
            raise

    # --- 1. VULNERABILITY MANAGEMENT (Intelligence) ---

    # --- Helper: Atomic Upsert ---
    # FIX: Extract the repeated lambda-d=data closure pattern into a reusable
    # method.  The original pattern was duplicated 15+ times with lambda
    # captures that are error-prone.
    async def _upsert(self, table: str, data: dict[str, Any], on_conflict: str, timeout: float = 30.0) -> Any | None:
        """Atomic upsert helper — runs the blocking Supabase call on a worker
        thread and returns the result.data or None on failure."""
        try:
            result = await self._run_sync(
                lambda t=table, d=data, c=on_conflict: self.supabase.table(t).upsert(d, on_conflict=c).execute(),
                _timeout=timeout,
            )
            return result.data
        except ConnectionError:
            return None  # Circuit breaker open — already logged by _run_sync
        except Exception as e:
            if not self._supabase_circuit_open:
                logger.warning("_upsert(%s) failed: %s", table, e)
            return None

    async def report_vulnerability(
        self, scan_id: str, endpoint: str, vuln_type: str, severity: str, evidence: dict[str, Any], validated_by: str
    ) -> str | None:
        """Reports a verified vulnerability with strict deduplication.

        Uses a hash-based hot-cache in Redis before performing the Supabase UPSERT.
        FIX: The Redis dedup check + Supabase upsert are now protected by a
        Redis lock to eliminate the TOCTOU race where two concurrent calls
        could both pass the dedup check and both write.
        """
        if not self.supabase:
            return None

        # 1. Generate Deduplication Signature
        signature = f"vuln:{scan_id}:{endpoint}:{vuln_type}"

        # 2. Acquire a dedup lock to prevent TOCTOU race.
        # When Redis is available we use a distributed SETNX lock.
        # When Redis is unavailable, we fall back to an in-process asyncio.Lock
        # so concurrent callers within the same process are serialized.
        _use_redis_lock = self.redis is not None
        if _use_redis_lock:
            lock_acquired = await self.redis.set(f"lock:{signature}", "1", nx=True, ex=10)
            if not lock_acquired:
                cached = await self.redis.get(signature)
                if cached:
                    return "CACHED"
                await asyncio.sleep(0.5)
                cached = await self.redis.get(signature)
                if cached:
                    return "CACHED"
        else:
            await self._vuln_lock.acquire()

        # 3. Upsert into Supabase (ON CONFLICT guarantees idempotency)
        data = {
            "scan_id": scan_id,
            "endpoint": endpoint,
            "vuln_type": vuln_type,
            "severity": severity,
            "evidence": evidence,
            "validated_by": validated_by,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        try:
            result_data = await self._upsert("vulnerabilities", data, "scan_id,endpoint,vuln_type")

            if result_data:
                vuln_id = result_data[0]["id"]
                # Update Hot-Cache for 1 hour to prevent redundant writes
                if self.redis:
                    await self.redis.set(signature, vuln_id, ex=3600)
                return vuln_id
        except Exception as e:
            logger.error("Failed to report vulnerability to Supabase: %s", e, exc_info=True)
        finally:
            # Always release the dedup lock
            if _use_redis_lock:
                with contextlib.suppress(Exception):
                    await self.redis.delete(f"lock:{signature}")
            else:
                self._vuln_lock.release()

        return None

    # --- 2. DISTRIBUTED TASK MANAGEMENT (Coordination) ---

    async def acquire_task_lock(self, task_id: str, worker_id: str) -> bool:
        """Attempts to acquire a distributed lock for a task.

        Implementation: Redis SETNX (Atomic) + Supabase Status Update.
        FIX: Lock expiry is 600s but there was no renewal mechanism. Long-
        running tasks (>10 min) would silently lose their lock and another
        worker could claim the same task.  We now return the lock_key so
        callers can pass it to renew_task_lock() periodically.
        """
        lock_key = f"lock:task:{task_id}"

        # 1. Atomic Redis Lock (expires in 10 minutes in case worker crashes)
        if self.redis:
            locked = await self.redis.set(lock_key, worker_id, nx=True, ex=600)
            if not locked:
                return False

        if not self.supabase:
            # No persistent ledger — Redis-only lock is authoritative.
            return True

        # 2. Sync State to Supabase
        try:
            data = {"status": "RUNNING", "locked_by": worker_id, "lock_time": datetime.now(UTC).isoformat()}
            result = await self._run_sync(
                lambda: (
                    self.supabase.table("distributed_tasks")
                    .update(data)
                    .eq("id", task_id)
                    .eq("status", "PENDING")
                    .execute()
                )
            )

            if not result.data:
                # Task was already claimed or moved state
                if self.redis:
                    await self.redis.delete(lock_key)
                return False

            return True
        except Exception as e:
            if not self._supabase_circuit_open:
                logger.error(f"Supabase task lock failed: {e}")
            if self.redis:
                await self.redis.delete(lock_key)
            return False

    async def complete_task(self, task_id: str, status: str = "COMPLETED"):
        """Releases the lock and updates task status."""
        lock_key = f"lock:task:{task_id}"
        if self.redis:
            await self.redis.delete(lock_key)
        if not self.supabase:
            return
        try:
            await self._run_sync(
                lambda: (
                    self.supabase.table("distributed_tasks")
                    .update({"status": status, "updated_at": datetime.now(UTC).isoformat()})
                    .eq("id", task_id)
                    .execute()
                )
            )
        except Exception as e:
            if not self._supabase_circuit_open:
                logger.error(f"Failed to complete task {task_id}: {e}")

    # --- 3. BATCH OPERATIONS (Optimization) ---

    async def create_tasks_batch(self, tasks: list[dict[str, Any]]):
        """Inserts multiple tasks in a single Supabase request."""
        if not self.supabase or not tasks:
            return
        try:
            await self._run_sync(lambda: self.supabase.table("distributed_tasks").insert(tasks).execute())
        except Exception as e:
            if not self._supabase_circuit_open:
                logger.error(f"Batch task creation failed: {e}")

    # --- 4. EXPLOIT & REMEDIATION ( Intelligence ) ---

    async def log_exploit_result(self, vuln_id: str, result: dict[str, Any]):
        """Logs the final evidence of a successful exploit."""
        if not self.supabase:
            return
        try:
            await self._run_sync(
                lambda: (
                    self.supabase.table("exploit_results")
                    .insert(
                        {
                            "vuln_id": vuln_id,
                            "payload": result.get("payload", "N/A"),
                            "worker_id": result.get("worker_id", "local"),
                            "status": result.get("status", "EXPLOITED"),
                            "response_dump": result.get("response", ""),
                            "execution_time_ms": result.get("time_ms", 0),
                        }
                    )
                    .execute()
                )
            )
        except Exception as e:
            if not self._supabase_circuit_open:
                logger.error(f"Failed to log exploit result: {e}")

    # --- 5. QUERY HELPERS ---

    async def get_vulnerabilities(self, scan_id: str) -> list[dict[str, Any]]:
        """Fetch all vulnerabilities for a given scan from Supabase."""
        if not self.supabase:
            return []
        try:
            result = await self._run_sync(
                lambda: self.supabase.table("vulnerabilities").select("*").eq("scan_id", scan_id).execute()
            )
            return result.data or []
        except Exception as e:
            if not self._supabase_circuit_open:
                logger.error(f"Failed to fetch vulnerabilities for scan {scan_id}: {e}")
            return []

    async def store_scan_episode(self, scan_id: str, event_type: str, payload: dict[str, Any]):
        if not self.supabase:
            return None
        try:
            result = await self._run_sync(
                lambda: (
                    self.supabase.table("scan_episodes")
                    .insert(
                        {
                            "scan_id": scan_id,
                            "event_type": event_type,
                            "payload": payload,
                        }
                    )
                    .execute()
                )
            )
            return result.data[0]["id"] if result.data else None
        except Exception as e:
            if not self._supabase_circuit_open:
                logger.warning("Failed to store scan episode: %s", e)
            return None

    # Circuit breaker constants (single source of truth)
    _CB_FAILURE_THRESHOLD = 3
    _CB_COOLDOWN_SECONDS = 120.0

    def _supabase_available(self) -> bool:
        """Circuit breaker check: returns False if Supabase is down.

        After _CB_FAILURE_THRESHOLD consecutive failures, the circuit opens
        for _CB_COOLDOWN_SECONDS so we stop hammering an unreachable endpoint.
        On cooldown expiry, allows one probe request (half-open state).
        """
        if self._supabase_circuit_open:
            if _time.time() < self._supabase_circuit_open_until:
                return False
            # Cooldown expired — allow one probe request.
            self._supabase_circuit_open = False
            logger.info("ELITE-DB: Supabase circuit breaker half-open — probing")
        return True

    def _supabase_record_success(self) -> None:
        self._supabase_failures = 0
        if self._supabase_circuit_open:
            logger.info("ELITE-DB: Supabase circuit breaker closed — connection restored")
            self._supabase_circuit_open = False

    def _supabase_record_failure(self) -> None:
        self._supabase_failures += 1
        if self._supabase_failures >= self._CB_FAILURE_THRESHOLD:
            self._supabase_circuit_open = True
            self._supabase_circuit_open_until = _time.time() + self._CB_COOLDOWN_SECONDS
            logger.warning(
                "ELITE-DB: Supabase circuit breaker OPEN — %d consecutive failures, pausing retries for %.0fs",
                self._supabase_failures,
                self._CB_COOLDOWN_SECONDS,
            )

    async def store_semantic_memory(
        self,
        *,
        memory_type: str,
        content: str,
        endpoint_pattern: str = "",
        vuln_type: str = "",
        metadata: dict[str, Any] | None = None,
        embedding: list[float] | None = None,
        confidence: float = 0.0,
    ):
        if not self.supabase:
            return None
        try:
            result = await self._run_sync(
                lambda: (
                    self.supabase.table("semantic_memory")
                    .insert(
                        {
                            "memory_type": memory_type,
                            "endpoint_pattern": endpoint_pattern,
                            "vuln_type": vuln_type,
                            "content": content,
                            "metadata": metadata or {},
                            "embedding": embedding,
                            "confidence": confidence,
                        }
                    )
                    .execute()
                )
            )
            return result.data[0]["id"] if result.data else None
        except Exception as e:
            if not self._supabase_circuit_open:
                logger.warning("Failed to store semantic memory: %s", e)
            return None

    async def create_recon_run(
        self,
        *,
        scan_id: str,
        target: str,
        mode: str,
        scope: dict[str, Any],
        artifact_root: str,
        status: str = "running",
    ):
        if not self.supabase:
            return None
        try:
            result = await self._run_sync(
                lambda: (
                    self.supabase.table("recon_runs")
                    .upsert(
                        {
                            "scan_id": scan_id,
                            "target": target,
                            "mode": mode,
                            "scope": scope,
                            "artifact_root": artifact_root,
                            "status": status,
                            "started_at": datetime.now(UTC).isoformat(),
                        },
                        on_conflict="scan_id",
                    )
                    .execute()
                )
            )
            return result.data[0]["scan_id"] if result.data else scan_id
        except Exception as e:
            logger.debug(f"Failed to create recon run: {e}")
            return None

    async def finish_recon_run(self, *, scan_id: str, status: str = "completed"):
        if not self.supabase:
            return None
        try:
            await self._run_sync(
                lambda: (
                    self.supabase.table("recon_runs")
                    .update(
                        {
                            "status": status,
                            "finished_at": datetime.now(UTC).isoformat(),
                        }
                    )
                    .eq("scan_id", scan_id)
                    .execute()
                )
            )
            return scan_id
        except Exception as e:
            logger.debug(f"Failed to finish recon run: {e}")
            return None

    async def upsert_recon_entity(
        self,
        *,
        id: str,
        scan_id: str,
        kind: str,
        label: str,
        normalized: dict[str, Any],
        sources: list[dict[str, Any]],
        confidence: float = 0.0,
    ):
        if not self.supabase:
            return None
        try:
            result = await self._run_sync(
                lambda: (
                    self.supabase.table("recon_entities")
                    .upsert(
                        {
                            "id": id,
                            "scan_id": scan_id,
                            "kind": kind,
                            "label": label,
                            "normalized": normalized,
                            "sources": sources,
                            "confidence": confidence,
                            "last_seen": datetime.now(UTC).isoformat(),
                        },
                        on_conflict="id",
                    )
                    .execute()
                )
            )
            return result.data[0]["id"] if result.data else id
        except Exception as e:
            logger.debug(f"Failed to upsert recon entity: {e}")
            return None

    async def create_recon_artifact(
        self,
        *,
        id: str,
        scan_id: str,
        tool_name: str,
        artifact_type: str,
        path: str,
        sha256: str = "",
        bytes: int = 0,
        metadata: dict[str, Any] | None = None,
    ):
        if not self.supabase:
            return None
        try:
            result = await self._run_sync(
                lambda: (
                    self.supabase.table("recon_artifacts")
                    .upsert(
                        {
                            "id": id,
                            "scan_id": scan_id,
                            "tool_name": tool_name,
                            "artifact_type": artifact_type,
                            "path": path,
                            "sha256": sha256,
                            "bytes": bytes,
                            "metadata": metadata or {},
                        },
                        on_conflict="id",
                    )
                    .execute()
                )
            )
            return result.data[0]["id"] if result.data else id
        except Exception as e:
            logger.debug(f"Failed to create recon artifact: {e}")
            return None

    async def upsert_endpoint_score(
        self,
        *,
        id: str,
        scan_id: str,
        endpoint_id: str,
        score: int,
        reasons: list[str],
        omega_modules: list[str] | None = None,
    ):
        if not self.supabase:
            return None
        try:
            result = await self._run_sync(
                lambda: (
                    self.supabase.table("recon_endpoint_scores")
                    .upsert(
                        {
                            "id": id,
                            "scan_id": scan_id,
                            "endpoint_id": endpoint_id,
                            "score": score,
                            "reasons": reasons,
                            "omega_modules": omega_modules or [],
                        },
                        on_conflict="id",
                    )
                    .execute()
                )
            )
            return result.data[0]["id"] if result.data else id
        except Exception as e:
            logger.debug(f"Failed to upsert endpoint score: {e}")
            return None

    async def create_toolcall(
        self,
        *,
        call_id: str,
        scan_id: str,
        tool_name: str,
        agent: str,
        args: dict[str, Any],
        status: str = "running",
        error: str = "",
    ):
        if not self.supabase:
            return None
        try:
            result = await self._run_sync(
                lambda: (
                    self.supabase.table("toolcalls")
                    .insert(
                        {
                            "call_id": call_id,
                            "scan_id": scan_id,
                            "tool_name": tool_name,
                            "agent": agent,
                            "args": args,
                            "status": status,
                            "error": error,
                            "started_at": datetime.now(UTC).isoformat(),
                        }
                    )
                    .execute()
                )
            )
            return result.data[0]["id"] if result.data else None
        except Exception as e:
            logger.debug(f"Failed to create toolcall: {e}")
            return None

    async def finish_toolcall(
        self,
        *,
        call_id: str,
        status: str,
        result: Any = None,
        error: str = "",
        duration_ms: int = 0,
        result_bytes: int = 0,
        result_sha256: str = "",
    ):
        if not self.supabase:
            return None
        try:
            payload = {
                "status": status,
                "result": result,
                "error": error,
                "duration_ms": duration_ms,
                "result_bytes": result_bytes,
                "result_sha256": result_sha256,
                "finished_at": datetime.now(UTC).isoformat(),
            }
            await self._run_sync(
                lambda: self.supabase.table("toolcalls").update(payload).eq("call_id", call_id).execute()
            )
        except Exception as e:
            logger.debug(f"Failed to finish toolcall: {e}")
            return None

    async def create_approval(
        self,
        *,
        approval_id: str,
        scan_id: str,
        tool_name: str,
        reason: str,
        payload: dict[str, Any],
        status: str = "pending",
    ):
        if not self.supabase:
            return None
        try:
            result = await self._run_sync(
                lambda: (
                    self.supabase.table("approvals")
                    .insert(
                        {
                            "approval_id": approval_id,
                            "scan_id": scan_id,
                            "tool_name": tool_name,
                            "reason": reason,
                            "payload": payload,
                            "status": status,
                            "created_at": datetime.now(UTC).isoformat(),
                        }
                    )
                    .execute()
                )
            )
            return result.data[0]["id"] if result.data else None
        except Exception as e:
            logger.debug(f"Failed to create approval: {e}")
            return None

    async def log_http_exchange(
        self,
        *,
        scan_id: str,
        request_id: str,
        method: str,
        url: str,
        request_headers: dict[str, str],
        request_body: Any,
        status: int,
        response_headers: dict[str, str],
        response_body: str,
        elapsed_ms: int,
    ):
        if not self.supabase:
            return None
        try:
            req = await self._run_sync(
                lambda: (
                    self.supabase.table("http_requests")
                    .insert(
                        {
                            "request_id": request_id,
                            "scan_id": scan_id,
                            "method": method,
                            "url": url,
                            "headers": request_headers,
                            "body": request_body,
                            "elapsed_ms": elapsed_ms,
                        }
                    )
                    .execute()
                )
            )
            db_request_id = req.data[0]["id"] if req.data else None
            await self._run_sync(
                lambda: (
                    self.supabase.table("http_responses")
                    .insert(
                        {
                            "request_db_id": db_request_id,
                            "request_id": request_id,
                            "scan_id": scan_id,
                            "status": status,
                            "headers": response_headers,
                            "body": response_body,
                            "body_preview": response_body[:4000],
                        }
                    )
                    .execute()
                )
            )
            return db_request_id
        except Exception as e:
            logger.debug(f"Failed to log HTTP exchange: {e}")
            return None

    async def renew_task_lock(self, task_id: str, worker_id: str, ttl: int = 600) -> bool:
        """Renew the TTL on an existing task lock.

        Call this periodically (e.g. every 120s) from within a long-running
        task to prevent the lock from expiring and being claimed by another
        worker.
        """
        lock_key = f"lock:task:{task_id}"
        if not self.redis:
            return True  # No Redis = no lock to renew
        try:
            current_owner = await self.redis.get(lock_key)
            if current_owner != worker_id:
                return False  # Lock was stolen or expired
            await self.redis.expire(lock_key, ttl)
            return True
        except Exception as e:
            logger.warning("renew_task_lock(%s) failed: %s", task_id, e)
            return False

    # --- 6. LIFECYCLE ---

    async def close(self):
        """Close any connections held by the manager (Architecture §29.13).
        Safe to call multiple times; never raises. Drops the Supabase
        reference (the supabase-py client uses a synchronous httpx session
        that doesn't need explicit close) and gracefully closes Redis."""
        try:
            if self.redis is not None:
                try:
                    await self.redis.close()
                except Exception as e:  # pragma: no cover - best-effort cleanup
                    logger.debug(f"Redis close error: {e}")
                self.redis = None
        finally:
            self.supabase = None
            self._initialized = False


# Global Instance
db_manager = EliteDBManager()
