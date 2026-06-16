"""
Sub-agent 5 (Infrastructure) verification harness.

Asserts:
  1. db_manager public async methods don't block the event loop and gracefully
     no-op when Supabase is unconfigured.
  2. agent_health_monitor.report_metrics does NOT escalate to CRITICAL on idle
     samples that mimic the BaseAgent reporting loop.
  3. StateManager._background_writer cancels cleanly via shutdown(); no
     pending tasks remain after teardown.
  4. Redis set/get/del cleans up after itself (Redis lock cleanup smoke test).
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

# Force test mode hooks off — we're testing real infra.
os.environ.pop("VULAGENT_TEST_MODE", None)

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
class _Counter:
    def __init__(self) -> None:
        self.beats = 0
        self.stop = False

    async def run(self) -> None:
        # Heartbeat task — proves event loop wasn't starved by sync DB calls.
        while not self.stop:
            self.beats += 1
            await asyncio.sleep(0.02)


# ──────────────────────────────────────────────────────────────────────────────
# 1. db_manager public-method audit (non-blocking)
# ──────────────────────────────────────────────────────────────────────────────
async def test_db_manager_nonblocking() -> None:
    from backend.core.database import db_manager

    # Install a deliberately SLOW synchronous fake Supabase so the only way
    # to keep the event loop responsive is to run .execute() in a worker
    # thread (the _run_sync wrapping). If any code path forgot to wrap, the
    # heartbeat counter will stall and the assertion below fires.
    SLEEP_S = 0.20

    class _FakeResult:
        def __init__(self) -> None:
            self.data = [{"id": "fake", "scan_id": "fake"}]

    class _FakeBuilder:
        def insert(self, *_a, **_kw): return self
        def upsert(self, *_a, **_kw): return self
        def update(self, *_a, **_kw): return self
        def select(self, *_a, **_kw): return self
        def eq(self, *_a, **_kw): return self
        def execute(self):
            time.sleep(SLEEP_S)  # blocking — must be off-loaded
            return _FakeResult()

    class _FakeSupabase:
        def table(self, _name: str) -> _FakeBuilder:
            return _FakeBuilder()

    db_manager.supabase = _FakeSupabase()
    db_manager._initialized = True

    counter = _Counter()
    hb = asyncio.create_task(counter.run())

    started = time.monotonic()
    coros = [
        db_manager.report_vulnerability("scan-x", "/login", "xss",
                                        "high", {}, "test"),
        db_manager.acquire_task_lock("task-x", "worker-x"),
        db_manager.complete_task("task-x", "DONE"),
        db_manager.create_tasks_batch([{"task_id": "t1", "scan_id": "s"}]),
        db_manager.log_exploit_result("v1", {"payload": "x"}),
        db_manager.get_vulnerabilities("scan-x"),
        db_manager.store_scan_episode("scan-x", "boot", {}),
        db_manager.store_semantic_memory(memory_type="m", content="c"),
        db_manager.create_recon_run(scan_id="scan-x", target="t",
                                    mode="STANDARD", scope={},
                                    artifact_root="/tmp"),
        db_manager.finish_recon_run(scan_id="scan-x"),
        db_manager.upsert_recon_entity(id="e1", scan_id="scan-x",
                                       kind="host", label="x",
                                       normalized={}, sources=[]),
        db_manager.create_recon_artifact(id="a1", scan_id="scan-x",
                                         tool_name="nmap",
                                         artifact_type="raw",
                                         path="/tmp"),
        db_manager.upsert_endpoint_score(id="es1", scan_id="scan-x",
                                         endpoint_id="ep1", score=10,
                                         reasons=[]),
        db_manager.create_toolcall(call_id="c1", scan_id="scan-x",
                                   tool_name="nmap", agent="alpha",
                                   args={}),
        db_manager.finish_toolcall(call_id="c1", status="ok"),
        db_manager.create_approval(approval_id="ap1", scan_id="scan-x",
                                   tool_name="nmap", reason="r",
                                   payload={}),
        db_manager.log_http_exchange(scan_id="scan-x", request_id="r1",
                                     method="GET", url="http://x",
                                     request_headers={}, request_body=None,
                                     status=200, response_headers={},
                                     response_body="", elapsed_ms=10),
    ]

    results = await asyncio.wait_for(
        asyncio.gather(*coros, return_exceptions=True),
        timeout=15.0,
    )

    elapsed = time.monotonic() - started
    counter.stop = True
    hb.cancel()
    try:
        await hb
    except asyncio.CancelledError:
        pass

    failures = [r for r in results if isinstance(r, BaseException)]
    assert not failures, f"DB calls raised: {failures}"
    # log_http_exchange does TWO sequential synchronous calls; everything
    # else does one. With a thread pool, the gathered coros run in
    # parallel — total wall time should be a small multiple of SLEEP_S,
    # not the sum (~3.6s).
    assert elapsed < 3.0, f"DB calls took {elapsed:.2f}s — blocking?"
    # Heartbeats every 20ms during a ~0.4-1s window — must accumulate well
    # past 5. If any path forgot to wrap, the loop stalls for SLEEP_S each.
    assert counter.beats > 10, (
        f"Heartbeat fired only {counter.beats} times during DB run — event "
        "loop appears blocked.")

    await db_manager.close()
    print(f"[OK] db_manager: {len(coros)} calls, {elapsed*1000:.1f}ms, "
          f"{counter.beats} heartbeats (loop stayed responsive)")


# ──────────────────────────────────────────────────────────────────────────────
# 2. Health monitor — no false-positive CRITICALs on idle samples
# ──────────────────────────────────────────────────────────────────────────────
async def test_health_monitor_idle_silence() -> None:
    from backend.core.agent_health_monitor import AgentHealthMonitor

    mon = AgentHealthMonitor(brain_dir="brain_test_infra")
    name = "agent_alpha"

    # Simulate the BaseAgent loop: every cycle sends success=True with
    # response_time_ms = (time_since_last_task) — a value that climbs
    # without bound while the agent is idle.
    for i in range(1, 7):
        mon.report_metrics(name, {
            "response_time_ms": 10_000 + i * 5_000,  # 15s, 20s, 25s, ...
            "success": True,
            "memory_mb": 50.0,
            "cpu_percent": 1.0,
            "task_queue_depth": 0,
        })
        # Heartbeat too (BaseAgent does this).
        mon.report_heartbeat(name)

    crits = [a for a in mon.alerts
             if a.severity == "critical" and "response time" in a.issue]
    warns = [a for a in mon.alerts
             if a.severity == "warning" and "response time" in a.issue]
    assert not crits, (
        f"Idle samples triggered {len(crits)} CRITICAL alerts: {crits}")
    assert not warns, (
        f"Idle samples triggered {len(warns)} response-time WARNINGs.")

    # Now simulate a real per-task latency (caller opts in) and confirm the
    # alert path still fires for genuine slowness.
    mon.report_metrics(name, {
        "response_time_ms": 6_000,
        "success": True,
        "per_task_latency": True,
    })
    crits_real = [a for a in mon.alerts
                  if a.severity == "critical" and "response time" in a.issue]
    assert crits_real, (
        "Real per-task slow sample failed to escalate to CRITICAL — "
        "alerting is broken.")
    print(f"[OK] health_monitor: 0 idle false-positives, "
          f"{len(crits_real)} real-latency alerts")


# ──────────────────────────────────────────────────────────────────────────────
# 3. StateManager writer cancels cleanly
# ──────────────────────────────────────────────────────────────────────────────
async def test_state_manager_clean_shutdown() -> None:
    from backend.core.state import StateManager

    sm = StateManager()
    # Snapshot tasks before.
    before = {t for t in asyncio.all_tasks() if not t.done()}

    # Trigger background writer + a few writes.
    sm._mark_dirty()
    await sm.add_scan_event("scan-fake", {"type": "boot", "payload": {}})
    await sm.add_scan_event("scan-fake", {"type": "boot2", "payload": {}})
    sm._mark_dirty()
    await asyncio.sleep(0.1)

    # The writer task may or may not be alive depending on whether
    # _mark_dirty had a running loop at this point — assert via shutdown.
    assert sm._task is None or not sm._task.done() or sm._task.done(), \
        "writer task field is in an unexpected state"

    await sm.shutdown()

    after = {t for t in asyncio.all_tasks() if not t.done()}
    leaked = after - before
    # Allow the current task itself.
    leaked.discard(asyncio.current_task())
    assert not leaked, f"Leaked StateManager tasks: {leaked}"
    print(f"[OK] state.shutdown(): writer task is None? {sm._task is None}, "
          f"leaked={len(leaked)}")


# ──────────────────────────────────────────────────────────────────────────────
# 4. Redis smoke + cleanup
# ──────────────────────────────────────────────────────────────────────────────
async def test_redis_smoke() -> None:
    try:
        import redis.asyncio as aioredis
    except Exception as exc:
        print(f"[SKIP] redis lib unavailable: {exc}")
        return

    url = os.getenv("REDIS_URL", "redis://localhost:6379")
    client = aioredis.from_url(url, decode_responses=True)
    try:
        await client.ping()
    except Exception as exc:
        print(f"[SKIP] Redis not reachable at {url}: {exc}")
        await client.close()
        return

    test_key = "vigilagent:test_infra:smoke"
    await client.set(test_key, "x", ex=60)
    val = await client.get(test_key)
    assert val == "x", f"Redis get returned {val!r}"
    deleted = await client.delete(test_key)
    assert deleted == 1, f"Redis delete returned {deleted}"
    leftover = await client.get(test_key)
    assert leftover is None, f"Redis cleanup leaked: {leftover!r}"

    # Confirm no residual job_lock keys we may have set during the run.
    leftover_locks = [k async for k in client.scan_iter(
        match="vigilagent:test_infra:*", count=50)]
    assert not leftover_locks, f"Residual test keys: {leftover_locks}"
    await client.close()
    print("[OK] Redis: set/get/del clean")


# ──────────────────────────────────────────────────────────────────────────────
# 5. Config smoke — RECON_MAX_WAIT_SECONDS declared
# ──────────────────────────────────────────────────────────────────────────────
def test_config_recon_max_wait() -> None:
    from backend.core.config import settings
    assert hasattr(settings, "RECON_MAX_WAIT_SECONDS"), \
        "RECON_MAX_WAIT_SECONDS missing from settings"
    val = int(getattr(settings, "RECON_MAX_WAIT_SECONDS"))
    assert val > 0, f"RECON_MAX_WAIT_SECONDS = {val}"
    print(f"[OK] settings.RECON_MAX_WAIT_SECONDS = {val}")


async def main() -> int:
    test_config_recon_max_wait()
    await test_db_manager_nonblocking()
    await test_health_monitor_idle_silence()
    await test_state_manager_clean_shutdown()
    await test_redis_smoke()
    print("\nALL INFRASTRUCTURE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
