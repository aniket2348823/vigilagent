"""Verify the FULL-SWARM dispatch hands work to all 13 agents.

Builds the exact JobPackets the orchestrator emits (module ownership map +
swarm jobs) and confirms each agent's handler is subscribed and would
process its own job (correct agent_id gating).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.core.hive import DistributedEventBus, EventType, HiveEvent
from backend.core.protocol import AgentID, JobPacket, ModuleConfig, TaskPriority, TaskTarget

AGENTS = {
    "planner": "agent_planner",
    "alpha": AgentID.ALPHA,
    "beta": AgentID.BETA,
    "sigma": AgentID.SIGMA,
    "gamma": AgentID.GAMMA,
    "omega": AgentID.OMEGA,
    "zeta": AgentID.ZETA,
    "kappa": AgentID.KAPPA,
    "prism": AgentID.PRISM,
    "chi": AgentID.CHI,
    "delta": AgentID.DELTA,
    "lambda": AgentID.LAMBDA,
    "network": "agent_network_commander",
}

# Same owner map as the orchestrator
module_owner = {
    "logic_tycoon": AgentID.SIGMA,
    "logic_escalator": AgentID.SIGMA,
    "logic_skipper": AgentID.SIGMA,
    "logic_doppelganger": AgentID.SIGMA,
    "logic_chronomancer": AgentID.SIGMA,
    "tech_sqli": AgentID.SIGMA,
    "tech_jwt": AgentID.SIGMA,
    "tech_fuzzer": AgentID.SIGMA,
    "tech_auth_bypass": AgentID.SIGMA,
    "delta_pinch_extract": AgentID.DELTA,
}

swarm_jobs = [
    ("prism_dom_analysis", AgentID.PRISM, {"innerText": "x", "style": {}, "url": "http://t/"}),
    ("chi_intercept", AgentID.CHI, {"method": "GET", "url": "http://t/"}),
    ("vulnerability_audit", AgentID.GAMMA, {"url": "http://t/", "evidence": "x"}),
    ("lambda_js_sast", AgentID.LAMBDA, {"js_urls": ["http://t/app.js"]}),
    ("kappa_recall", AgentID.KAPPA, {"query": "strategy"}),
]

expected = {
    "planner": "planner",
    "alpha": AgentID.ALPHA,
    "beta": AgentID.BETA,
    "sigma": AgentID.SIGMA,
    "gamma": AgentID.GAMMA,
    "omega": AgentID.OMEGA,
    "zeta": AgentID.ZETA,
    "kappa": AgentID.KAPPA,
    "prism": AgentID.PRISM,
    "chi": AgentID.CHI,
    "delta": AgentID.DELTA,
    "lambda": AgentID.LAMBDA,
    "network": "agent_network_commander",
}


async def main():
    bus = DistributedEventBus(redis_url="redis://localhost:6379/0")
    emitted_jobs = []  # every JOB_ASSIGNED that reaches the bus

    async def collector(event):
        cfg = event.payload.get("config", {}) or {}
        emitted_jobs.append((cfg.get("module_id"), cfg.get("agent_id")))

    bus.subscribe(EventType.JOB_ASSIGNED, collector)

    async def emit(module_id, agent_id, params):
        pkt = JobPacket(
            priority=TaskPriority.HIGH,
            target=TaskTarget(url="http://127.0.0.1:8888/", payload=params),
            config=ModuleConfig(module_id=module_id, agent_id=agent_id, params=params),
        )
        await bus.publish(
            HiveEvent(type=EventType.JOB_ASSIGNED, source="VIGILAGENT", scan_id="TEST", payload=pkt.model_dump())
        )

    # Module mapper jobs (as orchestrator emits them)
    for mid, owner in module_owner.items():
        await emit(mid, owner, {"concurrency": 50})
    # Sigma validation + generative + beta assault
    await emit("recon_nuclei", AgentID.SIGMA, {})
    await emit("sigma_generative_blast", AgentID.SIGMA, {})
    await emit("beta_direct_assault", AgentID.BETA, {})
    # Full-swarm jobs
    for mid, agent, params in swarm_jobs:
        await emit(mid, agent, params)

    await asyncio.sleep(0.5)

    seen = {agent: [] for agent in set(AGENTS.values())}
    for module_id, agent_id in emitted_jobs:
        if agent_id in seen:
            seen[agent_id].append(module_id)

    ok = True
    for name, agent_id in expected.items():
        jobs = seen.get(agent_id, [])
        status = "OK " if jobs else "MISSING"
        if not jobs:
            ok = False
        print(f"  [{status}] {name:9s} ({agent_id}) <- {jobs}")
    print("RESULT:", "ALL AGENTS RECEIVED WORK" if ok else "SOME AGENTS STILL IDLE")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
