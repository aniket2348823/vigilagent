import asyncio
import logging
import os
import time
import uuid
from collections import deque
from datetime import UTC, datetime
from typing import Any

# Import Agents
from backend.agents.alpha import AlphaAgent
from backend.agents.beta import BetaAgent
from backend.agents.chi import AgentChi  # Agent Iota (The Inspector)
from backend.agents.delta import AgentDelta  # Agent Delta (Hybrid DOM Controller)
from backend.agents.gamma import GammaAgent
from backend.agents.kappa import KappaAgent
from backend.agents.lambda_agent import LambdaAgent  # Lambda (Pre-code Scanner)
from backend.agents.omega import OmegaAgent

# Xytherion Distributed Architecture (Logic Integrated Locally)
# Legacy imports removed to prevent shadowing
# Unified Safety Agents (Prism & Chi)
from backend.agents.prism import AgentPrism  # Agent Theta (The Sentinel)
from backend.agents.sigma import SigmaAgent
from backend.agents.zeta import ZetaAgent

# Hybrid AI Engine for campaign strategy
from backend.ai.cortex import get_cortex_engine
from backend.api.socket_manager import manager
from backend.core.agent_roles import role_for as _role_for
from backend.core.broadcast_throttle import BroadcastThrottle
from backend.core.cluster.master import MasterNode  # noqa: F401

# --- CLUSTER COMPONENTS (Extracted to backend.core.cluster for Clean Architecture) ---
from backend.core.cluster.pinchtab import PinchTabInstance  # noqa: F401
from backend.core.cluster.worker import WorkerNode  # noqa: F401
from backend.core.config import settings
from backend.core.database import db_manager  # [NEW] Distributed Intelligence Backbone
from backend.core.endpoint_tracker import EndpointTracker
from backend.core.guard_layer import guard_layer
from backend.core.hive import DistributedEventBus, EventBus, EventType, HiveEvent

# CVSS 4.0 engine: imported at module level for efficiency (was per-finding
# inside event_listener, adding ~50ms import overhead per VULN_CONFIRMED event).
# See _cvss_score, _cvss_evidence, etc. below.
# V6 Lifecycle Management
from backend.core.phase_gate import PhaseGate, ScanPhase
from backend.core.planner import MissionPlanner
from backend.core.protocol import AgentID, JobPacket, ModuleConfig, TaskPriority, TaskTarget

# recorder removed - unused import cleanup V6
from backend.core.reporting import ReportGenerator  # The Voice
from backend.core.scope import ScopePolicy
from backend.core.state import stats_db_manager
from backend.core.task_manager import TaskManager
from backend.modules.tech.http_client import http_client
from backend.core.verification import canary as _canary_instance

# CRITICAL FIX: Move CVSS engine import to module level to avoid per-event
# import overhead (was inside event_listener closure, adding ~50ms latency
# on every VULN_CONFIRMED event).
try:
    from backend.reporting.cvss_engine import (
        generate_cwe as _cvss_cwe,
    )
    from backend.reporting.cvss_engine import (
        generate_evidence as _cvss_evidence,
    )
    from backend.reporting.cvss_engine import (
        score_for_vuln_class as _cvss_score,
    )
    from backend.reporting.cvss_engine import (
        severity_band as _cvss_severity_band,
    )

    _CVSS_AVAILABLE = True
except ImportError:
    _CVSS_AVAILABLE = False
    _cvss_score = _cvss_evidence = _cvss_cwe = _cvss_severity_band = None

logger = logging.getLogger("HiveOrchestrator")
ai_cortex = get_cortex_engine()

# Short-name alias mapping: API sends "sqli", orchestrator needs "SQL Injection Probe"
# Module-level constant — recreated on every import, never changes.
_MODULE_ALIASES = {
    "sqli": "SQL Injection Probe",
    "xss": "API Fuzzer (REST)",
    "cmdi": "The Skipper",
    "path_traversal": "The Escalator",
    "idor": "Doppelganger (IDOR)",
    "ssti": "The Tycoon",
    "open_redirect": "Chronomancer",
    "ssrf": "Auth Bypass Tester",
    "jwt": "JWT Token Cracker",
}


class _DispatchPacer:
    """Bounded-burst pacing for JOB_ASSIGNED dispatch.

    WHY: The swarm dispatches ~70+ jobs in three tight loops (module mapper,
    Sigma validation, full-swarm). Fired back-to-back, they saturate the
    CommandLane *instantly*, which makes Zeta's governor oscillate
    THROTTLE→RESUME every cycle (observed 60×/60× per scan). Pacing the
    publishes with a small inter-burst delay lets the lane drain between
    bursts, so the governor stays quiet and agents actually start work while
    the rest of the dispatch is still in flight.

    Semantics are unchanged: every job is still published, in the same order,
    with the same payload. Only the timing is spread.
    """

    __slots__ = ("_burst", "_delay", "_fired")

    def __init__(self, burst: int | None = None, delay: float | None = None):
        try:
            self._burst = max(1, int(getattr(settings, "DISPATCH_BURST_SIZE", 8) or 8))
        except Exception:
            self._burst = 8
        try:
            self._delay = max(0.0, float(getattr(settings, "DISPATCH_BURST_DELAY_SECONDS", 0.05) or 0.05))
        except Exception:
            self._delay = 0.05
        if burst is not None:
            self._burst = max(1, int(burst))
        if delay is not None:
            self._delay = max(0.0, float(delay))
        self._fired = 0

    async def wait(self) -> None:
        """Call before each publish; sleeps every ``burst`` publishes."""
        self._fired += 1
        if self._delay > 0 and self._fired % self._burst == 0:
            await asyncio.sleep(self._delay)


def _log_task_error(task, label="task", scan_id="unknown"):
    """Callback for asyncio.create_task() to surface silent exceptions.

    MUST be defined at module level (not inside bootstrap_hive) so that
    callbacks attached to master/worker tasks created early in the method
    can reference it. Closures capture ``scan_id`` via default argument.
    """
    exc = task.exception()
    if exc is not None:
        logger.error("[%s] Background %s raised: %s", scan_id, label, exc, exc_info=exc)


class HiveOrchestrator:
    # Global Registry for API Access (Nervous System)
    # NOTE: active_agents and _orphaned_tasks are class-level. Concurrent
    # scans are NOT fully supported — they share this registry and can
    # interfere. For concurrent scan support, these must be moved to
    # per-scan instances (tracked by scan_id).
    active_agents = {}
    # Per-scan agent registry: maps scan_id -> {agent_name: agent_instance}.
    # Enables surgical stop of only agents belonging to a specific scan
    # instead of nuking the global registry on cancel/crash.
    _scan_agents: dict[str, dict[str, Any]] = {}
    _active_agents_lock: asyncio.Lock | None = None  # CRIT-04: lazily created per-loop

    @classmethod
    def _get_lock(cls) -> asyncio.Lock:
        """Return a loop-bound lock, creating it lazily if needed."""
        if cls._active_agents_lock is None:
            cls._active_agents_lock = asyncio.Lock()
        return cls._active_agents_lock

    # Control plane (Architecture §5.5): delegation manager + campaign budget.
    delegation = None
    campaign_budget = None
    _orphaned_tasks = set()
    _task_manager = TaskManager("HiveOrchestrator")
    _zombie_sweep_task: asyncio.Task | None = None

    @staticmethod
    async def bootstrap_hive(target_config, scan_id=None):
        """
        Initializes the Vigilagent Singularity.
        """
        start_time = datetime.now()
        if not scan_id:
            scan_id = f"HIVE-V5-{int(start_time.timestamp())}"
        http_client.scope = ScopePolicy.from_target(target_config.get("url"))

        # 0. Scan registration is deferred until ScanLifecycleManager is
        #    constructed (after scan_events, broadcast_throttle, phase_gate, bus
        #    are all defined).  See "# --- LIFECYCLE WIRING ---" below.
        # 1. Create Nervous System (Distributed Switch)
        redis_url = getattr(settings, "REDIS_URL", None)
        if redis_url:
            bus = DistributedEventBus(redis_url)
            await bus.start()
            logger.info("🕸️ Xytherion Distributed Singularity Initialized.")

            # --- START DISTRIBUTED COMMAND LAYER ---
            # Automatically start Master for this scan
            master = MasterNode(redis_url, settings.SUPABASE_URL, settings.SUPABASE_KEY)
            _master_task = HiveOrchestrator._task_manager.create_task(master.start(), name="master_node")
            _master_task.add_done_callback(lambda t: _log_task_error(t, "master_node", scan_id))

            # Start Worker for dynamic execution
            worker_id = f"local-hive-{uuid.uuid4().hex[:4]}"
            worker = WorkerNode(worker_id, "hybrid", redis_url, settings.SUPABASE_URL, settings.SUPABASE_KEY)
            _worker_task = HiveOrchestrator._task_manager.create_task(worker.start(), name="worker_node")
            _worker_task.add_done_callback(lambda t: _log_task_error(t, "worker_node", scan_id))

            # The Unified Agents (Prism/Chi) handle individual guardian duties
            # they are already in the core_agents list and started below.
            logger.info("🛡️ Xytherion Command Matrix Activated (Master + Local Worker). Safety Guardians Unified.")

            # V6-HARDENED: Start Cluster Telemetry Loop
            _telemetry_task = HiveOrchestrator._task_manager.create_task(
                HiveOrchestrator._cluster_telemetry_loop(redis_url, scan_id), name="cluster_telemetry"
            )
            # ----------------------------------------

        else:
            bus = EventBus()
            master = None
            logger.info("🛡️ Local Singularity Initialized (Standalone).")

        # --- CONTROL PLANE (Architecture §5.5, §24 step 13) ---
        # Layer the DelegationManager on top of the EventBus so commander agents
        # can spawn budgeted, isolated child agents and await structured results.
        # The EventBus remains the telemetry/coordination plane (frontend feed).
        try:
            from backend.core.cognitive_router import CognitiveRouter
            from backend.core.delegation_manager import make_delegation_manager
            from backend.core.iteration_budget import campaign_budget
            from backend.core.scan_lifecycle_manager import ScanLifecycleManager

            delegation = make_delegation_manager(
                bus=bus, master=master if redis_url else None, scan_id=scan_id or "GLOBAL"
            )
            HiveOrchestrator.delegation = delegation
            HiveOrchestrator.campaign_budget = campaign_budget(label=f"campaign:{scan_id or 'GLOBAL'}")
            logger.info(
                "🧭 Delegation control plane active (campaign budget=%d).", HiveOrchestrator.campaign_budget.max_total
            )
        except Exception as _de:
            logger.warning(f"Delegation manager not attached: {_de}")

        # --- REPORTING LINK ---
        # FIX-003: Bound scan_events to prevent OOM on long-running scans
        scan_events: deque = deque(maxlen=10000)
        alpha_recon_complete = asyncio.Event()
        # Per-scan broadcast throttle: drops repeated (type, url, agent)
        # broadcasts that fire within 500ms of the last one. The synthetic
        # WebSocket batcher already coalesces frames at ~50fps, but we
        # were pushing the same logical event into the queue 1500+ times
        # during real scans. Suppressing duplicates *before* they hit the
        # queue cuts JSON serialization + send overhead by an order of
        # magnitude on noisy scans without changing the public broadcast
        # contract (event types/payload shapes are unchanged).
        broadcast_throttle = BroadcastThrottle(window_ms=500)
        cognitive_router = None  # Set after lifecycle.activate_agents(); closure captures by ref

        async def event_listener(event: HiveEvent):
            # [CRITICAL SYNC: V6] Persist every event to the scan's hot buffer for LiveMonitor/Reports
            # IMPORTANT: serialize with mode="json" so the EventType enum is
            # rendered as a plain string ("VULN_CONFIRMED"), not its repr
            # (`<EventType.VULN_CONFIRMED: 'VULN_CONFIRMED'>`). The scans
            # findings API filters events by ``str(ev["type"]).upper()`` and
            # would otherwise miss every confirmed finding.
            event_data = event.model_dump(mode="json")
            scan_events.append(event_data)
            await stats_db_manager.add_scan_event(scan_id, event_data)

            if event.type == EventType.RECON_COMPLETE and event.source == "agent_alpha":
                alpha_recon_complete.set()

            real_payload = None  # Initialized safely; set per event type below
            # REAL-TIME DASHBOARD SYNC
            if event.type == EventType.VULN_CONFIRMED:
                # Update global stats immediately
                real_payload = event.payload
                if "payload" in real_payload and isinstance(real_payload["payload"], dict):
                    pass

                # [NEW] GuardLayer Hallucination & Deduplication Filter
                real_payload["validation"] = "VALID"  # Inherent to VULN_CONFIRMED
                if not guard_layer.filter_single(real_payload):
                    logger.debug("🛡️ GuardLayer Dropped VULN_CONFIRMED: Did not meet mathematical strictness bounds.")
                    return
                if real_payload is not None:
                    # CognitiveRouter: route event to additional agents
                    if cognitive_router:
                        target_agents = cognitive_router.route_event(event)
                        if target_agents:
                            logger.debug(
                                "[CognitiveRouter] event=%s -> targets=%s",
                                event.type,
                                [a.__class__.__name__ for a in target_agents],
                            )

                        severity = real_payload.get("severity", "High")
                        # Passing normalized signature data to StateManager for robust deduplication
                        sig_data = {
                            "url": str(real_payload.get("url", "")).strip().lower(),
                            "type": str(real_payload.get("type", "")).upper(),
                            "data": str(real_payload.get("data", real_payload.get("payload", ""))),
                        }

                        # [NEW] Distributed Intelligence Injection (Supabase Backbone)
                        # Schedule the Supabase write off the listener's critical path
                        # so 1500+ VULN_CONFIRMED events don't serialize behind HTTPS
                        # round-trips. Errors are absorbed inside report_vulnerability
                        # and surface in db_manager logs.
                        async def _persist_vuln():
                            try:
                                await db_manager.initialize()
                                await db_manager.report_vulnerability(
                                    scan_id=scan_id,
                                    endpoint=sig_data["url"],
                                    vuln_type=sig_data["type"],
                                    severity=severity,
                                    evidence=real_payload,
                                    validated_by=event.source,
                                )
                            except Exception as _persist_err:
                                logger.warning(
                                    "[Orchestrator] Deferred vuln persist failed: %s",
                                    _persist_err,
                                )

                        _persist_task = asyncio.create_task(_persist_vuln())
                        HiveOrchestrator._orphaned_tasks.add(_persist_task)
                        _persist_task.add_done_callback(HiveOrchestrator._orphaned_tasks.discard)

                        # Generate CVSS 4.0 score, evidence, and remediation for this finding
                        # Uses module-level imports (_cvss_score, etc.) for efficiency.
                        # MITRE ATT&CK tagging (always runs, no external deps)
                        from backend.reporting.mitre_tagger import enrich_finding as _mitre_enrich
                        _mitre_enrich(real_payload)

                        _import_ok = _CVSS_AVAILABLE

                        # Default CVSS values — overridden below if enrichment succeeds
                        cvss_score_val = 0.0
                        cvss_vector_val = ""

                        if _import_ok:
                            try:
                                vuln_type_key = sig_data["type"]
                                _data_str = str(real_payload.get("data", "")).lower()
                                cvss_score_val, cvss_vector_val = _cvss_score(
                                    vuln_type_key,
                                    data_leak="leak" in _data_str or "sensitive" in _data_str,
                                )
                                evidence_record = _cvss_evidence(vuln_type_key, url=sig_data["url"])
                                enriched_finding = {
                                    "url": sig_data["url"],
                                    "type": vuln_type_key,
                                    "severity": severity,
                                    "data": sig_data["data"],
                                    "cvss_score": round(cvss_score_val, 1),
                                    "cvss_vector": cvss_vector_val,
                                    "cvss_version": "4.0",
                                    "cvss_severity": _cvss_severity_band(cvss_score_val),
                                    "cwe": _cvss_cwe(vuln_type_key),
                                    "evidence": evidence_record,
                                    "remediation": evidence_record.get("remediation", ""),
                                    "agent": event.source,
                                    "discovered_at": datetime.now(UTC).isoformat(),
                                }
                                await stats_db_manager.record_finding(scan_id, severity, enriched_finding)
                            except Exception as _enrich_err:
                                logger.warning("Finding enrichment failed, recording raw: %s", _enrich_err)
                                sig_data["severity"] = severity
                                await stats_db_manager.record_finding(scan_id, severity, sig_data)
                        else:
                            sig_data["severity"] = severity
                            await stats_db_manager.record_finding(scan_id, severity, sig_data)

                        # Inject CVSS into real_payload for downstream consumers
                        # (WebSocket broadcast, Bayesian fusion).
                        if cvss_score_val > 0:
                            try:
                                real_payload["cvss_score"] = cvss_score_val
                                real_payload["cvss_vector"] = cvss_vector_val
                                real_payload["cvss_severity"] = _cvss_severity_band(cvss_score_val)

                                # Bayesian Fusion: Combine CVSS with existing signals
                                gamma_score = real_payload.get("gamma_score", 0.5)
                                gi5_score = real_payload.get("gi5_risk", 0.5)
                                cvss_normalized = cvss_score_val / 10.0
                                final_risk = gi5_score * 0.35 + gamma_score * 0.30 + cvss_normalized * 0.35
                                real_payload["final_risk_score"] = round(final_risk, 4)
                            except Exception as cvss_err:
                                logger.warning(f"CVSS payload injection failed: {cvss_err}")

                        # Broadcast authoritative stats to UI
                        # Throttle: VULN_UPDATE is just dashboard counters; emitting
                        # one per finding floods the WebSocket with redundant frames.
                        # 500ms window keeps the dashboard reactive while collapsing
                        # bursts. The throttle key is per-scan so two scans don't
                        # mask each other's metric updates.
                        current_stats = stats_db_manager.get_stats()
                        if broadcast_throttle.should_emit(("VULN_UPDATE", scan_id, "_metrics")):
                            await manager.broadcast(
                                {
                                    "type": "VULN_UPDATE",
                                    "payload": {
                                        "metrics": {
                                            "vulnerabilities": current_stats["vulnerabilities"],
                                            "critical": current_stats["critical"],
                                            "active_scans": current_stats["active_scans"],
                                            "total_scans": current_stats["total_scans"],
                                        },
                                        "graph_data": current_stats["history"],
                                    },
                                }
                            )

                        # V6: Persist Threat Metrics (Async Fix)
                        threat_type = real_payload.get("type", "Unknown Threat")
                        risk_score = real_payload.get("data", {}).get("risk_score", 0)
                        await stats_db_manager.record_threat(threat_type, risk_score)

                        # Broadcast LIVE THREAT LOG (New Feature)
                        log_payload = {
                            "agent": event.source,
                            "agent_role": _role_for(str(event.source)),
                            "threat_type": threat_type,
                            "url": real_payload.get("url", "Unknown Source"),
                            "severity": severity,
                            "timestamp": datetime.now().strftime("%H:%M:%S"),
                            "risk_score": risk_score,
                        }
                        # Throttle key: (event_type, url, agent) — same triple
                        # firing inside 500ms is treated as the same logical
                        # alert. Persistence to the scan buffer still happens so
                        # report builders see every event.
                        _threat_key = ("LIVE_THREAT_LOG", log_payload["url"], log_payload["agent"])
                        if broadcast_throttle.should_emit(_threat_key):
                            await manager.broadcast(
                                {
                                    "type": "LIVE_THREAT_LOG",
                                    "scan_id": scan_id,  # [V7] Isolation Injection
                                    "payload": log_payload,
                                }
                            )
                        # Ensure the filtered log also makes it to the scan buffer
                        await stats_db_manager.add_scan_event(
                            scan_id, {"type": "LIVE_THREAT_LOG", "scan_id": scan_id, "payload": log_payload}
                        )

            elif event.type == EventType.VULN_CANDIDATE:
                real_payload = event.payload
                threat_type = real_payload.get("tag", "Anomaly Target")
                # Throttle: recon-phase candidates often re-fire on the same
                # URL (multiple agents probing the same endpoint). Suppress
                # repeats so the dashboard log doesn't drown.
                _cand_key = ("VULN_CANDIDATE", real_payload.get("url", "Unknown Source"), event.source)
                if broadcast_throttle.should_emit(_cand_key):
                    await manager.broadcast(
                        {
                            "type": "LIVE_THREAT_LOG",
                            "scan_id": scan_id,  # [V7] Isolation Injection
                            "payload": {
                                "agent": event.source,
                                "agent_role": _role_for(str(event.source)),
                                "threat_type": f"[RECON] {threat_type}",
                                "url": real_payload.get("url", "Unknown Source"),
                                "severity": "INFO",
                                "timestamp": datetime.now().strftime("%H:%M:%S"),
                                "risk_score": 0,
                            },
                        }
                    )

            elif event.type == EventType.LIVE_ATTACK:
                # Compute a dynamic severity based on keywords in the action/arsenal
                action_str = (event.payload.get("action", "") + event.payload.get("arsenal", "")).lower()
                if any(k in action_str for k in ["inject", "sqli", "xss", "bypass", "exploit", "crack"]):
                    attack_severity = "HIGH"
                    attack_risk = 75
                elif any(k in action_str for k in ["fuzz", "mutation", "brute", "payload"]):
                    attack_severity = "MEDIUM"
                    attack_risk = 50
                else:
                    attack_severity = "LOW"
                    attack_risk = 25

                attack_payload = {
                    "agent": event.source,
                    "agent_role": _role_for(str(event.source)),
                    "url": event.payload.get("url", "N/A"),
                    "arsenal": event.payload.get("arsenal", "General"),
                    "action": event.payload.get("action", "Processing"),
                    "payload": event.payload.get("payload", "N/A"),
                    "severity": attack_severity,
                    "risk_score": attack_risk,
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                }
                # Throttle: repeated attacks against the same URL by the
                # same agent (typical fuzzing pattern). Persistence is
                # NOT throttled — the feed history below still records
                # every event for the scan buffer.
                _atk_key = ("LIVE_ATTACK_FEED", attack_payload["url"], attack_payload["agent"])
                if broadcast_throttle.should_emit(_atk_key):
                    await manager.broadcast(
                        {
                            "type": "LIVE_ATTACK_FEED",
                            "scan_id": scan_id,  # [V7] Isolation Injection
                            "payload": attack_payload,
                        }
                    )
                # Persistence for Feed History (always)
                await stats_db_manager.add_scan_event(
                    scan_id, {"type": "LIVE_ATTACK_FEED", "scan_id": scan_id, "payload": attack_payload}
                )

            elif event.type == EventType.RECON_PACKET:
                _rp_url = event.payload.get("url", "Unknown")
                # Throttle: alpha emits one RECON_PACKET per discovered
                # endpoint; re-discoveries within 500ms are noise.
                if broadcast_throttle.should_emit(("RECON_PACKET", _rp_url, event.source)):
                    await manager.broadcast(
                        {
                            "type": "RECON_PACKET",
                            "scan_id": scan_id,  # [V7] Isolation Injection
                            "payload": {
                                "url": _rp_url,
                                "severity": event.payload.get("severity", "INFO"),
                                "risk_score": event.payload.get("risk_score", 10),
                                "source": event.source,
                                "timestamp": datetime.now().strftime("%H:%M:%S"),
                            },
                        }
                    )

            elif event.type == EventType.JOB_ASSIGNED:
                # Broadcast job dispatch as a visual event for the dashboard
                target_data = event.payload.get("target", {})
                config_data = event.payload.get("config", {})
                job_url = (
                    target_data.get("url", "System Process") if isinstance(target_data, dict) else "System Process"
                )
                job_module = config_data.get("module_id", "Unknown") if isinstance(config_data, dict) else "Unknown"
                if broadcast_throttle.should_emit(("JOB_ASSIGNED", job_url, event.source)):
                    await manager.broadcast(
                        {
                            "type": "JOB_ASSIGNED",
                            "scan_id": scan_id,  # [V7] Isolation Injection
                            "payload": {
                                "source": event.source,
                                "agent": event.source,
                                "agent_role": _role_for(str(event.source)),
                                "url": job_url,
                                "module": job_module,
                                "timestamp": datetime.now().strftime("%H:%M:%S"),
                            },
                        }
                    )

        # Subscribe Recorder to Everything for maximum fidelity
        for etype in EventType:
            bus.subscribe(etype, event_listener)
        # ----------------------

        # ═══════════════════════════════════════════════════════════════════════
        # V6 LIFECYCLE MANAGEMENT: Initialize PhaseGate and EndpointTracker
        # ═══════════════════════════════════════════════════════════════════════
        phase_gate = PhaseGate(scan_id)
        endpoint_tracker = EndpointTracker(scan_id)

        # Subscribe to endpoint discovery and testing events
        async def track_endpoint_discovery(event: HiveEvent):
            if event.type == EventType.ENDPOINT_DISCOVERED:
                url = event.payload.get("url")
                source = event.source
                if url:
                    endpoint_tracker.add_discovered(url, source=source)
                    # Broadcast coverage update
                    metrics = endpoint_tracker.get_metrics()
                    await manager.broadcast({"type": "COVERAGE_UPDATE", "scan_id": scan_id, "payload": metrics})

        async def track_endpoint_testing(event: HiveEvent):
            if event.type == EventType.ENDPOINT_TESTED:
                url = event.payload.get("url")
                agent = event.source
                if url:
                    endpoint_tracker.mark_tested(url, agent=agent)
                    # Broadcast coverage update
                    metrics = endpoint_tracker.get_metrics()
                    await manager.broadcast({"type": "COVERAGE_UPDATE", "scan_id": scan_id, "payload": metrics})

        async def track_vulnerabilities(event: HiveEvent):
            if event.type == EventType.VULN_CONFIRMED:
                url = event.payload.get("url")
                vuln_type = event.payload.get("type", "Unknown")
                if url:
                    endpoint_tracker.mark_vulnerable(url, vuln_type=vuln_type)

        bus.subscribe(EventType.ENDPOINT_DISCOVERED, track_endpoint_discovery)
        bus.subscribe(EventType.ENDPOINT_TESTED, track_endpoint_testing)
        bus.subscribe(EventType.VULN_CONFIRMED, track_vulnerabilities)

        logger.info(f"[{scan_id}] PhaseGate and EndpointTracker initialized")

        # --- LIFECYCLE WIRING (Two-Tiered Architecture Phase 1) ---
        # All dependencies (scan_events, broadcast_throttle, phase_gate, bus)
        # are now defined, so we can safely construct the lifecycle manager
        # and perform scan registration.
        lifecycle = ScanLifecycleManager(
            manager=manager,
            stats_db=stats_db_manager,
            phase_gate=phase_gate,
            event_bus=bus,
            scan_id=scan_id,
            target_config=target_config,
            scan_events=scan_events,
            broadcast_throttle=broadcast_throttle,
        )
        await lifecycle.register_scan()
        # ═══════════════════════════════════════════════════════════════════════

        # --- PHASE 1: MISSION PLANNING ---
        await phase_gate.advance_to(ScanPhase.PLANNING)
        await manager.broadcast(
            {
                "type": "PHASE_STARTED",
                "scan_id": scan_id,
                "payload": {"phase": "PLANNING", "timestamp": datetime.now().strftime("%H:%M:%S")},
            }
        )
        await manager.broadcast(
            {
                "type": "LIVE_ATTACK_FEED",
                "scan_id": scan_id,
                "payload": {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "agent": "planner",
                    "threat_type": "PLANNING",
                    "url": target_config["url"],
                    "result": "📋 Mission Planning — Analyzing target scope & selecting attack vectors",
                    "severity": "INFO",
                    "risk_score": 0,
                },
            }
        )
        await asyncio.sleep(0.1)  # Let the event propagate

        # 2. Spawn Agents (Singularity V5)
        # All agents now inherit from Hive BaseAgent and take `bus`
        scout = AlphaAgent(bus)
        breaker = BetaAgent(bus)
        analyst = GammaAgent(bus)
        strategist = OmegaAgent(bus)
        governor = ZetaAgent(bus)

        # AWAKENING: The Smith and The Librarian
        sigma = SigmaAgent(bus)
        kappa = KappaAgent(bus)

        # AWAKENING: The Sentinel and The Inspector (Purple Team Expansion)
        sentinel = AgentPrism(bus)
        inspector = AgentChi(bus)

        # AWAKENING: The Hybrid Controller (Browser DOM Wrapper)
        delta = AgentDelta(bus)

        # AWAKENING: The Pre-code Scanner (SAST + IaC + SBOM)
        lambda_sast = LambdaAgent(bus=bus)

        # AWAKENING: The Mission Planner (V6 Strategic Heart)
        planner = MissionPlanner(bus)

        # AWAKENING: The Network Service Commander (Architecture §5, §29.7)
        # Importing the package also registers delegation child runners (§5.1.2).
        try:
            from backend.agents.commanders import NetworkServiceCommander

            net_commander = NetworkServiceCommander(bus)
        except Exception as _ne:
            logger.warning(f"NetworkServiceCommander unavailable: {_ne}")
            net_commander = None

        # ═══════════════════════════════════════════════════════════════════════
        # AGENT AWAKENING BROADCASTS: Show all agents coming online in live monitor
        # ═══════════════════════════════════════════════════════════════════════
        awakening_agents = [
            ("planner", "MISSION PLANNER", "Strategic campaign planning"),
            ("alpha", "ALPHA", "Reconnaissance & endpoint discovery"),
            ("beta", "BETA", "Direct assault & polyglot attacks"),
            ("sigma", "SIGMA", "Exploitation engine & generative blasts"),
            ("gamma", "GAMMA", "Forensic audit & vulnerability validation"),
            ("omega", "OMEGA", "Campaign strategy & attack coordination"),
            ("zeta", "ZETA", "Governance & resource throttling"),
            ("kappa", "KAPPA", "Memory & contextual intelligence"),
            ("prism", "PRISM", "Safety sentinel & ethical guardrails"),
            ("chi", "CHI", "Inspector & defense validation"),
            ("delta", "DELTA", "DOM controller & browser-level attacks"),
            ("lambda", "LAMBDA", "Pre-code scanner (SAST/IaC)"),
        ]
        if net_commander is not None:
            awakening_agents.append(("network", "NETWORK", "Network service discovery"))
        for ag_id, ag_name, ag_role in awakening_agents:
            await manager.broadcast(
                {
                    "type": "LIVE_ATTACK_FEED",
                    "scan_id": scan_id,
                    "payload": {
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "agent": ag_id,
                        "threat_type": "AGENT_ONLINE",
                        "url": target_config["url"],
                        "result": f"⚡ {ag_name} online — {ag_role}",
                        "severity": "INFO",
                        "risk_score": 0,
                    },
                }
            )

        # 4. Wake Up the Hive
        # DATA WIRING: Pass Mission Profile
        {
            "modules": target_config.get("modules", []),
            "filters": target_config.get("filters", []),
            "scope": target_config.get("url", ""),
        }

        # MODULE-BASED AGENT ROUTING
        # Core agents always run — these provide essential cross-cutting services
        # Alpha: Recon, Kappa: Memory, Planner: Strategy, Prism: Defense, Chi: Defense
        # Gamma: Forensic Audit, Omega: Campaign Strategy, Zeta: Governance/Throttle, Delta: DOM Interceptor
        core_agents = [planner, scout, kappa, sentinel, inspector, analyst, strategist, governor, delta, lambda_sast]
        if net_commander is not None:
            core_agents.append(net_commander)

        # Offensive agents mapped to modules (Beta + Sigma are attack-specific)
        module_agent_map = {
            "The Tycoon": [breaker, sigma],
            "The Escalator": [breaker, sigma],
            "The Skipper": [breaker, sigma],
            "Doppelganger (IDOR)": [breaker, sigma],
            "Chronomancer": [breaker, sigma],
            "SQL Injection Probe": [breaker, sigma],
            "JWT Token Cracker": [breaker, sigma],
            "API Fuzzer (REST)": [breaker, sigma],
            "Auth Bypass Tester": [breaker, sigma],
        }

        # Resolve short names to full names
        selected_modules = target_config.get("modules", [])
        selected_modules = [_MODULE_ALIASES.get(m, m) for m in selected_modules]

        # BUG FIX: Always include Sigma and Beta — they handle unconditional
        # jobs (sigma_generative_blast, beta_direct_assault) that are always
        # dispatched regardless of module selection.
        agents = core_agents + [sigma, breaker]

        if selected_modules:
            # Also add offensive agents for any matched modules
            for mod in selected_modules:
                for agent in module_agent_map.get(mod, []):
                    if agent not in agents:
                        agents.append(agent)

        # --- Agent Activation (via ScanLifecycleManager) ---
        await lifecycle.activate_agents(
            agents,
            mission_config={
                "target": target_config["url"],
                "scan_id": scan_id,
                "modules": target_config.get("modules", []),
            },
        )

        # --- Self-Healing Registration (via ScanLifecycleManager) ---
        from backend.core.recovery_engine import healing_engine

        lifecycle.register_self_healing(agents, healing_engine=healing_engine)

        # Start self-healing monitoring loop
        healing_task = asyncio.create_task(healing_engine.monitor_and_heal())
        HiveOrchestrator._orphaned_tasks.add(healing_task)
        healing_task.add_done_callback(HiveOrchestrator._orphaned_tasks.discard)
        healing_task.add_done_callback(lambda t: _log_task_error(t, "healing", scan_id))
        logger.info("[Orchestrator] Self-healing engine activated")

        # Start zombie agent sweep if not already running
        if HiveOrchestrator._zombie_sweep_task is None or HiveOrchestrator._zombie_sweep_task.done():
            HiveOrchestrator._zombie_sweep_task = asyncio.create_task(HiveOrchestrator._zombie_agent_sweep())
            logger.info("[Orchestrator] Zombie agent sweep activated")

        # --- CognitiveRouter (requires active_agents populated) ---
        cognitive_router = CognitiveRouter(HiveOrchestrator.active_agents)

        # ═══════════════════════════════════════════════════════════════════════
        # V6 LIFECYCLE: Complete Planning Phase, Start Reconnaissance
        # ═══════════════════════════════════════════════════════════════════════
        await phase_gate.advance_to(ScanPhase.RECONNAISSANCE)
        await manager.broadcast(
            {
                "type": "PHASE_STARTED",
                "scan_id": scan_id,
                "payload": {"phase": "RECONNAISSANCE", "timestamp": datetime.now().strftime("%H:%M:%S")},
            }
        )
        logger.info(f"[{scan_id}] Phase transition: PLANNING → RECONNAISSANCE")
        # ═══════════════════════════════════════════════════════════════════════
        # Agent registry population is handled by lifecycle.activate_agents()
        # above. Wire enum-keyed aliases for agents that need them:
        async with HiveOrchestrator._get_lock():
            HiveOrchestrator.active_agents[AgentID.PRISM] = sentinel
            HiveOrchestrator.active_agents[AgentID.CHI] = inspector
            HiveOrchestrator.active_agents[AgentID.OMEGA] = strategist
            HiveOrchestrator.active_agents[AgentID.ALPHA] = scout
            HiveOrchestrator.active_agents[AgentID.BETA] = breaker
            HiveOrchestrator.active_agents[AgentID.GAMMA] = analyst
            HiveOrchestrator.active_agents[AgentID.ZETA] = governor
            HiveOrchestrator.active_agents[AgentID.SIGMA] = sigma
            HiveOrchestrator.active_agents[AgentID.KAPPA] = kappa
            HiveOrchestrator.active_agents[AgentID.DELTA] = delta
            HiveOrchestrator.active_agents["PLANNER"] = planner
            HiveOrchestrator.active_agents["LAMBDA"] = lambda_sast
            if net_commander is not None:
                HiveOrchestrator.active_agents["agent_network_commander"] = net_commander

        # HYBRID AI: Log campaign strategy
        strategy_name = "Dynamic Multi-Core Heuristics"
        logger.info(f"AI Campaign Strategy: {strategy_name}")

        await manager.broadcast({"type": "GI5_LOG", "payload": f"SINGULARITY V6 ONLINE. AI Strategy: {strategy_name}."})
        # CRITICAL FIX: Include target_url in SCAN_UPDATE so Dashboard can filter
        await manager.broadcast(
            {"type": "SCAN_UPDATE", "payload": {"id": scan_id, "status": "Running", "target_url": target_config["url"]}}
        )

        # 5. Seed the Mission — PUBLISH WITH SCAN_ID FOR CONTEXT ISOLATION
        await bus.publish(
            HiveEvent(
                type=EventType.TARGET_ACQUIRED,
                source="VIGILAGENT",
                scan_id=scan_id,
                payload={
                    "url": target_config["url"],
                    "tech_stack": ["Unknown"],
                    "scan_mode": target_config.get("scan_mode")
                    or target_config.get("mode")
                    or getattr(settings, "ALPHA_DEFAULT_MODE", "STANDARD"),
                },
            )
        )

        # ═══════════════════════════════════════════════════════════════════════
        # V6 LIFECYCLE FIX: MANDATORY ALPHA RECON COMPLETION (NO TIMEOUT)
        # ═══════════════════════════════════════════════════════════════════════
        # CRITICAL: All attack agents MUST wait for Alpha to complete recon
        # NO TIME LIMIT - Alpha gets unlimited time to discover all endpoints
        # ═══════════════════════════════════════════════════════════════════════

        await manager.broadcast(
            {
                "type": "LIVE_ATTACK_FEED",
                "scan_id": scan_id,
                "payload": {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "agent": "alpha",
                    "threat_type": "PHASE_TRANSITION",
                    "url": target_config["url"],
                    "result": "⏳ Alpha reconnaissance phase started. All attack agents on standby (NO TIME LIMIT).",
                    "severity": "INFO",
                    "risk_score": 0,
                },
            }
        )

        # BLOCKING WAIT - No timeout, Alpha must complete
        logger.info(f"[{scan_id}] Waiting for Alpha recon completion (with safety timeout)...")
        # Robust gate: wait up to RECON_MAX_WAIT for the formal RECON_COMPLETE
        # signal, but proceed regardless so a stalled recon spine never deadlocks
        # the attack pipeline (Architecture §16 phase ordering — phases must
        # advance, not block forever). The seeder + attack stages still run with
        try:
            recon_max_wait = float(getattr(settings, "RECON_MAX_WAIT_SECONDS", 180))
        except Exception:
            logger.warning("[Orchestrator] RECON_MAX_WAIT_SECONDS parse failed; defaulting to 180s")
            recon_max_wait = 180.0
        try:
            await asyncio.wait_for(alpha_recon_complete.wait(), timeout=recon_max_wait)
            logger.info(f"[{scan_id}] Alpha recon COMPLETE signal received - releasing attack agents")
        except TimeoutError:
            logger.warning(
                "[%s] Alpha recon did not emit RECON_COMPLETE within %.0fs; proceeding "
                "to attack phase with whatever surface recon produced.",
                scan_id,
                recon_max_wait,
            )

        # ═══════════════════════════════════════════════════════════════════════
        # ATTACK SURFACE SEEDING (recon → exploitation handoff):
        # A real operator authenticates first, then attacks the actual
        # vulnerable endpoints. Seed authenticated, param-carrying targets so
        # Sigma/Beta exploit real injection points instead of the bare base URL.
        # ═══════════════════════════════════════════════════════════════════════
        seeded_targets = []
        seeded_surface = None
        try:
            from backend.core.attack_surface_seeder import seed_attack_surface

            # Gather recon-discovered endpoints from the RECON_COMPLETE payload
            # (authoritative attack_surface) plus any live RECON_PACKET URLs.
            # Feeding the FULL surface — not just URLs carrying '?' — lets the
            # seeder authenticate and then point Sigma/Beta at the actual
            # discovered injection points.
            recon_eps = []
            try:
                for ev in scan_events:
                    if not isinstance(ev, dict):
                        continue
                    ev_type = str(ev.get("type", "")).upper()
                    payload = ev.get("payload", {}) if isinstance(ev.get("payload"), dict) else {}
                    if ev_type == "RECON_COMPLETE":
                        for ep in payload.get("attack_surface", []) or []:
                            u = (ep or {}).get("url") if isinstance(ep, dict) else None
                            if isinstance(u, str) and u:
                                recon_eps.append(u)
                    elif ev_type == "RECON_PACKET":
                        u = payload.get("url")
                        if isinstance(u, str) and u:
                            recon_eps.append(u)
            except Exception as exc:
                logger.warning("[Orchestrator] recon endpoint extraction failed: %s", exc)
                recon_eps = []
            recon_eps = list(dict.fromkeys(recon_eps))[:500]
            seeded_surface = await seed_attack_surface(target_config["url"], scan_id, recon_endpoints=recon_eps)
            seeded_targets = seeded_surface.targets
            logger.info(
                "[%s] Attack surface seeded: app=%s authenticated=%s targets=%d",
                scan_id,
                seeded_surface.app,
                seeded_surface.authenticated,
                len(seeded_targets),
            )
            await manager.broadcast(
                {
                    "type": "LIVE_ATTACK_FEED",
                    "scan_id": scan_id,
                    "payload": {
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "agent": "alpha",
                        "threat_type": "AUTH" if seeded_surface.authenticated else "TARGETING",
                        "url": target_config["url"],
                        "result": (
                            f"🔑 Authenticated as {seeded_surface.principal} & seeded "
                            f"{len(seeded_targets)} attack target(s)"
                            if seeded_surface.authenticated
                            else f"🎯 Seeded {len(seeded_targets)} attack target(s)"
                        ),
                        "severity": "INFO",
                        "risk_score": 0,
                    },
                }
            )
        except Exception as _se:
            logger.warning(f"[{scan_id}] Attack surface seeding failed: {_se}")

        # Helper: build the JobPacket target list for an attack job. Prefer the
        # seeded authenticated endpoints; fall back to the base URL.
        def _attack_targets():
            if seeded_targets:
                return list(seeded_targets)
            return [TaskTarget(url=target_config["url"])]

        # ═══════════════════════════════════════════════════════════════════════
        # Phase Transition via ScanLifecycleManager
        await lifecycle.advance_phase(ScanPhase.ASSESSMENT, metadata={"scan_id": scan_id})
        await lifecycle.broadcast_phase_feed("RECON_COMPLETE", "Alpha reconnaissance phase complete")
        logger.info(f"[{scan_id}] Phase transition: RECONNAISSANCE → ASSESSMENT")
        logger.info(f"[{scan_id}] Endpoints discovered: {len(endpoint_tracker.discovered)}")
        # ═══════════════════════════════════════════════════════════════════════

        await manager.broadcast(
            {
                "type": "LIVE_ATTACK_FEED",
                "scan_id": scan_id,
                "payload": {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "agent": "sigma",
                    "threat_type": "PHASE_TRANSITION",
                    "url": target_config["url"],
                    "result": f"✅ Alpha reconnaissance COMPLETE ({len(endpoint_tracker.discovered)} endpoints). Releasing Sigma and Beta execution.",
                    "severity": "INFO",
                    "risk_score": 0,
                },
            }
        )

        # ═══════════════════════════════════════════════════════════════════════
        # METHOD 18+21: PRE-SCAN TECH FINGERPRINTING
        # Fingerprint the target's technology stack and WAF before dispatching
        # modules. This eliminates wrong-stack FPs and enables WAF bypass.
        # ═══════════════════════════════════════════════════════════════════════
        pre_scan_result = None
        try:
            from backend.core.tech_fingerprint import run_pre_scan

            async def _pre_scan_request(url, method="GET", headers=None):
                try:
                    record = await http_client.request(
                        method, url, headers=headers or {}, scan_id=scan_id, timeout=10,
                    )
                    return record.status, dict(record.response_headers), record.response_body
                except Exception:
                    return 0, {}, ""

            pre_scan_result = await run_pre_scan(_pre_scan_request, target_config["url"])
            fp = pre_scan_result.fingerprint
            logger.info(
                "[%s] Pre-scan fingerprint: lang=%s db=%s server=%s waf=%s",
                scan_id, fp.language, fp.database, fp.server, pre_scan_result.waf_detected,
            )
            # Broadcast fingerprint to dashboard
            await manager.broadcast({
                "type": "LIVE_ATTACK_FEED",
                "scan_id": scan_id,
                "payload": {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "agent": "planner",
                    "threat_type": "FINGERPRINT",
                    "url": target_config["url"],
                    "result": (
                        f"🔍 Tech stack: {fp.language}/{fp.framework} | DB: {fp.database} | "
                        f"Server: {fp.server} | WAF: {pre_scan_result.waf_detected}"
                    ),
                    "severity": "INFO",
                    "risk_score": 0,
                },
            })
            # Log module enablement
            if pre_scan_result.enabled_modules:
                logger.info(
                    "[%s] Enabled modules: %s | Disabled: %s",
                    scan_id, pre_scan_result.enabled_modules, pre_scan_result.disabled_modules,
                )
            for rec in pre_scan_result.recommendations:
                logger.info("[%s] Recommendation: %s", scan_id, rec)
        except Exception as _fp_err:
            logger.debug("[%s] Pre-scan fingerprint failed (non-fatal): %s", scan_id, _fp_err)

        # ═══════════════════════════════════════════════════════════════════════
        # METHOD 8: CANARY SERVER LIFECYCLE
        # Start a real HTTP canary server for OOB verification across all probe
        # modules.  Each module calls set_canary() with this instance before
        # generating payloads and clear_canary() on shutdown.
        # ═══════════════════════════════════════════════════════════════════════
        try:
            await _canary_instance.start()
            logger.info("[%s] Canary server started: %s", scan_id, _canary_instance.base_url)
            await manager.broadcast({
                "type": "LIVE_ATTACK_FEED",
                "scan_id": scan_id,
                "payload": {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "agent": "planner",
                    "threat_type": "CANARY",
                    "url": target_config["url"],
                    "result": f"🐦 Canary server online — {_canary_instance.base_url}",
                    "severity": "INFO",
                    "risk_score": 0,
                },
            })
        except Exception as _canary_err:
            logger.debug("[%s] Canary server failed to start (non-fatal): %s", scan_id, _canary_err)

        # Wire the canary into probe modules that support OOB verification
        _canary_modules = []
        try:
            from backend.modules.tech import sqli as _sqli_mod
            _sqli_mod.set_canary(_canary_instance)
            _canary_modules.append(_sqli_mod)
        except Exception:
            pass
        try:
            from backend.modules.tech import command_injection as _cmdi_mod
            _cmdi_mod.set_canary(_canary_instance)
            _canary_modules.append(_cmdi_mod)
        except Exception:
            pass
        try:
            from backend.modules.tech import lfi as _lfi_mod
            _lfi_mod.set_canary(_canary_instance)
            _canary_modules.append(_lfi_mod)
        except Exception:
            pass
        try:
            from backend.modules.logic import chronomancer as _chrono_mod
            _chrono_mod.set_canary(_canary_instance)
            _canary_modules.append(_chrono_mod)
        except Exception:
            pass
        try:
            from backend.modules.tech import auth_bypass as _ab_mod
            _ab_mod.set_canary(_canary_instance)
            _canary_modules.append(_ab_mod)
        except Exception:
            pass
        logger.info("[%s] Canary wired into %d probe modules", scan_id, len(_canary_modules))

        # [V6 REAL-TIME FIX] Dispatch selected modules concurrently!
        # Bounded-burst pacing: ~70 jobs fire across the module mapper, Sigma
        # validation and swarm loops below. Fired back-to-back they saturate
        # the CommandLane instantly → Zeta THROTTLE/RESUME oscillation. One
        # pacer spans all four loops so the lane drains between bursts.
        _dispatch_pacer = _DispatchPacer()
        module_mapper = {
            "The Tycoon": "logic_tycoon",
            "The Escalator": "logic_escalator",
            "The Skipper": "logic_skipper",
            "Doppelganger (IDOR)": "logic_doppelganger",
            "Chronomancer": "logic_chronomancer",
            "SQL Injection Probe": "tech_sqli",
            "JWT Token Cracker": "tech_jwt",
            "API Fuzzer (REST)": "tech_fuzzer",
            "Auth Bypass Tester": "tech_auth_bypass",
            "Hybrid DOM Extraction": "delta_pinch_extract",
        }

        # Bug Fix #5: Core Module Fallback Breakage
        # selected_modules was already resolved from short names to full names above.
        # If empty, dispatch all modules.
        if not selected_modules:
            selected_modules = list(module_mapper.keys())

        # FULL-SWARM ROUTING FIX: each module is owned by the agent whose
        # handler implements it. Previously EVERY module (including
        # ``delta_pinch_extract``) was hardcoded to AgentID.SIGMA — so Delta's
        # browser pipeline never received a job and the other specialized
        # agents starved. Modules default to Sigma (exploitation engine);
        # browser/DOM work is owned by Delta.
        _module_owner = {mid: AgentID.SIGMA for mid in module_mapper.values()}
        _module_owner["delta_pinch_extract"] = AgentID.DELTA

        for ui_module_name in selected_modules:
            internal_id = module_mapper.get(ui_module_name)
            if not internal_id:
                logger.debug("[Orchestrator] No internal_id for module '%s', skipping", ui_module_name)
                continue

            # Dispatch one job PER seeded target so each module attacks the real
            # vulnerable endpoints (with auth + params), not just the base URL.
            for atk in _attack_targets():
                packet = JobPacket(
                    priority=TaskPriority.HIGH,
                    target=atk,
                    config=ModuleConfig(
                        module_id=internal_id,
                        agent_id=_module_owner.get(internal_id, AgentID.SIGMA),
                        params={
                            "concurrency": target_config.get("concurrency", 50),
                            "rps": target_config.get("rps", 100),
                        },
                    ),
                )
                await _dispatch_pacer.wait()
                await bus.publish(
                    HiveEvent(
                        type=EventType.JOB_ASSIGNED, source="VIGILAGENT", scan_id=scan_id, payload=packet.model_dump()
                    )
                )

        # ═══════════════════════════════════════════════════════════════════════
        # RECON→SIGMA FINDINGS FEED (Architecture §5.1.1 handoff):
        # Sigma's 5 exclusive CLI tools (nuclei/httpx/dalfox/whatweb/wafw00f)
        # were wired in _technique_tool_map but NEVER dispatched — the module
        # mapper only ever emits tech_sqli/logic_*/etc ids. Dispatch the
        # Sigma-owned validation modules now, against the AUTHENTICATED seeded
        # targets, so recon findings + the seeder session reach the CLI
        # validators (which now forward the Cookie header). This is what makes
        # nuclei/dalfox actually find things on login-gated labs like DVWA.
        for _sigtool_target in _attack_targets():
            for _vmod in ("recon_nuclei", "tech_fingerprint", "tech_xss"):
                try:
                    _vp = JobPacket(
                        priority=TaskPriority.NORMAL,
                        target=_sigtool_target,
                        config=ModuleConfig(
                            module_id=_vmod,
                            agent_id=AgentID.SIGMA,
                            params={"concurrency": 15, "rps": 150},
                        ),
                    )
                    await _dispatch_pacer.wait()
                    await bus.publish(
                        HiveEvent(
                            type=EventType.JOB_ASSIGNED,
                            source="VIGILAGENT",
                            scan_id=scan_id,
                            payload=_vp.model_dump(),
                        )
                    )
                    logger.info("[%s] Dispatched Sigma validation module %s -> %s", scan_id, _vmod, _sigtool_target.url)
                except Exception as _vd_exc:
                    logger.warning("[%s] Sigma validation dispatch failed (%s): %s", scan_id, _vmod, _vd_exc)

        # [V6 REAL-TIME FIX] Always force an AI Generative Assault payload to feed BetaAgent
        ai_packet = JobPacket(
            priority=TaskPriority.NORMAL,
            target=TaskTarget(url=target_config["url"]),
            config=ModuleConfig(
                module_id="sigma_generative_blast",
                agent_id=AgentID.SIGMA,
                params={"concurrency": target_config.get("concurrency", 50), "rps": target_config.get("rps", 100)},
            ),
        )

        await _dispatch_pacer.wait()
        await bus.publish(
            HiveEvent(type=EventType.JOB_ASSIGNED, source="VIGILAGENT", scan_id=scan_id, payload=ai_packet.model_dump())
        )

        # [V6 REAL-TIME FIX] Also dispatch direct Beta assault jobs (one per
        # seeded target) so Beta's polyglot/bandit pipeline hits the real
        # authenticated vulnerable endpoints.
        for atk in _attack_targets():
            beta_assault_packet = JobPacket(
                priority=TaskPriority.HIGH,
                target=atk,
                config=ModuleConfig(module_id="beta_direct_assault", agent_id=AgentID.BETA, aggression=8),
            )
            await _dispatch_pacer.wait()
            await bus.publish(
                HiveEvent(
                    type=EventType.JOB_ASSIGNED,
                    source="VIGILAGENT",
                    scan_id=scan_id,
                    payload=beta_assault_packet.model_dump(),
                )
            )

        # ═══════════════════════════════════════════════════════════════════════
        # FULL-SWARM DISPATCH — every agent gets assigned work.
        # All 13 agents previously came online but only Sigma/Beta (and the
        # event-driven Omega/Zeta/Network/Planner) ever received jobs — Prism,
        # Chi, Gamma, Lambda and Kappa sat idle after their AGENT_ACTIVATED
        # broadcast. Fetch one page snapshot per seeded target and hand each
        # agent the payload its handler actually consumes so the whole swarm
        # participates in the pentest.
        # ═══════════════════════════════════════════════════════════════════════
        _snapshots: dict[str, dict[str, Any]] = {}
        try:
            for _atk in _attack_targets():
                _u = _atk.url
                if _u in _snapshots:
                    continue
                try:
                    _rec = await http_client.request(
                        "GET", _u, headers=dict(_atk.headers or {}), scan_id=scan_id, timeout=10
                    )
                    _snapshots[_u] = {
                        "text": str(getattr(_rec, "response_body", "") or "")[:20000],
                        "headers": dict(getattr(_rec, "response_headers", {}) or {}),
                        "status": int(getattr(_rec, "status", 0) or 0),
                    }
                except Exception:
                    _snapshots[_u] = {"text": "", "headers": {}, "status": 0}
        except Exception:
            pass

        for _atk in _attack_targets():
            _snap = _snapshots.get(_atk.url, {"text": "", "headers": {}, "status": 0})
            _base_headers = dict(_atk.headers or {})
            _swarm_jobs = [
                # Prism: DOM safety analysis (expects target.payload = DOM snapshot).
                (
                    "prism_dom_analysis",
                    AgentID.PRISM,
                    {"innerText": _snap["text"], "style": {}, "url": _atk.url},
                ),
                # Chi: traffic interception + token extraction (expects
                # target.payload = intercepted request/response event data).
                (
                    "chi_intercept",
                    AgentID.CHI,
                    {"method": "GET", "url": _atk.url, "headers": _snap["headers"], "body": _snap["text"]},
                ),
                # Gamma: forensic audit of the seeded target.
                ("vulnerability_audit", AgentID.GAMMA, {"url": _atk.url, "evidence": _snap["text"][:5000]}),
                # Lambda: SAST on JS assets discovered during recon.
                (
                    "lambda_js_sast",
                    AgentID.LAMBDA,
                    {"js_urls": [u for u in endpoint_tracker.discovered if ".js" in u.lower()][:10] or [_atk.url]},
                ),
                # Kappa: tactic recall to arm the swarm with memory.
                ("kappa_recall", AgentID.KAPPA, {"query": f"Exploit strategy for {_atk.url}"}),
            ]
            for _module_id, _agent_id, _job_payload in _swarm_jobs:
                try:
                    _sp = JobPacket(
                        priority=TaskPriority.NORMAL,
                        target=TaskTarget(url=_atk.url, headers=_base_headers, payload=_job_payload),
                        config=ModuleConfig(module_id=_module_id, agent_id=_agent_id, params=_job_payload),
                    )
                    await _dispatch_pacer.wait()
                    await bus.publish(
                        HiveEvent(
                            type=EventType.JOB_ASSIGNED,
                            source="VIGILAGENT",
                            scan_id=scan_id,
                            payload=_sp.model_dump(),
                        )
                    )
                    logger.info("[%s] Dispatched %s -> %s", scan_id, _module_id, _atk.url)
                except Exception as _sw_exc:
                    logger.warning("[%s] Swarm dispatch %s failed: %s", scan_id, _module_id, _sw_exc)

        await manager.broadcast({"type": "GI5_LOG", "payload": "HYPER-MIND ONLINE. Parallel Overdrive Active."})

        # ═══════════════════════════════════════════════════════════════════════
        # V6 LIFECYCLE: Start Exploitation Phase
        # ═══════════════════════════════════════════════════════════════════════
        await phase_gate.advance_to(ScanPhase.EXPLOITATION)
        await manager.broadcast(
            {
                "type": "PHASE_COMPLETED",
                "scan_id": scan_id,
                "payload": {"phase": "ASSESSMENT", "timestamp": datetime.now().strftime("%H:%M:%S")},
            }
        )
        await manager.broadcast(
            {
                "type": "PHASE_STARTED",
                "scan_id": scan_id,
                "payload": {"phase": "EXPLOITATION", "timestamp": datetime.now().strftime("%H:%M:%S")},
            }
        )
        logger.info(f"[{scan_id}] Phase transition: ASSESSMENT → EXPLOITATION")
        # ═══════════════════════════════════════════════════════════════════════

        # --- PHASE 3: ATTACK EXECUTION ---
        await manager.broadcast(
            {
                "type": "LIVE_ATTACK_FEED",
                "scan_id": scan_id,
                "payload": {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "agent": "sigma",
                    "threat_type": "PHASE_TRANSITION",
                    "url": target_config["url"],
                    "result": "🚀 All agents active — Entering Attack Execution Phase",
                    "severity": "MEDIUM",
                    "risk_score": 30,
                },
            }
        )

        # 6. Run Duration (Custom duration from config or default)
        duration_val = target_config.get("duration")
        scan_duration = int(duration_val) if duration_val is not None else settings.SCAN_TIMEOUT
        scan_duration = max(scan_duration, 1)  # Ensure at least 1s
        try:
            # [TEST HARNESS COMPLIANCE: TC010]
            # Replace long sleep with frequent status broadcasts to ensure late-connecting
            # test clients receive the expected SCAN_UPDATE and LIVE_ATTACK_FEED events.
            loop_start = time.time()
            broadcast_interval = 2.0

            # Early-stop rule: when the scan has confirmed a healthy number of
            # findings AND has gone quiet (no new VULN_CONFIRMED signal for the
            # idle window), end the exploitation phase instead of burning the
            # full SCAN_TIMEOUT. Preserves full-length scans on slow/quiet
            # targets; turns DVWA-class scans from ~1h into minutes.
            _early_stop_min_findings = int(getattr(settings, "SCAN_EARLY_STOP_MIN_FINDINGS", 5) or 5)
            _early_stop_idle = float(getattr(settings, "SCAN_EARLY_STOP_IDLE_SECONDS", 45) or 45)
            _early_stop_min_elapsed = float(getattr(settings, "SCAN_EARLY_STOP_MIN_ELAPSED", 90) or 90)
            _last_finding_ts = loop_start
            _last_finding_count = 0

            _monitor_agents = [
                "planner",
                "alpha",
                "beta",
                "sigma",
                "gamma",
                "omega",
                "kappa",
                "zeta",
                "prism",
                "chi",
                "delta",
                "lambda",
                "network",
            ]
            try:
                from backend.core.metrics import metrics as _m

                _m.scans_started_total.inc()
                _m.scans_active.inc()
            except Exception:
                pass
            while time.time() - loop_start < scan_duration:
                _mon_idx = int((time.time() - loop_start) / broadcast_interval) % len(_monitor_agents)
                _cur_mon = _monitor_agents[_mon_idx]

                # ── Early-stop check ────────────────────────────────────────
                # Only fires when findings have stopped growing: a scan that is
                # still producing signal keeps running exactly as before.
                _cur_findings = len(endpoint_tracker.vulnerable)
                _elapsed = time.time() - loop_start
                _coverage_pct = endpoint_tracker.get_metrics().get("coverage_percent", 0.0)
                if _cur_findings != _last_finding_count:
                    _last_finding_count = _cur_findings
                    _last_finding_ts = time.time()
                _idle_too_long = time.time() - _last_finding_ts >= _early_stop_idle
                _min_elapsed = _elapsed >= _early_stop_min_elapsed
                _enough_findings = _cur_findings >= _early_stop_min_findings
                _high_coverage = _coverage_pct >= 98.0
                _should_stop = False
                _stop_reason = ""
                if _min_elapsed and _idle_too_long:
                    if _enough_findings:
                        _should_stop = True
                        _stop_reason = (
                            f"{_cur_findings} findings, no new signal for "
                            f"{int(_early_stop_idle)}s"
                        )
                    elif _high_coverage:
                        _should_stop = True
                        _stop_reason = (
                            f"{_cur_findings} findings, coverage {_coverage_pct:.0f}%, "
                            f"no new signal for {int(_early_stop_idle)}s"
                        )
                if _should_stop:
                    logger.info(
                        "[%s] Early-stop: %s (min elapsed %.0fs). "
                        "Ending exploitation phase.",
                        scan_id, _stop_reason, _early_stop_min_elapsed,
                    )
                    await manager.broadcast(
                        {
                            "type": "LIVE_ATTACK_FEED",
                            "scan_id": scan_id,
                            "payload": {
                                "timestamp": datetime.now().strftime("%H:%M:%S"),
                                "agent": "zeta",
                                "threat_type": "EARLY_STOP",
                                "url": target_config["url"],
                                "result": (
                                    f"\u26a1 Early stop: {_stop_reason}"
                                ),
                                "severity": "INFO",
                                "risk_score": 0,
                            },
                        }
                    )
                    break
                # ────────────────────────────────────────────────────────────

                # Use broadcast_immediate to ensure events hit the listener
                await manager.broadcast_immediate(
                    {
                        "type": "SCAN_UPDATE",
                        "payload": {"id": scan_id, "status": "Running", "target_url": target_config["url"]},
                    }
                )
                await manager.broadcast_immediate(
                    {
                        "type": "LIVE_ATTACK_FEED",
                        "scan_id": scan_id,
                        "payload": {
                            "timestamp": datetime.now().strftime("%H:%M:%S"),
                            "agent": _cur_mon,
                            "threat_type": "MONITORING",
                            "url": target_config["url"],
                            "result": f"Scan in progress - {_cur_mon.upper()} active...",
                            "severity": "INFO",
                            "risk_score": 0,
                        },
                    }
                )
                await asyncio.sleep(broadcast_interval)
        except asyncio.CancelledError:
            try:
                from backend.core.metrics import metrics as _m

                _m.scans_failed_total.inc()
                _m.scans_active.dec()
            except Exception:
                pass
            pass
        finally:
            # ═══════════════════════════════════════════════════════════════════════
            # V6 LIFECYCLE: Complete Exploitation, Start Reporting
            # ═══════════════════════════════════════════════════════════════════════
            await phase_gate.advance_to(ScanPhase.REPORTING)
            await manager.broadcast(
                {
                    "type": "PHASE_COMPLETED",
                    "scan_id": scan_id,
                    "payload": {
                        "phase": "EXPLOITATION",
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "endpoints_tested": len(endpoint_tracker.tested),
                        "vulnerabilities_found": len(endpoint_tracker.vulnerable),
                    },
                }
            )
            await manager.broadcast(
                {
                    "type": "PHASE_STARTED",
                    "scan_id": scan_id,
                    "payload": {"phase": "REPORTING", "timestamp": datetime.now().strftime("%H:%M:%S")},
                }
            )

            # Get final coverage metrics
            coverage_metrics = endpoint_tracker.get_metrics()
            endpoint_tracker.get_telemetry()

            logger.info(f"[{scan_id}] Phase transition: EXPLOITATION → REPORTING")
            logger.info(f"[{scan_id}] Coverage: {coverage_metrics['coverage_percent']}%")
            logger.info(
                f"[{scan_id}] Endpoints: {coverage_metrics['endpoints_discovered']} discovered, {coverage_metrics['endpoints_tested']} tested"
            )
            logger.info(f"[{scan_id}] Vulnerabilities: {coverage_metrics['endpoints_vulnerable']} endpoints vulnerable")

            # Broadcast final coverage
            await manager.broadcast({"type": "COVERAGE_UPDATE", "scan_id": scan_id, "payload": coverage_metrics})

            # Warn if coverage is incomplete
            if not endpoint_tracker.is_complete(threshold=95.0):
                untested = endpoint_tracker.get_untested_sample(limit=5)
                logger.warning(
                    f"[{scan_id}] Incomplete coverage: {coverage_metrics['coverage_percent']}% "
                    f"({coverage_metrics['untested_count']} endpoints untested)"
                )
                logger.warning(f"[{scan_id}] Sample untested endpoints: {untested}")
                await manager.broadcast(
                    {
                        "type": "LIVE_ATTACK_FEED",
                        "scan_id": scan_id,
                        "payload": {
                            "timestamp": datetime.now().strftime("%H:%M:%S"),
                            "agent": "zeta",
                            "threat_type": "WARNING",
                            "url": target_config["url"],
                            "result": f"⚠️ Coverage: {coverage_metrics['coverage_percent']}% ({coverage_metrics['untested_count']} endpoints untested)",
                            "severity": "MEDIUM",
                            "risk_score": 40,
                        },
                    }
                )
            else:
                logger.info(f"[{scan_id}] ✅ Complete coverage achieved: {coverage_metrics['coverage_percent']}%")
                await manager.broadcast(
                    {
                        "type": "LIVE_ATTACK_FEED",
                        "scan_id": scan_id,
                        "payload": {
                            "timestamp": datetime.now().strftime("%H:%M:%S"),
                            "agent": "gamma",
                            "threat_type": "SUCCESS",
                            "url": target_config["url"],
                            "result": f"✅ Complete coverage: {coverage_metrics['coverage_percent']}%",
                            "severity": "INFO",
                            "risk_score": 0,
                        },
                    }
                )
            # ═══════════════════════════════════════════════════════════════════════

            await manager.broadcast({"type": "GI5_LOG", "payload": "Hyper-Mind: Mission Complete. Shutting down."})
            # Pop from per-scan registry BEFORE stopping agents to prevent
            # the zombie sweep from racing with the shutdown loop.
            async with HiveOrchestrator._get_lock():
                HiveOrchestrator._scan_agents.pop(scan_id, None)
            for agent in agents:
                agent_name = getattr(agent, "name", type(agent).__name__)
                try:
                    await asyncio.wait_for(agent.stop(), timeout=5.0)
                except Exception as e:
                    logger.error(f"Failed to stop agent {agent_name}: {e}")

            # --- V6 GRACE PERIOD ---
            await asyncio.sleep(1.0)

            # --- SHUTDOWN CORTEX ENSURING SOCKET RELEASE ---
            try:
                await asyncio.wait_for(ai_cortex.shutdown(), timeout=15.0)
            except asyncio.TimeoutError:
                logger.warning("[%s] Cortex shutdown timed out, forcing", scan_id)

            # --- AWAIT CAPTURED ORPHAN TASKS ---
            if HiveOrchestrator._orphaned_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*HiveOrchestrator._orphaned_tasks, return_exceptions=True),
                        timeout=30.0,
                    )
                except asyncio.TimeoutError:
                    logger.warning("[%s] Orphaned tasks did not complete in 30s, proceeding to report", scan_id)
                HiveOrchestrator._orphaned_tasks.clear()

            # --- METHOD 8: STOP CANARY SERVER & CLEAR MODULE STATE ---
            try:
                await _canary_instance.stop()
            except Exception:
                pass
            for _mod in _canary_modules:
                try:
                    _mod.clear_canary()
                except Exception:
                    pass
            logger.info("[%s] Canary server stopped, module state cleared", scan_id)

            # --- SCAN ISOLATION: UNSUBSCRIBE LISTENERS ---
            for etype in EventType:
                bus.unsubscribe(etype, event_listener)

            # Surgically remove this scan's agents from the global registry
            # (CRIT-04: protected by lock).  NOTE: We do NOT use
            # active_agents.clear() because concurrent scans may share it.
            # _scan_agents[scan_id] was already popped above before the stop
            # loop to prevent racing with the zombie sweep.
            _this_scan_names = {getattr(a, "name", None) for a in agents if getattr(a, "name", None)}
            async with HiveOrchestrator._get_lock():
                for name in list(HiveOrchestrator.active_agents):
                    if name in _this_scan_names:
                        HiveOrchestrator.active_agents.pop(name, None)
            logger.info(f"[Orchestrator] Scan {scan_id} Cleaned Up. Listeners detached.")

            # --- GENERATE GOD MODE REPORT ---
            try:
                items_found = [e for e in scan_events if e.get("type") in (EventType.VULN_CONFIRMED, "VULN_CONFIRMED")]
                stats_db_manager.complete_scan(scan_id, items_found, scan_duration)
                await manager.broadcast({"type": "SCAN_UPDATE", "payload": {"id": scan_id, "status": "Finalizing"}})
            except Exception as e:
                logger.error(f"Failed to record complete_scan (Finalizing): {e}")

            # --- FINAL MEMORY PURGE (Hard-Zero Gap Fix) ---
            try:
                await bus.evict_scan_context(scan_id)
            except Exception as _evict_err:
                logger.warning("[%s] Scan context eviction skipped: %s", scan_id, _evict_err)

            try:

                async def generate_and_mark_ready():
                    try:
                        report_gen = ReportGenerator()
                        logger.info(f"[Orchestrator] Starting AI report generation for scan {scan_id}...")

                        end_time = datetime.now()
                        requested_concurrency = target_config.get("velocity", len(agents))

                        # Get REAL AI telemetry from CortexEngine
                        cortex_telemetry = ai_cortex.get_telemetry()
                        real_ai_calls = cortex_telemetry.get("llm_calls", 0)
                        real_avg_latency = cortex_telemetry.get("avg_llm_latency", 0.0)
                        real_cb_trips = cortex_telemetry.get("circuit_breaker_trips", 0)

                        total_attack_events = sum(
                            1 for e in scan_events if e.get("type") in (EventType.LIVE_ATTACK, "LIVE_ATTACK")
                        )
                        avg_request_latency = round((scan_duration / max(total_attack_events, 1)) * 1000, 1)

                        scan_elapsed = time.time() - loop_start

                        # V6 LIFECYCLE: Include phase gate and coverage telemetry
                        phase_telemetry = phase_gate.get_telemetry()
                        coverage_telemetry = endpoint_tracker.get_telemetry()

                        telemetry = {
                            "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                            "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S"),
                            "duration": f"{scan_elapsed:.0f}s",
                            "total_requests": len(scan_events),
                            "avg_latency_ms": avg_request_latency,
                            "peak_concurrency": requested_concurrency,
                            "ai_calls": real_ai_calls,
                            "llm_avg_latency": f"{real_avg_latency:.1f}" if real_avg_latency else "N/A",
                            "circuit_breaker_activations": real_cb_trips,
                            # V6 Lifecycle metrics
                            "phase_durations": phase_telemetry.get("phase_durations", {}),
                            "phases_completed": phase_telemetry.get("phases_completed", []),
                            "endpoints_discovered": coverage_telemetry.get("endpoints_discovered", 0),
                            "endpoints_tested": coverage_telemetry.get("endpoints_tested", 0),
                            "endpoints_vulnerable": coverage_telemetry.get("endpoints_vulnerable", 0),
                            "coverage_percent": coverage_telemetry.get("coverage_percent", 0.0),
                            "vulnerability_rate": coverage_telemetry.get("vulnerability_rate_percent", 0.0),
                        }

                        # Finalize scan lifecycle
                        await lifecycle.finalize(ai_cortex=ai_cortex)

                        await asyncio.wait_for(
                            report_gen.generate_report(
                                scan_id, scan_events, target_config["url"], telemetry=telemetry, manager=manager
                            ),
                            timeout=900.0,
                        )

                        # [V7] ADAPTIVE FINALIZATION DELAY
                        # Cooldown scales with request volume: 2s base + 1s per 5000 requests (Cap 10s)
                        total_reqs = telemetry.get("total_requests", 0)

                        # [ATOMIC SYNC: V6] Mark READY and COMPLETED in one atomic operation
                        adaptive_delay = min(2.0 + (total_reqs / 5000.0), 10.0)

                        # [ATOMIC SYNC: V6] Mark READY and COMPLETED in one atomic operation
                        # We do this BEFORE the delay to ensure UI activation is instant
                        stats_db_manager.sync_complete_scan(scan_id, status="Completed", report_ready=True)

                        # ═══════════════════════════════════════════════════════════════════════
                        # V6 LIFECYCLE: Complete Reporting Phase - Scan COMPLETED
                        # ═══════════════════════════════════════════════════════════════════════
                        await phase_gate.advance_to(ScanPhase.COMPLETED)
                        await manager.broadcast(
                            {
                                "type": "PHASE_COMPLETED",
                                "scan_id": scan_id,
                                "payload": {"phase": "REPORTING", "timestamp": datetime.now().strftime("%H:%M:%S")},
                            }
                        )
                        await manager.broadcast(
                            {
                                "type": "PHASE_STARTED",
                                "scan_id": scan_id,
                                "payload": {
                                    "phase": "COMPLETED",
                                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                                    "total_duration": f"{scan_elapsed:.1f}s",
                                    "coverage": f"{coverage_telemetry.get('coverage_percent', 0):.1f}%",
                                },
                            }
                        )
                        logger.info(f"[{scan_id}] Phase transition: REPORTING → COMPLETED")
                        logger.info(f"[{scan_id}] ✅ Scan lifecycle complete!")
                        # ═══════════════════════════════════════════════════════════════════════

                        # ═══════════════════════════════════════════════════════════════════════
                        # CONTINUOUS LEARNING: Analyze completed scan
                        # ═══════════════════════════════════════════════════════════════════════
                        try:
                            from backend.core.learning_engine import learning_engine

                            await learning_engine.analyze_scan_complete(scan_id)
                            metrics = learning_engine.get_metrics()
                            logger.info(
                                f"[{scan_id}] Learning complete: "
                                f"{metrics['total_patterns']} patterns "
                                f"({metrics['high_confidence_patterns']} high-confidence)"
                            )
                        except Exception as le:
                            logger.warning(f"[{scan_id}] Learning analysis failed: {le}")

                        # PER-SCAN LEARNING LOOP (Architecture §13.3): collect
                        # outcomes, update tool/agent reliability, create/promote
                        # skills, store a learning update.
                        try:
                            from backend.skills.learning_loop import ScanOutcome, per_scan_learning_loop

                            findings = [
                                e.get("payload", {})
                                for e in scan_events
                                if e.get("type") in (EventType.VULN_CONFIRMED, "VULN_CONFIRMED")
                            ]
                            outcome = ScanOutcome(scan_id=scan_id, findings=findings)
                            lo = await per_scan_learning_loop.run(outcome)
                            logger.info(
                                f"[{scan_id}] Per-scan learning: {len(lo.new_candidate_skills)} new skills, "
                                f"{len(lo.promoted)} promoted"
                            )
                        except Exception as le:
                            logger.warning(f"[{scan_id}] Per-scan learning loop failed: {le}")
                        # ═══════════════════════════════════════════════════════════════════════

                        # Emit a terminating LIVE_ATTACK_FEED event to flush the pipeline
                        await manager.broadcast(
                            {
                                "type": "LIVE_ATTACK_FEED",
                                "scan_id": scan_id,
                                "payload": {
                                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                                    "agent": "sigma",
                                    "threat_type": "TERMINATION",
                                    "url": "LOCAL_HIVE",
                                    "result": "Scan Lifecycle Completed",
                                    "severity": "INFO",
                                    "risk_score": 0,
                                },
                            }
                        )
                        await manager.broadcast({"type": "REPORT_READY", "payload": {"id": scan_id}})
                        await manager.broadcast(
                            {"type": "SCAN_UPDATE", "payload": {"id": scan_id, "status": "Completed"}}
                        )

                        logger.info(f"[Orchestrator] Report Generated. AI Report for {scan_id} is now READY.")
                        logger.info(
                            f"[Orchestrator] Entering adaptive cooldown for {adaptive_delay:.1f}s before final release..."
                        )
                        await asyncio.sleep(adaptive_delay)

                    except TimeoutError:
                        logger.warning(f"[Orchestrator] Report generation TIMED OUT for {scan_id}. Force completing.")
                        # Fallback to ensure scan isn't stuck in 'Finalizing'
                        stats_db_manager.sync_complete_scan(scan_id, status="Completed", report_ready=True)
                        await manager.broadcast(
                            {
                                "type": "LIVE_ATTACK_FEED",
                                "scan_id": scan_id,
                                "payload": {"agent": "sigma", "threat_type": "TERMINATION", "result": "Timeout"},
                            }
                        )
                        await manager.broadcast({"type": "REPORT_READY", "payload": {"id": scan_id}})
                        await manager.broadcast(
                            {"type": "SCAN_UPDATE", "payload": {"id": scan_id, "status": "Completed"}}
                        )

                    except Exception as ge:
                        logger.error(f"[Orchestrator] Background Report Async Task Error: {ge}")
                        # Even if report failed, we MUST mark the scan as completed to release the UI
                        stats_db_manager.sync_complete_scan(scan_id, status="Completed", report_ready=True)
                        await manager.broadcast({"type": "REPORT_READY", "payload": {"id": scan_id}})
                        await manager.broadcast(
                            {"type": "SCAN_UPDATE", "payload": {"id": scan_id, "status": "Completed"}}
                        )
                        try:
                            from backend.core.metrics import metrics as _m

                            _m.scans_completed_total.inc()
                            _m.scans_active.dec()
                        except Exception:
                            pass

                        for s in stats_db_manager._stats["scans"]:
                            if s["id"] == scan_id:
                                s["status"] = "Completed"
                                break

                        stats_db_manager.flush_immediate()
                        logger.error("[Orchestrator] Report generation failed", exc_info=True)

                task = asyncio.create_task(generate_and_mark_ready())
                HiveOrchestrator._orphaned_tasks.add(task)
                task.add_done_callback(HiveOrchestrator._orphaned_tasks.discard)
                task.add_done_callback(lambda t: _log_task_error(t, "report_gen", scan_id))

                await manager.broadcast(
                    {"type": "GI5_LOG", "payload": f"FORENSIC REPORT GENERATION INITIATED FOR {scan_id}"}
                )
            except Exception as e:
                logger.error(f"Report Background Gen Trigger Failed: {e}")

            await manager.broadcast(
                {"type": "GI5_LOG", "payload": f"SCAN FINISHED. AI FINALIZING FORENSIC DATA FOR {scan_id}..."}
            )

    @staticmethod
    async def _zombie_agent_sweep():
        """Periodic sweep that detects and stops agents whose scans are no longer active.

        Runs every 30 seconds. For each scan_id in _scan_agents whose database
        status is not in (Running, Initializing, Finalizing), the agents are
        stopped and removed from the registry.

        Emits ZOMBIE_SWEEP_RESULT WebSocket events so the frontend can display
        cleanup notifications.

        Also performs per-scan agent health checks: if an agent's asyncio task
        is done (finished/cancelled/crashed) but the scan is still running,
        the agent is restarted via its restart callback.
        """
        import asyncio as _aio

        from backend.core.recovery_engine import healing_engine  # hoisted above loop — cached by sys.modules anyway

        while True:
            try:
                await _aio.sleep(30)
                # Snapshot active scan statuses from the database
                try:
                    stats = stats_db_manager.get_stats()
                    active_statuses = {
                        s["id"]
                        for s in stats.get("scans", [])
                        if s.get("status") in ("Running", "Initializing", "Finalizing")
                    }
                except Exception:
                    active_statuses = set()

                # --- PART 1: Stop agents for inactive scans ---
                async with HiveOrchestrator._get_lock():
                    orphans = [sid for sid in list(HiveOrchestrator._scan_agents) if sid not in active_statuses]

                for scan_id in orphans:
                    async with HiveOrchestrator._get_lock():
                        scan_agents = HiveOrchestrator._scan_agents.pop(scan_id, {})
                    if not scan_agents:
                        continue
                    stopped = []
                    failed = []
                    logger.warning(
                        "[ZombieSweep] Stopping %d orphaned agents for inactive scan %s", len(scan_agents), scan_id
                    )
                    for name, agent in scan_agents.items():
                        try:
                            if hasattr(agent, "stop"):
                                await _aio.wait_for(agent.stop(), timeout=5.0)
                            stopped.append(name)
                            # Remove from global registry
                            async with HiveOrchestrator._get_lock():
                                HiveOrchestrator.active_agents.pop(name, None)
                        except Exception as e:
                            failed.append(f"{name}: {e}")
                            logger.warning("[ZombieSweep] Failed to stop %s: %s", name, e)
                    # Broadcast cleanup result to frontend
                    await manager.broadcast(
                        {
                            "type": "ZOMBIE_SWEEP_RESULT",
                            "payload": {
                                "scan_id": scan_id,
                                "stopped_agents": stopped,
                                "failed_agents": failed,
                                "timestamp": datetime.now().strftime("%H:%M:%S"),
                            },
                        }
                    )

                # --- PART 2: Per-scan agent health check (active scans only) ---
                # Agents now store self._task in BaseAgent.start(), so the
                # check below can detect crashed tasks and trigger auto-restart.
                # healing_engine is imported once above the while loop.
                async with HiveOrchestrator._get_lock():
                    active_scan_agents = {
                        sid: dict(agents)
                        for sid, agents in HiveOrchestrator._scan_agents.items()
                        if sid in active_statuses
                    }

                for scan_id, scan_agents in active_scan_agents.items():
                    for name, agent in scan_agents.items():
                        # Check if the agent's asyncio task crashed
                        # Agents may store their task in _task or _background_task
                        task = (
                            getattr(agent, "_task", None)
                            or getattr(agent, "_background_task", None)
                            or getattr(agent, "_running_task", None)
                        )
                        if task is not None and task.done():
                            exc = task.exception() if not task.cancelled() else None
                            if exc:
                                logger.warning(
                                    "[ZombieSweep] Agent %s task crashed for scan %s: %s", name, scan_id, exc
                                )
                                # Attempt restart via self-healing callback
                                try:
                                    callback = healing_engine.restart_callbacks.get(name)
                                    if callback:
                                        await _aio.wait_for(callback(), timeout=10.0)
                                        logger.info("[ZombieSweep] Restarted %s for scan %s", name, scan_id)
                                        await manager.broadcast(
                                            {
                                                "type": "ZOMBIE_SWEEP_RESULT",
                                                "payload": {
                                                    "scan_id": scan_id,
                                                    "restarted_agent": name,
                                                    "reason": "task_crash",
                                                    "error": str(exc)[:200],
                                                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                                                },
                                            }
                                        )
                                except Exception as restart_err:
                                    logger.error("[ZombieSweep] Failed to restart %s: %s", name, restart_err)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[ZombieSweep] Sweep error: {e}")

    @staticmethod
    async def _cluster_telemetry_loop(redis_url: str, scan_id: str):
        """Syncs distributed cluster metrics to the UI Dashboard.

        HIGH-10: Uses ``redis.asyncio`` (non-blocking) instead of the
        synchronous ``redis`` client which blocked the event loop on every
        iteration.
        """
        from backend.core.redis_client import get_redis_client

        r = None
        try:
            _rc = await get_redis_client()
            r = _rc.client
            if r is None:
                logger.warning("[ClusterTelemetry] Redis client unavailable, telemetry loop will retry")
            while True:
                if r is None:
                    try:
                        _rc = await get_redis_client()
                        r = _rc.client
                    except Exception:
                        await asyncio.sleep(5)
                        continue
                    if r is None:
                        await asyncio.sleep(5)
                        continue
                # 1. Gather Metrics (async — no event-loop blocking)
                worker_data = await r.hgetall("workers")
                worker_count = len(worker_data)
                queue_depth = await r.llen("pending_tasks")
                audit_depth = await r.llen("xytherion_audit_queue")

                # 2. Broadcast to UI
                await manager.broadcast(
                    {
                        "type": "CLUSTER_TELEMETRY",
                        "payload": {
                            "scan_id": scan_id,
                            "workers_active": worker_count,
                            "queue_depth": queue_depth,
                            "audit_depth": audit_depth,
                            "timestamp": datetime.now().strftime("%H:%M:%S"),
                        },
                    }
                )

                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning(f"Cluster Telemetry loop failure: {e}")
        finally:
            # Don't close r — it's the centralized pool client; other
            # callers share the same connection pool.
            pass
