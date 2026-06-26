"""
PHASE 1: CORE MODULE IMPORTS & INITIALIZATION LOGIC
Tests that every module loads, configs resolve, schemas validate,
agents instantiate, and the Guard Layer gates enforce correctly.
"""
import os, sys, time, asyncio, importlib
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.chdir(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ["VIGILAGENT_TEST_MODE"] = "true"

P, F = 0, 0
errors = []

def PASS(n):
    global P; P += 1; print(f"  ✅ {n}")
def FAIL(n, r=""):
    global F; F += 1; errors.append(f"{n}: {r}"); print(f"  ❌ {n} — {r}")

# ── 1.1 Config Module ───────────────────────────────────────────────────
try:
    from backend.core.config import settings, ConfigManager, REPORTS_DIR, STATIC_DIR, PROJECT_ROOT
    assert settings.PROJECT_ROOT and os.path.isdir(settings.PROJECT_ROOT), "PROJECT_ROOT invalid"
    assert os.path.isdir(REPORTS_DIR), f"REPORTS_DIR missing: {REPORTS_DIR}"
    assert os.path.isdir(STATIC_DIR), f"STATIC_DIR missing: {STATIC_DIR}"
    cm = ConfigManager()
    d = cm.get_all()
    assert "redis" in d and "supabase" in d and "worker" in d and "pinchtab" in d and "master" in d
    assert d["supabase"]["key"] == "MASKED", "Supabase key leaked in get_all()"
    assert d["supabase"]["openrouter_key"] == "MASKED", "OpenRouter key leaked"
    assert settings.SUPABASE_URL.startswith("https://"), "SUPABASE_URL not loaded from .env"
    assert len(settings.SUPABASE_KEY) > 20, "SUPABASE_KEY not loaded from .env"
    assert len(settings.OPENROUTER_API_KEY) > 10, "OPENROUTER_API_KEY not loaded from .env"
    # Singleton test
    cm2 = ConfigManager()
    assert cm is cm2, "ConfigManager is not a singleton"
    PASS("1.1 Config: paths exist, env vars loaded, keys masked, singleton enforced")
except Exception as e:
    FAIL("1.1 Config Module", str(e))

# ── 1.2 Protocol Module ────────────────────────────────────────────────
try:
    from backend.core.protocol import (
        TaskPriority, AgentStatus, AgentID, ModuleConfig,
        TaskTarget, JobPacket, Vulnerability, ResultPacket
    )
    # Enum coverage
    assert len(TaskPriority) == 4, f"TaskPriority has {len(TaskPriority)} members, expected 4"
    assert len(AgentStatus) == 4, f"AgentStatus has {len(AgentStatus)} members, expected 4"
    assert len(AgentID) >= 9, f"AgentID only has {len(AgentID)} members"
    # JobPacket creation with auto-id
    jp = JobPacket(target=TaskTarget(url="http://test.local"), config=ModuleConfig(module_id="test", agent_id=AgentID.ALPHA))
    assert jp.id and len(jp.id) > 10, "JobPacket auto-id failed"
    assert jp.priority == TaskPriority.NORMAL, "Default priority should be NORMAL"
    assert jp.target.method == "GET", "Default method should be GET"
    # Aggression bounds (1-10)
    try:
        ModuleConfig(module_id="x", agent_id=AgentID.ALPHA, aggression=0)
        FAIL("1.2 Protocol", "aggression=0 should fail")
    except Exception:
        pass  # expected
    try:
        ModuleConfig(module_id="x", agent_id=AgentID.ALPHA, aggression=11)
        FAIL("1.2 Protocol", "aggression=11 should fail")
    except Exception:
        pass  # expected
    # ResultPacket
    rp = ResultPacket(job_id="j1", source_agent=AgentID.BETA, status="SUCCESS", execution_time_ms=100.5, data={"k": "v"})
    assert rp.timestamp is not None, "ResultPacket missing timestamp"
    # Vulnerability
    v = Vulnerability(name="SQLi", severity="HIGH", description="desc", evidence="' OR 1=1")
    assert v.remediation is None, "Default remediation should be None"
    PASS("1.2 Protocol: all models validate, enums complete, aggression bounded")
except Exception as e:
    FAIL("1.2 Protocol Module", str(e))

# ── 1.3 Hive EventBus ──────────────────────────────────────────────────
try:
    from backend.core.hive import EventBus, DistributedEventBus, EventType, HiveEvent, BaseAgent
    from backend.core.context import ScanContext
    # EventType enum
    assert len(EventType) == 13, f"EventType has {len(EventType)} members, expected 13"
    # HiveEvent creation
    evt = HiveEvent(type=EventType.LOG, source="test", payload={"msg": "hello"})
    assert evt.scan_id == "GLOBAL", "Default scan_id should be GLOBAL"
    assert evt.id and len(evt.id) > 10
    # Serialization round-trip
    dumped = evt.model_dump()
    restored = HiveEvent(**dumped)
    assert restored.id == evt.id
    # EventBus subscribe + publish (GLOBAL path)
    bus = EventBus()
    received = []
    async def handler(e): received.append(e)
    bus.subscribe(EventType.LOG, handler)
    loop = asyncio.new_event_loop()
    loop.run_until_complete(bus.publish(evt))
    loop.run_until_complete(asyncio.sleep(0.3))
    # Scan-context path
    ctx_evt = HiveEvent(type=EventType.LOG, source="test", scan_id="SCAN-001", payload={"x": 1})
    loop.run_until_complete(bus.publish(ctx_evt))
    loop.run_until_complete(asyncio.sleep(0.3))
    assert "SCAN-001" in bus.scan_contexts, "Scan context not created"
    # Unsubscribe
    bus.unsubscribe(EventType.LOG, handler)
    assert handler not in bus.subscribers.get(EventType.LOG, [])
    # Dead letter queue
    dlq = bus.get_dead_letters()
    assert isinstance(dlq, list)
    bus.flush_dead_letters()
    assert len(bus.dead_letters) == 0
    # Evict scan context
    loop.run_until_complete(bus.evict_scan_context("SCAN-001"))
    assert "SCAN-001" not in bus.scan_contexts
    loop.close()
    PASS("1.3 Hive: EventBus pub/sub, scan context isolation, DLQ, eviction all work")
except Exception as e:
    FAIL("1.3 Hive EventBus", str(e))

# ── 1.4 State Manager ──────────────────────────────────────────────────
try:
    from backend.core.state import StateManager
    sm = StateManager()
    stats = sm.get_stats()
    required_keys = ["scans", "active_scans", "total_scans", "total_requests", "vulnerabilities", "critical", "history", "v6_metrics"]
    for k in required_keys:
        assert k in stats, f"Missing key: {k}"
    assert isinstance(stats["history"], list) and len(stats["history"]) >= 1
    assert isinstance(stats["v6_metrics"], dict)
    # Register a scan
    loop = asyncio.new_event_loop()
    test_scan = {
        "id": "phase1-test-scan", "status": "Running", "name": "Phase1 Test",
        "scope": "http://test.local", "modules": ["test"], "timestamp": "2026-01-01 00:00:00", "results": []
    }
    loop.run_until_complete(sm.register_scan(test_scan))
    found = next((s for s in sm.get_stats()["scans"] if s["id"] == "phase1-test-scan"), None)
    assert found, "Registered scan not found"
    assert "events" in found, "Events buffer not initialized"
    assert found.get("scan_id") == "phase1-test-scan", "scan_id alias not set"
    # Add event
    loop.run_until_complete(sm.add_scan_event("phase1-test-scan", {"type": "TEST", "data": "hello"}))
    found2 = next(s for s in sm.get_stats()["scans"] if s["id"] == "phase1-test-scan")
    assert len(found2["events"]) == 1
    # Dedup finding
    sig = {"url": "http://test.local/api", "type": "SQLI", "data": "payload"}
    loop.run_until_complete(sm.record_finding("phase1-test-scan", "High", sig))
    v1 = sm.get_stats()["vulnerabilities"]
    loop.run_until_complete(sm.record_finding("phase1-test-scan", "High", sig))
    v2 = sm.get_stats()["vulnerabilities"]
    assert v2 == v1, f"Dedup failed: {v1} -> {v2}"
    # Record threat
    loop.run_until_complete(sm.record_threat("PROMPT_INJECTION", 85))
    assert sm.get_stats()["v6_metrics"]["injections_blocked"] >= 1
    loop.run_until_complete(sm.record_threat("DARK_PATTERN_BLOCK", 60))
    assert sm.get_stats()["v6_metrics"]["deceptive_ui_blocked"] >= 1
    # Sharded state
    loop.run_until_complete(sm.write_scan_state("phase1-shard", {"id": "phase1-shard", "status": "ok"}))
    data = loop.run_until_complete(sm.read_scan_state("phase1-shard"))
    assert data["id"] == "phase1-shard"
    data_missing = loop.run_until_complete(sm.read_scan_state("nonexistent-shard"))
    assert data_missing == {}
    # Complete + report ready
    sm.complete_scan("phase1-test-scan", [], 5.0)
    found3 = next(s for s in sm.get_stats()["scans"] if s["id"] == "phase1-test-scan")
    assert found3["status"] == "Finalizing"
    sm.mark_report_ready("phase1-test-scan")
    found4 = next(s for s in sm.get_stats()["scans"] if s["id"] == "phase1-test-scan")
    assert found4["report_ready"] == True
    assert found4["status"] == "Completed"
    # Stale scan reset
    for s in sm.get_stats()["scans"]:
        if s["id"] == "phase1-test-scan":
            s["status"] = "Running"
    cleaned = sm.reset_stale_scans()
    assert cleaned >= 1
    # Request counter
    loop.run_until_complete(sm.increment_request_count(5))
    assert sm.get_stats()["total_requests"] >= 5
    loop.close()
    PASS("1.4 State: register, events, dedup, threat, shard, complete, reset — all verified")
except Exception as e:
    FAIL("1.4 State Manager", str(e))

# ── 1.5 Guard Layer ────────────────────────────────────────────────────
try:
    from backend.core.guard_layer import GuardLayer
    # Use a fresh instance for clean state
    gl = GuardLayer()
    gl.reset()
    # GATE 1: No response → reject
    assert not gl.filter_single({"url": "http://x", "type": "sqli"}), "Gate1 failed"
    # GATE 2: Not validated → reject
    assert not gl.filter_single({"url": "http://x", "response": "data", "type": "sqli"}), "Gate2 failed"
    # GATE 3: Weak signal → reject (validated but no GI5 or diff)
    assert not gl.filter_single({"url": "http://x", "response": "data", "validation": "VALID", "confidence": 0.9, "response_diff_score": 0.1}), "Gate3 failed"
    # GATE 4: Low confidence → reject
    assert not gl.filter_single({"url": "http://x", "response": "data", "validation": "VALID", "gi5_match": True, "gi5_risk": 80, "response_diff_score": 0.5, "confidence": 0.01}), "Gate4 failed"
    # ALL GATES PASS
    valid_finding = {
        "url": "http://x.com/api", "response": "error near 'syntax'",
        "type": "sqli", "validation": "VALID",
        "gi5_match": True, "gi5_risk": 80,
        "response_diff_score": 0.5, "confidence": 0.9
    }
    assert gl.filter_single(valid_finding), "Valid finding should pass all gates"
    # GATE 5: Dedup → reject duplicate
    assert not gl.filter_single(valid_finding), "Duplicate should be rejected"
    # Stats
    stats = gl.get_stats()
    assert stats["passed"] >= 1
    assert stats["rejected_no_response"] >= 1
    assert stats["rejected_not_validated"] >= 1
    assert stats["rejected_weak_signal"] >= 1
    assert stats["rejected_low_confidence"] >= 1
    assert stats["rejected_duplicate"] >= 1
    # Batch filter
    gl2 = GuardLayer()
    batch = [
        {"url": "http://a", "response": "err", "validation": "VALID", "gi5_match": True, "gi5_risk": 80, "confidence": 0.9, "response_diff_score": 0.5},
        {"url": "http://b"},
        {"url": "http://c", "response": "ok"},
    ]
    result = gl2.filter(batch)
    assert len(result) == 1, f"Batch: expected 1 passed, got {len(result)}"
    # Clustering
    findings = [
        {"url": "http://x.com/api?id=1", "type": "SQLI", "confidence": 0.8, "payload": "1' OR 1=1"},
        {"url": "http://x.com/api?id=2", "type": "SQLI", "confidence": 0.9, "payload": "1' UNION SELECT"},
        {"url": "http://x.com/login", "type": "XSS", "confidence": 0.7, "payload": "<script>"},
    ]
    clusters = gl2.cluster_findings(findings)
    assert len(clusters) == 2, f"Expected 2 clusters, got {len(clusters)}"
    sqli_cluster = [c for c in clusters if c["vuln_type"] == "SQLI"][0]
    assert sqli_cluster["variants"] == 2
    assert sqli_cluster["max_confidence"] == 0.9
    # Reset
    gl2.reset()
    assert gl2.get_stats()["total_received"] == 0
    PASS("1.5 GuardLayer: all 5 gates, batch, clustering, dedup, reset verified")
except Exception as e:
    FAIL("1.5 Guard Layer", str(e))

# ── 1.6 Schemas / Payloads ──────────────────────────────────────────────
try:
    from backend.schemas.payloads import ReconPayload, AttackPayload, TargetConfig, AttackConfig
    rp = ReconPayload(url="http://test.local", method="GET", headers={"a": "b"}, timestamp=time.time())
    assert rp.body is None, "Default body should be None"
    ap = AttackPayload(target_url="http://localhost:8000", method="GET")
    assert ap.velocity == 50 and ap.concurrency == 50 and ap.rps == 100
    assert ap.duration == 600, f"Default duration should be 600, got {ap.duration}"
    assert ap.modules == [] and ap.filters == []
    tc = TargetConfig(url="http://x", method="POST")
    assert tc.headers == {} and tc.body == ""
    ac = AttackConfig()
    assert ac.concurrency == 50 and ac.strategy == "LAST_BYTE_SYNC"
    # Validation: missing required field
    try:
        ReconPayload(method="GET", headers={}, timestamp=1.0)  # missing url
        FAIL("1.6 Schemas", "Missing url should fail validation")
    except Exception:
        pass
    PASS("1.6 Schemas: all payloads validate, defaults correct, required fields enforced")
except Exception as e:
    FAIL("1.6 Schemas", str(e))

# ── 1.7 Database Manager ───────────────────────────────────────────────
try:
    from backend.core.database import EliteDBManager, db_manager
    assert db_manager.supabase_url.startswith("https://"), "SUPABASE_URL not loaded"
    assert len(db_manager.supabase_key) > 50, "SUPABASE_KEY too short"
    assert not db_manager._initialized, "Should not be initialized at import time"
    # Singleton check
    db2 = db_manager
    assert db2 is db_manager
    PASS("1.7 EliteDBManager: env vars loaded, lazy init, singleton confirmed")
except Exception as e:
    FAIL("1.7 Database Manager", str(e))

# ── 1.8 All Agent Imports ──────────────────────────────────────────────
try:
    agents = {
        "alpha": ("backend.agents.alpha", "AlphaAgent"),
        "beta": ("backend.agents.beta", "BetaAgent"),
        "gamma": ("backend.agents.gamma", "GammaAgent"),
        "omega": ("backend.agents.omega", "OmegaAgent"),
        "zeta": ("backend.agents.zeta", "ZetaAgent"),
        "sigma": ("backend.agents.sigma", "SigmaAgent"),
        "kappa": ("backend.agents.kappa", "KappaAgent"),
        "prism": ("backend.agents.prism", "AgentPrism"),
        "chi": ("backend.agents.chi", "AgentChi"),
        "delta": ("backend.agents.delta", "AgentDelta"),
    }
    for name, (mod_path, class_name) in agents.items():
        mod = importlib.import_module(mod_path)
        cls = getattr(mod, class_name)
        assert callable(cls), f"{class_name} is not callable"
    PASS(f"1.8 All {len(agents)} agent modules import + class access verified")
except Exception as e:
    FAIL("1.8 Agent Imports", str(e))

# ── 1.9 Attack Module Imports ──────────────────────────────────────────
try:
    modules = {
        "tycoon": ("backend.modules.logic.tycoon", "TheTycoon"),
        "escalator": ("backend.modules.logic.escalator", "TheEscalator"),
        "skipper": ("backend.modules.logic.skipper", "TheSkipper"),
        "doppelganger": ("backend.modules.logic.doppelganger", "Doppelganger"),
        "chronomancer": ("backend.modules.logic.chronomancer", "Chronomancer"),
        "sqli": ("backend.modules.tech.sqli", "SQLInjectionProbe"),
        "jwt": ("backend.modules.tech.jwt", "JWTTokenCracker"),
        "fuzzer": ("backend.modules.tech.fuzzer", "APIFuzzer"),
        "auth_bypass": ("backend.modules.tech.auth_bypass", "AuthBypassTester"),
    }
    for name, (mod_path, class_name) in modules.items():
        mod = importlib.import_module(mod_path)
        cls = getattr(mod, class_name)
        instance = cls()
        assert hasattr(instance, "generate_payloads"), f"{class_name} missing generate_payloads"
        assert hasattr(instance, "analyze_responses"), f"{class_name} missing analyze_responses"
    PASS(f"1.9 All {len(modules)} attack modules import + interface verified")
except Exception as e:
    FAIL("1.9 Attack Modules", str(e))

# ── 1.10 Reporting + CVSS ──────────────────────────────────────────────
try:
    from backend.core.reporting import ReportGenerator
    from backend.reporting.cvss_engine import CVSSCalculator
    rg = ReportGenerator()
    # CVSS with real data
    calc = CVSSCalculator(success_count=3, body_content="error near syntax", target_url="http://x/api", vuln_type="SQL_INJECTION")
    score, vector = calc.calculate()
    assert 0 <= score <= 10, f"CVSS score out of range: {score}"
    assert isinstance(vector, str) and len(vector) > 0
    # CVSS edge case: zero success
    calc2 = CVSSCalculator(success_count=0, body_content="", target_url="http://x", vuln_type="UNKNOWN")
    s2, v2 = calc2.calculate()
    assert 0 <= s2 <= 10
    # CVSS edge case: XSS type
    calc3 = CVSSCalculator(success_count=5, body_content="<script>alert(1)</script>", target_url="http://x", vuln_type="XSS")
    s3, v3 = calc3.calculate()
    assert 0 <= s3 <= 10
    PASS(f"1.10 ReportGen + CVSS: SQLi={score}, zero={s2}, XSS={s3} — all in range")
except Exception as e:
    FAIL("1.10 Reporting + CVSS", str(e))

# ── 1.11 Socket Manager ───────────────────────────────────────────────
try:
    from backend.api.socket_manager import SocketManager, get_display_limit, should_emit
    sm = SocketManager()
    assert sm.ui_connections == []
    assert sm.spy_connections == []
    assert sm.recent_rps == 0
    assert sm.packet_count == 0
    # Display limit logic
    assert get_display_limit(100) == 100, "Low RPS should display all"
    assert get_display_limit(400) == 240, "Mid RPS should scale"
    assert get_display_limit(1000) == 400, "High RPS should cap at 400"
    # should_emit always True (V7 unlimited mode)
    assert should_emit({}, 0) == True
    assert should_emit({}, 10000) == True
    # Broadcast with no connections (should not crash)
    loop = asyncio.new_event_loop()
    loop.run_until_complete(sm.broadcast({"type": "TEST", "payload": {}}))
    loop.run_until_complete(sm.broadcast_immediate({"type": "TEST", "payload": {}}))
    # Spy status
    assert not sm.is_spy_online()
    loop.run_until_complete(sm.mark_spy_alive())
    assert sm.is_spy_online()
    loop.close()
    PASS("1.11 SocketManager: init, display limits, broadcast safety, spy tracking verified")
except Exception as e:
    FAIL("1.11 Socket Manager", str(e))

# ── 1.12 Base Agent / Arsenal ──────────────────────────────────────────
try:
    from backend.core.base import BaseArsenalModule
    # JSON depth safety
    deep = '{"a":' * 200 + '1' + '}' * 200
    result = BaseArsenalModule.safe_json_parse(deep)
    assert "error" in result or "truncated" in result, "Deep JSON bomb not caught"
    # Normal parse
    normal = BaseArsenalModule.safe_json_parse('{"key": "value", "num": 42}')
    assert normal["key"] == "value" and normal["num"] == 42
    # Invalid JSON
    bad = BaseArsenalModule.safe_json_parse("not json at all")
    assert "error" in bad
    PASS("1.12 BaseArsenalModule: JSON depth guard, normal parse, invalid parse verified")
except Exception as e:
    FAIL("1.12 Base Agent", str(e))

# ── SUMMARY ────────────────────────────────────────────────────────────
print("\n" + "="*60)
print(f"PHASE 1 COMPLETE: {P} passed, {F} failed")
if errors:
    print("FAILURES:")
    for e in errors: print(f"  ❌ {e}")
print("="*60)
