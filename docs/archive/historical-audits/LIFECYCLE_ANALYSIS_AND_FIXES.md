# Agent Lifecycle Analysis & Comprehensive Fixes

**Date**: May 26, 2026  
**Status**: 🔍 Analysis Complete → 🔧 Ready for Implementation

## Current Architecture Analysis

### ✅ What's Working Well

1. **Event-Driven Architecture**: Proper pub/sub system via `EventBus`
2. **Agent Hierarchy**: All 11 agents properly defined
3. **Mission Planner**: Exists and has 3-phase strategy (RECON → ASSESSMENT → EXPLOITATION)
4. **Test Mode**: Fast-path for testing without real HTTP
5. **Watchdog**: Self-healing agent restart mechanism
6. **Lifecycle Phases**: Clear phase transitions with broadcasts

### ❌ Critical Issues Identified

#### Issue 1: Planner Not Enforced as First Agent
**Problem**: Planner is created but doesn't execute before other agents
```python
# Current: All agents start simultaneously
agents = [planner, scout, kappa, sentinel, inspector, analyst, strategist, governor, delta, sigma, breaker]
for agent in agents:
    await agent.start()  # ❌ No sequencing!
```

**Impact**: 
- No strategic planning before execution
- Agents may start attacking before reconnaissance
- No coordinated mission strategy

#### Issue 2: Alpha Recon Not Guaranteed Complete
**Problem**: Alpha timeout is optional and may be skipped
```python
if getattr(settings, "ALPHA_RECON_VIA_PLANNER", True):
    # Only waits if this setting is True
    await asyncio.wait_for(alpha_recon_complete.wait(), timeout=alpha_timeout)
```

**Impact**:
- Attack agents may start before recon finishes
- Incomplete target mapping
- Wasted attack attempts on unknown endpoints

#### Issue 3: No Strict Phase Gates
**Problem**: Agents can execute out of order
- No enforcement of Planner → Alpha → Others sequence
- Event-driven but no state machine validation
- Agents subscribe to events but don't check prerequisites

**Impact**:
- Chaotic execution order
- Duplicate work
- Inefficient resource usage

#### Issue 4: Module Selection Bypasses Lifecycle
**Problem**: Module-based agent routing skips planning
```python
if selected_modules:
    # Directly dispatches jobs without planner coordination
    for ui_module_name in selected_modules:
        await bus.publish(HiveEvent(type=EventType.JOB_ASSIGNED, ...))
```

**Impact**:
- Planner's 3-phase strategy ignored
- No intelligent chaining
- Modules run independently

#### Issue 5: Incomplete Scanning
**Problem**: No verification that all discovered endpoints are tested
- Alpha discovers endpoints
- But no tracking of "tested vs untested"
- No completion percentage
- No guarantee all endpoints get attacked

**Impact**:
- Incomplete coverage
- False sense of security
- Missed vulnerabilities

## Comprehensive Fix Strategy

### Phase 1: Enforce Strict Lifecycle Sequencing

#### Fix 1.1: Mandatory Planner Execution
```python
# NEW: Planner MUST run first and complete
planner = MissionPlanner(bus)
await planner.start()

# Wait for planner to create mission plan
planning_complete = asyncio.Event()
bus.subscribe(EventType.MISSION_PLANNED, lambda e: planning_complete.set())

await bus.publish(HiveEvent(
    type=EventType.TARGET_ACQUIRED,
    source="Orchestrator",
    scan_id=scan_id,
    payload={"url": target_config['url'], ...}
))

# BLOCK until planning completes
await asyncio.wait_for(planning_complete.wait(), timeout=30)
```

#### Fix 1.2: Guaranteed Alpha Recon Completion
```python
# NEW: Alpha ALWAYS completes before attack agents
scout = AlphaAgent(bus)
await scout.start()

# MANDATORY wait for recon
alpha_timeout = max(60, target_config.get('recon_timeout', 180))
try:
    await asyncio.wait_for(alpha_recon_complete.wait(), timeout=alpha_timeout)
except asyncio.TimeoutError:
    # Log warning but continue with partial data
    logger.warning("Alpha recon incomplete - continuing with partial data")
```

#### Fix 1.3: Phase Gate State Machine
```python
class ScanPhase(Enum):
    PLANNING = "PLANNING"
    RECONNAISSANCE = "RECONNAISSANCE"
    ASSESSMENT = "ASSESSMENT"
    EXPLOITATION = "EXPLOITATION"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"

class PhaseGate:
    def __init__(self):
        self.current_phase = ScanPhase.PLANNING
        self.phase_events = {phase: asyncio.Event() for phase in ScanPhase}
    
    async def advance_to(self, next_phase: ScanPhase):
        """Only advance if current phase is complete"""
        if self.current_phase.value < next_phase.value:
            self.current_phase = next_phase
            self.phase_events[next_phase].set()
    
    async def wait_for_phase(self, phase: ScanPhase):
        """Block until specified phase is reached"""
        await self.phase_events[phase].wait()
```

### Phase 2: Complete Endpoint Coverage Tracking

#### Fix 2.1: Endpoint Registry
```python
class EndpointTracker:
    def __init__(self):
        self.discovered = set()  # All found endpoints
        self.tested = set()      # Endpoints that were attacked
        self.vulnerable = set()  # Endpoints with confirmed vulns
    
    def add_discovered(self, url: str):
        self.discovered.add(url)
    
    def mark_tested(self, url: str):
        self.tested.add(url)
    
    def get_coverage(self) -> float:
        if not self.discovered:
            return 0.0
        return len(self.tested) / len(self.discovered) * 100
    
    def get_untested(self) -> set:
        return self.discovered - self.tested
```

#### Fix 2.2: Completeness Verification
```python
# After attack phase, verify coverage
tracker = EndpointTracker()

# ... during scan ...
# Alpha discovers: tracker.add_discovered(url)
# Beta tests: tracker.mark_tested(url)

# Before finalizing
coverage = tracker.get_coverage()
if coverage < 80:
    logger.warning(f"Only {coverage}% coverage - {len(tracker.get_untested())} endpoints untested")
    # Optionally: dispatch additional jobs for untested endpoints
```

### Phase 3: Enhanced Planner Integration

#### Fix 3.1: Planner Emits Mission Plan Event
```python
# In MissionPlanner
async def handle_new_target(self, event: HiveEvent):
    target_url = event.payload.get("url")
    
    # Create comprehensive mission plan
    mission_plan = {
        "target": target_url,
        "phases": [
            {"phase": "RECON", "agent": "Alpha", "timeout": 180},
            {"phase": "ASSESSMENT", "agents": ["Gamma", "Delta"], "timeout": 120},
            {"phase": "EXPLOITATION", "agents": ["Beta", "Sigma"], "timeout": 300}
        ],
        "modules": event.payload.get("modules", []),
        "strategy": "sequential"  # or "parallel" for certain phases
    }
    
    # Emit plan for orchestrator to execute
    await self.bus.publish(HiveEvent(
        type=EventType.MISSION_PLANNED,
        source=self.name,
        scan_id=event.scan_id,
        payload=mission_plan
    ))
```

#### Fix 3.2: Orchestrator Executes Plan
```python
# In Orchestrator
async def execute_mission_plan(plan: dict, bus, agents_map):
    for phase_spec in plan["phases"]:
        phase_name = phase_spec["phase"]
        phase_agents = phase_spec.get("agents", [phase_spec.get("agent")])
        timeout = phase_spec["timeout"]
        
        # Start phase
        await broadcast_phase_start(phase_name)
        
        # Activate agents for this phase
        phase_complete = asyncio.Event()
        for agent_name in phase_agents:
            agent = agents_map[agent_name]
            # Dispatch jobs to agent
            ...
        
        # Wait for phase completion
        await asyncio.wait_for(phase_complete.wait(), timeout=timeout)
        
        # Advance to next phase
        await broadcast_phase_complete(phase_name)
```

### Phase 4: Error Handling & Recovery

#### Fix 4.1: Phase Failure Recovery
```python
class PhaseExecutor:
    async def execute_phase(self, phase_spec, retry_count=2):
        for attempt in range(retry_count):
            try:
                await self._run_phase(phase_spec)
                return True
            except PhaseTimeoutError:
                if attempt < retry_count - 1:
                    logger.warning(f"Phase {phase_spec['phase']} timeout, retrying...")
                    continue
                else:
                    logger.error(f"Phase {phase_spec['phase']} failed after {retry_count} attempts")
                    return False
            except Exception as e:
                logger.error(f"Phase {phase_spec['phase']} error: {e}")
                return False
```

#### Fix 4.2: Graceful Degradation
```python
# If Alpha recon fails, continue with limited data
# If Gamma assessment fails, skip to exploitation with assumptions
# If Beta exploitation fails, still generate report with findings so far
```

## Implementation Plan

### Step 1: Add New Event Types (5 min)
```python
# In backend/core/hive.py
class EventType(str, Enum):
    # ... existing ...
    MISSION_PLANNED = "MISSION_PLANNED"
    PHASE_STARTED = "PHASE_STARTED"
    PHASE_COMPLETED = "PHASE_COMPLETED"
    ENDPOINT_DISCOVERED = "ENDPOINT_DISCOVERED"
    ENDPOINT_TESTED = "ENDPOINT_TESTED"
```

### Step 2: Implement Phase Gate (10 min)
- Create `backend/core/phase_gate.py`
- Implement `PhaseGate` class
- Add to orchestrator

### Step 3: Implement Endpoint Tracker (10 min)
- Create `backend/core/endpoint_tracker.py`
- Implement `EndpointTracker` class
- Integrate with Alpha and Beta

### Step 4: Update Planner (15 min)
- Add mission plan generation
- Emit MISSION_PLANNED event
- Add plan validation

### Step 5: Update Orchestrator (20 min)
- Enforce planner-first execution
- Implement phase-based agent activation
- Add coverage verification
- Update lifecycle flow

### Step 6: Update Alpha Agent (10 min)
- Emit ENDPOINT_DISCOVERED for each found endpoint
- Emit RECON_COMPLETE with endpoint count

### Step 7: Update Attack Agents (10 min)
- Emit ENDPOINT_TESTED for each tested endpoint
- Wait for RECON_COMPLETE before starting

### Step 8: Testing (20 min)
- Run unit tests
- Run integration tests
- Verify lifecycle sequencing
- Check coverage tracking

### Step 9: Documentation (10 min)
- Update architecture docs
- Document new lifecycle
- Create flow diagrams

### Step 10: Deployment (5 min)
- Commit changes
- Push to GitHub
- Update STATUS.md

## Expected Outcomes

✅ **Guaranteed Execution Order**: Planner → Alpha → Assessment → Exploitation  
✅ **Complete Coverage**: All discovered endpoints tested  
✅ **Progress Tracking**: Real-time phase and coverage metrics  
✅ **Error Recovery**: Graceful degradation on failures  
✅ **Comprehensive Scanning**: No missed endpoints  
✅ **Strategic Coordination**: Intelligent agent chaining  
✅ **Lifecycle Visibility**: Clear phase transitions in UI  

## Success Metrics

- **Phase Sequencing**: 100% of scans follow correct order
- **Coverage**: >95% of discovered endpoints tested
- **Completion Rate**: 100% of scans reach COMPLETED state
- **Error Rate**: <5% phase failures
- **Test Pass Rate**: 100% unit + integration tests passing

---

**Total Implementation Time**: ~115 minutes  
**Risk Level**: Medium (requires careful testing)  
**Impact**: High (fundamental improvement to scan quality)
