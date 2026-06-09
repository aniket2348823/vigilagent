import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional, Callable
from backend.core.hive import BaseAgent, EventType, HiveEvent
from backend.core.protocol import JobPacket, ModuleConfig, AgentID, TaskPriority, TaskTarget
from backend.core.config import settings
from backend.ai.cortex import CortexEngine, get_cortex_engine
from backend.core.skill_library import skill_library
from backend.core.unified_knowledge_graph import unified_knowledge_graph

logger = logging.getLogger("MissionPlanner")

class MissionState(str, Enum):
    RECON = "RECON"
    ASSESSMENT = "ASSESSMENT"
    EXPLOITATION = "EXPLOITATION"
    COMPLETED = "COMPLETED"


class TaskStatus(str, Enum):
    """Lifecycle of a single task node, mirroring Hermes's todo statuses
    (pending|in_progress|completed|cancelled) so the DAG can track progress and
    survive re-prioritization (Hermes tools/todo_tool.py)."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


# Architecture §16 phase lifecycle. The planner may only advance through these
# gates in order; a task cannot be dispatched before the campaign reaches its
# phase. MissionState maps onto the validation-bearing phases.
PHASE_ORDER: List[MissionState] = [
    MissionState.RECON,         # §16 passive/active recon, surface modeling
    MissionState.ASSESSMENT,    # §16 planning + controlled validation
    MissionState.EXPLOITATION,  # §16 verification + evidence capture
    MissionState.COMPLETED,
]


@dataclass
class TaskNode:
    """A single unit of work in the campaign DAG.

    Adopts Hermes's structured-todo item shape (id, content, status) and extends
    it with the evidence-driven fields Vigilagent planning needs: the phase gate
    the task belongs to (§16), its priority value derived from attack-surface
    scoring, the dependencies that must complete first (DAG edges), and the
    skill recommendations that seeded it (§6.7/§29.1)."""
    id: str
    content: str
    phase: MissionState
    agent_id: AgentID
    module_id: str
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.NORMAL
    value: float = 0.0  # attack-surface value, higher == do sooner
    depends_on: List[str] = field(default_factory=list)
    params: Dict[str, Any] = field(default_factory=dict)
    job_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "content": self.content,
            "phase": self.phase.value,
            "agent_id": self.agent_id.value,
            "module_id": self.module_id,
            "status": self.status.value,
            "priority": self.priority.value,
            "value": round(self.value, 4),
            "depends_on": list(self.depends_on),
        }


class TaskGraph:
    """Durable-in-memory task DAG for one campaign (Architecture §5.5).

    Replaces ad-hoc reactive dispatch with a prioritized, dependency-aware plan.
    Order is value-driven the way Hermes's todo list is position-driven, but here
    position is recomputed from attack-surface value as evidence arrives instead
    of being fixed by the model. Tasks only become "ready" once their
    dependencies are satisfied AND their phase gate is open (§16)."""

    def __init__(self):
        self._tasks: Dict[str, TaskNode] = {}

    def add(self, task: TaskNode) -> TaskNode:
        self._tasks[task.id] = task
        return task

    def get(self, task_id: str) -> Optional[TaskNode]:
        return self._tasks.get(task_id)

    def all(self) -> List[TaskNode]:
        return list(self._tasks.values())

    def has(self, task_id: str) -> bool:
        return task_id in self._tasks

    def _deps_met(self, task: TaskNode) -> bool:
        for dep_id in task.depends_on:
            dep = self._tasks.get(dep_id)
            if dep is None or dep.status != TaskStatus.COMPLETED:
                return False
        return True

    def ready(self, current_phase: MissionState) -> List[TaskNode]:
        """Pending tasks whose dependencies are met and whose phase gate is
        open, ordered by attack-surface value then priority (re-prioritized on
        every call so newly-arrived evidence reshapes the queue)."""
        gate = PHASE_ORDER.index(current_phase)
        priority_rank = {
            TaskPriority.CRITICAL: 3,
            TaskPriority.HIGH: 2,
            TaskPriority.NORMAL: 1,
            TaskPriority.LOW: 0,
        }
        ready = [
            t for t in self._tasks.values()
            if t.status == TaskStatus.PENDING
            and PHASE_ORDER.index(t.phase) <= gate  # §16: never jump the gate
            and self._deps_met(t)
        ]
        ready.sort(key=lambda t: (t.value, priority_rank.get(t.priority, 1)), reverse=True)
        return ready

    def mark(self, task_id: str, status: TaskStatus) -> None:
        task = self._tasks.get(task_id)
        if task is not None:
            task.status = status

    def reprioritize(self, score_fn: Callable[[TaskNode], float]) -> None:
        """Recompute attack-surface value for every pending task from fresh
        evidence (§5.5 KnowledgeGraph -> Planner feedback loop)."""
        for task in self._tasks.values():
            if task.status == TaskStatus.PENDING:
                task.value = score_fn(task)

    def snapshot(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in self.all()]



    async def execute_dag(self, commands: dict) -> dict:
        """Execute recon tools as a dependency DAG.

        Tools start as soon as their dependencies finish, not when
        the entire phase finishes. This saves 15-30s per scan.
        """
        import asyncio as _aio
        completed = {}
        pending = {}
        results = {}

        while len(results) < len(commands):
            ready = [
                name for name, cmd in commands.items()
                if name not in results
                and name not in pending
                and all(dep in results for dep in getattr(cmd, 'depends_on', []))
            ]

            for name in ready:
                pending[name] = _aio.create_task(self._run_dag_tool(name, commands[name]))

            if not pending:
                break

            done, _ = await _aio.wait(
                list(pending.values()), return_when=_aio.FIRST_COMPLETED
            )

            for task in done:
                for name, t in list(pending.items()):
                    if t is task:
                        results[name] = task.result()
                        del pending[name]
                        break

        return results

    async def _run_dag_tool(self, name, cmd):
        """Run a single tool from the DAG."""
        from backend.core.terminal_engine import terminal_engine
        argv = getattr(cmd, 'argv', None)
        if argv:
            return await terminal_engine.run(
                argv,
                timeout=getattr(cmd, 'timeout', 120),
                agent="dag_executor",
            )
        return None

class MissionPlanner(BaseAgent):
    """
    AGENT OMEGA-PLANNER: THE STRATEGIST
    Role: Hierarchical Mission Planning & Autonomous Chaining.
    
    V6 Innovation: Instead of simple event reaction, the Planner generates
    structured 3-step offensive chains for every targets.
    """
    def __init__(self, bus):
        super().__init__("agent_planner", bus)
        self.cortex = get_cortex_engine()
        self.active_missions = {} # {target_url: mission_data}
        self.job_to_target = {}   # {job_id: target_url}

    async def setup(self):
        # 1. Listen for new targets
        self.bus.subscribe(EventType.TARGET_ACQUIRED, self.handle_new_target)
        # 2. Listen for findings to pivot strategy
        self.bus.subscribe(EventType.VULN_CANDIDATE, self.handle_candidate)
        # 3. Listen for job completions to trigger logical next steps
        self.bus.subscribe(EventType.JOB_COMPLETED, self.handle_job_completion)

    def _pre_plan(self, target_url: str) -> Dict[str, Any]:
        """Query the SkillLibrary and unified knowledge graph before planning.

        Architecture §6.7 / §29.1: the planner consumes learned skills and graph
        evidence up front so plans are informed by prior outcomes, not formed in
        a vacuum. Failures here are non-fatal (planning proceeds without recs)."""
        recs: Dict[str, Any] = {"skills": [], "graph_predictions": [], "chains": []}
        try:
            recs["skills"] = skill_library.get_recommendations(target_url=target_url, limit=10)
        except Exception as exc:
            logger.debug(f"[{self.name}] skill recommendations unavailable: {exc}")
        try:
            recs["graph_predictions"] = unified_knowledge_graph.predict_next("TARGET_ACQUIRED", target_url)
            recs["chains"] = unified_knowledge_graph.find_chains(max_depth=3)[:5]
        except Exception as exc:
            logger.debug(f"[{self.name}] graph pre-plan unavailable: {exc}")
        if recs["skills"] or recs["graph_predictions"]:
            logger.info(f"[{self.name}] pre-plan for {target_url}: "
                        f"{len(recs['skills'])} skills, {len(recs['graph_predictions'])} graph predictions")
        return recs

    # ──────────────────────────────────────────────────────────────────────
    # Evidence-driven decomposition & prioritization (Hermes todo/curator
    # pattern adapted for a phase-gated attack DAG — §5.5 TaskGraph, §16).
    # ──────────────────────────────────────────────────────────────────────
    def _score_task(self, task: TaskNode, recommendations: Dict[str, Any]) -> float:
        """Attack-surface value for a task, blending skill confidence/success
        (§6.7/§29.1 skill recs) and knowledge-graph chain/prediction confidence
        (§5.5). Higher value == higher priority. Hermes's curator scores skills
        by confidence × success_rate; we reuse that shape for task ordering."""
        value = 0.0
        content = task.content.lower()
        for rec in recommendations.get("skills", []):
            text = f"{rec.get('name', '')} {rec.get('skill_type', '')} {rec.get('description', '')}".lower()
            if rec.get("skill_type") and rec["skill_type"].lower() in content:
                value += float(rec.get("score", 0.0))
            elif any(tok and tok in text for tok in content.split()):
                value += float(rec.get("score", 0.0)) * 0.5
        for pred in recommendations.get("graph_predictions", []):
            if str(pred.get("suggestion", "")).lower() in content:
                value += float(pred.get("confidence", 0.0)) / 100.0
        for chain in recommendations.get("chains", []):
            # Deeper, higher-confidence chains lift the value of their members.
            for node in chain.get("chain", []):
                if str(node.get("type", "")).lower() in content:
                    value += float(chain.get("confidence", 0.0)) / 100.0 * 0.25
        return round(value, 4)

    def _decompose_campaign(self, target_url: str, scan_id: str,
                            recommendations: Dict[str, Any]) -> TaskGraph:
        """Decompose a campaign goal into an ordered, phase-gated task DAG.

        Mirrors Hermes's structured-todo decomposition (break a complex goal
        into discrete, individually-trackable items) but every node is bound to
        a §16 phase, an owning agent, and a dependency edge so the DAG enforces
        recon → assessment → exploitation ordering. Tasks are then scored by
        attack-surface value so the highest-value work surfaces first."""
        graph = TaskGraph()

        recon = graph.add(TaskNode(
            id=f"recon::{target_url}",
            content=f"Map attack surface of {target_url}",
            phase=MissionState.RECON,
            agent_id=AgentID.ALPHA,
            module_id="alpha_v6_recon",
            priority=TaskPriority.NORMAL,
            params={"skill_recommendations": recommendations.get("skills", [])},
        ))
        assess = graph.add(TaskNode(
            id=f"assess::{target_url}",
            content=f"Vulnerability audit of {target_url}",
            phase=MissionState.ASSESSMENT,
            agent_id=AgentID.GAMMA,
            module_id="vulnerability_audit",
            priority=TaskPriority.HIGH,
            depends_on=[recon.id],
        ))
        graph.add(TaskNode(
            id=f"exploit::{target_url}",
            content=f"Controlled exploitation of {target_url}",
            phase=MissionState.EXPLOITATION,
            agent_id=AgentID.BETA,
            module_id="exploit_delivery",
            priority=TaskPriority.CRITICAL,
            depends_on=[assess.id],
        ))

        graph.reprioritize(lambda t: self._score_task(t, recommendations))
        return graph

    def _reprioritize_mission(self, mission: Dict[str, Any]) -> None:
        """Re-score the DAG from the latest recommendations so the queue reflects
        evidence gathered since planning began (§5.5 graph → planner loop)."""
        graph: Optional[TaskGraph] = mission.get("task_graph")
        if graph is None:
            return
        recs = mission.get("recommendations", {})
        graph.reprioritize(lambda t: self._score_task(t, recs))
        ordered = ", ".join(f"{t.id}({t.value})" for t in graph.ready(mission["state"]))
        if ordered:
            logger.info(f"[{self.name}] re-prioritized ready tasks: {ordered}")

    async def handle_new_target(self, event: HiveEvent):
        """
        Phase 1: RECONNAISSANCE
        Triggered when a new URL enters the scope.
        """
        target_url = event.payload.get("url")
        if not target_url or target_url in self.active_missions:
             return

        logger.info(f"[{self.name}] [MISSION] Target '{target_url}' acquired. Starting Phase 1: RECON.")

        # Pre-planning: consume learned skills + graph evidence BEFORE planning
        # (Architecture §29.1 priority 13, §6.7 — query skills/graph up front,
        # not only when stuck).
        recommendations = self._pre_plan(target_url)

        # Decompose the campaign goal into a prioritized, phase-gated task DAG
        # (Architecture §5.5 TaskGraph, §16). The graph is the durable plan; the
        # event dispatch below executes its first ready node.
        task_graph = self._decompose_campaign(target_url, event.scan_id, recommendations)

        self.active_missions[target_url] = {
            "scan_id": event.scan_id,
            "state": MissionState.RECON,
            "findings": [],
            "history": [],
            "recommendations": recommendations,
            "task_graph": task_graph,
        }

        recon_task = task_graph.get(f"recon::{target_url}")
        if recon_task is not None:
            recon_task.status = TaskStatus.IN_PROGRESS

        # Dispatch Alpha for intelligent mapping
        recon_job = JobPacket(
            priority=TaskPriority.NORMAL,
            target=TaskTarget(url=target_url),
            config=ModuleConfig(
                module_id="alpha_v6_recon",
                agent_id=AgentID.ALPHA,
                params={
                    "scan_mode": event.payload.get("scan_mode")
                    or event.payload.get("mode")
                    or getattr(settings, "ALPHA_DEFAULT_MODE", "STANDARD"),
                    "skill_recommendations": recommendations.get("skills", []),
                },
            )
        )
        
        self.job_to_target[recon_job.id] = target_url
        if recon_task is not None:
            recon_task.job_id = recon_job.id

        await self.bus.publish(HiveEvent(
            type=EventType.JOB_ASSIGNED,
            source=self.name,
            scan_id=event.scan_id,
            payload=recon_job.model_dump()
        ))

    async def handle_candidate(self, event: HiveEvent):
        """
        Phase 2: ASSESSMENT
        Triggered when Alpha finds an interesting endpoint.
        """
        target_url = event.payload.get("url")
        if target_url not in self.active_missions:
            return

        mission = self.active_missions[target_url]
        if mission["state"] == MissionState.RECON:
            logger.info(f"[{self.name}] [MISSION] '{target_url}' - Recon confirmed potential. Pivoting to Phase 2: ASSESSMENT.")

            # Evidence arrived: refresh graph predictions and re-prioritize the
            # DAG before advancing the phase gate (§5.5 graph → planner loop).
            graph: TaskGraph = mission.get("task_graph")
            try:
                mission["recommendations"]["graph_predictions"] = \
                    unified_knowledge_graph.predict_next("TARGET_ACQUIRED", target_url)
            except Exception as exc:
                logger.debug(f"[{self.name}] graph re-query unavailable: {exc}")
            if graph is not None:
                graph.mark(f"recon::{target_url}", TaskStatus.COMPLETED)

            # §16 phase gate: only advance one step along PHASE_ORDER.
            mission["state"] = MissionState.ASSESSMENT
            self._reprioritize_mission(mission)

            assess_task = graph.get(f"assess::{target_url}") if graph is not None else None
            if assess_task is not None:
                assess_task.status = TaskStatus.IN_PROGRESS

            # Dispatch Gamma for forensic audit
            assess_job = JobPacket(
                priority=(assess_task.priority if assess_task else TaskPriority.HIGH),
                target=TaskTarget(url=target_url),
                config=ModuleConfig(
                    module_id="vulnerability_audit",
                    agent_id=AgentID.GAMMA
                )
            )

            self.job_to_target[assess_job.id] = target_url
            if assess_task is not None:
                assess_task.job_id = assess_job.id

            await self.bus.publish(HiveEvent(
                type=EventType.JOB_ASSIGNED,
                source=self.name,
                scan_id=mission["scan_id"],
                payload=assess_job.model_dump()
            ))

    async def handle_job_completion(self, event: HiveEvent):
        """
        Phase 3: EXPLOITATION
        Triggered when Gamma confirms a vulnerability.
        """
        payload = event.payload
        job_id = payload.get("job_id")
        target_url = self.job_to_target.get(job_id)
        
        if not target_url or target_url not in self.active_missions:
            return

        mission = self.active_missions[target_url]

        if payload.get("status") == "VULN_FOUND":
            vulns = payload.get("vulnerabilities", [])
            for vuln in vulns:
                if mission["state"] == MissionState.ASSESSMENT:
                    logger.info(f"[{self.name}] [MISSION] '{target_url}' - Vuln Vetted ({vuln.get('type')}). Launching Phase 3: EXPLOITATION.")

                    graph: TaskGraph = mission.get("task_graph")
                    if graph is not None:
                        graph.mark(f"assess::{target_url}", TaskStatus.COMPLETED)

                    # §16 phase gate: advance one step, then re-prioritize the
                    # exploitation tasks against the freshest evidence.
                    mission["state"] = MissionState.EXPLOITATION
                    self._reprioritize_mission(mission)

                    exploit_task = graph.get(f"exploit::{target_url}") if graph is not None else None
                    if exploit_task is not None:
                        exploit_task.status = TaskStatus.IN_PROGRESS

                    # Dispatch Beta for active breach
                    exploit_job = JobPacket(
                        priority=(exploit_task.priority if exploit_task else TaskPriority.CRITICAL),
                        target=TaskTarget(url=target_url),
                        config=ModuleConfig(
                            module_id="exploit_delivery",
                            agent_id=AgentID.BETA,
                            params={"vuln_type": vuln.get("type"), "evidence": vuln.get("evidence")}
                        )
                    )
                    
                    self.job_to_target[exploit_job.id] = target_url
                    if exploit_task is not None:
                        exploit_task.job_id = exploit_job.id

                    await self.bus.publish(HiveEvent(
                        type=EventType.JOB_ASSIGNED,
                        source=self.name,
                        scan_id=mission["scan_id"],
                        payload=exploit_job.model_dump()
                    ))
        
        elif mission["state"] == MissionState.EXPLOITATION:
             # Mission Over
             logger.info(f"[{self.name}] [MISSION] '{target_url}' - Mission Successfully Completed.")
             graph = mission.get("task_graph")
             if graph is not None:
                 graph.mark(f"exploit::{target_url}", TaskStatus.COMPLETED)
             mission["state"] = MissionState.COMPLETED

    async def lifecycle(self):
        """Monitor mission timeouts and cleanup."""
        while self.active:
            await asyncio.sleep(60)
            # Periodic cleanup of completed or stale missions could go here
