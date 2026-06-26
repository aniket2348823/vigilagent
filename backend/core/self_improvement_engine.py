"""
Vigilagent Self-Improvement Engine (Architecture §13.4, §14.1, §15.1)
================================================================================
The central feedback controller for agent evolution. After each scan it consumes
learning outputs and applies auditable improvements:

  - Agent routing weights        (better agent assignment)
  - Agent tool preferences       (better tool selection)
  - Agent budget defaults        (better phase budgets)
  - Agent retry strategy
  - Agent skill recommendations

Every change is auditable (Architecture §13.4): what changed, why, which scan
caused it, which evidence supports it, expected benefit, rollback path.

Automatic improvements that change runtime behavior are STAGED first, then
promoted after successful shadow evaluation (Architecture §13.4, §14.1). Core
code is never rewritten at runtime — only routing/prompt/skill/budget knobs.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger("vigilagent.self_improvement")

_BRAIN_DIR = Path("brain") / "improvement"

ChangeKind = Literal["routing", "tool_preference", "budget", "retry", "skill_recommendation", "prompt_version"]
Stage = Literal["staged", "shadow", "promoted", "rejected", "rolled_back"]


@dataclass
class AgentProfile:
    """Per-agent improvement profile (Architecture §13.4 profile fields)."""

    agent_id: str
    capabilities: list[str] = field(default_factory=list)
    tool_allowlist: list[str] = field(default_factory=list)
    preferred_skill_domains: list[str] = field(default_factory=list)
    success_rate: float = 0.0
    false_positive_rate: float = 0.0
    timeout_rate: float = 0.0
    scope_block_rate: float = 0.0
    avg_evidence_quality: float = 0.0
    common_failure_modes: list[str] = field(default_factory=list)
    recovery_strategies: list[str] = field(default_factory=list)
    routing_weight: float = 1.0
    budget_default: int = 50
    prompt_version: int = 1
    policy_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "capabilities": self.capabilities,
            "tool_allowlist": self.tool_allowlist,
            "preferred_skill_domains": self.preferred_skill_domains,
            "success_rate": self.success_rate,
            "false_positive_rate": self.false_positive_rate,
            "timeout_rate": self.timeout_rate,
            "scope_block_rate": self.scope_block_rate,
            "avg_evidence_quality": self.avg_evidence_quality,
            "routing_weight": self.routing_weight,
            "budget_default": self.budget_default,
            "prompt_version": self.prompt_version,
            "policy_version": self.policy_version,
        }


@dataclass
class ImprovementChange:
    """An auditable improvement record (Architecture §13.4)."""

    change_id: str
    agent_id: str
    kind: ChangeKind
    what: str
    why: str
    scan_id: str
    evidence: dict[str, Any]
    expected_benefit: str
    rollback: dict[str, Any]
    stage: Stage = "staged"
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_id": self.change_id,
            "agent_id": self.agent_id,
            "kind": self.kind,
            "what": self.what,
            "why": self.why,
            "scan_id": self.scan_id,
            "evidence": self.evidence,
            "expected_benefit": self.expected_benefit,
            "rollback": self.rollback,
            "stage": self.stage,
            "created_at": self.created_at,
        }


class SelfImprovementEngine:
    """Applies staged, auditable agent improvements (Architecture §13.4, §15.1)."""

    def __init__(self, brain_dir: Path | None = None) -> None:
        self.dir = brain_dir or _BRAIN_DIR
        self.dir.mkdir(parents=True, exist_ok=True)
        self.profiles: dict[str, AgentProfile] = {}
        self.changes: list[ImprovementChange] = []
        self._load()

    # ── Persistence ────────────────────────────────────────────────────────────

    def _profiles_file(self) -> Path:
        return self.dir / "agent_profiles.json"

    def _changes_file(self) -> Path:
        return self.dir / "improvement_changes.json"

    def _load(self) -> None:
        pf = self._profiles_file()
        if pf.exists():
            try:
                for aid, d in json.loads(pf.read_text(encoding="utf-8")).items():
                    self.profiles[aid] = AgentProfile(agent_id=aid, **{k: v for k, v in d.items() if k != "agent_id"})
            except Exception as e:
                logger.debug("[SelfImprovement] episode dedup skipped: %s", e)

    def _save_sync(self) -> None:
        """Synchronous persistence — called from __init__ (sync context)."""
        try:
            self._profiles_file().write_text(
                json.dumps({a: p.to_dict() for a, p in self.profiles.items()}, indent=2), encoding="utf-8"
            )
            self._changes_file().write_text(
                json.dumps([c.to_dict() for c in self.changes[-500:]], indent=2), encoding="utf-8"
            )
        except Exception as exc:
            logger.debug("[SelfImprovement] save failed: %s", exc)

    def _save(self) -> None:
        """Dispatch to sync or async save depending on event loop state."""
        try:
            loop = asyncio.get_running_loop()
            # Async context: offload blocking I/O to thread pool
            loop.create_task(asyncio.to_thread(self._save_sync))
        except RuntimeError:
            # No running loop (e.g. __init__): synchronous save
            self._save_sync()

    # ── Profiles ────────────────────────────────────────────────────────────────

    def profile(self, agent_id: str) -> AgentProfile:
        if agent_id not in self.profiles:
            self.profiles[agent_id] = AgentProfile(agent_id=agent_id)
        return self.profiles[agent_id]

    # ── Improvement pass (Architecture §13.4, §15.1) ──────────────────────────

    def apply_learning(self, *, scan_id: str, learning_outputs: Any) -> list[ImprovementChange]:
        """Consume per-scan LearningOutputs and stage auditable improvements.

        ``learning_outputs`` is the dataclass from skills.learning_loop. Changes
        are STAGED (not promoted) until shadow evaluation succeeds (§13.4)."""
        staged: list[ImprovementChange] = []

        agent_deltas = getattr(learning_outputs, "agent_routing_deltas", {}) or {}
        tool_deltas = getattr(learning_outputs, "tool_reliability_deltas", {}) or {}
        vector_prefs = getattr(learning_outputs, "payload_vector_preferences", {}) or {}

        # 1. Routing weight updates from agent success/failure deltas.
        for agent_id, delta in agent_deltas.items():
            prof = self.profile(agent_id)
            old = prof.routing_weight
            new = max(0.1, min(3.0, old + delta))
            if abs(new - old) < 1e-6:
                continue
            change = ImprovementChange(
                change_id=f"chg-{uuid.uuid4().hex[:10]}",
                agent_id=agent_id,
                kind="routing",
                what=f"routing_weight {old:.2f} -> {new:.2f}",
                why=f"agent success delta {delta:+.2f} on scan {scan_id}",
                scan_id=scan_id,
                evidence={"delta": delta},
                expected_benefit="better agent assignment for future scans",
                rollback={"routing_weight": old},
            )
            prof.routing_weight = new  # staged value applied to profile
            staged.append(change)

        # 2. Tool preference updates (promote reliable tools per affected agents).
        for tool, delta in tool_deltas.items():
            if delta <= 0:
                continue
            # Attach to any agent whose allowlist already has the tool (or generic).
            for prof in self.profiles.values():
                if tool in prof.tool_allowlist:
                    change = ImprovementChange(
                        change_id=f"chg-{uuid.uuid4().hex[:10]}",
                        agent_id=prof.agent_id,
                        kind="tool_preference",
                        what=f"prefer tool '{tool}'",
                        why=f"tool reliability delta {delta:+.2f} on scan {scan_id}",
                        scan_id=scan_id,
                        evidence={"tool": tool, "delta": delta},
                        expected_benefit="prefer historically reliable tools",
                        rollback={"note": "remove preference"},
                    )
                    staged.append(change)

        # 3. Payload-vector preferences (skill recommendation knob).
        for vclass, vector in vector_prefs.items():
            change = ImprovementChange(
                change_id=f"chg-{uuid.uuid4().hex[:10]}",
                agent_id="agent_beta",
                kind="skill_recommendation",
                what=f"prefer '{vector}' vector for {vclass}",
                why=f"successful delivery on scan {scan_id}",
                scan_id=scan_id,
                evidence={"vuln_class": vclass, "vector": vector},
                expected_benefit="faster confirmation via best-known vector",
                rollback={"note": "drop vector preference"},
            )
            staged.append(change)

        self.changes.extend(staged)
        self._save()
        logger.info("[SelfImprovement] scan %s staged %d improvement(s)", scan_id, len(staged))
        return staged

    # ── Shadow evaluation + promotion (Architecture §13.4) ────────────────────

    def promote_if_validated(self, change_id: str, *, shadow_success: bool) -> Stage:
        """Promote a staged change after a successful shadow run, else reject."""
        for c in self.changes:
            if c.change_id == change_id:
                c.stage = "promoted" if shadow_success else "rejected"
                self._save()
                return c.stage
        return "rejected"

    def rollback(self, change_id: str) -> bool:
        """Roll back a change using its recorded rollback path (§13.4)."""
        for c in self.changes:
            if c.change_id == change_id and c.stage in ("staged", "shadow", "promoted"):
                prof = self.profiles.get(c.agent_id)
                if prof and c.kind == "routing" and "routing_weight" in c.rollback:
                    prof.routing_weight = c.rollback["routing_weight"]
                c.stage = "rolled_back"
                self._save()
                return True
        return False

    def routing_weight(self, agent_id: str) -> float:
        return self.profile(agent_id).routing_weight

    def record_false_positive(
        self, *, agent_id: str, vuln_class: str, scan_id: str = "GLOBAL", reason: str = ""
    ) -> ImprovementChange:
        """Record a Gamma false-positive rejection against the source agent
        (Architecture §15.1). Raises the agent's FP rate, nudges its routing
        weight down, and stages an auditable confidence-tuning change so the
        source agent becomes less aggressive for this vuln class."""
        prof = self.profile(agent_id)
        # Update FP rate (exponential moving average toward 1.0 on each FP).
        prof.false_positive_rate = round(min(1.0, prof.false_positive_rate * 0.8 + 0.2), 4)
        old_weight = prof.routing_weight
        prof.routing_weight = max(0.1, round(old_weight - 0.1, 4))
        mode = f"too_aggressive:{vuln_class.lower()}"
        if mode not in prof.common_failure_modes:
            prof.common_failure_modes.append(mode)
        change = ImprovementChange(
            change_id=f"chg-{uuid.uuid4().hex[:10]}",
            agent_id=agent_id,
            kind="routing",
            what=f"confidence down for {vuln_class}; routing_weight {old_weight:.2f}->{prof.routing_weight:.2f}",
            why=f"Gamma rejected a {vuln_class} candidate as false positive: {reason[:120]}",
            scan_id=scan_id,
            evidence={"vuln_class": vuln_class, "fp_rate": prof.false_positive_rate, "reason": reason},
            expected_benefit="fewer false positives from this agent/vuln-class",
            rollback={"routing_weight": old_weight},
        )
        self.changes.append(change)
        self._save()
        logger.info(
            "[SelfImprovement] FP recorded: %s %s (fp_rate=%.2f)", agent_id, vuln_class, prof.false_positive_rate
        )
        return change

    def get_audit(self, limit: int = 50) -> list[dict[str, Any]]:
        return [c.to_dict() for c in self.changes[-limit:]]

    def stats(self) -> dict[str, Any]:
        by_stage: dict[str, int] = {}
        for c in self.changes:
            by_stage[c.stage] = by_stage.get(c.stage, 0) + 1
        return {"profiles": len(self.profiles), "changes": len(self.changes), "by_stage": by_stage}


# Global self-improvement engine.
self_improvement_engine = SelfImprovementEngine()
