"""
Per-Scan Learning Loop (Architecture §13.3, §13.4, §14.1)
================================================================================
Every scan ends with a learning pass:

  scan completed
  -> collect decisions, tool runs, findings, false positives, failures
  -> compare plan vs outcome
  -> identify agent mistakes + useful new techniques
  -> update tool reliability + agent routing scores
  -> create or revise skills
  -> compress scan lessons
  -> promote safe improvements
  -> store learning update

This module orchestrates that pass using the components already built:
  - ScanStateDB (durable history + learning_updates)
  - SkillCreator/Evaluator/PromotionGate (skill creation)
  - MemoryManager providers (tool/agent reliability)
The system learns from both success and failure (Architecture §13.3).
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field

from backend.skills.creator import create_and_evaluate

logger = logging.getLogger("vigilagent.skills.learning_loop")

# Mistake categories (Architecture §14.1).
MISTAKE_CATEGORIES = {
    "false_positive",
    "missed_vulnerability",
    "bad_tool_choice",
    "bad_payload_vector",
    "bad_parser",
    "bad_timeout",
    "bad_rate_limit",
    "bad_browser_strategy",
    "bad_auth_session",
    "bad_llm_assumption",
    "duplicate_work",
    "scope_block",
    "worker_crash",
    "report_quality",
}


@dataclass
class ScanOutcome:
    """Inputs to the learning pass (Architecture §13.3)."""

    scan_id: str
    decisions: list[dict] = field(default_factory=list)
    tool_runs: list[dict] = field(default_factory=list)  # {tool, success}
    findings: list[dict] = field(default_factory=list)
    false_positives: list[dict] = field(default_factory=list)
    failures: list[dict] = field(default_factory=list)
    agent_runs: list[dict] = field(default_factory=list)  # {agent, success}
    successful_techniques: list[dict] = field(default_factory=list)


@dataclass
class LearningOutputs:
    """Results of the learning pass (Architecture §13.3 learning outputs)."""

    new_candidate_skills: list[str] = field(default_factory=list)
    tool_reliability_deltas: dict[str, float] = field(default_factory=dict)
    agent_routing_deltas: dict[str, float] = field(default_factory=dict)
    payload_vector_preferences: dict[str, str] = field(default_factory=dict)
    agent_mistakes: list[dict] = field(default_factory=list)
    lessons: list[str] = field(default_factory=list)
    promoted: list[str] = field(default_factory=list)


class PerScanLearningLoop:
    """Runs the post-scan learning pass (Architecture §13.3)."""

    def __init__(self, scan_state_db=None, memory_manager=None) -> None:
        self._db = scan_state_db
        self._mm = memory_manager
        if self._db is None:
            try:
                from backend.core.scan_state_db import scan_state_db as _db

                self._db = _db
            except Exception as exc:
                logger.debug("[LearningLoop] scan_state_db unavailable: %s", exc)
                self._db = None
        if self._mm is None:
            try:
                from backend.core.memory_manager import memory_manager as _mm

                self._mm = _mm
            except Exception as exc:
                logger.debug("[LearningLoop] memory_manager unavailable: %s", exc)
                self._mm = None

    @staticmethod
    def _identify_mistakes(outcome: ScanOutcome) -> list[dict]:
        """Classify agent mistakes from false positives + failures into the
        §14.1 mistake categories so they can drive routing/skill revision."""
        mistakes: list[dict] = []
        for fp in outcome.false_positives:
            mistakes.append(
                {
                    "category": "false_positive",
                    "agent": fp.get("agent", ""),
                    "detail": fp.get("reason", ""),
                }
            )
        for fail in outcome.failures:
            cat = fail.get("category") or fail.get("type") or "bad_tool_choice"
            if cat not in MISTAKE_CATEGORIES:
                cat = "bad_tool_choice"
            mistakes.append(
                {
                    "category": cat,
                    "agent": fail.get("agent", ""),
                    "detail": fail.get("detail") or fail.get("error", ""),
                }
            )
        return mistakes

    async def run(self, outcome: ScanOutcome) -> LearningOutputs:
        out = LearningOutputs()

        # 0. Identify agent mistakes from false positives + failures
        #    (Architecture §13.3 "Identify agent mistakes", §14.1 categories).
        out.agent_mistakes = self._identify_mistakes(outcome)

        # 1. Update tool reliability (Architecture §13.3).
        for tr in outcome.tool_runs:
            tool = tr.get("tool")
            if not tool:
                continue
            delta = 0.1 if tr.get("success") else -0.1
            out.tool_reliability_deltas[tool] = out.tool_reliability_deltas.get(tool, 0.0) + delta
            if self._mm:
                await self._mm.sync({"tool": tool, "success": bool(tr.get("success"))})

        # 2. Update agent routing scores (Architecture §13.4).
        for ar in outcome.agent_runs:
            agent = ar.get("agent")
            if not agent:
                continue
            delta = 0.1 if ar.get("success") else -0.1
            out.agent_routing_deltas[agent] = out.agent_routing_deltas.get(agent, 0.0) + delta
            if self._mm:
                await self._mm.sync({"agent": agent, "success": bool(ar.get("success"))})

        # 3. Create/revise skills from useful new techniques (Architecture §13.2).
        for tech in outcome.successful_techniques:
            summary = create_and_evaluate(
                trigger=tech.get("trigger", "tool_sequence_succeeded"),
                scan_id=outcome.scan_id,
                name=tech.get("name", "learned-technique"),
                description=tech.get("description", ""),
                steps=tech.get("steps", []),
                expected_evidence=tech.get("expected_evidence", []),
                success_rate=tech.get("success_rate", 0.0),
                known_false_positives=tech.get("known_false_positives", []),
                examples=tech.get("examples", []),
            )
            if summary.get("created"):
                out.new_candidate_skills.append(summary["skill_id"])
                if summary.get("promotion_state") in ("shadow", "assisted", "active"):
                    out.promoted.append(summary["skill_id"])

        # 4. Learn from false positives (reusable FP lessons -> skills).
        for fp in outcome.false_positives:
            reason = fp.get("reason")
            if reason:
                out.lessons.append(f"false_positive: {reason}")

        # 5. Payload vector preferences from successful findings.
        for f in outcome.findings:
            vector = f.get("vector")
            vclass = f.get("vuln_type") or f.get("type")
            if vector and vclass:
                out.payload_vector_preferences[str(vclass).lower()] = vector

        # 6. Compress lessons + persist a learning update (Architecture §5.6).
        out.lessons.append(
            f"scan {outcome.scan_id}: {len(outcome.findings)} findings, "
            f"{len(outcome.false_positives)} FPs, {len(outcome.failures)} failures, "
            f"{len(out.new_candidate_skills)} new skills"
        )

        # 7. Feed the self-improvement engine (Architecture §13.4, §15.1):
        #    stage auditable routing/tool/skill improvements (promoted only after
        #    shadow evaluation — not applied to runtime automatically here).
        try:
            from backend.core.self_improvement_engine import self_improvement_engine

            staged = self_improvement_engine.apply_learning(scan_id=outcome.scan_id, learning_outputs=out)
            if staged:
                out.lessons.append(f"staged {len(staged)} self-improvement change(s)")
        except Exception as exc:
            logger.debug("[LearningLoop] self-improvement staging skipped: %s", exc)

        if self._db:
            try:
                self._db.record_learning_update(
                    update_id=f"learn-{uuid.uuid4().hex[:10]}",
                    scan_id=outcome.scan_id,
                    kind="per_scan_learning",
                    subsystem="learning_loop",
                    detail={
                        "tool_deltas": out.tool_reliability_deltas,
                        "agent_deltas": out.agent_routing_deltas,
                        "new_skills": out.new_candidate_skills,
                        "promoted": out.promoted,
                        "vector_prefs": out.payload_vector_preferences,
                        "agent_mistakes": out.agent_mistakes,
                        "lessons": out.lessons[-10:],
                        "ts": time.time(),
                    },
                )
            except Exception as exc:
                logger.debug("[LearningLoop] could not persist learning update: %s", exc)

        logger.info(
            "[LearningLoop] scan %s: %d new skills, %d tool deltas, %d agent deltas",
            outcome.scan_id,
            len(out.new_candidate_skills),
            len(out.tool_reliability_deltas),
            len(out.agent_routing_deltas),
        )
        return out


# Global learning loop.
per_scan_learning_loop = PerScanLearningLoop()
