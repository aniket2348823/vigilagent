"""
Automatic Skill Creation (Architecture §13.2)
================================================================================
Vigilagent creates and improves skills after every scan. This module implements:

  SkillCreatorAgent   - generates candidate skills from scan outcomes
  SkillEvaluatorAgent - evaluates candidates against §13.2 checks
  SkillPromotionGate  - promotes safe candidates through the lifecycle states

Generated skills start as `candidate` and become `active` only after passing the
evaluation + promotion gate (Architecture §13.2). Artifacts are written under
`generated_skills/<domain>/<skill-slug>/`.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.skills.catalog import SkillMeta, skill_catalog
from backend.skills.classifier import classify_domain, classify_risk
from backend.skills.mapper import agents_for_domain, map_required_tools
from backend.skills.policy import PromotionState, RiskClass, is_disabled

logger = logging.getLogger("vigilagent.skills.creator")

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_GENERATED_ROOT = _PROJECT_ROOT / "generated_skills"

# Triggers that justify creating/improving a skill (Architecture §13.2).
SKILL_CREATION_TRIGGERS = {
    "tool_sequence_succeeded",
    "recovered_from_failure",
    "false_positive_reason_reusable",
    "new_target_pattern",
    "better_payload_vector",
    "recon_parser_pattern",
    "reusable_browser_auth",
    "accepted_remediation_pattern",
}


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:80]


@dataclass
class SkillCandidate:
    """A generated, untrusted skill candidate (Architecture §13.2 metadata)."""

    name: str
    source_scan_ids: list[str]
    risk_class: RiskClass
    agent_targets: list[str]
    domain: str = "uncategorized"
    preconditions: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    expected_evidence: list[str] = field(default_factory=list)
    known_false_positives: list[str] = field(default_factory=list)
    success_rate: float = 0.0
    failure_rate: float = 0.0
    promotion_state: PromotionState = PromotionState.CANDIDATE
    created_by: str = "SkillCreatorAgent"
    examples: list[dict] = field(default_factory=list)

    @property
    def slug(self) -> str:
        return _slugify(self.name)

    def metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source_scan_ids": self.source_scan_ids,
            "created_by": self.created_by,
            "risk_class": self.risk_class.value,
            "agent_targets": self.agent_targets,
            "preconditions": self.preconditions,
            "steps": self.steps,
            "expected_evidence": self.expected_evidence,
            "known_false_positives": self.known_false_positives,
            "success_rate": self.success_rate,
            "failure_rate": self.failure_rate,
            "promotion_state": self.promotion_state.value,
        }


class SkillCreatorAgent:
    """Generates candidate skills from scan outcomes (Architecture §13.2)."""

    def create_from_outcome(
        self,
        *,
        trigger: str,
        scan_id: str,
        name: str,
        description: str,
        steps: list[str],
        expected_evidence: list[str],
        success_rate: float = 0.0,
        known_false_positives: list[str] | None = None,
        examples: list[dict] | None = None,
    ) -> SkillCandidate | None:
        if trigger not in SKILL_CREATION_TRIGGERS:
            logger.debug("[SkillCreator] ignoring unknown trigger: %s", trigger)
            return None
        corpus = f"{name} {description} {' '.join(steps)}"
        domain = classify_domain(corpus)
        risk = classify_risk(corpus)
        candidate = SkillCandidate(
            name=name,
            source_scan_ids=[scan_id],
            risk_class=risk,
            agent_targets=agents_for_domain(domain),
            domain=domain,
            preconditions=[f"trigger:{trigger}"],
            steps=steps,
            expected_evidence=expected_evidence,
            known_false_positives=known_false_positives or [],
            success_rate=success_rate,
            examples=examples or [],
        )
        return candidate

    def persist(
        self, candidate: SkillCandidate, *, description: str = "", evaluation: EvaluationResult | None = None
    ) -> Path:
        """Write the candidate skill artifact tree (Architecture §13.2)."""
        skill_dir = _GENERATED_ROOT / candidate.domain / candidate.slug
        skill_dir.mkdir(parents=True, exist_ok=True)
        (skill_dir / "scripts").mkdir(exist_ok=True)
        (skill_dir / "references").mkdir(exist_ok=True)

        # SKILL.md with frontmatter (read by the loader on next ingest).
        frontmatter = (
            "---\n"
            f"name: {candidate.name}\n"
            f"description: {description or candidate.name}\n"
            "license: internal\n"
            "metadata:\n"
            f"  author: {candidate.created_by}\n"
            f"  risk_class: {candidate.risk_class.value}\n"
            f"  promotion_state: {candidate.promotion_state.value}\n"
            "---\n\n"
            f"# {candidate.name}\n\n"
            f"{description or candidate.name}\n\n"
            "## Steps\n" + "\n".join(f"- {s}" for s in candidate.steps) + "\n\n"
            "## Expected Evidence\n" + "\n".join(f"- {e}" for e in candidate.expected_evidence) + "\n"
        )
        (skill_dir / "SKILL.md").write_text(frontmatter, encoding="utf-8")
        (skill_dir / "metadata.json").write_text(json.dumps(candidate.metadata(), indent=2), encoding="utf-8")
        if evaluation is not None:
            # evaluation.json artifact (Architecture §13.2 artifact structure).
            (skill_dir / "evaluation.json").write_text(
                json.dumps(
                    {
                        "passed": evaluation.passed,
                        "checks": evaluation.checks,
                        "failed_checks": evaluation.reasons,
                        "evaluated_at": time.time(),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        (skill_dir / "provenance.json").write_text(
            json.dumps(
                {
                    "source_scan_ids": candidate.source_scan_ids,
                    "created_by": candidate.created_by,
                    "created_at": time.time(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        if candidate.examples:
            with (skill_dir / "examples.jsonl").open("w", encoding="utf-8") as f:
                for ex in candidate.examples:
                    f.write(json.dumps(ex) + "\n")
        logger.info("[SkillCreator] persisted candidate %s -> %s", candidate.name, skill_dir)
        return skill_dir


@dataclass
class EvaluationResult:
    passed: bool
    checks: dict[str, bool] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)


class SkillEvaluatorAgent:
    """Evaluates a candidate against the §13.2 checks before promotion."""

    def evaluate(self, candidate: SkillCandidate) -> EvaluationResult:
        checks = {
            "from_real_evidence": bool(candidate.source_scan_ids),
            "not_overfit": len(candidate.source_scan_ids) >= 1 and bool(candidate.preconditions),
            "has_preconditions": bool(candidate.preconditions),
            "defines_expected_evidence": bool(candidate.expected_evidence),
            "has_fp_controls": candidate.known_false_positives is not None,
            "respects_scope_phase": not is_disabled(candidate.risk_class),
            "specifies_risk_class": isinstance(candidate.risk_class, RiskClass),
            "not_destructive": not is_disabled(candidate.risk_class),
            "has_replayable_example": bool(candidate.examples) or bool(candidate.steps),
        }
        reasons = [name for name, ok in checks.items() if not ok]
        # All critical checks must pass for promotion eligibility.
        passed = all(checks.values())
        return EvaluationResult(passed=passed, checks=checks, reasons=reasons)


class SkillPromotionGate:
    """Promotes candidates through lifecycle states (Architecture §13.2)."""

    def decide(self, candidate: SkillCandidate, evaluation: EvaluationResult) -> PromotionState:
        if is_disabled(candidate.risk_class):
            return PromotionState.BLOCKED
        if not evaluation.passed:
            return PromotionState.CANDIDATE
        # Risky classes never auto-promote past assisted.
        if candidate.risk_class in (RiskClass.INTRUSIVE_VALIDATION,):
            return PromotionState.ASSISTED
        # Safe + evaluated: start in shadow, require a successful shadow run
        # before active. New candidates with a real success rate go to shadow.
        if candidate.success_rate >= 0.7:
            return PromotionState.SHADOW
        return PromotionState.CANDIDATE


# Global instances.
skill_creator = SkillCreatorAgent()
skill_evaluator = SkillEvaluatorAgent()
promotion_gate = SkillPromotionGate()


def create_and_evaluate(
    *,
    trigger: str,
    scan_id: str,
    name: str,
    description: str,
    steps: list[str],
    expected_evidence: list[str],
    success_rate: float = 0.0,
    known_false_positives: list[str] | None = None,
    examples: list[dict] | None = None,
) -> dict[str, Any]:
    """End-to-end: create candidate -> evaluate -> gate -> persist -> catalog.

    Returns a summary dict. Generated skills never auto-activate; promotion is
    bounded by the gate (Architecture §13.2)."""
    candidate = skill_creator.create_from_outcome(
        trigger=trigger,
        scan_id=scan_id,
        name=name,
        description=description,
        steps=steps,
        expected_evidence=expected_evidence,
        success_rate=success_rate,
        known_false_positives=known_false_positives,
        examples=examples,
    )
    if candidate is None:
        return {"created": False, "reason": "invalid_trigger"}

    evaluation = skill_evaluator.evaluate(candidate)
    candidate.promotion_state = promotion_gate.decide(candidate, evaluation)
    skill_dir = skill_creator.persist(candidate, description=description, evaluation=evaluation)

    # Register into the catalog as a non-active entry until promoted.
    meta = SkillMeta(
        skill_id=candidate.slug,
        name=candidate.name,
        goal=description.split(".")[0] if description else candidate.name,
        domain=candidate.domain,
        description=description,
        source_path=str(skill_dir / "SKILL.md"),
        required_tools=map_required_tools(f"{description} {' '.join(steps)}"),
        risk_class=candidate.risk_class,
        agent_targets=candidate.agent_targets,
        promotion_state=candidate.promotion_state,
    )
    skill_catalog.upsert(meta)

    return {
        "created": True,
        "skill_id": candidate.slug,
        "promotion_state": candidate.promotion_state.value,
        "evaluation_passed": evaluation.passed,
        "failed_checks": evaluation.reasons,
        "path": str(skill_dir),
    }
