"""
Vigilagent Skill Registry (Architecture §5.3, §5.3.6)
================================================================================
First-class skill and playbook library. Skills are indexed, categorized, mapped
to agents, mapped to ATT&CK/OWASP/NIST where available, and executed only
through the same scope, sandbox, approval, budget, and evidence controls as
every other capability.

Components (Architecture §5.3.6):
  catalog.py    - skill metadata model + in-memory catalog
  loader.py     - scan SKILL.md files + index.json, parse frontmatter
  classifier.py - domain + risk-class classification
  mapper.py     - map skills to agents and required tools
  executor.py   - runtime skill execution contract (scope/approval/evidence)
  policy.py     - promotion states + risk policy gates

Skill files stay read-only; LLM prompt snippets are generated at runtime only.
"""

from backend.skills.catalog import SkillCatalog, SkillMeta, skill_catalog
from backend.skills.creator import (
    SkillCreatorAgent,
    SkillEvaluatorAgent,
    SkillPromotionGate,
    create_and_evaluate,
    promotion_gate,
    skill_creator,
    skill_evaluator,
)
from backend.skills.executor import SkillExecutor, SkillRunResult, skill_executor
from backend.skills.learning_loop import (
    PerScanLearningLoop,
    ScanOutcome,
    per_scan_learning_loop,
)
from backend.skills.loader import SkillLoader, ingest_skills, skill_loader
from backend.skills.policy import PromotionState, RiskClass

__all__ = [
    "SkillCatalog",
    "SkillMeta",
    "skill_catalog",
    "PromotionState",
    "RiskClass",
    "SkillLoader",
    "skill_loader",
    "ingest_skills",
    "SkillExecutor",
    "SkillRunResult",
    "skill_executor",
    "SkillCreatorAgent",
    "SkillEvaluatorAgent",
    "SkillPromotionGate",
    "skill_creator",
    "skill_evaluator",
    "promotion_gate",
    "create_and_evaluate",
    "PerScanLearningLoop",
    "ScanOutcome",
    "per_scan_learning_loop",
]
