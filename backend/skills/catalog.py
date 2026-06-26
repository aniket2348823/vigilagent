"""
Skill catalog + metadata model (Architecture §5.3.1, §5.3.6)
================================================================================
Normalized metadata extracted from every skill (Architecture §5.3.1) and an
in-memory catalog that caches it. Source skill files remain read-only.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from backend.skills.policy import PromotionState, RiskClass


@dataclass
class SkillMeta:
    """Normalized skill metadata (Architecture §5.3.1)."""

    skill_id: str
    name: str
    goal: str = ""
    domain: str = "uncategorized"  # see classifier domains (§5.3.2)
    description: str = ""
    source_path: str = ""  # read-only source location
    # Capability descriptors
    required_tools: list[str] = field(default_factory=list)
    required_files: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    # Safety descriptors
    risk_class: RiskClass = RiskClass.ANALYSIS_ONLY
    offensive: bool = False
    requires_network: bool = False
    changes_remote_state: bool = False
    requires_approval: bool = False
    # Mappings (Architecture §5.3.1)
    attack: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    nist: list[str] = field(default_factory=list)
    # Agent routing (Architecture §5.3.5)
    agent_targets: list[str] = field(default_factory=list)
    # Lifecycle
    promotion_state: PromotionState = PromotionState.CANDIDATE
    version: str = "1.0.0"
    author: str = ""
    raw_frontmatter: dict[str, Any] = field(default_factory=dict)

    def prompt_snippet(self) -> str:
        """Generate an LLM prompt snippet at runtime (Architecture §5.3.6).

        Built on demand and never persisted, so source skill files stay
        read-only. Used by agents to inject a skill into their reasoning."""
        tools = ", ".join(self.required_tools) or "agent-native tooling"
        attack = ", ".join(self.attack) if self.attack else "n/a"
        return (
            f"Skill: {self.name} (id={self.skill_id})\n"
            f"Goal: {self.goal or self.description or self.name}\n"
            f"Domain: {self.domain} | Risk: {self.risk_class.value}\n"
            f"Suggested tools: {tools}\n"
            f"ATT&CK: {attack}\n"
            "Constraints: stay in scope; non-destructive unless approved; capture evidence."
        )

    def to_dict(self) -> dict[str, Any]:
        d = {
            "skill_id": self.skill_id,
            "name": self.name,
            "goal": self.goal,
            "domain": self.domain,
            "description": self.description,
            "source_path": self.source_path,
            "required_tools": self.required_tools,
            "required_files": self.required_files,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "risk_class": self.risk_class.value,
            "offensive": self.offensive,
            "requires_network": self.requires_network,
            "changes_remote_state": self.changes_remote_state,
            "requires_approval": self.requires_approval,
            "attack": self.attack,
            "owasp": self.owasp,
            "nist": self.nist,
            "agent_targets": self.agent_targets,
            "promotion_state": self.promotion_state.value,
            "version": self.version,
            "author": self.author,
        }
        return d


class SkillCatalog:
    """Thread-safe in-memory catalog of normalized skill metadata."""

    def __init__(self) -> None:
        self._skills: dict[str, SkillMeta] = {}
        self._lock = threading.RLock()

    def upsert(self, meta: SkillMeta) -> None:
        with self._lock:
            self._skills[meta.skill_id] = meta

    def get(self, skill_id: str) -> SkillMeta | None:
        with self._lock:
            return self._skills.get(skill_id)

    def all(self) -> list[SkillMeta]:
        with self._lock:
            return list(self._skills.values())

    def by_domain(self, domain: str) -> list[SkillMeta]:
        with self._lock:
            return [s for s in self._skills.values() if s.domain == domain]

    def by_agent(self, agent: str) -> list[SkillMeta]:
        a = agent.lower()
        with self._lock:
            return [s for s in self._skills.values() if any(a == t.lower() for t in s.agent_targets)]

    def by_risk(self, risk: RiskClass) -> list[SkillMeta]:
        with self._lock:
            return [s for s in self._skills.values() if s.risk_class == risk]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            by_domain: dict[str, int] = {}
            by_risk: dict[str, int] = {}
            for s in self._skills.values():
                by_domain[s.domain] = by_domain.get(s.domain, 0) + 1
                by_risk[s.risk_class.value] = by_risk.get(s.risk_class.value, 0) + 1
            return {"total": len(self._skills), "by_domain": by_domain, "by_risk": by_risk}

    def clear(self) -> None:
        with self._lock:
            self._skills.clear()


# Global catalog singleton.
skill_catalog = SkillCatalog()
