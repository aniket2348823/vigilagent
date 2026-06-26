"""
SKILL LIBRARY
Persistent storage and management for agent skills.

This library:
1. CRUD operations for skills
2. Version control and skill evolution tracking
3. Skill search by type, confidence, tags
4. Skill validation and safety checks
5. Skill deprecation and lifecycle management
6. Import/export for skill sharing
"""

import json
import logging
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from backend.core.skill_extractor import Skill

logger = logging.getLogger("SkillLibrary")


# ============================================================================
# BrowserSkill (Task §3.1 — Deep System Integration)
# ----------------------------------------------------------------------------
# Field contract (must remain stable for downstream tasks 3.2, 3.4, 3.6):
#   skill_id, name, description, skill_type, execution_context,
#   browser_requirements, workflow_steps, evidence_requirements,
#   framework, vuln_type, confidence,
#   success_count, failure_count, scan_count, last_used, created_at,
#   promoted, tags, source_pattern_id
#
# Architecture invariants honored here:
#   §11  two-LLM exclusivity   — pure dataclass, no LLM in scope
#   §17  ≥2-signal             — promotion is the consumer's job (task 3.2);
#                                this class only stores `promoted: bool`
#   §29.13 non-blocking        — no blocking I/O in any method
#   §9   scope-is-law          — `evidence_requirements` MUST NOT contain a
#                                'host' key. Host context is stored on the
#                                informational-only `evidence_host_hint`
#                                field; it must NEVER be used as a filter.
#
# Compatibility shim: the previous BrowserSkill shape (used by
# learning_engine.store_auth_pattern_as_skill, skill_extractor.WorkflowSkill-
# Extractor, and BrowserSkillLibraryExtension.compose_workflows) is preserved
# by accepting legacy kwargs (`success_rate`, `version`,
# `required_capabilities`, `usage_count`, `deprecated`, `deprecation_reason`,
# `last_updated`, `parameters`) and translating them into the new model.
# ============================================================================

_BROWSER_SKILL_TYPES = (
    "browser_vulnerability",
    "browser_workflow",
    "framework_pattern",
)
_BROWSER_AUTOMATION_TAG = "browser_automation"


@dataclass(init=False)
class BrowserSkill:
    """Browser-specific skill with execution requirements (Task §3.1)."""

    # --- Contract fields ---
    skill_id: str = ""
    name: str = ""
    description: str = ""
    skill_type: str = ""
    execution_context: str = "browser_required"
    browser_requirements: dict[str, Any] = field(default_factory=dict)
    workflow_steps: list[dict[str, Any]] = field(default_factory=list)
    evidence_requirements: dict[str, Any] = field(default_factory=dict)
    framework: str | None = None
    vuln_type: str | None = None
    confidence: float = 0.6
    success_count: int = 0
    failure_count: int = 0
    scan_count: int = 0
    last_used: float | None = None
    created_at: float = field(default_factory=time.time)
    promoted: bool = False
    tags: list[str] = field(default_factory=list)
    source_pattern_id: str | None = None
    # §9 — informational only; MUST NOT be used as a filter or scope gate.
    evidence_host_hint: str | None = None

    # --- Legacy compatibility fields (preserved for existing callers) ---
    version: str = "1.0.0"
    required_capabilities: frozenset = field(default_factory=frozenset)
    usage_count: int = 0
    deprecated: bool = False
    deprecation_reason: str = ""
    last_updated: float = 0.0
    parameters: dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        skill_id: str = "",
        name: str = "",
        description: str = "",
        skill_type: str = "",
        execution_context: str = "browser_required",
        browser_requirements: dict[str, Any] | None = None,
        workflow_steps: list[dict[str, Any]] | None = None,
        evidence_requirements: Any | None = None,
        framework: str | None = None,
        vuln_type: str | None = None,
        confidence: float = 0.6,
        success_count: int = 0,
        failure_count: int = 0,
        scan_count: int = 0,
        last_used: float | None = None,
        created_at: float | None = None,
        promoted: bool = False,
        tags: list[str] | None = None,
        source_pattern_id: str | None = None,
        evidence_host_hint: str | None = None,
        # --- Legacy kwargs (compat shim) ---
        success_rate: float | None = None,
        version: str = "1.0.0",
        required_capabilities: Iterable[str] | None = None,
        usage_count: int = 0,
        deprecated: bool = False,
        deprecation_reason: str = "",
        last_updated: float = 0.0,
        parameters: dict[str, Any] | None = None,
        **_unknown: Any,
    ) -> None:
        # ---- Contract assignments ----
        self.skill_id = str(skill_id)
        self.name = str(name)
        self.description = str(description)
        self.skill_type = str(skill_type)
        self.execution_context = str(execution_context) if execution_context else "browser_required"
        self.browser_requirements = dict(browser_requirements) if browser_requirements else {}
        self.workflow_steps = list(workflow_steps) if workflow_steps else []

        # evidence_requirements: contract type is Dict[str, Any]; legacy callers
        # may pass a List[str] (from old JSON on disk). Normalize.
        if evidence_requirements is None:
            self.evidence_requirements = {}
        elif isinstance(evidence_requirements, dict):
            self.evidence_requirements = dict(evidence_requirements)
        elif isinstance(evidence_requirements, (list, tuple, set, frozenset)):
            self.evidence_requirements = {str(item): True for item in evidence_requirements}
        else:
            self.evidence_requirements = {}
        # §9: scope-is-law — strip any 'host' key proactively.
        self.evidence_requirements.pop("host", None)

        self.framework = framework if framework is None else str(framework)
        self.vuln_type = vuln_type if vuln_type is None else str(vuln_type)
        try:
            self.confidence = float(confidence)
        except (TypeError, ValueError):
            self.confidence = 0.6
        self.success_count = max(0, int(success_count))
        self.failure_count = max(0, int(failure_count))
        self.scan_count = max(0, int(scan_count))
        self.last_used = float(last_used) if last_used is not None else None
        self.created_at = float(created_at) if created_at is not None else time.time()
        self.promoted = bool(promoted)

        # tags: always contains "browser_automation" per contract.
        tag_list = [str(t) for t in tags] if tags else []
        if _BROWSER_AUTOMATION_TAG not in tag_list:
            tag_list.append(_BROWSER_AUTOMATION_TAG)
        self.tags = tag_list

        self.source_pattern_id = source_pattern_id if source_pattern_id is None else str(source_pattern_id)
        self.evidence_host_hint = evidence_host_hint if evidence_host_hint is None else str(evidence_host_hint)

        # ---- Legacy field assignments (preserved for compat) ----
        self.version = str(version) if version else "1.0.0"
        if required_capabilities is None:
            self.required_capabilities = frozenset()
        elif isinstance(required_capabilities, frozenset):
            self.required_capabilities = required_capabilities
        else:
            try:
                self.required_capabilities = frozenset(required_capabilities)
            except TypeError:
                self.required_capabilities = frozenset()
        self.usage_count = max(0, int(usage_count))
        self.deprecated = bool(deprecated)
        self.deprecation_reason = str(deprecation_reason)
        try:
            self.last_updated = float(last_updated)
        except (TypeError, ValueError):
            self.last_updated = 0.0
        self.parameters = dict(parameters) if parameters else {}

        # Legacy `success_rate=X` kwarg: seed counts when caller hasn't supplied
        # success_count/failure_count. We approximate fractional rates with a
        # 10-sample baseline so the property returns roughly the same value.
        if success_rate is not None and self.success_count == 0 and self.failure_count == 0:
            try:
                rate = max(0.0, min(1.0, float(success_rate)))
            except (TypeError, ValueError):
                rate = 0.0
            if rate >= 1.0:
                self.success_count = 1
            elif rate <= 0.0:
                self.failure_count = 1
            else:
                self.success_count = int(round(rate * 10))
                self.failure_count = max(0, 10 - self.success_count)

        # _unknown is intentionally ignored (forward-compat for from_dict).

    # ---- Properties ----
    @property
    def success_rate(self) -> float:
        """Per §3.1 contract: success_count / max(1, success_count + failure_count)."""
        return self.success_count / max(1, self.success_count + self.failure_count)

    # ---- Helpers ----
    def matches_capabilities(self, caps: dict[str, bool]) -> bool:
        """Return True only when every key of `browser_requirements` whose value
        is truthy-boolean is also truthy in `caps`. Non-bool requirement values
        (e.g., a `framework` string) are not capability gates and are skipped.
        """
        if not isinstance(caps, dict):
            return False
        for key, value in self.browser_requirements.items():
            if value is True and not bool(caps.get(key, False)):
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe serialization. frozensets become lists."""
        return {
            # Contract fields
            "skill_id": self.skill_id,
            "name": self.name,
            "description": self.description,
            "skill_type": self.skill_type,
            "execution_context": self.execution_context,
            "browser_requirements": dict(self.browser_requirements),
            "workflow_steps": list(self.workflow_steps),
            "evidence_requirements": dict(self.evidence_requirements),
            "framework": self.framework,
            "vuln_type": self.vuln_type,
            "confidence": self.confidence,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "scan_count": self.scan_count,
            "last_used": self.last_used,
            "created_at": self.created_at,
            "promoted": self.promoted,
            "tags": list(self.tags),
            "source_pattern_id": self.source_pattern_id,
            "evidence_host_hint": self.evidence_host_hint,
            # Derived (read-only)
            "success_rate": self.success_rate,
            # Legacy fields (round-trip with on-disk JSON)
            "version": self.version,
            "required_capabilities": sorted(self.required_capabilities),
            "usage_count": self.usage_count,
            "deprecated": self.deprecated,
            "deprecation_reason": self.deprecation_reason,
            "last_updated": self.last_updated,
            "parameters": dict(self.parameters),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BrowserSkill":
        """Strict reverse with field validation.

        - Unknown fields are ignored (dropped silently).
        - Missing required contract fields raise ValueError.
        """
        if not isinstance(data, dict):
            raise ValueError("BrowserSkill.from_dict expects a dict")

        required = (
            "skill_id",
            "name",
            "description",
            "skill_type",
            "execution_context",
            "browser_requirements",
            "workflow_steps",
            "evidence_requirements",
        )
        missing = [k for k in required if k not in data]
        if missing:
            raise ValueError(f"BrowserSkill.from_dict missing required fields: {missing}")

        # Whitelist of constructor kwargs (contract + legacy compat).
        known = {
            "skill_id",
            "name",
            "description",
            "skill_type",
            "execution_context",
            "browser_requirements",
            "workflow_steps",
            "evidence_requirements",
            "framework",
            "vuln_type",
            "confidence",
            "success_count",
            "failure_count",
            "scan_count",
            "last_used",
            "created_at",
            "promoted",
            "tags",
            "source_pattern_id",
            "evidence_host_hint",
            # Legacy
            "success_rate",
            "version",
            "required_capabilities",
            "usage_count",
            "deprecated",
            "deprecation_reason",
            "last_updated",
            "parameters",
        }
        kwargs = {k: v for k, v in data.items() if k in known}
        return cls(**kwargs)


def _sanitize_filename(name: str) -> str:
    """Sanitize a string to be a valid Windows filename."""
    # Windows invalid characters: < > : " / \ | ? *
    # Replace with safe alternatives
    replacements = {
        ":": "_",
        "<": "_",
        ">": "_",
        '"': "_",
        "/": "_",
        "\\": "_",
        "|": "_",
        "?": "_",
        "*": "_",
    }
    result = name
    for char, replacement in replacements.items():
        result = result.replace(char, replacement)
    return result


class SkillLibrary:
    """
    Manages persistent storage and retrieval of agent skills.
    """

    def __init__(self, brain_dir: str = "brain"):
        self.brain_dir = Path(brain_dir)
        self.skills_dir = self.brain_dir / "skills"
        self.skills_dir.mkdir(parents=True, exist_ok=True)

        # Create category directories
        self.categories = ["payload", "endpoint", "chain", "evasion"]
        for category in self.categories:
            (self.skills_dir / category).mkdir(exist_ok=True)

        # Metadata index
        self.metadata_file = self.skills_dir / "metadata.json"
        self.metadata: dict[str, dict[str, Any]] = {}

        # Browser skill indexes
        self.capability_index: dict[str, set] = {}  # capability -> set of skill_ids
        self.context_index: dict[str, set] = {}  # context -> set of skill_ids
        self.framework_index: dict[str, set] = {}  # framework -> set of skill_ids
        self.version_tracking: dict[str, list[str]] = {}  # skill_name -> list of versions

        self._load_metadata()
        self._rebuild_indexes()

    def _load_metadata(self):
        """Load skill metadata index."""
        if self.metadata_file.exists():
            try:
                self.metadata = json.loads(self.metadata_file.read_text(encoding="utf-8"))
                logger.info(f"[SkillLibrary] Loaded {len(self.metadata)} skills from metadata")
            except Exception as e:
                logger.error(f"[SkillLibrary] Failed to load metadata: {e}")
                self.metadata = {}
        else:
            self.metadata = {}

    def _rebuild_indexes(self):
        """Rebuild indexes - implemented in extension"""
        pass

    def _save_metadata(self):
        """Save skill metadata index."""
        try:
            self.metadata_file.write_text(json.dumps(self.metadata, indent=2), encoding="utf-8")
        except Exception as e:
            logger.error(f"[SkillLibrary] Failed to save metadata: {e}")

    def add_skill(self, skill: Skill) -> bool:
        """
        Add a new skill to the library.
        Returns True if successful.
        """
        try:
            # Check if skill already exists
            if skill.skill_id in self.metadata:
                logger.warning(f"[SkillLibrary] Skill {skill.skill_id} already exists")
                return False

            # Determine category directory
            category = self._get_category(skill.skill_type)
            safe_id = _sanitize_filename(skill.skill_id)
            skill_file = self.skills_dir / category / f"{safe_id}.json"

            # Save skill to file
            skill_file.write_text(json.dumps(asdict(skill), indent=2), encoding="utf-8")

            # Update metadata index
            self.metadata[skill.skill_id] = {
                "name": skill.name,
                "skill_type": skill.skill_type,
                "confidence": skill.confidence,
                "success_rate": skill.success_rate,
                "version": skill.version,
                "created_at": skill.created_at,
                "tags": skill.tags,
                "file_path": str(skill_file.relative_to(self.skills_dir)),
            }

            self._save_metadata()

            logger.info(f"[SkillLibrary] Added skill: {skill.name} ({skill.skill_id})")
            return True

        except Exception as e:
            logger.error(f"[SkillLibrary] Failed to add skill: {e}")
            return False

    def get_skill(self, skill_id: str) -> Skill | None:
        """
        Retrieve a skill by ID.
        Returns None if not found.
        """
        if skill_id not in self.metadata:
            return None

        try:
            file_path = self.skills_dir / self.metadata[skill_id]["file_path"]
            skill_data = json.loads(file_path.read_text(encoding="utf-8"))
            return Skill(**skill_data)
        except Exception as e:
            logger.error(f"[SkillLibrary] Failed to load skill {skill_id}: {e}")
            return None

    def update_skill(self, skill: Skill) -> bool:
        """
        Update an existing skill.
        Increments version number.
        """
        if skill.skill_id not in self.metadata:
            logger.warning(f"[SkillLibrary] Cannot update non-existent skill {skill.skill_id}")
            return False

        try:
            # Increment version
            version_parts = skill.version.split(".")
            version_parts[-1] = str(int(version_parts[-1]) + 1)
            skill.version = ".".join(version_parts)
            skill.last_updated = time.time()

            # Save updated skill
            file_path = self.skills_dir / self.metadata[skill.skill_id]["file_path"]
            file_path.write_text(json.dumps(asdict(skill), indent=2), encoding="utf-8")

            # Update metadata
            self.metadata[skill.skill_id].update(
                {
                    "confidence": skill.confidence,
                    "success_rate": skill.success_rate,
                    "version": skill.version,
                    "last_updated": skill.last_updated,
                }
            )

            self._save_metadata()

            logger.info(f"[SkillLibrary] Updated skill: {skill.name} to v{skill.version}")
            return True

        except Exception as e:
            logger.error(f"[SkillLibrary] Failed to update skill: {e}")
            return False

    def delete_skill(self, skill_id: str) -> bool:
        """
        Delete a skill from the library.
        """
        if skill_id not in self.metadata:
            return False

        try:
            # Delete file
            file_path = self.skills_dir / self.metadata[skill_id]["file_path"]
            if file_path.exists():
                file_path.unlink()

            # Remove from metadata
            del self.metadata[skill_id]
            self._save_metadata()

            logger.info(f"[SkillLibrary] Deleted skill: {skill_id}")
            return True

        except Exception as e:
            logger.error(f"[SkillLibrary] Failed to delete skill: {e}")
            return False

    def search_skills(
        self,
        skill_type: str | None = None,
        min_confidence: float | None = None,
        min_success_rate: float | None = None,
        tags: list[str] | None = None,
        limit: int = 50,
    ) -> list[Skill]:
        """
        Search for skills matching criteria.
        """
        results = []

        for skill_id, meta in self.metadata.items():
            # Apply filters
            if skill_type and meta["skill_type"] != skill_type:
                continue

            if min_confidence and meta["confidence"] < min_confidence:
                continue

            if min_success_rate and meta["success_rate"] < min_success_rate:
                continue

            if tags:
                skill_tags = set(meta.get("tags", []))
                if not any(tag in skill_tags for tag in tags):
                    continue

            # Load full skill
            skill = self.get_skill(skill_id)
            if skill:
                results.append(skill)

            if len(results) >= limit:
                break

        # Sort by confidence
        results.sort(key=lambda s: s.confidence, reverse=True)

        return results

    def get_all_skills(self) -> list[Skill]:
        """Get all skills in the library."""
        skills = []
        for skill_id in self.metadata.keys():
            skill = self.get_skill(skill_id)
            if skill:
                skills.append(skill)
        return skills

    def get_skills_by_type(self, skill_type: str) -> list[Skill]:
        """Get all skills of a specific type."""
        return self.search_skills(skill_type=skill_type, limit=1000)

    def get_top_skills(self, limit: int = 10) -> list[Skill]:
        """Get top skills by confidence and success rate."""
        all_skills = self.get_all_skills()

        # Sort by combined score
        all_skills.sort(key=lambda s: s.confidence * 0.5 + s.success_rate * 0.5, reverse=True)

        return all_skills[:limit]

    def get_recommendations(
        self,
        *,
        target_url: str | None = None,
        vuln_class: str | None = None,
        skill_type: str | None = None,
        min_confidence: float = 0.5,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Return ranked skill recommendations for planning.

        This is the READ path required by Architecture §6.7 and §29.2: Omega,
        Sigma, Beta, Gamma, Kappa, and the Planner query this before forming a
        plan (not only when stuck). Results are scored by confidence and
        historical success rate and returned as plain dicts so any consumer can
        use them without importing the Skill type.
        """
        candidates = self.search_skills(skill_type=skill_type, min_confidence=min_confidence, limit=1000)
        recs: list[dict[str, Any]] = []
        needle = (vuln_class or skill_type or "").lower()
        target = (target_url or "").lower()
        for skill in candidates:
            score = getattr(skill, "confidence", 0.5) * 0.5 + getattr(skill, "success_rate", 0.0) * 0.5
            text = f"{getattr(skill, 'name', '')} {getattr(skill, 'description', '')} {getattr(skill, 'skill_type', '')}".lower()
            # Light relevance boost when the recommendation matches the query.
            if needle and needle in text:
                score += 0.25
            if target and target in text:
                score += 0.1
            recs.append(
                {
                    "skill_id": getattr(skill, "skill_id", ""),
                    "name": getattr(skill, "name", ""),
                    "skill_type": getattr(skill, "skill_type", ""),
                    "description": getattr(skill, "description", ""),
                    "confidence": getattr(skill, "confidence", 0.5),
                    "success_rate": getattr(skill, "success_rate", 0.0),
                    "score": round(score, 4),
                }
            )
        recs.sort(key=lambda r: r["score"], reverse=True)
        return recs[:limit]

    def deprecate_skill(self, skill_id: str, reason: str) -> bool:
        """
        Mark a skill as deprecated.
        """
        skill = self.get_skill(skill_id)
        if not skill:
            return False

        # Add deprecation info to parameters
        skill.parameters["deprecated"] = True
        skill.parameters["deprecation_reason"] = reason
        skill.parameters["deprecated_at"] = time.time()

        return self.update_skill(skill)

    def export_skill(self, skill_id: str, export_path: str) -> bool:
        """
        Export a skill to a file for sharing.
        """
        skill = self.get_skill(skill_id)
        if not skill:
            return False

        try:
            export_file = Path(export_path)
            export_file.parent.mkdir(parents=True, exist_ok=True)

            export_data = {"skill": asdict(skill), "exported_at": time.time(), "exported_from": "Vigilagent"}

            export_file.write_text(json.dumps(export_data, indent=2), encoding="utf-8")

            logger.info(f"[SkillLibrary] Exported skill {skill_id} to {export_path}")
            return True

        except Exception as e:
            logger.error(f"[SkillLibrary] Failed to export skill: {e}")
            return False

    def import_skill(self, import_path: str) -> str | None:
        """
        Import a skill from a file.
        Returns skill_id if successful.
        """
        try:
            import_file = Path(import_path)
            if not import_file.exists():
                logger.error(f"[SkillLibrary] Import file not found: {import_path}")
                return None

            import_data = json.loads(import_file.read_text(encoding="utf-8"))
            skill_data = import_data.get("skill")

            if not skill_data:
                logger.error("[SkillLibrary] Invalid import file format")
                return None

            skill = Skill(**skill_data)

            # Reset usage stats for imported skill
            skill.times_used = 0
            skill.times_successful = 0
            skill.created_at = time.time()
            skill.last_updated = time.time()

            if self.add_skill(skill):
                logger.info(f"[SkillLibrary] Imported skill: {skill.name}")
                return skill.skill_id

            return None

        except Exception as e:
            logger.error(f"[SkillLibrary] Failed to import skill: {e}")
            return None

    def record_skill_usage(self, skill_id: str, success: bool):
        """
        Record usage of a skill for tracking effectiveness.
        """
        skill = self.get_skill(skill_id)
        if not skill:
            return

        skill.times_used += 1
        if success:
            skill.times_successful += 1

        # Update success rate
        if skill.times_used > 0:
            skill.success_rate = skill.times_successful / skill.times_used

        self.update_skill(skill)

    def _get_category(self, skill_type: str) -> str:
        """Get category directory for skill type."""
        if "payload" in skill_type:
            return "payload"
        elif "endpoint" in skill_type:
            return "endpoint"
        elif "chain" in skill_type:
            return "chain"
        elif "evasion" in skill_type:
            return "evasion"
        else:
            return "payload"  # Default

    def get_library_stats(self) -> dict[str, Any]:
        """Get statistics about the skill library."""
        all_skills = self.get_all_skills()

        by_type = {}
        for skill in all_skills:
            by_type[skill.skill_type] = by_type.get(skill.skill_type, 0) + 1

        total_usage = sum(s.times_used for s in all_skills)
        total_success = sum(s.times_successful for s in all_skills)

        return {
            "total_skills": len(all_skills),
            "by_type": by_type,
            "total_usage": total_usage,
            "total_success": total_success,
            "overall_success_rate": total_success / total_usage if total_usage > 0 else 0.0,
            "avg_confidence": sum(s.confidence for s in all_skills) / len(all_skills) if all_skills else 0.0,
            "timestamp": time.time(),
        }

    # ------------------------------------------------------------------
    # Browser-skill surface (deep-system-integration spec, Tasks 3.2 / 3.4 / 3.6)
    # ------------------------------------------------------------------
    #
    # These delegating methods expose the BrowserSkillLibraryExtension API
    # directly on SkillLibrary so callers (and the v2 migration in
    # backend/skills/migrations/v2_browser.py) can do
    # ``skill_library.add_browser_skill(...)`` without reaching into the
    # extension singleton.
    #
    # Architecture invariants honoured here:
    #   §11 two-LLM exclusivity   — pure storage / index ops, no LLM calls.
    #   §17 ≥2-signal evidence    — these methods do NOT verify or promote;
    #                                that's the learning loop's job.
    #   §29.13 non-blocking       — synchronous ops only; no awaits.
    #   §9 scope-is-law           — host info on a skill is NEVER a scope grant.
    # ------------------------------------------------------------------
    def add_browser_skill(
        self,
        skill: "BrowserSkill",
        context_requirements: dict[str, Any] | None = None,
    ) -> bool:
        """Validate semver, dedupe by skill_id, persist, update indexes.

        Delegates to ``BrowserSkillLibraryExtension.add_browser_skill`` so
        capability/context/framework indexes stay in sync.
        """
        ext = _get_browser_skill_extension(self)
        return ext.add_browser_skill(skill, context_requirements or {})

    def search_browser_skills(
        self,
        context: str | None = None,
        framework: str | None = None,
        capabilities: list[str] | None = None,
        limit: int = 50,
    ) -> list["BrowserSkill"]:
        """O(1) index lookups, intersect sets, filter deprecated, sort by
        success_rate then usage.

        Per Task 3.4 contract: ``capabilities`` is the agent's capability list;
        a skill is included only when its ``required_capabilities`` is a
        subset of the agent's caps.
        """
        ext = _get_browser_skill_extension(self)
        return ext.search_browser_skills(
            agent_capabilities=list(capabilities or []),
            context=context,
            framework=framework,
            limit=limit,
        )

    def compose_workflows(self, skill_ids: list[str]) -> Optional["BrowserSkill"]:
        """Compose multiple workflow skills (referenced by skill_id) into one.

        Per Task 3.6 contract:
          * validate every constituent is a workflow
          * merge ``workflow_steps`` in order
          * union ``browser_requirements`` (booleans OR-merged)
          * union ``evidence_requirements``
          * new ``skill_id`` = sha256 of the constituent ids
        """
        if not isinstance(skill_ids, list) or not skill_ids:
            return None
        # Resolve each skill_id from disk metadata.
        resolved: list[BrowserSkill] = []
        for sid in skill_ids:
            if sid not in self.metadata:
                logger.warning(f"[SkillLibrary] compose_workflows: skill_id {sid} not found")
                return None
            meta = self.metadata[sid]
            skill_path = self.skills_dir / meta["file_path"]
            try:
                data = json.loads(skill_path.read_text(encoding="utf-8"))
            except Exception as e:
                logger.error(f"[SkillLibrary] compose_workflows: cannot read {sid}: {e}")
                return None
            # Convert to BrowserSkill iff it has the browser shape.
            if "execution_context" not in data:
                logger.warning(f"[SkillLibrary] compose_workflows: {sid} is not a browser skill")
                return None
            try:
                resolved.append(BrowserSkill.from_dict(data))
            except Exception as e:
                logger.error(f"[SkillLibrary] compose_workflows: bad skill data for {sid}: {e}")
                return None

        # Delegate the merge logic to the extension, then override the
        # synthesized skill_id with the SHA-256 of the constituent ids
        # (per Task 3.6 contract).
        ext = _get_browser_skill_extension(self)
        composed = ext.compose_workflows(resolved)
        if composed is None:
            return None

        import hashlib as _hl

        sha = _hl.sha256(json.dumps(skill_ids, sort_keys=True).encode()).hexdigest()[:24]
        composed.skill_id = f"composed_{sha}"

        # Union of evidence_requirements (extension already merges browser_reqs).
        merged_evidence: dict[str, Any] = {}
        for s in resolved:
            for k, v in (s.evidence_requirements or {}).items():
                # Booleans OR-merge; non-booleans last-write-wins.
                if isinstance(v, bool):
                    merged_evidence[k] = bool(merged_evidence.get(k, False)) or v
                else:
                    merged_evidence[k] = v
        composed.evidence_requirements = merged_evidence

        return composed


# Global skill library instance
skill_library = SkillLibrary()


# ============================================================================
# BROWSER SKILL LIBRARY EXTENSION
# ============================================================================


class BrowserSkillLibraryExtension:
    """Extension for browser-specific skill management with indexing"""

    def __init__(self, skill_library: SkillLibrary):
        self.library = skill_library

    def _rebuild_indexes(self):
        """Rebuild all indexes from metadata"""
        self.library.capability_index.clear()
        self.library.context_index.clear()
        self.library.framework_index.clear()
        self.library.version_tracking.clear()

        for skill_id, meta in self.library.metadata.items():
            # Index by capabilities
            caps = meta.get("required_capabilities", [])
            if isinstance(caps, (list, set)):
                for cap in caps:
                    if cap not in self.library.capability_index:
                        self.library.capability_index[cap] = set()
                    self.library.capability_index[cap].add(skill_id)

            # Index by execution context
            context = meta.get("execution_context")
            if context:
                if context not in self.library.context_index:
                    self.library.context_index[context] = set()
                self.library.context_index[context].add(skill_id)

            # Index by framework
            browser_reqs = meta.get("browser_requirements", {})
            framework = browser_reqs.get("framework") if isinstance(browser_reqs, dict) else None
            if framework:
                if framework not in self.library.framework_index:
                    self.library.framework_index[framework] = set()
                self.library.framework_index[framework].add(skill_id)

            # Track versions
            name = meta.get("name", "")
            version = meta.get("version", "1.0.0")
            if name:
                if name not in self.library.version_tracking:
                    self.library.version_tracking[name] = []
                if version not in self.library.version_tracking[name]:
                    self.library.version_tracking[name].append(version)

    def add_browser_skill(self, skill: BrowserSkill, context_requirements: dict[str, Any]) -> bool:
        """
        Add a browser skill to the library with indexing.
        Returns True if successful.
        """
        try:
            # Validate version format (semver)
            version_parts = skill.version.split(".")
            if len(version_parts) != 3 or not all(p.isdigit() for p in version_parts):
                logger.error(f"[SkillLibrary] Invalid version format: {skill.version}")
                return False

            # Check for duplicates
            if skill.skill_id in self.library.metadata:
                logger.warning(f"[SkillLibrary] Browser skill {skill.skill_id} already exists")
                return False

            # Determine category directory
            category = self.library._get_category(skill.skill_type)
            safe_id = _sanitize_filename(skill.skill_id)
            skill_file = self.library.skills_dir / category / f"{safe_id}.json"

            # Save skill to file - convert frozenset to list for proper JSON serialization
            skill_dict = asdict(skill)
            if isinstance(skill_dict.get("required_capabilities"), frozenset):
                skill_dict["required_capabilities"] = list(skill_dict["required_capabilities"])
            skill_file.write_text(json.dumps(skill_dict, indent=2, default=str), encoding="utf-8")

            # Update metadata index
            self.library.metadata[skill.skill_id] = {
                "name": skill.name,
                "skill_type": skill.skill_type,
                "execution_context": skill.execution_context,
                "browser_requirements": skill.browser_requirements,
                "required_capabilities": list(skill.required_capabilities),
                "confidence": skill.confidence,
                "success_rate": skill.success_rate,
                "version": skill.version,
                "deprecated": skill.deprecated,
                "created_at": skill.created_at or time.time(),
                "tags": skill.tags + ["browser_automation"],
                "file_path": str(skill_file.relative_to(self.library.skills_dir)),
            }

            # Update indexes
            for cap in skill.required_capabilities:
                if cap not in self.library.capability_index:
                    self.library.capability_index[cap] = set()
                self.library.capability_index[cap].add(skill.skill_id)

            if skill.execution_context:
                if skill.execution_context not in self.library.context_index:
                    self.library.context_index[skill.execution_context] = set()
                self.library.context_index[skill.execution_context].add(skill.skill_id)

            framework = skill.browser_requirements.get("framework")
            if framework:
                if framework not in self.library.framework_index:
                    self.library.framework_index[framework] = set()
                self.library.framework_index[framework].add(skill.skill_id)

            # Track version
            if skill.name not in self.library.version_tracking:
                self.library.version_tracking[skill.name] = []
            if skill.version not in self.library.version_tracking[skill.name]:
                self.library.version_tracking[skill.name].append(skill.version)

            self.library._save_metadata()

            logger.info(f"[SkillLibrary] Added browser skill: {skill.name} ({skill.skill_id})")
            return True

        except Exception as e:
            logger.error(f"[SkillLibrary] Failed to add browser skill: {e}")
            return False

    def search_browser_skills(
        self, agent_capabilities: list[str], context: str | None = None, framework: str | None = None, limit: int = 50
    ) -> list[BrowserSkill]:
        """
        Search for browser skills matching criteria using indexes.
        Returns skills that match agent capabilities.
        """
        # Start with all skills
        candidate_ids = set(self.library.metadata.keys())

        # Filter by context if provided
        if context and context in self.library.context_index:
            candidate_ids &= self.library.context_index[context]

        # Filter by framework if provided
        if framework and framework in self.library.framework_index:
            candidate_ids &= self.library.framework_index[framework]

        # Filter by capabilities (skill capabilities must be subset of agent capabilities)
        agent_caps_set = set(agent_capabilities)
        matching_skills = []

        for skill_id in candidate_ids:
            meta = self.library.metadata[skill_id]

            # Skip deprecated skills
            if meta.get("deprecated", False):
                continue

            # Check if skill capabilities are subset of agent capabilities
            skill_caps = set(meta.get("required_capabilities", []))
            if skill_caps.issubset(agent_caps_set):
                # Load full skill
                skill_file = self.library.skills_dir / meta["file_path"]
                try:
                    skill_data = json.loads(skill_file.read_text(encoding="utf-8"))
                    # Convert to BrowserSkill if it has browser fields
                    if "execution_context" in skill_data:
                        # Convert required_capabilities back to frozenset
                        if "required_capabilities" in skill_data:
                            skill_data["required_capabilities"] = frozenset(skill_data["required_capabilities"])
                        skill = BrowserSkill(**skill_data)
                        matching_skills.append(skill)
                except Exception as e:
                    logger.error(f"[SkillLibrary] Failed to load skill {skill_id}: {e}")

            if len(matching_skills) >= limit:
                break

        # Sort by success rate and usage
        matching_skills.sort(key=lambda s: s.success_rate * 0.6 + (s.usage_count / 100) * 0.4, reverse=True)

        return matching_skills[:limit]

    def compose_workflows(self, workflow_skills: list[BrowserSkill]) -> BrowserSkill | None:
        """
        Compose multiple workflow skills into a single composed skill.
        Returns composed skill or None if incompatible.
        """
        if not workflow_skills:
            return None

        # Validate all are workflows
        for skill in workflow_skills:
            if not skill.workflow_steps:
                logger.error(f"[SkillLibrary] Skill {skill.name} is not a workflow")
                return None

        # Check compatibility (all must have compatible browser requirements)
        base_reqs = workflow_skills[0].browser_requirements
        for skill in workflow_skills[1:]:
            if skill.browser_requirements.get("framework") != base_reqs.get("framework"):
                logger.error("[SkillLibrary] Incompatible frameworks in workflow composition")
                return None

        # Merge workflow steps
        all_steps = []
        for skill in workflow_skills:
            all_steps.extend(skill.workflow_steps)

        # Merge success conditions
        all_conditions = []
        for skill in workflow_skills:
            if "success_conditions" in skill.parameters:
                all_conditions.extend(skill.parameters["success_conditions"])

        # Merge browser requirements
        merged_reqs = base_reqs.copy()
        for skill in workflow_skills:
            for key, value in skill.browser_requirements.items():
                if key == "stealth" or key == "session":
                    # Use OR logic for boolean requirements
                    merged_reqs[key] = merged_reqs.get(key, False) or value
                else:
                    merged_reqs[key] = value

        # Merge capabilities
        all_caps = set()
        for skill in workflow_skills:
            all_caps.update(skill.required_capabilities)

        # Create composed skill
        composed = BrowserSkill(
            skill_id=f"composed_{'_'.join(s.skill_id[:8] for s in workflow_skills)}",
            name=f"Composed: {' + '.join(s.name for s in workflow_skills)}",
            skill_type="composed_workflow",
            execution_context="browser_required",
            browser_requirements=merged_reqs,
            workflow_steps=all_steps,
            version="1.0.0",
            required_capabilities=frozenset(all_caps),
            success_rate=min(s.success_rate for s in workflow_skills),
            confidence=min(s.confidence for s in workflow_skills),
            created_at=time.time(),
            tags=["composed", "workflow"],
            parameters={"success_conditions": all_conditions},
        )

        logger.info(f"[SkillLibrary] Composed workflow from {len(workflow_skills)} skills")
        return composed

    def deprecate_skill(self, skill_id: str, reason: str, migration_path: str | None = None) -> bool:
        """
        Mark a skill as deprecated.
        """
        if skill_id not in self.library.metadata:
            return False

        # Update metadata
        self.library.metadata[skill_id]["deprecated"] = True
        self.library.metadata[skill_id]["deprecation_reason"] = reason
        if migration_path:
            self.library.metadata[skill_id]["migration_path"] = migration_path

        self.library._save_metadata()

        logger.info(f"[SkillLibrary] Deprecated skill {skill_id}: {reason}")
        return True


# Create global browser skill library extension
browser_skill_library = BrowserSkillLibraryExtension(skill_library)


# ------------------------------------------------------------------
# Lazy resolver for SkillLibrary.add_browser_skill / search_browser_skills /
# compose_workflows. Defined after the extension class so methods on
# SkillLibrary can reach the singleton without a forward-reference.
# ------------------------------------------------------------------
def _get_browser_skill_extension(library: SkillLibrary) -> "BrowserSkillLibraryExtension":
    """Return the BrowserSkillLibraryExtension bound to ``library``.

    For the global ``skill_library`` singleton we return the global
    ``browser_skill_library`` instance; for any other ``library`` (e.g. test
    fixtures), we lazily attach a fresh extension so each library gets its
    own indexes.
    """
    if library is skill_library:
        return browser_skill_library
    cached = getattr(library, "_browser_skill_extension", None)
    if cached is None:
        cached = BrowserSkillLibraryExtension(library)
        library._browser_skill_extension = cached
    return cached
