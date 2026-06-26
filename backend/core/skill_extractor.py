"""
SKILL EXTRACTOR
Converts learned patterns into executable skills.

This extractor:
1. Identifies high-confidence patterns worthy of becoming skills
2. Extracts reusable components (templates, generators, procedures)
3. Generates skill metadata (name, description, prerequisites)
4. Validates skill structure
5. Versions skills for evolution tracking
"""

import hashlib
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from backend.core.learning_engine import LearningPattern, learning_engine

logger = logging.getLogger("SkillExtractor")


@dataclass
class Skill:
    """Represents an executable skill extracted from learned patterns."""

    skill_id: str
    name: str
    description: str
    skill_type: str  # "payload_generation", "endpoint_discovery", "attack_chain", "evasion"

    # Pattern source
    source_pattern_ids: list[str]
    confidence: float
    success_rate: float
    sample_size: int

    # Execution data
    payload_template: str | None = None
    target_pattern: str | None = None
    prerequisites: list[str] = None
    parameters: dict[str, Any] = None

    # Metadata
    version: str = "1.0.0"
    created_at: float = 0.0
    last_updated: float = 0.0
    times_used: int = 0
    times_successful: int = 0

    # Tags for categorization
    tags: list[str] = None

    def __post_init__(self):
        if self.prerequisites is None:
            self.prerequisites = []
        if self.parameters is None:
            self.parameters = {}
        if self.tags is None:
            self.tags = []
        if self.created_at == 0.0:
            self.created_at = time.time()
        if self.last_updated == 0.0:
            self.last_updated = time.time()


class SkillExtractor:
    """
    Extracts executable skills from learned patterns.
    """

    def __init__(self, brain_dir: str = "brain"):
        self.brain_dir = Path(brain_dir)
        self.skills_dir = self.brain_dir / "skills"
        self.skills_dir.mkdir(parents=True, exist_ok=True)

        # Extraction thresholds
        self.thresholds = {
            "min_confidence": 0.7,
            "min_success_rate": 0.6,
            "min_sample_size": 10,
        }

    async def extract_skills_from_patterns(self) -> list[Skill]:
        """
        Extract skills from all high-confidence patterns.
        Returns list of newly created skills.
        """
        logger.info("[SkillExtractor] Extracting skills from learned patterns...")

        new_skills = []

        # Get all patterns from learning engine
        # CRITICAL FIX (#36): Iterate directly over the dict items view without
        # materializing intermediate lists. Each pattern is processed once and
        # discarded, keeping memory O(1) instead of O(n).
        patterns = learning_engine.patterns

        for pattern in patterns.values():
            if not self._is_skill_worthy(pattern):
                continue
            pt = pattern.pattern_type
            skill = None
            if pt == "payload_success":
                skill = self._extract_payload_skill(pattern)
            elif pt == "endpoint_pattern":
                skill = self._extract_endpoint_skill(pattern)
            elif pt == "vuln_correlation":
                skill = self._extract_chain_skill(pattern)
            if skill:
                new_skills.append(skill)

        logger.info(f"[SkillExtractor] Extracted {len(new_skills)} new skills")

        return new_skills

    def _is_skill_worthy(self, pattern: LearningPattern) -> bool:
        """Check if pattern meets thresholds to become a skill."""
        return (
            pattern.confidence >= self.thresholds["min_confidence"]
            and pattern.success_rate >= self.thresholds["min_success_rate"]
            and (pattern.success_count + pattern.failure_count) >= self.thresholds["min_sample_size"]
        )

    def _extract_payload_skill(self, pattern: LearningPattern) -> Skill | None:
        """Extract payload generation skill from pattern."""
        try:
            vuln_type = pattern.pattern_data.get("vuln_type", "unknown")
            payload_sample = pattern.pattern_data.get("payload_sample", "")
            features = pattern.pattern_data.get("payload_features", {})

            if not payload_sample:
                return None

            # Generate skill ID
            skill_id = self._generate_skill_id("payload", vuln_type, pattern.pattern_id)

            # Create descriptive name
            name = f"{vuln_type.replace('_', ' ').title()} Payload Generator"

            # Generate description
            description = f"Generates {vuln_type} payloads based on learned patterns. "
            description += f"Success rate: {pattern.success_rate:.1%} over {pattern.success_count + pattern.failure_count} attempts."

            # Extract payload template (replace specific values with placeholders)
            template = self._generalize_payload(payload_sample, features)

            # Determine prerequisites
            prerequisites = []
            if features.get("has_sql_keywords"):
                prerequisites.append("database_detected")
            if features.get("has_script_tag"):
                prerequisites.append("html_context")

            # Create skill
            skill = Skill(
                skill_id=skill_id,
                name=name,
                description=description,
                skill_type="payload_generation",
                source_pattern_ids=[pattern.pattern_id],
                confidence=pattern.confidence,
                success_rate=pattern.success_rate,
                sample_size=pattern.success_count + pattern.failure_count,
                payload_template=template,
                prerequisites=prerequisites,
                parameters={"vuln_type": vuln_type, "features": features},
                tags=[vuln_type.lower(), "payload", "generation"],
            )

            return skill

        except Exception as e:
            logger.error(f"[SkillExtractor] Failed to extract payload skill: {e}")
            return None

    def _extract_endpoint_skill(self, pattern: LearningPattern) -> Skill | None:
        """Extract endpoint discovery skill from pattern."""
        try:
            vuln_type = pattern.pattern_data.get("vuln_type", "unknown")
            url_pattern = pattern.pattern_data.get("url_pattern", "")

            if not url_pattern:
                return None

            # Generate skill ID
            skill_id = self._generate_skill_id("endpoint", vuln_type, pattern.pattern_id)

            # Create descriptive name
            name = f"{vuln_type.replace('_', ' ').title()} Endpoint Detector"

            # Generate description
            description = f"Identifies endpoints vulnerable to {vuln_type}. "
            description += f"Pattern: {url_pattern}. "
            description += f"Success rate: {pattern.success_rate:.1%} over {pattern.success_count + pattern.failure_count} attempts."

            # Create skill
            skill = Skill(
                skill_id=skill_id,
                name=name,
                description=description,
                skill_type="endpoint_discovery",
                source_pattern_ids=[pattern.pattern_id],
                confidence=pattern.confidence,
                success_rate=pattern.success_rate,
                sample_size=pattern.success_count + pattern.failure_count,
                target_pattern=url_pattern,
                parameters={"vuln_type": vuln_type, "url_pattern": url_pattern},
                tags=[vuln_type.lower(), "endpoint", "discovery"],
            )

            return skill

        except Exception as e:
            logger.error(f"[SkillExtractor] Failed to extract endpoint skill: {e}")
            return None

    def _extract_chain_skill(self, pattern: LearningPattern) -> Skill | None:
        """Extract attack chain skill from correlation pattern."""
        try:
            vuln_type_1 = pattern.pattern_data.get("vuln_type_1", "")
            vuln_type_2 = pattern.pattern_data.get("vuln_type_2", "")

            if not vuln_type_1 or not vuln_type_2:
                return None

            # Generate skill ID
            skill_id = self._generate_skill_id("chain", f"{vuln_type_1}_{vuln_type_2}", pattern.pattern_id)

            # Create descriptive name
            name = f"{vuln_type_1} → {vuln_type_2} Attack Chain"

            # Generate description
            description = f"Multi-step attack chain: {vuln_type_1} followed by {vuln_type_2}. "
            description += f"Correlation confidence: {pattern.confidence:.1%}."

            # Create skill
            skill = Skill(
                skill_id=skill_id,
                name=name,
                description=description,
                skill_type="attack_chain",
                source_pattern_ids=[pattern.pattern_id],
                confidence=pattern.confidence,
                success_rate=pattern.success_rate,
                sample_size=pattern.success_count + pattern.failure_count,
                prerequisites=[vuln_type_1.lower()],
                parameters={"step_1": vuln_type_1, "step_2": vuln_type_2, "correlation": "co_occurrence"},
                tags=[vuln_type_1.lower(), vuln_type_2.lower(), "chain", "multi-step"],
            )

            return skill

        except Exception as e:
            logger.error(f"[SkillExtractor] Failed to extract chain skill: {e}")
            return None

    def _generalize_payload(self, payload: str, features: dict[str, Any]) -> str:
        """
        Generalize payload by replacing specific values with placeholders.
        """
        template = payload

        # CRITICAL FIX (#41): re is now imported at module level.
        # Replace numbers with {number}
        template = re.sub(r"\b\d+\b", "{number}", template)

        # Replace quoted strings with {string}
        template = re.sub(r"'[^']*'", "'{string}'", template)
        template = re.sub(r'"[^"]*"', '"{string}"', template)

        # Replace common SQL keywords with uppercase
        if features.get("has_sql_keywords"):
            for keyword in ["select", "union", "from", "where", "or", "and"]:
                template = re.sub(rf"\b{keyword}\b", keyword.upper(), template, flags=re.IGNORECASE)

        return template

    def _generate_skill_id(self, skill_type: str, category: str, pattern_id: str) -> str:
        """Generate unique skill ID."""
        data = f"{skill_type}:{category}:{pattern_id}"
        hash_val = hashlib.sha256(data.encode()).hexdigest()[:12]
        return f"{skill_type}_{category.lower()}_{hash_val}"

    def get_extraction_metrics(self) -> dict[str, Any]:
        """Get metrics about skill extraction."""
        patterns = learning_engine.patterns

        skill_worthy = sum(1 for p in patterns.values() if self._is_skill_worthy(p))

        by_type = {
            "endpoint_pattern": sum(
                1 for p in patterns.values() if p.pattern_type == "endpoint_pattern" and self._is_skill_worthy(p)
            ),
            "payload_success": sum(
                1 for p in patterns.values() if p.pattern_type == "payload_success" and self._is_skill_worthy(p)
            ),
            "vuln_correlation": sum(
                1 for p in patterns.values() if p.pattern_type == "vuln_correlation" and self._is_skill_worthy(p)
            ),
        }

        return {
            "total_patterns": len(patterns),
            "skill_worthy_patterns": skill_worthy,
            "by_type": by_type,
            "thresholds": self.thresholds,
            "timestamp": time.time(),
        }


# Global skill extractor instance
skill_extractor = SkillExtractor()


# ============================================================================
# WORKFLOW SKILL EXTRACTION (Section 15)
# ============================================================================


class WorkflowSkillExtractor:
    """
    Extracts multi-step browser workflows as reusable skills.
    """

    def __init__(self, skill_library: Any):
        self.skill_library = skill_library
        self.workflow_tracking: dict[str, dict[str, Any]] = {}

    def extract_workflow_skill(self, workflow_data: dict[str, Any], success: bool) -> Any | None:
        """
        Extract workflow from successful multi-step browser operation.
        Returns BrowserSkill if workflow is worthy of extraction.
        """
        if not success:
            return None

        workflow_id = workflow_data.get("workflow_id")
        steps = workflow_data.get("steps", [])

        if not steps or len(steps) < 2:
            return None  # Not a multi-step workflow

        # Extract workflow steps with success conditions
        extracted_steps = []
        for step in steps:
            extracted_steps.append(
                {
                    "action": step.get("action"),
                    "target": step.get("target"),
                    "parameters": step.get("parameters", {}),
                    "success_condition": step.get("success_condition"),
                    "timing_ms": step.get("timing_ms", 0),
                }
            )

        # Extract session requirements
        session_required = workflow_data.get("session_required", False)
        stealth_required = workflow_data.get("stealth_required", False)
        framework = workflow_data.get("framework")

        # Create workflow skill
        from backend.core.skill_library import BrowserSkill

        skill = BrowserSkill(
            skill_id=f"workflow_{hashlib.sha256(workflow_id.encode()).hexdigest()[:12]}",
            name=f"Workflow: {workflow_data.get('name', 'Unnamed')}",
            skill_type="browser_workflow",
            execution_context="browser_required",
            browser_requirements={"stealth": stealth_required, "session": session_required, "framework": framework},
            workflow_steps=extracted_steps,
            version="1.0.0",
            required_capabilities=frozenset(["browser", "workflow"]),
            success_rate=1.0,  # Initial success
            confidence=0.7,
            created_at=time.time(),
            tags=["workflow", "browser", "multi_step"],
            parameters={
                "success_conditions": [
                    step.get("success_condition") for step in steps if step.get("success_condition")
                ],
                "total_timing_ms": sum(step.get("timing_ms", 0) for step in steps),
            },
        )

        logger.info(f"[WorkflowExtractor] Extracted workflow skill: {skill.name} ({len(extracted_steps)} steps)")

        return skill

    def track_workflow_execution(self, workflow_id: str, success: bool, execution_time_ms: float):
        """Track workflow execution for success rate calculation."""
        if workflow_id not in self.workflow_tracking:
            self.workflow_tracking[workflow_id] = {
                "success_count": 0,
                "failure_count": 0,
                "total_time_ms": 0.0,
                "executions": 0,
            }

        tracking = self.workflow_tracking[workflow_id]
        tracking["executions"] += 1
        tracking["total_time_ms"] += execution_time_ms

        if success:
            tracking["success_count"] += 1
        else:
            tracking["failure_count"] += 1

        # Calculate success rate
        tracking["success_rate"] = tracking["success_count"] / tracking["executions"]

    def get_workflow_stats(self, workflow_id: str) -> dict[str, Any] | None:
        """Get statistics for a workflow."""
        return self.workflow_tracking.get(workflow_id)


class AdaptiveWorkflowExecutor:
    """
    Executes workflow skills with adaptive step modification.
    """

    def __init__(self):
        self.execution_history: list[dict[str, Any]] = []

    async def execute_workflow(self, workflow_skill: Any, target_url: str, browser_orchestrator: Any) -> dict[str, Any]:
        """
        Execute workflow skill with adaptive step modification.
        Adapts steps based on target responses.
        """
        logger.info(f"[AdaptiveWorkflow] Executing workflow: {workflow_skill.name}")

        execution_result = {
            "workflow_id": workflow_skill.skill_id,
            "success": False,
            "steps_completed": 0,
            "steps_total": len(workflow_skill.workflow_steps),
            "adaptations": [],
            "execution_time_ms": 0.0,
        }

        start_time = time.time()

        try:
            for i, step in enumerate(workflow_skill.workflow_steps):
                step_result = await self._execute_step(step, target_url, browser_orchestrator, execution_result)

                execution_result["steps_completed"] += 1

                if not step_result["success"]:
                    # Try to adapt step
                    adapted = await self._adapt_step(step, step_result, browser_orchestrator)
                    if adapted:
                        execution_result["adaptations"].append(
                            {"step_index": i, "original_action": step["action"], "adaptation": adapted}
                        )
                        # Retry with adapted step
                        step_result = await self._execute_step(
                            adapted, target_url, browser_orchestrator, execution_result
                        )

                if not step_result["success"]:
                    logger.warning(f"[AdaptiveWorkflow] Step {i + 1} failed, aborting workflow")
                    break

            # Check if all steps completed
            execution_result["success"] = execution_result["steps_completed"] == execution_result["steps_total"]

        except Exception as e:
            logger.error(f"[AdaptiveWorkflow] Workflow execution error: {e}")
            execution_result["error"] = str(e)

        execution_result["execution_time_ms"] = (time.time() - start_time) * 1000

        self.execution_history.append(execution_result)

        return execution_result

    async def _execute_step(
        self, step: dict[str, Any], target_url: str, browser_orchestrator: Any, execution_context: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a single workflow step."""
        action = step.get("action")
        target = step.get("target")
        step.get("parameters", {})

        logger.debug(f"[AdaptiveWorkflow] Executing step: {action} on {target}")

        # Simulate step execution (actual implementation would call browser_orchestrator)
        # For now, return success
        return {"success": True, "action": action, "target": target, "response": {}}

    async def _adapt_step(
        self, step: dict[str, Any], step_result: dict[str, Any], browser_orchestrator: Any
    ) -> dict[str, Any] | None:
        """
        Adapt a failed step based on the failure reason.
        Returns adapted step or None if no adaptation possible.
        """
        action = step.get("action")

        # Example adaptations
        if action == "click":
            # Try alternative selector
            return {
                **step,
                "target": step["target"].replace("id=", "css="),
                "parameters": {**step.get("parameters", {}), "retry": True},
            }
        elif action == "input":
            # Try slower typing
            return {**step, "parameters": {**step.get("parameters", {}), "delay_ms": 100}}

        return None

    def get_execution_stats(self) -> dict[str, Any]:
        """Get workflow execution statistics."""
        if not self.execution_history:
            return {"total_executions": 0, "success_rate": 0.0, "avg_execution_time_ms": 0.0, "total_adaptations": 0}

        successful = sum(1 for e in self.execution_history if e["success"])
        total_time = sum(e["execution_time_ms"] for e in self.execution_history)
        total_adaptations = sum(len(e.get("adaptations", [])) for e in self.execution_history)

        return {
            "total_executions": len(self.execution_history),
            "success_rate": successful / len(self.execution_history),
            "avg_execution_time_ms": total_time / len(self.execution_history),
            "total_adaptations": total_adaptations,
            "adaptation_rate": total_adaptations / len(self.execution_history),
        }


# Global instances
workflow_extractor: WorkflowSkillExtractor | None = None
adaptive_executor = AdaptiveWorkflowExecutor()


def initialize_workflow_extractor(skill_library: Any):
    """Initialize the global workflow extractor."""
    global workflow_extractor
    workflow_extractor = WorkflowSkillExtractor(skill_library)
    return workflow_extractor
