"""
Skill runtime executor (Architecture §5.3.4, §5.3.3)
================================================================================
Every skill execution produces the structured output contract from §5.3.4 and
passes the same scope/approval/budget/evidence controls as every other
capability. This executor does NOT run arbitrary code; it orchestrates a skill's
declared tool runs through the governed Terminal Engine and records evidence.

Skill runtime contract (Architecture §5.3.4):
{
  "skill_id", "agent", "risk_class", "scope_decision", "approval_id",
  "inputs", "tool_runs", "evidence_ids", "findings", "confidence",
  "recommendations", "next_actions"
}
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.core.iteration_budget import IterationBudget, budget_config
from backend.core.scope import ScopePolicy, ScopeViolation, scope_guard
from backend.skills.catalog import SkillMeta, skill_catalog
from backend.skills.policy import PromotionState, RiskClass, can_auto_execute, is_disabled, requires_approval

logger = logging.getLogger("vigilagent.skills.executor")


# ──────────────────────────────────────────────────────────────────────────────
# Skill preprocessing — template variables (Architecture §29.3, §5.4)
# ------------------------------------------------------------------------------
# Adopted from Hermes' SKILL.md preprocessing (agent/skill_preprocessing.py):
# substitute ${TOKEN} placeholders in skill steps/inputs at runtime from the
# live scan/target/scope context. Following Hermes' stance, only tokens with a
# concrete value are substituted; unresolved tokens are left in place so the
# skill author can spot them instead of silently dropping context.
# ──────────────────────────────────────────────────────────────────────────────
_TEMPLATE_VAR_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")


def _substitute_template_vars(content: str, variables: dict[str, str]) -> str:
    """Replace ${TOKEN} placeholders in ``content`` from ``variables``.

    Unknown tokens are left untouched (Hermes parity) so missing scan/target
    context is debuggable rather than silently erased."""
    if not content or "${" not in content:
        return content

    def _replace(match: re.Match[str]) -> str:
        token = match.group(1)
        value = variables.get(token)
        return str(value) if value is not None else match.group(0)

    return _TEMPLATE_VAR_RE.sub(_replace, content)


def _render_obj(obj: Any, variables: dict[str, str]) -> Any:
    """Recursively substitute template vars in strings within ``obj``."""
    if isinstance(obj, str):
        return _substitute_template_vars(obj, variables)
    if isinstance(obj, list):
        return [_render_obj(item, variables) for item in obj]
    if isinstance(obj, dict):
        return {key: _render_obj(val, variables) for key, val in obj.items()}
    return obj


# Tool-availability cache (Architecture §5.4 "tool availability checks with
# caching"). Availability rarely changes within a process, so memoize the
# (relatively expensive) PATH/Docker probes per tool.
_tool_availability_cache: dict[str, dict] = {}


def _tool_availability(tool: str) -> dict:
    """Return cached availability info for ``tool`` (best-effort)."""
    cached = _tool_availability_cache.get(tool)
    if cached is not None:
        return cached
    try:
        from backend.tools.recon.registry import check_tool_availability

        info = check_tool_availability(tool)
    except Exception as exc:  # pragma: no cover - recon registry optional
        info = {"installed": None, "reason": f"check_unavailable:{exc}"}
    if not isinstance(info, dict):
        info = {"installed": bool(info)}
    _tool_availability_cache[tool] = info
    return info


def clear_tool_availability_cache() -> None:
    """Drop the in-process availability cache (test/reload hook)."""
    _tool_availability_cache.clear()


@dataclass
class SkillRunResult:
    """Structured skill runtime output (Architecture §5.3.4)."""

    skill_id: str
    agent: str
    risk_class: str
    scope_decision: str  # allowed | blocked | needs_approval | disabled
    approval_id: str = ""
    inputs: dict[str, Any] = field(default_factory=dict)
    tool_runs: list[dict] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    confidence: float = 0.0
    recommendations: list[str] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)
    error: str = ""
    # Preprocessing artifacts (Architecture §29.3, §5.4).
    template_vars: dict[str, str] = field(default_factory=dict)
    rendered_steps: list[Any] = field(default_factory=list)
    missing_tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "agent": self.agent,
            "risk_class": self.risk_class,
            "scope_decision": self.scope_decision,
            "approval_id": self.approval_id,
            "inputs": self.inputs,
            "tool_runs": self.tool_runs,
            "evidence_ids": self.evidence_ids,
            "findings": self.findings,
            "confidence": self.confidence,
            "recommendations": self.recommendations,
            "next_actions": self.next_actions,
            "error": self.error,
            "template_vars": self.template_vars,
            "rendered_steps": self.rendered_steps,
            "missing_tools": self.missing_tools,
        }


class SkillExecutor:
    """Executes a catalog skill under scope/approval/budget controls."""

    def __init__(self, scope: ScopePolicy | None = None) -> None:
        self.scope = scope or scope_guard

    def _build_template_vars(
        self,
        meta: SkillMeta,
        *,
        agent: str,
        scan_id: str,
        target: str,
        inputs: dict[str, Any],
    ) -> dict[str, str]:
        """Build the ${TOKEN} substitution map from live scan/target/scope
        context (Architecture §29.3). Mirrors Hermes' template-var approach
        (skill_preprocessing.substitute_template_vars) but sourced from the
        engagement instead of CLI session state.

        SKILL_DIR is the read-only source directory (parity with Hermes'
        HERMES_SKILL_DIR); SCAN_ID parallels HERMES_SESSION_ID."""
        skill_dir = ""
        if meta.source_path:
            try:
                skill_dir = str(Path(meta.source_path).parent)
            except Exception as e:
                logger.debug("[SkillExecutor] skill_dir resolve failed: %s", e)
                skill_dir = ""

        scope_name = ""
        try:
            scope_name = getattr(self.scope, "engagement_name", "") or ""
        except Exception as e:
            logger.debug("[SkillExecutor] scope_name resolve failed: %s", e)
            scope_name = ""

        variables: dict[str, str] = {
            "SCAN_ID": scan_id or "",
            "TARGET": target or "",
            "AGENT": agent or "",
            "SKILL_ID": meta.skill_id,
            "SKILL_NAME": meta.name,
            "SKILL_DIR": skill_dir,
            "DOMAIN": meta.domain,
            "SCOPE": scope_name,
        }
        # Expose scalar inputs as ${INPUT_<KEY>} so skill authors can thread
        # caller-supplied values (e.g. ${INPUT_PORT}) into steps at runtime.
        for key, val in (inputs or {}).items():
            if isinstance(val, (str, int, float, bool)):
                token = re.sub(r"[^A-Z0-9_]", "_", str(key).upper())
                variables[f"INPUT_{token}"] = str(val)
        # Only keep tokens that actually resolved (Hermes parity: unresolved
        # tokens are left in the text rather than substituted with blanks).
        return {k: v for k, v in variables.items() if v != ""}

    async def execute(
        self,
        skill_id: str,
        *,
        agent: str,
        scan_id: str = "GLOBAL",
        target: str = "",
        inputs: dict[str, Any] | None = None,
        budget: IterationBudget | None = None,
        approval_id: str = "",
    ) -> SkillRunResult:
        meta: SkillMeta | None = skill_catalog.get(skill_id)
        if not meta:
            return SkillRunResult(skill_id, agent, "unknown", "blocked", error=f"skill not found: {skill_id}")

        risk = meta.risk_class
        result = SkillRunResult(
            skill_id=skill_id,
            agent=agent,
            risk_class=risk.value,
            scope_decision="allowed",
            approval_id=approval_id,
            inputs=inputs or {},
        )

        # 1. Disabled risk classes never run (Architecture §5.3.3, §9).
        if is_disabled(risk):
            result.scope_decision = "disabled"
            result.error = "skill risk class is disabled_by_default"
            return result

        # 2. Approval gate for intrusive skills (Architecture §9).
        if requires_approval(risk) and not approval_id:
            result.scope_decision = "needs_approval"
            result.error = "intrusive skill requires an approval ticket"
            return result

        # 3. Promotion/auto-execute gate for generated skills (Architecture §13.2).
        if meta.promotion_state != PromotionState.ACTIVE and not approval_id:
            if not can_auto_execute(risk, meta.promotion_state):
                result.scope_decision = "needs_approval"
                result.error = f"skill promotion state '{meta.promotion_state.value}' not auto-executable"
                return result

        # 4. Scope check for network-touching skills (Architecture §9, §29.14).
        if meta.requires_network and target:
            action = (
                "validate" if risk in (RiskClass.CONTROLLED_VALIDATION, RiskClass.INTRUSIVE_VALIDATION) else "recon"
            )
            try:
                self.scope.assert_allowed(target, action=action)
            except ScopeViolation as exc:
                result.scope_decision = "blocked"
                result.error = f"scope: {exc}"
                return result

        # 5. Budget consume (Architecture §5, §29.3).
        budget = budget or budget_config.make("skill_run", label=f"skill:{skill_id}")
        if not budget.consume(1):
            result.scope_decision = "blocked"
            result.error = "skill_run budget exhausted"
            return result

        # 6. Skill preprocessing — template variables (Architecture §29.3, §5.4).
        # Build the live ${TOKEN} map and render it into the skill inputs/steps
        # so scan/target/scope context is substituted at runtime (Hermes parity).
        variables = self._build_template_vars(
            meta,
            agent=agent,
            scan_id=scan_id,
            target=target,
            inputs=result.inputs,
        )
        result.template_vars = variables
        result.inputs = _render_obj(result.inputs, variables)
        steps = meta.raw_frontmatter.get("steps") if isinstance(meta.raw_frontmatter, dict) else None
        if isinstance(steps, (list, dict)):
            result.rendered_steps = _render_obj(steps, variables)

        # 7. Precondition / tool-availability check before execution (§5.4).
        # Record which declared tools are not installed so the agent knows the
        # plan's gaps up front. Availability probes are cached per tool.
        missing: list[str] = []
        for tool in meta.required_tools:
            if _tool_availability(tool).get("installed") is False:
                missing.append(tool)
        result.missing_tools = missing

        # The catalog skill is a playbook reference. Concrete tool execution is
        # delegated to the requesting agent through the governed TerminalEngine /
        # payload delivery paths; here we return the prepared, authorized plan so
        # the agent can run the declared tools with full evidence capture.
        result.recommendations = [
            f"Run via {agent} using tools: {', '.join(meta.required_tools) or 'agent-native'}",
            f"Domain={meta.domain}, attack={meta.attack or 'n/a'}",
        ]
        if missing:
            result.recommendations.append(f"Preflight: install missing tools before execution: {', '.join(missing)}")
        result.next_actions = [f"execute_tool:{t}" for t in meta.required_tools]
        # Lower confidence when preconditions are unmet (some tools missing).
        result.confidence = 0.5 if not missing else max(0.1, 0.5 - 0.1 * len(missing))
        logger.info(
            "[SkillExecutor] %s authorized for %s (risk=%s, scope=%s, missing_tools=%d)",
            skill_id,
            agent,
            risk.value,
            result.scope_decision,
            len(missing),
        )
        return result


# Global executor.
skill_executor = SkillExecutor()
