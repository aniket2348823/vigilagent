"""
Skill risk + promotion policy (Architecture §5.3.3, §13.2)
================================================================================
Risk classes (Architecture §5.3.3) and promotion states (Architecture §13.2)
plus the gate that decides whether a skill may execute automatically.
"""

from __future__ import annotations

from enum import StrEnum


class RiskClass(StrEnum):
    """Offensive skill risk model (Architecture §5.3.3)."""

    ANALYSIS_ONLY = "analysis_only"  # read artifacts/logs/code/packets
    PASSIVE_RECON = "passive_recon"  # OSINT, public data
    ACTIVE_RECON = "active_recon"  # in-scope probing/scanning
    CONTROLLED_VALIDATION = "controlled_validation"  # bounded non-destructive PoV
    INTRUSIVE_VALIDATION = "intrusive_validation"  # higher-risk, explicit approval
    DISABLED_BY_DEFAULT = "disabled_by_default"  # persistence/stealth/destructive


# Risk classes that may run without per-action human approval inside an
# authorized engagement. Everything else requires approval or is disabled.
_AUTO_ALLOWED = {
    RiskClass.ANALYSIS_ONLY,
    RiskClass.PASSIVE_RECON,
    RiskClass.ACTIVE_RECON,
    RiskClass.CONTROLLED_VALIDATION,
}
_APPROVAL_REQUIRED = {RiskClass.INTRUSIVE_VALIDATION}
_DISABLED = {RiskClass.DISABLED_BY_DEFAULT}


class PromotionState(StrEnum):
    """Generated-skill lifecycle states (Architecture §13.2)."""

    CANDIDATE = "candidate"  # generated but not trusted
    SHADOW = "shadow"  # suggested but not executed automatically
    ASSISTED = "assisted"  # executable with approval/confirmation
    ACTIVE = "active"  # available for automatic use within policy
    DEPRECATED = "deprecated"  # replaced by a better skill
    BLOCKED = "blocked"  # unsafe / unreliable / harmful


def requires_approval(risk: RiskClass) -> bool:
    return risk in _APPROVAL_REQUIRED


def is_disabled(risk: RiskClass) -> bool:
    return risk in _DISABLED


def can_auto_execute(risk: RiskClass, promotion: PromotionState) -> bool:
    """Whether a skill may execute automatically (Architecture §5.3.3, §13.2).

    Both the risk class must be auto-allowed AND the promotion state must be
    ACTIVE. Disabled risk classes never run; intrusive needs approval; candidate/
    shadow/assisted/deprecated/blocked never auto-run."""
    if risk in _DISABLED:
        return False
    if promotion != PromotionState.ACTIVE:
        return False
    return risk in _AUTO_ALLOWED
