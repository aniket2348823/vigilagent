from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ObjectivePhase(str, Enum):
    RECON = "recon"
    DETECTION = "detection"
    VERIFICATION = "verification"
    EXPLOIT_VERIFY = "exploit-verify"
    REPORT = "report"


class ObjectiveStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in-progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingConfidence(str, Enum):
    VERIFIED = "verified"
    PROBABLE = "probable"
    UNVERIFIED = "unverified"


class VerificationSignal(str, Enum):
    """Independent verification signals (Architecture §17).

    A vulnerability requires MULTIPLE signals before it can be ``CONFIRMED``;
    these are the exact signal classes the verification model recognises.
    """
    STATUS_DIVERGENCE = "status_divergence"        # status code divergence
    BODY_STRUCTURAL_DIFF = "body_structural_diff"  # response body structural difference
    LENGTH_DIFF = "length_diff"                     # response length difference
    TIMING_DIFF = "timing_diff"                     # timing difference
    DOM_DIFF = "dom_diff"                           # DOM difference
    AUTH_BOUNDARY_DIFF = "auth_boundary_diff"      # auth boundary difference
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    REPEATABILITY = "repeatability"
    BASELINE_COMPARISON = "baseline_comparison"
    NEGATIVE_CONTROL = "negative_control"


class FindingState(str, Enum):
    """Finding lifecycle states (Architecture §17 verification model).

    A finding moves through these states as evidence accumulates. Only
    `CONFIRMED` findings carry full weight in reports; `FALSE_POSITIVE`,
    `DUPLICATE`, and `OUT_OF_SCOPE` are excluded from the active finding set.
    """
    CANDIDATE = "candidate"          # detected, not yet evidenced
    NEEDS_EVIDENCE = "needs_evidence"  # requires more signals
    LIKELY = "likely"                # strong but < confirmation threshold
    CONFIRMED = "confirmed"          # >= 2 independent signals agree
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    OUT_OF_SCOPE = "out_of_scope"
    ACCEPTED_RISK = "accepted_risk"


# Allowed forward transitions between finding states (Architecture §17).
FINDING_STATE_TRANSITIONS: dict[FindingState, set[FindingState]] = {
    FindingState.CANDIDATE: {FindingState.NEEDS_EVIDENCE, FindingState.LIKELY,
                             FindingState.CONFIRMED, FindingState.FALSE_POSITIVE,
                             FindingState.DUPLICATE, FindingState.OUT_OF_SCOPE},
    FindingState.NEEDS_EVIDENCE: {FindingState.LIKELY, FindingState.CONFIRMED,
                                  FindingState.FALSE_POSITIVE, FindingState.DUPLICATE,
                                  FindingState.OUT_OF_SCOPE},
    FindingState.LIKELY: {FindingState.CONFIRMED, FindingState.FALSE_POSITIVE,
                          FindingState.DUPLICATE, FindingState.OUT_OF_SCOPE},
    FindingState.CONFIRMED: {FindingState.FALSE_POSITIVE, FindingState.DUPLICATE,
                             FindingState.ACCEPTED_RISK},
    FindingState.FALSE_POSITIVE: set(),
    FindingState.DUPLICATE: set(),
    FindingState.OUT_OF_SCOPE: {FindingState.CANDIDATE},  # re-scoped
    FindingState.ACCEPTED_RISK: set(),
}


def can_transition(current: FindingState, target: FindingState) -> bool:
    """Whether a finding may move from ``current`` to ``target`` (Architecture §17)."""
    if current == target:
        return True
    return target in FINDING_STATE_TRANSITIONS.get(current, set())


class RemediationPriority(str, Enum):
    IMMEDIATE = "immediate"
    SHORT_TERM = "short-term"
    LONG_TERM = "long-term"


class Evidence(BaseModel):
    type: str = Field(description="http-request, http-response, screenshot, terminal-log, scan-output")
    path: str = ""
    description: str = ""
    sha256: str = ""
    collected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    data: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    title: str
    severity: FindingSeverity
    affected_target: str
    affected_component: str = ""
    description: str
    cvss_score: float | None = None
    cvss_vector: str = ""
    cvss_version: str = "3.1"
    cwe: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    steps_to_reproduce: list[str] = Field(default_factory=list)
    # Impact split (Architecture §18: business impact vs technical impact).
    impact: str = ""
    business_impact: str = ""
    technical_impact: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    remediation: str = ""
    remediation_priority: RemediationPriority | None = None
    references: list[str] = Field(default_factory=list)
    objective_id: str = ""
    phase: ObjectivePhase | None = None
    agent: str = ""
    confidence: FindingConfidence = FindingConfidence.VERIFIED
    # Lifecycle state + scope status (Architecture §17, §18).
    state: FindingState = FindingState.CANDIDATE
    scope_status: str = "in_scope"   # in_scope | out_of_scope | unknown
    # False-positive controls applied during verification (Architecture §18).
    false_positive_controls: list[str] = Field(default_factory=list)
    verified_methods: list[str] = Field(default_factory=list)
    # Independent verification signals observed (Architecture §17). A finding
    # requires MULTIPLE signals before it can be confirmed.
    verification_signals: list[VerificationSignal] = Field(default_factory=list)
    discovered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def has_multiple_signals(self, minimum: int = 2) -> bool:
        """Whether enough independent signals exist to support confirmation (§17)."""
        return len(set(self.verification_signals)) >= minimum


class ScanObjective(BaseModel):
    id: str
    phase: ObjectivePhase
    title: str
    description: str = ""
    endpoint_group: str = ""
    status: ObjectiveStatus = ObjectiveStatus.PENDING
    owasp_category: str = ""
    priority: int = 5
    blocked_by: list[str] = Field(default_factory=list)
    acceptance_criteria: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    owner: str = ""
    notes: str = ""
    parent_id: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class AttackPathStep(BaseModel):
    order: int
    phase: ObjectivePhase
    technique: str
    source: str
    target: str
    tool: str = ""
    finding_id: str = ""


class AttackPath(BaseModel):
    id: str
    name: str
    description: str = ""
    steps: list[AttackPathStep] = Field(default_factory=list)
    combined_severity: FindingSeverity = FindingSeverity.CRITICAL
    finding_ids: list[str] = Field(default_factory=list)
