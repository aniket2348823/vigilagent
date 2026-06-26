"""
Alpha V6 Structured Event Schemas.

Type-safe Pydantic schemas for all EventBus payloads emitted by Alpha.
Replaces loose dicts with validated, documented event structures.
"""

from __future__ import annotations

import time
from typing import Any, Literal

from pydantic import BaseModel, Field


class ReconEventBase(BaseModel):
    """Base schema for all Alpha recon events."""

    scan_id: str
    agent: str = "agent_alpha"
    timestamp: float = Field(default_factory=time.time)


# ── Phase Lifecycle Events ────────────────────────────────────


class PhaseStartedEvent(ReconEventBase):
    event_type: Literal["RECON_PHASE_STARTED"] = "RECON_PHASE_STARTED"
    phase: str
    phase_index: int = 0
    total_phases: int = 0
    tools_planned: list[str] = Field(default_factory=list)


class PhaseCompletedEvent(ReconEventBase):
    event_type: Literal["RECON_PHASE_COMPLETED"] = "RECON_PHASE_COMPLETED"
    phase: str
    entities_found: int = 0
    tools_run: int = 0
    tools_failed: int = 0
    duration_ms: int = 0


# ── Tool Lifecycle Events ─────────────────────────────────────


class ToolStartedEvent(ReconEventBase):
    event_type: Literal["RECON_TOOL_STARTED"] = "RECON_TOOL_STARTED"
    tool_name: str
    phase: str
    argv_hash: str = ""


class ToolCompletedEvent(ReconEventBase):
    event_type: Literal["RECON_TOOL_COMPLETED"] = "RECON_TOOL_COMPLETED"
    tool_name: str
    phase: str
    status: str  # finished | failed | timeout | skipped | blocked
    exit_code: int = 0
    duration_ms: int = 0
    output_bytes: int = 0
    entities_parsed: int = 0
    artifact_id: str = ""


class ToolSkippedEvent(ReconEventBase):
    event_type: Literal["RECON_TOOL_SKIPPED"] = "RECON_TOOL_SKIPPED"
    tool_name: str
    phase: str
    reason: str


# ── Entity Discovery Events ──────────────────────────────────


class EntityDiscoveredEvent(ReconEventBase):
    event_type: Literal["RECON_ENTITY_DISCOVERED"] = "RECON_ENTITY_DISCOVERED"
    kind: str
    label: str
    confidence: float = 0.0
    source_tool: str = ""
    phase: str = ""
    properties: dict[str, Any] = Field(default_factory=dict)


class VulnCandidateEvent(ReconEventBase):
    event_type: Literal["RECON_VULN_CANDIDATE"] = "RECON_VULN_CANDIDATE"
    name: str
    severity: str
    target: str
    confidence: float
    template_id: str = ""
    source_tool: str = ""
    description: str = ""


class SecretFoundEvent(ReconEventBase):
    event_type: Literal["RECON_SECRET_FOUND"] = "RECON_SECRET_FOUND"
    secret_type: str
    redacted_value: str  # Always redacted for events
    source_file: str = ""
    source_tool: str = ""
    confidence: float = 0.0


# ── Scope & Approval Events ──────────────────────────────────


class ScopeViolationEvent(ReconEventBase):
    event_type: Literal["RECON_SCOPE_VIOLATION"] = "RECON_SCOPE_VIOLATION"
    target: str
    reason: str
    phase: str = ""


class ApprovalRequiredEvent(ReconEventBase):
    event_type: Literal["RECON_APPROVAL_REQUIRED"] = "RECON_APPROVAL_REQUIRED"
    approval_id: str
    phase: str
    tools: list[str] = Field(default_factory=list)
    description: str = ""
    target_count: int = 0


class ApprovalResponseEvent(ReconEventBase):
    event_type: Literal["RECON_APPROVAL_RESPONSE"] = "RECON_APPROVAL_RESPONSE"
    approval_id: str
    approved: bool
    responded_by: str = "user"


# ── Scan Lifecycle Events ─────────────────────────────────────


class ReconStartedEvent(ReconEventBase):
    event_type: Literal["RECON_STARTED"] = "RECON_STARTED"
    target: str
    mode: str
    phases_planned: list[str] = Field(default_factory=list)


class ReconPacketEvent(ReconEventBase):
    """Incremental recon data packet — sent after each phase."""

    event_type: Literal["RECON_PACKET"] = "RECON_PACKET"
    phase: str
    subdomains: list[str] = Field(default_factory=list)
    live_hosts: list[str] = Field(default_factory=list)
    endpoints: list[dict[str, Any]] = Field(default_factory=list)
    js_files: list[str] = Field(default_factory=list)
    secrets_count: int = 0
    vuln_candidates_count: int = 0
    summary: dict[str, Any] = Field(default_factory=dict)


class ReconCompleteEvent(ReconEventBase):
    """Final recon completion event — contains full summary for downstream agents."""

    event_type: Literal["RECON_COMPLETE"] = "RECON_COMPLETE"
    target: str
    mode: str
    duration_seconds: float = 0
    total_subdomains: int = 0
    total_live_hosts: int = 0
    total_endpoints: int = 0
    total_open_ports: int = 0
    total_js_files: int = 0
    total_parameters: int = 0
    total_secrets: int = 0
    total_vuln_candidates: int = 0
    tools_run: list[str] = Field(default_factory=list)
    tools_failed: list[str] = Field(default_factory=list)
    top_endpoints: list[dict[str, Any]] = Field(default_factory=list)
    attack_surface: dict[str, Any] = Field(default_factory=dict)
    artifact_manifest_path: str = ""
    export_paths: dict[str, str] = Field(default_factory=dict)


# ── OOB Interaction Events ────────────────────────────────────


class OOBInteractionEvent(ReconEventBase):
    event_type: Literal["RECON_OOB_INTERACTION"] = "RECON_OOB_INTERACTION"
    protocol: str
    remote_address: str = ""
    correlation_id: str = ""
    severity: str = "high"


# ── Event Registry ────────────────────────────────────────────

EVENT_SCHEMAS: dict[str, type[ReconEventBase]] = {
    "RECON_PHASE_STARTED": PhaseStartedEvent,
    "RECON_PHASE_COMPLETED": PhaseCompletedEvent,
    "RECON_TOOL_STARTED": ToolStartedEvent,
    "RECON_TOOL_COMPLETED": ToolCompletedEvent,
    "RECON_TOOL_SKIPPED": ToolSkippedEvent,
    "RECON_ENTITY_DISCOVERED": EntityDiscoveredEvent,
    "RECON_VULN_CANDIDATE": VulnCandidateEvent,
    "RECON_SECRET_FOUND": SecretFoundEvent,
    "RECON_SCOPE_VIOLATION": ScopeViolationEvent,
    "RECON_APPROVAL_REQUIRED": ApprovalRequiredEvent,
    "RECON_APPROVAL_RESPONSE": ApprovalResponseEvent,
    "RECON_STARTED": ReconStartedEvent,
    "RECON_PACKET": ReconPacketEvent,
    "RECON_COMPLETE": ReconCompleteEvent,
    "RECON_OOB_INTERACTION": OOBInteractionEvent,
}


def validate_event(event_type: str, data: dict) -> ReconEventBase:
    """Validate and parse an event payload against its schema."""
    schema = EVENT_SCHEMAS.get(event_type)
    if not schema:
        raise ValueError(f"Unknown event type: {event_type}")
    return schema(**data)
