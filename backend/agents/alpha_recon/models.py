from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ScanMode(StrEnum):
    PASSIVE_ONLY = "PASSIVE_ONLY"
    STANDARD = "STANDARD"
    AGGRESSIVE = "AGGRESSIVE"


class ReconPhase(StrEnum):
    INITIALIZATION = "initialization"
    PASSIVE = "passive_intelligence"
    INFRA = "dns_infrastructure"
    HTTP = "http_browser_intelligence"
    DISCOVERY = "directory_route_discovery"
    API = "api_reconnaissance"
    VISUAL = "visual_documentation"
    VALIDATION = "template_validation"
    CORRELATION = "correlation_scoring"
    COMPLETE = "complete"


class ReconScope(BaseModel):
    base_domain: str = ""
    root_url: str = ""
    target_url: str = ""
    base_url: str = ""
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_host_suffixes: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    denied_hosts: list[str] = Field(default_factory=list)
    denied_url_globs: list[str] = Field(default_factory=list)
    scan_mode: ScanMode = ScanMode.STANDARD
    explicit_authorization: bool = False
    max_rps: int = 50
    max_depth: int = 3


class SourceRef(BaseModel):
    tool: str
    phase: str = ""
    artifact_id: str = ""
    confidence: float = 0.5


class ReconEntity(BaseModel):
    id: str = ""
    kind: str
    label: str
    scan_id: str
    confidence: float = 0.0
    sources: list[SourceRef] = Field(default_factory=list)
    properties: dict[str, Any] = Field(default_factory=dict)
    first_seen: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

    def ensure_id(self) -> ReconEntity:
        if not self.id:
            self.id = stable_id(self.scan_id, self.kind, self.label)
        return self


class HTTPServiceFinding(BaseModel):
    url: str
    method: str = "GET"
    status_code: int = 0
    response_time_ms: int = 0
    content_type: str = ""
    content_length: int = 0
    server: str = ""
    server_header: str = ""
    title: str = ""
    technologies: list[str] = Field(default_factory=list)
    source: str = ""
    response_hash: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body_preview: str = ""


class ParameterFinding(BaseModel):
    name: str
    location: str = "query"
    value_type: str = "string"
    examples: list[str] = Field(default_factory=list)


# Alias for external consumers (scoring, tests)
EndpointParameter = ParameterFinding


class TargetScope(BaseModel):
    """Simplified scope for quick target validation."""

    target_url: str
    base_domain: str = ""
    mode: ScanMode = ScanMode.STANDARD
    authorized: bool = False


class EndpointFinding(BaseModel):
    url: str
    method: str = "GET"
    normalized_path: str = ""
    path: str = "/"
    host: str = ""
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    response_time_ms: int = 0
    server: str = ""
    server_header: str = ""
    technologies: list[str] = Field(default_factory=list)
    parameters: list[ParameterFinding] = Field(default_factory=list)
    auth_required: bool = False
    endpoint_type: str = "UNKNOWN"
    risk_class: str = "LOW"
    priority_score: int = 0
    score_reasons: list[str] = Field(default_factory=list)
    source: str = ""
    sources: list[SourceRef] = Field(default_factory=list)
    baseline_response_hash: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class SecretFinding(BaseModel):
    secret_type: str
    redacted_value: str
    source_url: str
    line: int = 0
    confidence: float = 0.75
    artifact_id: str = ""


class VisualArtifact(BaseModel):
    url: str
    screenshot_path: str = ""
    har_path: str = ""
    snapshot_path: str = ""
    text_path: str = ""
    console_path: str = ""
    pinchtab_tab_id: str = ""


class ToolAvailability(BaseModel):
    name: str
    available: bool
    reason: str = ""
    path: str = ""


class ToolSkip(BaseModel):
    name: str
    phase: str
    reason: str


class ReconRunSummary(BaseModel):
    total_endpoints: int = 0
    total_subdomains: int = 0
    total_ips: int = 0
    total_open_ports: int = 0
    total_js_files: int = 0
    total_parameters: int = 0
    total_secrets: int = 0
    total_vulns: int = 0
    attack_surface_stats: dict[str, int] = Field(default_factory=dict)
    subdomains_discovered: int = 0
    live_hosts: int = 0
    open_ports: int = 0
    api_endpoints: int = 0
    parameters_discovered: int = 0
    secrets_found: int = 0
    historical_urls: int = 0
    cloud_assets: int = 0
    graphql_endpoints: int = 0
    admin_panels: int = 0
    screenshots_taken: int = 0


class ReconRunResult(BaseModel):
    scan_id: str
    target: str
    mode: ScanMode
    duration_seconds: int
    summary: ReconRunSummary
    # Human-readable failure reason when the run aborted (``orchestrator_error``
    # stat in the summary is set in that case). Empty string = clean run.
    error: str = ""
    attack_surface: list[EndpointFinding] = Field(default_factory=list)
    tools_run: list[str] = Field(default_factory=list)
    tools_skipped: list[ToolSkip] = Field(default_factory=list)
    raw_data_path: str = ""
    screenshots_path: str = ""
    artifact_manifest_path: str = ""
    neo4j_export_path: str = ""
    maltego_export_path: str = ""
    pinchtab_profile_id: str = ""
    pinchtab_instance_id: str = ""


def stable_id(*parts: str) -> str:
    raw = "|".join(str(part).lower().strip() for part in parts)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
