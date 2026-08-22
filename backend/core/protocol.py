import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TaskPriority(StrEnum):
    CRITICAL = "CRITICAL"  # Immediate execution, overrides locks
    HIGH = "HIGH"  # Active attacks (SQLi, Race Conditions)
    NORMAL = "NORMAL"  # Standard Recon
    LOW = "LOW"  # Background Logging/Archiving


class AgentStatus(StrEnum):
    IDLE = "IDLE"
    WORKING = "WORKING"
    THROTTLED = "THROTTLED"
    SLEEPING = "SLEEPING"


class AgentID(StrEnum):
    OMEGA = "agent_omega"
    ZETA = "agent_zeta"
    ALPHA = "agent_alpha"
    BETA = "agent_beta"
    GAMMA = "agent_gamma"
    SIGMA = "agent_sigma"
    KAPPA = "agent_kappa"
    DELTA = "agent_delta"
    PRISM = "agent_prism"
    CHI = "agent_chi"
    LAMBDA = "agent_lambda"


# --- THE JOB PACKET (Input) ---
class ModuleConfig(BaseModel):
    module_id: str  # e.g., "logic_tycoon"
    agent_id: AgentID  # Who owns this? e.g., "agent_gamma"
    aggression: int = Field(5, ge=1, le=10)
    ai_mode: bool = True  # Use advanced AI features?
    session_id: str | None = None  # V6: Session Persistence
    params: dict[str, Any] = Field(default_factory=dict)


class TaskTarget(BaseModel):
    url: str
    method: str = "GET"
    headers: dict[str, str] = {}
    payload: dict[str, Any] | None = None


class JobPacket(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    priority: TaskPriority = TaskPriority.NORMAL
    target: TaskTarget
    config: ModuleConfig
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# --- THE RESULT PACKET (Output) ---
class Vulnerability(BaseModel):
    name: str
    severity: str  # HIGH, MED, LOW
    description: str
    evidence: str  # The payload that worked
    remediation: str | None = None  # Fix suggestion
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)  # 0.0–1.0 detection confidence score


class ResultPacket(BaseModel):
    job_id: str
    source_agent: AgentID
    status: str  # SUCCESS, FAILURE, VULN_FOUND
    execution_time_ms: float
    data: dict[str, Any]  # Raw response data
    vulnerabilities: list[Vulnerability] = []
    next_step: str | None = None  # Hint for the next agent
    timestamp: datetime = Field(default_factory=datetime.utcnow)  # V6: Temporal Tracking
