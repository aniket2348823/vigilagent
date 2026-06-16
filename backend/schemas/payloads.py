from pydantic import BaseModel, Field
from typing import Dict, Optional, Any

class ReconPayload(BaseModel):
    url: str
    method: str
    headers: Dict[str, str]
    body: Optional[Any] = None
    timestamp: float

class TargetConfig(BaseModel):
    url: str
    method: str
    headers: Dict[str, str] = {}
    body: Optional[str] = ""

class AttackConfig(BaseModel):
    concurrency: int = Field(default=50, ge=1, le=200)
    strategy: str = "LAST_BYTE_SYNC"

class AttackPayload(BaseModel):
    target_url: str 
    method: str
    headers: Dict[str, str] = {}
    body: Optional[str] = ""
    velocity: int = Field(default=50, ge=1, le=500)
    concurrency: int = Field(default=50, ge=1, le=200)
    rps: int = Field(default=100, ge=1, le=1000)
    modules: list[str] = []
    filters: list[str] = []
    duration: Optional[int] = 600


