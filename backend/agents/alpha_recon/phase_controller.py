"""
Alpha V6 Phase Controller.

Manages the multi-phase recon pipeline with gates, state tracking,
and parse-after-run integration. Each phase feeds the next.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from backend.agents.alpha_recon.models import ReconPhase, ReconScope, ScanMode, ToolSkip

if TYPE_CHECKING:
    from pathlib import Path

    from backend.parsers.recon.base import ParsedEntity

logger = logging.getLogger("alpha.phases")


@dataclass
class PhaseResult:
    phase: ReconPhase
    status: str = "pending"  # pending | running | completed | skipped | failed
    started_at: float = 0.0
    finished_at: float = 0.0
    entities_produced: int = 0
    tools_run: list[str] = field(default_factory=list)
    tools_skipped: list[ToolSkip] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> int:
        if self.finished_at and self.started_at:
            return int((self.finished_at - self.started_at) * 1000)
        return 0


@dataclass
class PhaseState:
    """Accumulated state that flows between phases."""

    subdomains: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    live_hosts: list[str] = field(default_factory=list)
    open_ports: dict[str, list[int]] = field(default_factory=dict)  # host -> [ports]
    http_services: list[str] = field(default_factory=list)  # live HTTP URLs
    js_files: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    parameters: list[dict[str, Any]] = field(default_factory=list)
    secrets: list[dict[str, Any]] = field(default_factory=list)
    vulnerability_candidates: list[dict[str, Any]] = field(default_factory=list)
    all_entities: list[ParsedEntity] = field(default_factory=list)
    interactsh_url: str = ""

    def add_entities(self, entities: list[ParsedEntity]) -> None:
        """Ingest parsed entities into phase state for downstream consumption."""
        for e in entities:
            self.all_entities.append(e)
            if e.kind == "subdomain":
                self.subdomains.add(e.label)
            elif e.kind == "ip":
                self.ips.add(e.label)
            elif e.kind == "dns_record":
                self.subdomains.add(e.label)
                for ip in e.properties.get("a", []) + e.properties.get("aaaa", []):
                    self.ips.add(ip)
            elif e.kind == "open_port":
                host = e.properties.get("host", e.label.split(":")[0])
                port = int(e.properties.get("port", 0))
                self.open_ports.setdefault(host, []).append(port)
            elif e.kind == "http_service":
                self.http_services.append(e.label)
                self.live_hosts.append(e.label)
            elif e.kind in ("js_file", "js_endpoint"):
                self.js_files.append(e.label)
            elif e.kind in ("crawled_endpoint", "discovered_path", "api_route", "endpoint"):
                self.endpoints.append(e.label)
            elif e.kind == "parameter":
                self.parameters.append(e.properties)
            elif e.kind == "secret":
                self.secrets.append(e.properties)
            elif e.kind == "vulnerability_candidate":
                self.vulnerability_candidates.append(e.properties)

    def build_subdomain_file(self, raw_dir: Path) -> Path:
        """Write discovered subdomains to a file for downstream tools."""
        path = raw_dir / "discovered_subdomains.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(sorted(self.subdomains)) + "\n", encoding="utf-8")
        return path

    def build_hosts_file(self, raw_dir: Path) -> Path:
        """Write all discovered hosts (subdomains + IPs) for port/http scanning."""
        path = raw_dir / "all_hosts.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        all_hosts = sorted(self.subdomains | self.ips)
        path.write_text("\n".join(all_hosts) + "\n", encoding="utf-8")
        return path

    def build_live_hosts_file(self, raw_dir: Path) -> Path:
        """Write live HTTP hosts for downstream tools."""
        path = raw_dir / "live_http_hosts.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        # Deduplicate and limit
        seen: set[str] = set()
        unique: list[str] = []
        for h in self.http_services:
            if h not in seen:
                seen.add(h)
                unique.append(h)
        path.write_text("\n".join(unique[:500]) + "\n", encoding="utf-8")
        return path


class PhaseController:
    """Manages ordered execution of recon phases."""

    PHASE_ORDER = [
        ReconPhase.INITIALIZATION,
        ReconPhase.PASSIVE,
        ReconPhase.INFRA,
        ReconPhase.HTTP,
        ReconPhase.DISCOVERY,
        ReconPhase.API,
        ReconPhase.VISUAL,
        ReconPhase.VALIDATION,
        ReconPhase.CORRELATION,
    ]

    def __init__(self, scope: ReconScope):
        self.scope = scope
        self.state = PhaseState()
        self.results: dict[ReconPhase, PhaseResult] = {}
        self._current_phase: ReconPhase | None = None

    def should_run(self, phase: ReconPhase) -> bool:
        """Gate check: should this phase run given the scan mode?"""
        if phase == ReconPhase.INITIALIZATION:
            return True
        if phase == ReconPhase.PASSIVE:
            return True  # Always run passive
        if self.scope.scan_mode == ScanMode.PASSIVE_ONLY:
            return phase in {ReconPhase.INITIALIZATION, ReconPhase.PASSIVE, ReconPhase.CORRELATION}
        if phase == ReconPhase.VALIDATION and self.scope.scan_mode != ScanMode.AGGRESSIVE:
            # Standard mode runs nuclei but with limits
            return True
        return True

    def start_phase(self, phase: ReconPhase) -> PhaseResult:
        result = PhaseResult(phase=phase, status="running", started_at=time.time())
        self.results[phase] = result
        self._current_phase = phase
        logger.info(f"[Alpha] Phase {phase.value} started")
        return result

    def complete_phase(self, phase: ReconPhase, entities: list[ParsedEntity] | None = None) -> PhaseResult:
        result = self.results.get(phase)
        if not result:
            result = PhaseResult(phase=phase)
            self.results[phase] = result
        result.status = "completed"
        result.finished_at = time.time()
        if entities:
            self.state.add_entities(entities)
            result.entities_produced = len(entities)
        logger.info(
            f"[Alpha] Phase {phase.value} completed: {result.entities_produced} entities in {result.duration_ms}ms"
        )
        return result

    def skip_phase(self, phase: ReconPhase, reason: str) -> PhaseResult:
        result = PhaseResult(
            phase=phase,
            status="skipped",
            started_at=time.time(),
            finished_at=time.time(),
            metadata={"skip_reason": reason},
        )
        self.results[phase] = result
        logger.info(f"[Alpha] Phase {phase.value} skipped: {reason}")
        return result

    def fail_phase(self, phase: ReconPhase, error: str) -> PhaseResult:
        result = self.results.get(phase, PhaseResult(phase=phase))
        result.status = "failed"
        result.finished_at = time.time()
        result.errors.append(error)
        self.results[phase] = result
        logger.error(f"[Alpha] Phase {phase.value} failed: {error}")
        return result

    def summary(self) -> dict[str, Any]:
        return {
            phase.value: {
                "status": r.status,
                "duration_ms": r.duration_ms,
                "entities": r.entities_produced,
                "tools_run": r.tools_run,
                "errors": r.errors,
            }
            for phase, r in self.results.items()
        }
