# ═══════════════════════════════════════════════════════════════════════════════
# Vigilagent :: PHASE GATE — LIFECYCLE STATE MACHINE
# ═══════════════════════════════════════════════════════════════════════════════
# PURPOSE: Enforces strict sequential execution of scan phases
#          Prevents agents from executing out of order
# ═══════════════════════════════════════════════════════════════════════════════

import asyncio
import logging
from datetime import datetime
from enum import StrEnum

logger = logging.getLogger("PhaseGate")


class ScanPhase(StrEnum):
    """Coarse scan lifecycle phases in strict sequential order (runtime flow)."""
    PLANNING = "PLANNING"
    RECONNAISSANCE = "RECONNAISSANCE"
    ASSESSMENT = "ASSESSMENT"
    EXPLOITATION = "EXPLOITATION"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"


class LifecyclePhase(StrEnum):
    """The full 13 gated phases (Architecture §16). Each maps onto a coarse
    ScanPhase so the existing runtime flow is preserved while every architecture
    phase is explicitly modeled and gated."""
    INTAKE = "intake"
    SCOPE_COMPILATION = "scope_compilation"
    PASSIVE_RECON = "passive_recon"
    ACTIVE_RECON = "active_recon"
    SURFACE_MODELING = "surface_modeling"
    PLANNING = "planning"
    CONTROLLED_VALIDATION = "controlled_validation"
    VERIFICATION = "verification"
    EVIDENCE_CAPTURE = "evidence_capture"
    RISK_SCORING = "risk_scoring"
    REPORTING = "reporting"
    LEARNING = "learning"
    CLEANUP = "cleanup"


# Ordered list for jump checks (Architecture §16: agents cannot jump phases).
LIFECYCLE_ORDER = [
    LifecyclePhase.INTAKE,
    LifecyclePhase.SCOPE_COMPILATION,
    LifecyclePhase.PASSIVE_RECON,
    LifecyclePhase.ACTIVE_RECON,
    LifecyclePhase.SURFACE_MODELING,
    LifecyclePhase.PLANNING,
    LifecyclePhase.CONTROLLED_VALIDATION,
    LifecyclePhase.VERIFICATION,
    LifecyclePhase.EVIDENCE_CAPTURE,
    LifecyclePhase.RISK_SCORING,
    LifecyclePhase.REPORTING,
    LifecyclePhase.LEARNING,
    LifecyclePhase.CLEANUP,
]

# Which fine phases belong to each coarse runtime phase.
COARSE_TO_FINE: dict[ScanPhase, list] = {
    ScanPhase.PLANNING: [LifecyclePhase.INTAKE, LifecyclePhase.SCOPE_COMPILATION,
                         LifecyclePhase.PLANNING],
    ScanPhase.RECONNAISSANCE: [LifecyclePhase.PASSIVE_RECON, LifecyclePhase.ACTIVE_RECON],
    ScanPhase.ASSESSMENT: [LifecyclePhase.SURFACE_MODELING],
    ScanPhase.EXPLOITATION: [LifecyclePhase.CONTROLLED_VALIDATION, LifecyclePhase.VERIFICATION,
                             LifecyclePhase.EVIDENCE_CAPTURE],
    ScanPhase.REPORTING: [LifecyclePhase.RISK_SCORING, LifecyclePhase.REPORTING],
    ScanPhase.COMPLETED: [LifecyclePhase.LEARNING, LifecyclePhase.CLEANUP],
}


class PhaseGate:
    """
    State machine that enforces proper scan phase sequencing.
    Agents must wait for prerequisite phases to complete before executing.
    """

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.current_phase = ScanPhase.PLANNING
        self.phase_events: dict[ScanPhase, asyncio.Event] = {
            phase: asyncio.Event() for phase in ScanPhase
        }
        self.phase_start_times: dict[ScanPhase, datetime | None] = {
            phase: None for phase in ScanPhase
        }
        self.phase_end_times: dict[ScanPhase, datetime | None] = {
            phase: None for phase in ScanPhase
        }

        # Planning phase starts immediately
        self.phase_events[ScanPhase.PLANNING].set()
        self.phase_start_times[ScanPhase.PLANNING] = datetime.now()

        # Fine-grained lifecycle tracking (Architecture §16). The first fine
        # phase (INTAKE) is active when the gate starts.
        self.current_fine_phase: LifecyclePhase = LifecyclePhase.INTAKE
        self.completed_fine_phases: list[LifecyclePhase] = []

        logger.info(f"[{scan_id}] PhaseGate initialized - Starting in PLANNING phase")

    def enter_fine_phase(self, phase: "LifecyclePhase", *, allow_skip: bool = False) -> bool:
        """Advance the fine-grained lifecycle phase (Architecture §16).

        Agents cannot jump phases unless ``allow_skip`` is explicitly set
        (e.g. PASSIVE_ONLY scans that skip active recon). Returns True if the
        transition was accepted."""
        cur_idx = LIFECYCLE_ORDER.index(self.current_fine_phase)
        nxt_idx = LIFECYCLE_ORDER.index(phase)
        if nxt_idx < cur_idx:
            logger.warning(f"[{self.scan_id}] Rejected backward fine-phase {self.current_fine_phase}->{phase}")
            return False
        if nxt_idx > cur_idx + 1 and not allow_skip:
            logger.warning(f"[{self.scan_id}] Rejected fine-phase jump {self.current_fine_phase}->{phase}")
            return False
        if self.current_fine_phase not in self.completed_fine_phases:
            self.completed_fine_phases.append(self.current_fine_phase)
        self.current_fine_phase = phase
        logger.info(f"[{self.scan_id}] Lifecycle phase -> {phase.value}")
        return True

    def fine_phase_allowed(self, phase: "LifecyclePhase") -> bool:
        """Whether a fine phase may currently run (reached or earlier)."""
        return LIFECYCLE_ORDER.index(phase) <= LIFECYCLE_ORDER.index(self.current_fine_phase)

    async def advance_to(self, next_phase: ScanPhase) -> bool:
        """
        Advance to the next phase if prerequisites are met.
        Returns True if advancement succeeded, False otherwise.
        """
        # Get phase order
        phases = list(ScanPhase)
        current_idx = phases.index(self.current_phase)
        next_idx = phases.index(next_phase)

        # Can only advance forward sequentially
        if next_idx != current_idx + 1:
            logger.warning(
                f"[{self.scan_id}] Cannot advance from {self.current_phase} to {next_phase} "
                f"(must be sequential)"
            )
            return False

        # Mark current phase as complete
        self.phase_end_times[self.current_phase] = datetime.now()
        duration = (
            self.phase_end_times[self.current_phase] -
            self.phase_start_times[self.current_phase]
        ).total_seconds()

        logger.info(
            f"[{self.scan_id}] Phase {self.current_phase} completed in {duration:.1f}s"
        )

        # Advance to next phase
        self.current_phase = next_phase
        self.phase_start_times[next_phase] = datetime.now()
        self.phase_events[next_phase].set()

        # Auto-advance the fine lifecycle phases mapped to this coarse phase
        # (Architecture §16), so the full 13-phase lifecycle is tracked even
        # when callers drive the coarse phases.
        for fine in COARSE_TO_FINE.get(next_phase, []):
            self.enter_fine_phase(fine, allow_skip=True)

        logger.info(f"[{self.scan_id}] Advanced to phase: {next_phase}")
        return True

    async def wait_for_phase(self, phase: ScanPhase, timeout: float | None = None):
        """
        Block until the specified phase is reached.
        Raises asyncio.TimeoutError if timeout is exceeded.
        """
        if timeout:
            await asyncio.wait_for(
                self.phase_events[phase].wait(),
                timeout=timeout
            )
        else:
            await self.phase_events[phase].wait()

    def is_phase_active(self, phase: ScanPhase) -> bool:
        """Check if a specific phase is currently active"""
        return self.current_phase == phase

    def is_phase_complete(self, phase: ScanPhase) -> bool:
        """Check if a specific phase has completed"""
        return self.phase_events[phase].is_set() and self.phase_end_times[phase] is not None

    def get_phase_duration(self, phase: ScanPhase) -> float | None:
        """Get the duration of a completed phase in seconds"""
        if not self.is_phase_complete(phase):
            return None

        start = self.phase_start_times[phase]
        end = self.phase_end_times[phase]

        if start and end:
            return (end - start).total_seconds()
        return None

    def get_telemetry(self) -> dict:
        """Get phase gate telemetry for reporting"""
        return {
            "scan_id": self.scan_id,
            "current_phase": self.current_phase,
            "current_lifecycle_phase": self.current_fine_phase.value,
            "lifecycle_phases_completed": [p.value for p in self.completed_fine_phases],
            "lifecycle_total": len(LIFECYCLE_ORDER),
            "phase_durations": {
                phase.value: self.get_phase_duration(phase)
                for phase in ScanPhase
                if self.get_phase_duration(phase) is not None
            },
            "phases_completed": [
                phase.value for phase in ScanPhase
                if self.is_phase_complete(phase)
            ]
        }
