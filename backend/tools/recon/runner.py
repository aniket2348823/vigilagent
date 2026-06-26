"""
Alpha Recon Command Runner — thin shim over the Terminal Engine.

Per Architecture §8 and §29.13, all CLI/recon execution is consolidated into a
single governed module: backend/core/terminal_engine.py (TerminalEngine). This
runner no longer owns subprocess logic. It:

  - delegates execution to the TerminalEngine (guardrails, scope, Docker/local
    backend selection, output watchdog, timeouts),
  - retains the database toolcall audit logging it has always done, and
  - parses tool output into typed entities via the parsers/recon registry.

The public surface (ReconCommandRunner.execute / .run, ReconCommandResult) is
unchanged so existing callers (alpha_orchestrator) keep working.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from backend.core.database import db_manager
from backend.tools.recon.guardrails import validate_output_path

if TYPE_CHECKING:
    from backend.core.iteration_budget import IterationBudget
    from backend.tools.recon.commands import ReconCommand

logger = logging.getLogger("alpha.runner")

# PentAGI-style result size limit (16KB) for stderr persistence.
DEFAULT_RESULT_SIZE_LIMIT = 16 * 1024


@dataclass
class ReconCommandResult:
    tool_name: str
    phase: str
    status: str  # finished | failed | timeout | skipped | blocked
    exit_code: int
    output_path: str
    stderr: str = ""
    duration_ms: int = 0
    sha256: str = ""
    bytes: int = 0
    skipped_reason: str = ""
    entities_parsed: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


class ReconCommandRunner:
    """Runs recon tools through the governed Terminal Engine."""

    def __init__(self, engine: TerminalEngine | None = None) -> None:
        # Lazy import avoids a circular dependency: terminal_engine imports
        # tools.recon.guardrails, and the tools.recon package __init__ imports
        # this runner.
        if engine is None:
            from backend.core.terminal_engine import terminal_engine

            engine = terminal_engine
        self.engine = engine

    async def execute(
        self,
        command: ReconCommand,
        *,
        scan_id: str = "GLOBAL",
        agent: str = "agent_alpha",
        budget: IterationBudget | None = None,
    ) -> ReconCommandResult:
        """Execute a validated recon command via the Terminal Engine."""
        # Output-path traversal guard (kept here as a cheap pre-check).
        if not validate_output_path(str(command.output_path)):
            return ReconCommandResult(
                tool_name=command.tool_name,
                phase=command.phase,
                status="blocked",
                exit_code=-1,
                output_path=str(command.output_path),
                skipped_reason="output_path_traversal",
            )

        command.output_path.parent.mkdir(parents=True, exist_ok=True)
        call_id = f"recon_{command.tool_name}_{hashlib.sha256(str(command.argv).encode()).hexdigest()[:12]}"

        # Register toolcall in database (audit — retained per §29.13).
        await db_manager.create_toolcall(
            call_id=call_id,
            scan_id=scan_id,
            tool_name=command.tool_name,
            agent=agent,
            args={
                "argv": list(command.argv),
                "stdin": bool(command.stdin),
                "output_path": str(command.output_path),
                "timeout": command.timeout_seconds,
            },
            status="running",
        )

        started = time.time()
        term = await self.engine.run(
            command.argv,
            scan_id=scan_id,
            agent=agent,
            output_path=command.output_path,
            timeout_seconds=command.timeout_seconds,
            budget=budget,
            parser_hint=command.parser_hint,
            stdin=command.stdin or None,
            cwd=command.cwd,
            metadata=dict(command.metadata),
        )
        duration_ms = term.duration_ms or int((time.time() - started) * 1000)
        stderr_truncated = term.stderr_tail[-DEFAULT_RESULT_SIZE_LIMIT:]

        # Map terminal status -> recon status, preserving prior semantics.
        if term.blocked:
            status = "blocked"
        elif term.timed_out:
            status = "timeout"
        elif term.exit_code == 0:
            status = "finished"
        else:
            status = "failed"

        result_data = {
            "output_path": term.output_path,
            "stderr": stderr_truncated,
            "truncated": term.metadata.get("truncated", False),
            "exit_code": term.exit_code,
            "output_bytes": term.output_bytes,
            "backend": term.backend,
        }

        if status in ("blocked",):
            await db_manager.finish_toolcall(
                call_id=call_id, status="blocked", error=term.block_reason, duration_ms=duration_ms
            )
            return ReconCommandResult(
                tool_name=command.tool_name,
                phase=command.phase,
                status="blocked",
                exit_code=term.exit_code or -1,
                output_path=term.output_path,
                skipped_reason=term.block_reason,
                duration_ms=duration_ms,
                metadata={"backend": term.backend},
            )

        await db_manager.finish_toolcall(
            call_id=call_id,
            status=status,
            result=result_data,
            error="" if status == "finished" else stderr_truncated,
            duration_ms=duration_ms,
            result_bytes=term.output_bytes,
            result_sha256=term.sha256,
        )

        logger.info(
            "[RUNNER] %s %s in %dms (%d bytes, %s)",
            command.tool_name,
            status,
            duration_ms,
            term.output_bytes,
            term.backend,
        )

        return ReconCommandResult(
            tool_name=command.tool_name,
            phase=command.phase,
            status=status,
            exit_code=term.exit_code if term.exit_code is not None else 124,
            output_path=term.output_path,
            stderr=stderr_truncated,
            duration_ms=duration_ms,
            sha256=term.sha256,
            bytes=term.output_bytes,
            metadata={"parser_hint": command.parser_hint, "backend": term.backend},
        )

    # Legacy compatibility alias
    async def run(
        self,
        command: ReconCommand,
        *,
        scan_id: str = "GLOBAL",
        agent: str = "agent_alpha",
        budget: IterationBudget | None = None,
    ) -> ReconCommandResult:
        return await self.execute(command, scan_id=scan_id, agent=agent, budget=budget)
