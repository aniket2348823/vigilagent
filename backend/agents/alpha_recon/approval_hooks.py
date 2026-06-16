"""
Alpha V6 Approval Hooks — Active scanning requires explicit user approval.

Implements the approval flow:
1. Alpha plans active tools for a phase
2. Approval request is emitted to dashboard via EventBus + WebSocket
3. Orchestrator blocks until user approves/denies/times out
4. If denied, phase is skipped with audit log
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from pydantic import BaseModel, Field

from backend.agents.alpha_recon.event_schemas import (
    ApprovalRequiredEvent,
    ApprovalResponseEvent,
)
from backend.agents.alpha_recon.models import stable_id
from backend.core.database import db_manager

logger = logging.getLogger("alpha.approvals")


class ApprovalRequest(BaseModel):
    """A pending approval for an active scanning phase."""
    approval_id: str
    scan_id: str
    phase: str
    tools: list[str] = Field(default_factory=list)
    target_count: int = 0
    description: str = ""
    requested_at: float = Field(default_factory=time.time)
    status: str = "pending"  # pending | approved | denied | timeout
    responded_at: float | None = None
    responded_by: str = ""


class ApprovalManager:
    """Manages approval flow for active scanning phases."""

    def __init__(self):
        self._pending: dict[str, ApprovalRequest] = {}
        self._response_events: dict[str, asyncio.Event] = {}

    async def request_approval(
        self,
        scan_id: str,
        phase: str,
        tools: list[str],
        *,
        target_count: int = 0,
        description: str = "",
        timeout_seconds: int = 300,
        event_bus=None,
    ) -> bool:
        """
        Request approval for active scanning.
        Blocks until the user responds or timeout occurs.
        Returns True if approved, False if denied/timeout.
        """
        approval_id = stable_id(scan_id, "approval", phase)
        request = ApprovalRequest(
            approval_id=approval_id,
            scan_id=scan_id,
            phase=phase,
            tools=tools,
            target_count=target_count,
            description=description or f"Approve {len(tools)} active tools for phase '{phase}'?",
        )

        self._pending[approval_id] = request
        self._response_events[approval_id] = asyncio.Event()

        # Persist to DB
        try:
            await db_manager.create_approval(
                approval_id=approval_id,
                scan_id=scan_id,
                agent="agent_alpha",
                action_type="active_scan_phase",
                description=request.description,
                context={
                    "phase": phase,
                    "tools": tools,
                    "target_count": target_count,
                },
            )
        except Exception as exc:
            logger.warning(f"[APPROVAL] DB persist failed: {exc}")

        # Emit event to dashboard
        if event_bus:
            event = ApprovalRequiredEvent(
                scan_id=scan_id,
                approval_id=approval_id,
                phase=phase,
                tools=tools,
                description=request.description,
                target_count=target_count,
            )
            await event_bus.emit("RECON_APPROVAL_REQUIRED", event.model_dump())

        logger.info(f"[APPROVAL] Waiting for approval {approval_id} "
                     f"(phase={phase}, tools={tools})")

        # Wait for response
        try:
            await asyncio.wait_for(
                self._response_events[approval_id].wait(),
                timeout=timeout_seconds)
        except asyncio.TimeoutError:
            request.status = "timeout"
            request.responded_at = time.time()
            logger.warning(f"[APPROVAL] Timed out after {timeout_seconds}s: {approval_id}")
            self._cleanup(approval_id)
            return False

        # Check result
        approved = request.status == "approved"
        self._cleanup(approval_id)
        return approved

    async def respond(self, approval_id: str, approved: bool, *,
                       responded_by: str = "user") -> bool:
        """Submit a response to a pending approval."""
        request = self._pending.get(approval_id)
        if not request:
            logger.warning(f"[APPROVAL] Unknown approval ID: {approval_id}")
            return False
        
        # H-18: Validate that only pending approvals can be responded to
        if request.status != "pending":
            logger.warning(f"[APPROVAL] Cannot respond to non-pending approval {approval_id} (status={request.status})")
            return False

        request.status = "approved" if approved else "denied"
        request.responded_at = time.time()
        request.responded_by = responded_by

        # Persist response
        try:
            await db_manager.respond_approval(
                approval_id=approval_id,
                approved=approved,
                responded_by=responded_by,
            )
        except Exception as exc:
            logger.warning(f"[APPROVAL] DB response persist failed: {exc}")

        # Signal the waiting coroutine
        event = self._response_events.get(approval_id)
        if event:
            event.set()

        action = "APPROVED" if approved else "DENIED"
        logger.info(f"[APPROVAL] {action} by {responded_by}: {approval_id}")
        return True

    def get_pending(self, scan_id: str | None = None) -> list[ApprovalRequest]:
        """Get all pending approvals, optionally filtered by scan_id."""
        pending = list(self._pending.values())
        if scan_id:
            pending = [p for p in pending if p.scan_id == scan_id]
        return [p for p in pending if p.status == "pending"]

    def _cleanup(self, approval_id: str):
        """Clean up after an approval is resolved."""
        self._response_events.pop(approval_id, None)
        # Keep the request for audit purposes but remove from active
        if approval_id in self._pending:
            self._pending[approval_id].status = self._pending[approval_id].status or "expired"


# Singleton
approval_manager = ApprovalManager()
