from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from backend.core.tool_types import BarrierException


@dataclass
class ApprovalTicket:
    id: str
    scan_id: str
    tool_name: str
    reason: str
    payload: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    decided_by: str = ""


_MAX_TICKETS = 5000


class ApprovalStore:
    def __init__(self) -> None:
        self._tickets: dict[str, ApprovalTicket] = {}

    def request(self, *, scan_id: str, tool_name: str, reason: str, payload: dict[str, Any] | None = None) -> ApprovalTicket:
        ticket = ApprovalTicket(
            id=f"APR-{uuid.uuid4().hex[:12]}",
            scan_id=scan_id,
            tool_name=tool_name,
            reason=reason,
            payload=payload or {},
        )
        self._tickets[ticket.id] = ticket
        # Evict oldest resolved tickets when at capacity
        if len(self._tickets) > _MAX_TICKETS:
            resolved = [tid for tid, t in self._tickets.items() if t.status != "pending"]
            for tid in resolved[:len(resolved) // 2]:
                self._tickets.pop(tid, None)
        return ticket

    def approve(self, ticket_id: str, *, decided_by: str = "human") -> ApprovalTicket:
        ticket = self._tickets[ticket_id]
        ticket.status = "approved"
        ticket.decided_by = decided_by
        return ticket

    def deny(self, ticket_id: str, *, decided_by: str = "human") -> ApprovalTicket:
        ticket = self._tickets[ticket_id]
        ticket.status = "denied"
        ticket.decided_by = decided_by
        return ticket

    def is_approved(self, ticket_id: str | None) -> bool:
        return bool(ticket_id and ticket_id in self._tickets and self._tickets[ticket_id].status == "approved")

    def require(self, *, scan_id: str, tool_name: str, reason: str, payload: dict[str, Any] | None = None) -> None:
        ticket = self.request(scan_id=scan_id, tool_name=tool_name, reason=reason, payload=payload)
        raise BarrierException(tool_name, reason, {"approval_id": ticket.id, **(payload or {})})

    def pending(self, scan_id: str | None = None) -> list[ApprovalTicket]:
        return [
            ticket for ticket in self._tickets.values()
            if ticket.status == "pending" and (scan_id is None or ticket.scan_id == scan_id)
        ]


approval_store = ApprovalStore()
