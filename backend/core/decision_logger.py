"""
DECISION LOGGER
Records decision rationale and confidence levels.

This logger:
1. Logs decisions with rationale and confidence
2. Records rejected alternatives
3. Provides decision query capabilities
4. Formats decisions for reports
5. Maintains audit trails
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from backend.core.database import db_manager
from backend.core.self_awareness_config import SelfAwarenessConfig
from backend.core.tracing import get_tracer

logger = logging.getLogger("DecisionLogger")
tracer = get_tracer()


@dataclass
class Decision:
    """Represents a logged decision"""

    decision_id: str
    agent_id: str
    timestamp: datetime
    action_type: str
    rationale: str
    confidence: float
    alternatives_considered: list
    context: dict[str, Any]
    finding_id: str | None = None


class DecisionLogger:
    """Logs agent decisions with rationale"""

    def __init__(self, agent_id: str, config: SelfAwarenessConfig):
        self.agent_id = agent_id
        self.config = config
        self._pending_decisions = []

        logger.info(f"[DecisionLogger] Initialized for agent {agent_id}")

    async def log_decision(
        self,
        action: Any,
        rationale: str,
        confidence: float,
        context: dict[str, Any],
        alternatives: list[Any] | None = None,
    ) -> str:
        """Log a decision"""
        decision_id = str(uuid.uuid4())

        # Validate confidence
        confidence = max(0.0, min(1.0, confidence))

        decision = Decision(
            decision_id=decision_id,
            agent_id=self.agent_id,
            timestamp=datetime.utcnow(),
            action_type=action.action_type.value if hasattr(action, "action_type") else str(action),
            rationale=rationale[:1000],  # Truncate long rationales
            confidence=confidence,
            alternatives_considered=alternatives or [],
            context=context,
        )

        self._pending_decisions.append(decision)

        # Persist to database
        await self._save_to_db(decision)

        logger.debug(f"[DecisionLogger] Logged decision {decision_id}")

        return decision_id

    async def _save_to_db(self, decision: Decision):
        """Save decision to database.

        HIGH-18: Uses db_manager's async interface instead of assuming a
        raw asyncpg pool (which doesn't exist when EliteDBManager wraps
        Supabase). Falls back to debug log when DB is unavailable.
        """
        try:
            await db_manager.initialize()
            # EliteDBManager exposes Supabase client, not asyncpg pool.
            # Use a dict-based upsert if available; otherwise skip silently.
            if hasattr(db_manager, "client") and db_manager.client is not None:
                try:
                    db_manager.client.table("agent_decisions").upsert(
                        {
                            "decision_id": decision.decision_id,
                            "agent_id": decision.agent_id,
                            "timestamp": decision.timestamp.isoformat(),
                            "action_type": decision.action_type,
                            "rationale": decision.rationale,
                            "confidence": decision.confidence,
                            "alternatives_considered": decision.alternatives_considered,
                            "context": decision.context,
                        }
                    ).execute()
                except Exception as tbl_err:
                    logger.debug("[DecisionLogger] Supabase upsert failed: %s", tbl_err)
            else:
                logger.debug("[DecisionLogger] DB unavailable; decision %s logged in-memory only", decision.decision_id)
        except Exception as e:
            logger.error(f"[DecisionLogger] Failed to save decision: {e}")

    async def flush(self):
        """Flush pending decisions"""
        self._pending_decisions.clear()

    async def _query_db(self, conditions: list, params: list, limit: int = 100) -> list:
        """Shared helper for Supabase-backed queries.

        Uses the same approach as _save_to_db — checks for db_manager.client
        (Supabase) rather than db_manager.pool (asyncpg).
        """
        try:
            await db_manager.initialize()
            if not (hasattr(db_manager, "client") and db_manager.client is not None):
                logger.debug("[DecisionLogger] DB unavailable for query")
                return []
            # Supabase select — apply filters as eq/gte/lte
            q = db_manager.client.table("agent_decisions").select("*")
            for col, val in conditions:
                if val is None:
                    continue
                if col.endswith("_gte"):
                    q = q.gte(col.rsplit("_gte", 1)[0], val)
                elif col.endswith("_lte"):
                    q = q.lte(col.rsplit("_lte", 1)[0], val)
                else:
                    q = q.eq(col, val)
            q = q.order("timestamp", desc=True).limit(limit)
            result = q.execute()
            rows = result.data if hasattr(result, "data") else []
            return [
                Decision(
                    decision_id=r.get("decision_id", ""),
                    agent_id=r.get("agent_id", ""),
                    timestamp=datetime.fromisoformat(r["timestamp"])
                    if isinstance(r.get("timestamp"), str)
                    else r.get("timestamp", datetime.utcnow()),
                    action_type=r.get("action_type", ""),
                    rationale=r.get("rationale", ""),
                    confidence=r.get("confidence", 0.0),
                    alternatives_considered=r.get("alternatives_considered") or [],
                    context=r.get("context") or {},
                    finding_id=r.get("finding_id"),
                )
                for r in rows
            ]
        except Exception as e:
            logger.error("[DecisionLogger] Query failed: %s", e)
            return []

    async def query_decisions(
        self,
        agent_id: str | None = None,
        action_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        min_confidence: float | None = None,
        limit: int = 100,
    ) -> list[Decision]:
        """Query decisions with filters."""
        conditions = []
        if agent_id:
            conditions.append(("agent_id", agent_id))
        if action_type:
            conditions.append(("action_type", action_type))
        if start_time:
            conditions.append(
                ("timestamp_gte", start_time.isoformat() if hasattr(start_time, "isoformat") else str(start_time))
            )
        if end_time:
            conditions.append(
                ("timestamp_lte", end_time.isoformat() if hasattr(end_time, "isoformat") else str(end_time))
            )
        if min_confidence is not None:
            conditions.append(("confidence_gte", min_confidence))
        return await self._query_db(conditions, [], limit)

    async def get_decision_chain(self, finding_id: str) -> list[Decision]:
        """Get complete decision chain for a finding."""
        return await self._query_db([("finding_id", finding_id)], [], limit=1000)

    def format_for_report(self, decision: Decision) -> str:
        """Format decision rationale for human-readable report

        Args:
            decision: The decision to format

        Returns:
            Human-readable formatted decision
        """
        lines = [
            f"Decision: {decision.action_type}",
            f"Agent: {decision.agent_id}",
            f"Timestamp: {decision.timestamp.isoformat()}",
            f"Confidence: {decision.confidence:.2f}",
            "",
            "Rationale:",
            f"{decision.rationale}",
        ]

        if decision.alternatives_considered:
            lines.append("")
            lines.append("Alternatives Considered:")
            for alt in decision.alternatives_considered:
                lines.append(f"  - {alt}")

        return "\n".join(lines)
