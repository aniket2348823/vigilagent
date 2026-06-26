"""
Alpha V6 Database Extensions.

Additional database methods for the deep recon system.
Monkey-patches EliteDBManager with recon relationship, tool output,
and OOB interaction methods.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("ELITE-DB")


async def create_recon_relationship(
    self,
    *,
    id: str,
    scan_id: str,
    src_entity_id: str,
    dst_entity_id: str,
    relationship: str,
    confidence: float = 0.0,
    evidence: dict[str, Any] | None = None,
):
    if not self.supabase:
        return None
    try:
        result = await self._run_sync(
            lambda: (
                self.supabase.table("recon_relationships")
                .upsert(
                    {
                        "id": id,
                        "scan_id": scan_id,
                        "src_entity_id": src_entity_id,
                        "dst_entity_id": dst_entity_id,
                        "relationship": relationship,
                        "confidence": confidence,
                        "evidence": evidence or {},
                    },
                    on_conflict="id",
                )
                .execute()
            )
        )
        return result.data[0]["id"] if result.data else id
    except Exception as e:
        logger.debug(f"Failed to create recon relationship: {e}")
        return None


async def create_recon_tool_output(
    self,
    *,
    id: str,
    scan_id: str,
    tool_name: str,
    phase: str,
    parser_version: str = "v1",
    raw_artifact_id: str,
    normalized_count: int = 0,
    status: str,
    errors: list[dict[str, Any]] | None = None,
):
    if not self.supabase:
        return None
    try:
        result = await self._run_sync(
            lambda: (
                self.supabase.table("recon_tool_outputs")
                .upsert(
                    {
                        "id": id,
                        "scan_id": scan_id,
                        "tool_name": tool_name,
                        "phase": phase,
                        "parser_version": parser_version,
                        "raw_artifact_id": raw_artifact_id,
                        "normalized_count": normalized_count,
                        "status": status,
                        "errors": errors or [],
                    },
                    on_conflict="id",
                )
                .execute()
            )
        )
        return result.data[0]["id"] if result.data else id
    except Exception as e:
        logger.debug(f"Failed to create recon tool output: {e}")
        return None


async def create_recon_oob_interaction(
    self,
    *,
    id: str,
    scan_id: str,
    provider: str,
    interaction_type: str,
    correlation_id: str,
    source_endpoint: str = "",
    raw: dict[str, Any] | None = None,
    severity: str = "high",
):
    if not self.supabase:
        return None
    try:
        result = await self._run_sync(
            lambda: (
                self.supabase.table("recon_oob_interactions")
                .upsert(
                    {
                        "id": id,
                        "scan_id": scan_id,
                        "provider": provider,
                        "interaction_type": interaction_type,
                        "correlation_id": correlation_id,
                        "source_endpoint": source_endpoint,
                        "raw": raw or {},
                        "severity": severity,
                    },
                    on_conflict="id",
                )
                .execute()
            )
        )
        return result.data[0]["id"] if result.data else id
    except Exception as e:
        logger.debug(f"Failed to create recon OOB interaction: {e}")
        return None


async def update_recon_run_phase(self, *, scan_id: str, phase: str, phase_data: dict[str, Any]):
    if not self.supabase:
        return None
    try:
        await self._run_sync(
            lambda: (
                self.supabase.table("recon_runs")
                .update(
                    {
                        "current_phase": phase,
                        "phase_data": phase_data,
                    }
                )
                .eq("scan_id", scan_id)
                .execute()
            )
        )
    except Exception as e:
        logger.debug(f"Failed to update recon run phase: {e}")
        return None


def patch_db_manager():
    """Patch EliteDBManager with Alpha V6 recon extension methods."""
    from backend.core.database import EliteDBManager

    EliteDBManager.create_recon_relationship = create_recon_relationship
    EliteDBManager.create_recon_tool_output = create_recon_tool_output
    EliteDBManager.create_recon_oob_interaction = create_recon_oob_interaction
    EliteDBManager.update_recon_run_phase = update_recon_run_phase


# Auto-patch on import
patch_db_manager()
