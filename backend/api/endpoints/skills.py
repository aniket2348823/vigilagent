"""
Skills API (Architecture §5.3, §13.2, §22, §23)
================================================================================
Additive, read-mostly endpoints exposing the skill catalog, stats, and the
generated-skill lifecycle. New routes only — no existing contract changes
(Architecture §13.4 frontend contract invariance).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

logger = logging.getLogger("api.skills")
router = APIRouter()


@router.get("/")
async def list_skills(
    domain: str | None = Query(None), agent: str | None = Query(None), risk: str | None = Query(None)
):
    """List catalog skills, optionally filtered by domain/agent/risk."""
    try:
        from backend.skills import skill_catalog
        from backend.skills.policy import RiskClass

        skills = skill_catalog.all()
        if domain:
            skills = [s for s in skills if s.domain == domain]
        if agent:
            a = agent.lower()
            skills = [s for s in skills if any(a == t.lower() for t in s.agent_targets)]
        if risk:
            try:
                rc = RiskClass(risk)
                skills = [s for s in skills if s.risk_class == rc]
            except ValueError:
                pass
        return JSONResponse(content={"skills": [s.to_dict() for s in skills], "count": len(skills)})
    except Exception as e:
        logger.error(f"list_skills failed: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/stats")
async def skill_stats():
    """Catalog statistics: totals by domain and risk class."""
    try:
        from backend.skills import skill_catalog

        return JSONResponse(content=skill_catalog.stats())
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/{skill_id}")
async def get_skill(skill_id: str):
    """Get a single skill's normalized metadata."""
    try:
        from backend.skills import skill_catalog

        meta = skill_catalog.get(skill_id)
        if not meta:
            return JSONResponse(status_code=404, content={"error": "skill not found"})
        return JSONResponse(content=meta.to_dict())
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.post("/reload")
async def reload_skills():
    """Re-ingest the skill catalog from disk (Architecture §5.3.1)."""
    try:
        from backend.skills import ingest_skills, skill_catalog

        n = ingest_skills()
        return JSONResponse(content={"ingested": n, "stats": skill_catalog.stats()})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
