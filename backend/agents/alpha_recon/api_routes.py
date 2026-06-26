"""
Alpha V6 Recon API Routes — FastAPI endpoints for recon operations.

Provides REST + WebSocket endpoints for:
- Starting/stopping recon scans
- Querying scan results and entity graphs
- Live feed WebSocket for dashboard
- Export endpoints (SARIF, STIX, Markdown)
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from backend.agents.alpha_recon.live_feed import recon_live_feed

logger = logging.getLogger("alpha.api")

router = APIRouter(prefix="/api/v1/recon", tags=["recon"])


# ── Request/Response Models ──────────────────────────────────


class StartReconRequest(BaseModel):
    target_url: str
    mode: str = "STANDARD"
    scan_id: str = ""
    enable_pinchtab: bool = True
    enable_external_tools: bool = False
    phases: list[str] = Field(default_factory=list, description="Specific phases to run. Empty = all.")


class ReconStatusResponse(BaseModel):
    scan_id: str
    status: str
    current_phase: str = ""
    elapsed_seconds: int = 0
    phases_completed: int = 0
    total_entities: int = 0
    total_tools_run: int = 0
    vulns_found: int = 0
    entity_counts: dict[str, int] = Field(default_factory=dict)


class ExportRequest(BaseModel):
    scan_id: str
    format: str = "sarif"  # sarif | stix | markdown | neo4j | maltego | hackerone


# ── Active Scans Registry ────────────────────────────────────
_active_scans: dict[str, asyncio.Task] = {}


# ── REST Endpoints ───────────────────────────────────────────


@router.post("/start")
async def start_recon(req: StartReconRequest):
    """Start a new reconnaissance scan."""
    from backend.core.hive import event_bus

    if req.scan_id in _active_scans and not _active_scans[req.scan_id].done():
        raise HTTPException(409, f"Scan {req.scan_id} is already running")

    scan_id = req.scan_id or f"recon_{int(asyncio.get_event_loop().time())}"
    orch = AlphaOrchestrator(event_bus)

    async def _run():
        try:
            return await orch.run(req.target_url, scan_id=scan_id, mode=req.mode)
        except Exception as exc:
            logger.error(f"Scan {scan_id} failed: {exc}")
            await recon_live_feed.on_error(scan_id, str(exc), "orchestrator")
            raise

    task = asyncio.create_task(_run())
    _active_scans[scan_id] = task

    return {"scan_id": scan_id, "status": "started", "target": req.target_url, "mode": req.mode}


@router.get("/status/{scan_id}")
async def get_recon_status(scan_id: str) -> ReconStatusResponse:
    """Get current status of a recon scan."""
    stats = recon_live_feed.get_scan_stats(scan_id)
    if not stats:
        # Check if it's in active_scans
        task = _active_scans.get(scan_id)
        if task and task.done():
            return ReconStatusResponse(scan_id=scan_id, status="completed")
        elif task:
            return ReconStatusResponse(scan_id=scan_id, status="running")
        raise HTTPException(404, f"Scan {scan_id} not found")

    return ReconStatusResponse(
        scan_id=scan_id,
        status="running" if scan_id in _active_scans and not _active_scans[scan_id].done() else "completed",
        **stats,
    )


@router.post("/stop/{scan_id}")
async def stop_recon(scan_id: str):
    """Stop a running recon scan."""
    task = _active_scans.get(scan_id)
    if not task or task.done():
        raise HTTPException(404, "No active scan found")
    task.cancel()
    return {"scan_id": scan_id, "status": "stopping"}


@router.get("/scans")
async def list_scans(limit: int = Query(20, le=100)):
    """List recent scans."""
    from backend.core.database import db_manager

    rows = await db_manager.list_recon_runs(limit=limit)
    return {"scans": rows}


@router.get("/entities/{scan_id}")
async def get_entities(scan_id: str, kind: str = "", limit: int = Query(100, le=1000)):
    """Get entities discovered in a scan."""
    from backend.core.database import db_manager

    entities = await db_manager.get_recon_entities(scan_id=scan_id, kind=kind, limit=limit)
    return {"scan_id": scan_id, "count": len(entities), "entities": entities}


@router.get("/relationships/{scan_id}")
async def get_relationships(scan_id: str, limit: int = Query(200, le=1000)):
    """Get entity relationships for a scan."""
    from backend.core.database import db_manager

    rels = await db_manager.get_recon_relationships(scan_id=scan_id, limit=limit)
    return {"scan_id": scan_id, "count": len(rels), "relationships": rels}


@router.post("/export")
async def export_results(req: ExportRequest):
    """Export scan results in various formats."""
    from backend.agents.alpha_recon.exporters import HackerOneExporter, MarkdownReportExporter, SARIFExporter
    from backend.agents.alpha_recon.graph_exporters import MaltegoExporter, Neo4jExporter, STIXExporter
    from backend.core.database import db_manager

    # Load entities from DB
    entities = await db_manager.get_recon_entities(scan_id=req.scan_id, limit=5000)
    relationships = await db_manager.get_recon_relationships(scan_id=req.scan_id, limit=5000)

    # Build ParsedEntity list from DB rows
    from backend.parsers.recon.base import ParsedEntity

    parsed = []
    for e in entities:
        parsed.append(
            ParsedEntity(
                kind=e.get("kind", ""),
                label=e.get("label", ""),
                confidence=e.get("confidence", 0.0),
                source_tool=e.get("source_tool", ""),
                phase=e.get("phase", ""),
                scan_id=req.scan_id,
                id=e.get("id", ""),
                properties=e.get("properties", {}),
            )
        )

    base_dir = Path("data/scans") / req.scan_id / "exports"

    format_handlers = {
        "sarif": lambda: SARIFExporter().export(None, parsed, base_dir / "findings.sarif"),
        "stix": lambda: STIXExporter().export(parsed, None, base_dir / "stix_bundle.json"),
        "markdown": lambda: MarkdownReportExporter().export(None, parsed, base_dir / "report.md"),
        "neo4j": lambda: Neo4jExporter().export(parsed, relationships, base_dir / "import.cypher"),
        "maltego": lambda: MaltegoExporter().export(parsed, base_dir / "entities.csv"),
        "hackerone": lambda: HackerOneExporter().export(None, parsed, base_dir / "hackerone.json"),
    }

    handler = format_handlers.get(req.format)
    if not handler:
        raise HTTPException(400, f"Unknown format: {req.format}. Supported: {', '.join(format_handlers.keys())}")

    output_path = handler()
    return {"scan_id": req.scan_id, "format": req.format, "path": str(output_path), "status": "exported"}


# ── WebSocket Live Feed ──────────────────────────────────────


@router.websocket("/live/{scan_id}")
async def live_feed(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for live recon updates."""
    await websocket.accept()
    queue = recon_live_feed.subscribe(scan_id)

    try:
        # Send initial stats if available
        stats = recon_live_feed.get_scan_stats(scan_id)
        if stats:
            await websocket.send_json({"type": "initial_stats", "scan_id": scan_id, "data": stats})

        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=30.0)
                await websocket.send_json(message)
            except TimeoutError:
                # Send heartbeat
                await websocket.send_json({"type": "heartbeat", "scan_id": scan_id})
    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected from scan {scan_id}")
    except Exception as exc:
        logger.warning(f"WebSocket error for scan {scan_id}: {exc}")
    finally:
        recon_live_feed.unsubscribe(scan_id, queue)
