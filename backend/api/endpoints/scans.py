"""
Scans API (Architecture §22)
================================================================================
The §22 primary scan API surface, added additively (existing /api/attack/fire,
/api/recon, etc. are unchanged — Architecture §13.4 frontend-contract rule).

Endpoints (Architecture §22):
  POST   /api/scans                       create a scan
  GET    /api/scans                       list scans
  GET    /api/scans/{scan_id}             scan detail
  POST   /api/scans/{scan_id}/pause       pause
  POST   /api/scans/{scan_id}/resume      resume
  POST   /api/scans/{scan_id}/cancel      cancel
  GET    /api/scans/{scan_id}/events      event transcript
  GET    /api/scans/{scan_id}/findings    findings
  GET    /api/scans/{scan_id}/graph       knowledge-graph stats/snapshot
  GET    /api/scans/{scan_id}/report      report file/links
"""
from __future__ import annotations

import time
import uuid

import hashlib
import re
from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator

import logging
from backend.core.state import stats_db_manager

logger = logging.getLogger(__name__)

router = APIRouter()

# FIX-008: Strict scan_id validation
_SCAN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$", re.ASCII)
_TARGET_URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)
# FIX-009: Reject dangerous target URLs
forbidden_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254"}


class CreateScanRequest(BaseModel):
    target_url: str
    mode: str = "STANDARD"
    modules: list[str] = Field(default_factory=list)
    scan_id: str | None = None

    @validator("scan_id", pre=True, always=True)
    def _validate_scan_id(cls, v):
        if v is None:
            return v
        if not isinstance(v, str) or not _SCAN_ID_PATTERN.match(v):
            raise ValueError("scan_id must contain only alphanumeric, underscore, or hyphen characters")
        if len(v) > 128:
            raise ValueError("scan_id must be ≤128 characters")
        return v

    @validator("target_url")
    def _validate_target_url(cls, v):
        if not isinstance(v, str) or not _TARGET_URL_PATTERN.match(v):
            raise ValueError("target_url must be a valid HTTP/HTTPS URL")
        # Block private IP ranges and metadata endpoints
        from urllib.parse import urlparse
        parsed = urlparse(v)
        hostname = (parsed.hostname or "").lower()
        if hostname in forbidden_hosts or hostname.startswith(("192.168.", "10.", "172.")):
            raise ValueError("target_url points to a private/internal address which is not allowed")
        if hostname in {"169.254.169.254", "metadata.google.internal", "metadata.azure.com"}:
            raise ValueError("target_url points to a cloud metadata endpoint which is not allowed")
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("target_url scheme must be http or https")
        return v


@router.post("")
@router.post("/")
async def create_scan(req: CreateScanRequest, background_tasks: BackgroundTasks):
    """Create + launch a scan (Architecture §22 POST /api/scans)."""
    from backend.core.orchestrator import HiveOrchestrator

    scan_id = req.scan_id or f"HIVE-V5-{uuid.uuid4().hex[:10]}"
    target_config = {"url": req.target_url, "mode": req.mode, "modules": req.modules}
    _now_iso = time.strftime("%Y-%m-%dT%H:%M:%S")
    scan_record = {
        "id": scan_id, "scan_id": scan_id, "target_url": req.target_url,
        "scope": req.target_url, "status": "Initializing", "modules": req.modules,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "created_at": _now_iso,
        "report_ready": False,
        "results": [], "events": [],
    }
    await stats_db_manager.register_scan(scan_record)

    async def _run():
        try:
            await HiveOrchestrator.bootstrap_hive(target_config, scan_id)
        except Exception as exc:  # pragma: no cover - background
            stats_db_manager.update_scan_status(scan_id, "Failed")
            import logging
            logging.getLogger("api.scans").error("scan %s failed: %s", scan_id, exc)

    background_tasks.add_task(_run)
    return JSONResponse(status_code=202, content={"scan_id": scan_id, "status": "accepted"})


@router.get("")
@router.get("/")
async def list_scans():
    stats = stats_db_manager.get_stats()
    scans = stats.get("scans", []) or []

    def _created_at(scan: dict) -> str:
        # Accept ISO strings, pre-V6 ``YYYY-MM-DD HH:MM:SS`` strings, or float-as-string
        # event-loop timestamps. Always return an ISO-8601 representation so the
        # frontend can parse with ``new Date(...)`` without per-row branches.
        raw_ts = scan.get("created_at") or scan.get("timestamp") or ""
        s = str(raw_ts).strip()
        if not s:
            return ""
        # Already ISO-ish (contains 'T' or timezone marker) — pass through.
        if "T" in s or s.endswith("Z"):
            return s
        # ``YYYY-MM-DD HH:MM:SS`` -> ISO.
        try:
            from datetime import datetime as _dt
            return _dt.strptime(s, "%Y-%m-%d %H:%M:%S").isoformat()
        except Exception as exc:
            import logging as _log
            _log.getLogger("api.scans").debug("datetime parse failed: %s", exc)
        # Float seconds (event-loop time or unix epoch).
        try:
            from datetime import datetime as _dt, timezone as _tz
            ts = float(s)
            # Event-loop times are small (< ~1e9 only after years); treat
            # values < 1e9 as relative loop seconds and don't pretend they're
            # epochs — return the raw string so the UI shows something rather
            # than a 1970 date.
            if ts > 1e9:
                return _dt.fromtimestamp(ts, tz=_tz.utc).isoformat()
        except Exception as exc:
            import logging as _log
            _log.getLogger("api.scans").debug("timestamp conversion failed: %s", exc)
        return s

    rows = []
    for s in scans:
        rows.append({
            "id": s.get("id"),
            "target": s.get("target_url") or s.get("scope"),
            "target_url": s.get("target_url") or s.get("scope") or "",
            "status": s.get("status"),
            "report_ready": bool(s.get("report_ready", False)),
            "created_at": _created_at(s),
        })
    # Newest-first. Empty ``created_at`` strings sort last so freshly-created
    # scans without a timestamp don't push completed history off the top.
    rows.sort(key=lambda r: (r.get("created_at") or ""), reverse=True)
    return {"scans": rows, "count": len(rows)}


@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    scan = stats_db_manager.get_scan_state(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Unknown scan_id")
    return scan


def _signal(scan_id: str, signal: str) -> dict:
    """Publish a CONTROL_SIGNAL to the scan's context if the hive is live."""
    delivered = False
    try:
        from backend.core.orchestrator import HiveOrchestrator
        import asyncio
        from backend.core.hive import EventType, HiveEvent
        # Find any active agent's bus to publish the control signal.
        agents = getattr(HiveOrchestrator, "active_agents", {}) or {}
        bus = None
        for a in agents.values():
            bus = getattr(a, "bus", None)
            if bus is not None:
                break
        if bus is not None:
            asyncio.create_task(bus.publish(HiveEvent(
                type=EventType.CONTROL_SIGNAL, source="api.scans", scan_id=scan_id,
                payload={"signal": signal})))
            delivered = True
    except Exception as exc:
        import logging as _log
        _log.getLogger("api.scans").debug("control signal delivery failed: %s", exc)
        delivered = False
    return {"scan_id": scan_id, "signal": signal, "delivered": delivered}


@router.post("/{scan_id}/pause")
async def pause_scan(scan_id: str):
    stats_db_manager.update_scan_status(scan_id, "Paused")
    return _signal(scan_id, "THROTTLE")


@router.post("/{scan_id}/resume")
async def resume_scan(scan_id: str):
    stats_db_manager.update_scan_status(scan_id, "Running")
    return _signal(scan_id, "RESUME")


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    stats_db_manager.update_scan_status(scan_id, "Cancelled")
    return _signal(scan_id, "ABORT")


@router.get("/{scan_id}/events")
async def scan_events(scan_id: str, limit: int = 500):
    scan = stats_db_manager.get_scan_state(scan_id) or {}
    events = scan.get("events", [])
    return {"scan_id": scan_id, "events": events[-limit:], "count": len(events)}


def _findings_from_scan(scan: dict) -> list[dict]:
    """Extract findings from a scan record across every persistence path.

    Confirmed findings are persisted in three places at different points in the
    lifecycle:
      1. ``scan["results"]`` — populated when the scan finalizes
         (`StateManager.complete_scan`).
      2. ``scan["findings"]`` — populated by direct `StateManager.add_finding`
         calls.
      3. ``scan["events"]`` — every `VULN_CONFIRMED` HiveEvent is appended
         regardless of GuardLayer side-effect filtering.

    During an active scan only (3) is populated; after completion (1) is the
    canonical source. We merge all three and de-duplicate by ``(url, type)`` so
    the API always surfaces every confirmed finding, even mid-scan and even if
    the dashboard counters were filtered."""
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []

    def _coerce(item: dict) -> dict:
        # Normalise different storage shapes into the same finding dict.
        if not isinstance(item, dict):
            return {}
        if "payload" in item and isinstance(item["payload"], dict):
            payload = dict(item["payload"])
            for k in ("type", "source"):
                if k in item and k not in payload:
                    payload[k] = item[k]
            return payload
        return dict(item)

    for source in (scan.get("results") or [], scan.get("findings") or []):
        for it in source:
            f = _coerce(it)
            key = (str(f.get("url", "")).lower(), str(f.get("type", "")).upper())
            if key in seen or not f.get("url"):
                continue
            seen.add(key)
            out.append(f)

    for ev in scan.get("events", []) or []:
        # Tolerate both plain strings ("VULN_CONFIRMED") and the legacy
        # enum-repr form ("EventType.VULN_CONFIRMED" / Enum object) that older
        # event records may still carry. The orchestrator now serialises with
        # ``mode="json"`` so new events are plain strings; this fallback keeps
        # us readable across rolling restarts.
        ev_type = ev.get("type", "")
        ev_type_str = str(getattr(ev_type, "value", ev_type)).upper()
        if ev_type_str.endswith("VULN_CONFIRMED") or ev_type_str == "VULN_CONFIRMED":
            pass
        else:
            continue
        f = _coerce(ev)
        key = (str(f.get("url", "")).lower(), str(f.get("type", "")).upper())
        if key in seen or not f.get("url"):
            continue
        seen.add(key)
        out.append(f)

    return out


def _enrich_finding_for_api(f: dict, scan_id: str) -> dict:
    """Augment a raw finding with the fields the Live Monitor and the new PDF
    builder both rely on, without dropping any existing keys.

    Required output keys (Sub-Agent D contract): id, type, severity, url,
    cvss_score, cvss_severity, evidence, remediation, agent, timestamp.
    """
    out = dict(f)  # preserve every field already present
    # Stable id — fall back to a deterministic hash of (url, type) so
    # downstream UIs can key React lists without colliding.
    # FIX-016: Use SHA-256 instead of SHA-1 for stable finding IDs
    if not out.get("id"):
        sig = f"{scan_id}|{str(f.get('url',''))}|{str(f.get('type',''))}".lower()
        out["id"] = "F-" + hashlib.sha256(sig.encode("utf-8")).hexdigest()[:10]

    out.setdefault("type", f.get("type") or f.get("vuln_type") or "Unknown")
    out.setdefault("severity", f.get("severity") or "INFO")
    out.setdefault("url", f.get("url") or f.get("endpoint") or "")
    out.setdefault("timestamp", f.get("timestamp") or f.get("created_at") or "")

    # CVSS — if missing, compute deterministically from the vuln class.
    if not isinstance(out.get("cvss_score"), (int, float)) or not out.get("cvss_severity"):
        try:
            from backend.reporting.cvss_engine import score_for_vuln_class
            score, _vector = score_for_vuln_class(str(out.get("type", "")))
            out.setdefault("cvss_score", round(float(score), 1))
            band = (
                "CRITICAL" if score >= 9.0
                else "HIGH" if score >= 7.0
                else "MEDIUM" if score >= 4.0
                else "LOW" if score > 0
                else "INFO"
            )
            out.setdefault("cvss_severity", band)
        except Exception as exc:
            import logging as _log
            _log.getLogger("api.scans").debug("CVSS scoring failed for finding: %s", exc)
            out.setdefault("cvss_score", 0.0)
            out.setdefault("cvss_severity", out.get("severity", "INFO"))

    # Evidence dict shape: { request, response, ... } — never invent traffic.
    ev = out.get("evidence")
    if not isinstance(ev, dict):
        ev = {}
    ev.setdefault("request", f.get("request") or f.get("http_request") or "")
    ev.setdefault("response", f.get("response") or f.get("http_response") or "")
    out["evidence"] = ev

    # Remediation hint — accept legacy string / list / nested forms.
    if not out.get("remediation"):
        out["remediation"] = f.get("remediation_hint") or f.get("fix") or ""

    # Agent that confirmed the finding — orchestrator persists this as
    # ``validated_by`` (DB) or ``source`` (event payload); surface either.
    if not out.get("agent"):
        out["agent"] = f.get("validated_by") or f.get("source") or f.get("agent_confirmed") or ""

    return out


@router.get("/{scan_id}/findings")
async def scan_findings(scan_id: str):
    scan = stats_db_manager.get_scan_state(scan_id) or {}
    findings = _findings_from_scan(scan)
    enriched = [_enrich_finding_for_api(f, scan_id) for f in findings]
    return {"scan_id": scan_id, "findings": enriched, "count": len(enriched)}


@router.get("/{scan_id}/graph")
async def scan_graph(scan_id: str):
    """Knowledge-graph stats for the scan (Architecture §12, §22)."""
    try:
        from backend.core.unified_knowledge_graph import unified_knowledge_graph
        return unified_knowledge_graph.stats()
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.get("/{scan_id}/report")
async def scan_report(scan_id: str):
    """Return generated report links for the scan (Architecture §18, §22)."""
    import os
    from backend.core.config import settings
    reports_dir = settings.REPORTS_DIR
    pdf = f"Scan_Report_{scan_id}.pdf"
    findings_dir = os.path.join(reports_dir, scan_id)
    outputs = {}
    if os.path.exists(os.path.join(reports_dir, pdf)):
        outputs["pdf"] = f"/api/reports/download/{pdf}"
    if os.path.isdir(findings_dir):
        for f in os.listdir(findings_dir):
            outputs[f.rsplit(".", 1)[-1]] = os.path.join(findings_dir, f)
    return {"scan_id": scan_id, "reports": outputs,
            "export_endpoint": f"/api/reports/findings/{scan_id}/export"}
