import logging
import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

from backend.core.config import settings
from backend.core.database import db_manager
from backend.core.rate_limiter import rate_limit
from backend.core.reporting import ReportGenerator
from backend.core.state import stats_db_manager

logger = logging.getLogger(__name__)

router = APIRouter()
REPORTS_DIR = settings.REPORTS_DIR


@router.get("/download/{filename}")
async def download_report_file(filename: str):
    # FIX-059: Validate filename to prevent path traversal
    import re as _re

    if (
        not filename
        or ".." in filename
        or "/" in filename
        or "\\" in filename
        or not _re.match(r"^[A-Za-z0-9_\-. ]+\.pdf$", filename)
    ):
        raise HTTPException(status_code=400, detail="Invalid filename")
    file_path = os.path.join(REPORTS_DIR, filename)
    # Ensure resolved path is within REPORTS_DIR
    if not os.path.realpath(file_path).startswith(os.path.realpath(REPORTS_DIR)):
        raise HTTPException(status_code=400, detail="Invalid filename")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path=file_path, filename=filename, media_type="application/pdf")


def _to_finding(raw: dict):
    """Map a stored scan finding dict onto the unified Finding model (§17, §18).

    Accepts both the ``results`` shape (already a payload-first dict) and the
    HiveEvent shape (``{"payload": {...}}``). Source-level deduplication and
    extraction is handled upstream by ``_findings_from_scan``."""
    from backend.schemas.findings import (
        Finding,
        FindingConfidence,
        FindingSeverity,
        FindingState,
    )

    if isinstance(raw, dict) and isinstance(raw.get("payload"), dict):
        payload = raw["payload"]
    elif isinstance(raw, dict):
        payload = raw
    else:
        payload = {}
    sev_raw = str(payload.get("severity", "medium")).lower()
    sev = {
        "critical": FindingSeverity.CRITICAL,
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
        "info": FindingSeverity.INFORMATIONAL,
        "informational": FindingSeverity.INFORMATIONAL,
    }.get(sev_raw, FindingSeverity.MEDIUM)
    controls = payload.get("false_positive_controls", [])
    # A VULN_CONFIRMED event implies confirmation by the orchestrator's strict
    # path (Architecture §17). Fall back to PROBABLE only when no signals.
    confirmed = bool(payload.get("verified") or controls or payload.get("type") or payload.get("vuln_type"))
    return Finding(
        id=str(payload.get("vuln_id") or payload.get("id") or payload.get("url", "finding")),
        title=str(payload.get("type") or payload.get("vuln_type") or payload.get("name") or "Finding"),
        severity=sev,
        affected_target=str(payload.get("url") or payload.get("endpoint") or ""),
        description=str(payload.get("description") or payload.get("evidence") or ""),
        cvss_score=payload.get("cvss_score"),
        cvss_vector=str(payload.get("cvss_vector", "")),
        state=FindingState.CONFIRMED if confirmed else FindingState.CANDIDATE,
        scope_status=str(payload.get("scope_status", "in_scope")),
        business_impact=str(payload.get("business_impact", "")),
        technical_impact=str(payload.get("technical_impact", "")),
        steps_to_reproduce=list(payload.get("steps_to_reproduce", []) or []),
        false_positive_controls=list(controls or []),
        remediation=str(payload.get("remediation", "")),
        references=list(payload.get("references", []) or []),
        confidence=FindingConfidence.VERIFIED if confirmed else FindingConfidence.PROBABLE,
    )


@router.post("/findings/{scan_id}/export")
async def export_findings(scan_id: str):
    """Emit ALL evidence-first report formats from confirmed Finding objects
    (Architecture §18): JSON, SARIF, HackerOne markdown, STIX, Executive PDF,
    Technical PDF. Additive endpoint — existing /pdf route is unchanged."""
    from pathlib import Path

    from backend.api.endpoints.scans import _findings_from_scan
    from backend.reporting.finding_report import FindingReportEngine

    scan = stats_db_manager.get_scan_state(scan_id) or {}
    raw_findings = _findings_from_scan(scan)
    findings = [_to_finding(r) for r in raw_findings]
    target = scan.get("target_url") or scan.get("scope") or scan_id

    base_dir = Path(REPORTS_DIR) / scan_id
    engine = FindingReportEngine(scan_id, str(target))
    outputs = engine.emit_all(findings, base_dir)
    return {"scan_id": scan_id, "finding_count": len(findings), "outputs": outputs}


@router.get("/")
async def list_reports():
    """
    Lists all generated PDF reports.
    """
    if not os.path.exists(REPORTS_DIR):
        return []

    files = [f for f in os.listdir(REPORTS_DIR) if f.endswith(".pdf")]
    return [{"name": f, "path": f"/api/reports/pdf/{f.replace('Scan_Report_', '').replace('.pdf', '')}"} for f in files]


@router.get("/pdf/{scan_id}")
@rate_limit("/api/reports/pdf")
async def generate_pdf_report(request: Request, scan_id: str):
    """
    Serves or Generates a PDF security report.
    V6 OMEGA Stabilization: strictly awaits generation and validates paths.
    """
    filename = f"Scan_Report_{scan_id}.pdf"
    report_path = os.path.join(str(REPORTS_DIR), filename)  # Force string conversion to fix TypeError

    try:
        # 1. Check for Cached Report
        if os.path.exists(report_path):
            return FileResponse(path=report_path, media_type="application/pdf", filename=filename)

        # 2. On-Demand Generation if missing
        scan_data = next((s for s in stats_db_manager.get_stats().get("scans", []) if s["id"] == scan_id), None)
        if not scan_data:
            raise HTTPException(status_code=404, detail="Scan record not found.")

        # Trigger Real-Time Report Generation (V6 HARDENED)
        try:
            reporter = ReportGenerator()
            # Fetch events from the local scan record first
            scan_events = scan_data.get("events", [])

            # [NEW] Sync findings from Supabase for high-fidelity reports
            try:
                await db_manager.initialize()
                supabase_vulns = await db_manager.get_vulnerabilities(scan_id)
                for v in supabase_vulns:
                    # Map Supabase Row to HiveEvent format for the generator
                    scan_events.append(
                        {
                            "type": "VULN_CONFIRMED",
                            "source": v.get("validated_by", "EliteDB"),
                            "payload": {
                                "type": v.get("vuln_type"),
                                "url": v.get("endpoint"),
                                "severity": v.get("severity"),
                                "evidence": v.get("evidence"),
                                "description": v.get("description"),
                            },
                        }
                    )
            except Exception as db_err:
                logger.warning(f"Supabase fetch failed, falling back to local events: {db_err}")

            telemetry = scan_data.get("telemetry", {})
            target_url = scan_data.get("target", scan_data.get("name", "Unknown"))

            # CRITICAL FIX: Strictly await the report generation coroutine
            logger.info(f"Triggering On-Demand Generation for {scan_id}...")
            await reporter.generate_report(
                scan_id=scan_id, events=scan_events, target_url=target_url, telemetry=telemetry
            )

            # Verify the file was actually written after await
            if os.path.exists(report_path):
                return FileResponse(path=report_path, media_type="application/pdf", filename=filename)
            else:
                raise HTTPException(status_code=500, detail="Report generation failed to materialize.")

        except Exception as gen_err:
            logger.error(f"ON-DEMAND GEN FAILED: {gen_err}")
            raise HTTPException(status_code=500, detail=f"Generation Failure: {str(gen_err)}")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Atomic Serve Failure: {str(e)}")


@router.get("/consolidated")
@rate_limit("/api/reports/consolidated")
async def generate_consolidated_report(request: Request):
    """
    Generates a high-fidelity intelligence report aggregating ALL scans.
    Performs cross-scan deduplication and strategic multi-vector analysis.
    """
    scan_id = "Consolidated_Intelligence"
    filename = f"Scan_Report_{scan_id}.pdf"
    report_path = os.path.join(str(REPORTS_DIR), filename)

    try:
        # Aggregation Logic
        stats = stats_db_manager.get_stats()
        all_scans = stats.get("scans", [])
        # Aggregate events from each scan record (events key is per-scan, not top-level)
        all_events = []
        for scan in all_scans:
            all_events.extend(scan.get("events", []))

        if not all_scans:
            raise HTTPException(status_code=404, detail="No scan data available for consolidation.")

        consolidated_events = []
        total_requests = 0
        total_duration_secs = 0

        # Deduplication Map: (type, url, payload_hash) -> event
        dedup_map = {}

        for scan in all_scans:
            s_id = scan["id"]
            s_events = [e for e in all_events if e.get("scan_id") == s_id]

            # Aggregate Telemetry
            telemetry = scan.get("telemetry", {})
            total_requests += telemetry.get("total_requests", 0)
            # Duration parsing (approximate)
            try:
                dur_str = str(telemetry.get("duration", "0"))
                if "h" in dur_str:
                    # Logic for complex strings if needed
                    pass
                else:
                    total_duration_secs += int(dur_str.split()[0].replace("s", ""))
            except (ValueError, IndexError, AttributeError):
                # Skip malformed duration strings
                pass

            # Deduplicate Vulnerabilities across scans
            for e in s_events:
                if any(
                    t in str(e.get("type", "")).upper() for t in ["VULN_CONFIRMED", "HIDDEN_TEXT", "PROMPT_INJECTION"]
                ):
                    payload = e.get("payload", {})
                    v_type = str(payload.get("type", "")).upper()
                    v_url = str(payload.get("url", "")).lower()
                    v_data = str(payload.get("payload", payload.get("data", ""))).strip().lower()[:100]

                    sig = f"{v_type}|{v_url}|{v_data}"
                    if sig not in dedup_map:
                        dedup_map[sig] = e
                        consolidated_events.append(e)
                else:
                    # Non-vuln event? Maybe include some logs for timeline
                    if len(consolidated_events) < 500:  # Cap timeline size
                        consolidated_events.append(e)

        # Build Consolidated Telemetry
        consolidated_telemetry = {
            "start_time": all_scans[0].get("start_time"),
            "end_time": all_scans[-1].get("end_time"),
            "duration": f"{total_duration_secs}s",
            "total_requests": total_requests,
            "avg_latency_ms": sum(s.get("telemetry", {}).get("avg_latency_ms", 0) for s in all_scans) / len(all_scans),
            "peak_concurrency": max(s.get("telemetry", {}).get("peak_concurrency", 0) for s in all_scans),
            "ai_calls": sum(s.get("telemetry", {}).get("ai_calls", 0) for s in all_scans),
        }

        # Generate the Report
        reporter = ReportGenerator()
        await reporter.generate_report(
            scan_id=scan_id,
            events=consolidated_events,
            target_url="MULTI-TARGET CONSOLIDATED ASSET",
            telemetry=consolidated_telemetry,
        )

        if os.path.exists(report_path):
            return FileResponse(path=report_path, media_type="application/pdf", filename=filename)
        else:
            raise HTTPException(status_code=500, detail="Consolidated report generation failed.")

    except Exception as e:
        logger.error(f"CONSOLIDATED GEN FAILED: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# --- PROBLEM 12 FIX: Scan Diff Engine ---


@router.get("/diff/{scan_id_1}/{scan_id_2}")
async def diff_scans(scan_id_1: str, scan_id_2: str):
    """
    Compare two scans to identify new, fixed, worsened, and improved vulnerabilities.
    Essential for iterative security validation.
    """
    # Try sharded state first, fallback to stats.json
    scan1_data = await stats_db_manager.read_scan_state(scan_id_1)
    scan2_data = await stats_db_manager.read_scan_state(scan_id_2)

    # Fallback to stats.json scans
    if not scan1_data:
        scan1_data = next((s for s in stats_db_manager.get_stats().get("scans", []) if s["id"] == scan_id_1), None)
    if not scan2_data:
        scan2_data = next((s for s in stats_db_manager.get_stats().get("scans", []) if s["id"] == scan_id_2), None)

    if not scan1_data or not scan2_data:
        raise HTTPException(status_code=404, detail="One or both scan IDs not found.")

    # Extract vulnerabilities from results
    def extract_vulns(scan_data):
        vulns = {}
        for r in scan_data.get("results", scan_data.get("vulnerabilities", [])):
            payload = r.get("payload", r) if isinstance(r, dict) else {}
            vid = payload.get("vuln_id", payload.get("id", payload.get("url", "") + "|" + payload.get("type", "")))
            vulns[vid] = payload
        return vulns

    vulns1 = extract_vulns(scan1_data)
    vulns2 = extract_vulns(scan2_data)

    new_vulns = [v for vid, v in vulns2.items() if vid not in vulns1]
    fixed_vulns = [v for vid, v in vulns1.items() if vid not in vulns2]
    worsened = []
    improved = []

    for vid in set(vulns1) & set(vulns2):
        old_score = vulns1[vid].get("final_risk_score", vulns1[vid].get("confidence", 0))
        new_score = vulns2[vid].get("final_risk_score", vulns2[vid].get("confidence", 0))
        if isinstance(old_score, (int, float)) and isinstance(new_score, (int, float)):
            if new_score > old_score + 0.1:
                worsened.append({"vuln_id": vid, "old_score": old_score, "new_score": new_score})
            elif new_score < old_score - 0.1:
                improved.append({"vuln_id": vid, "old_score": old_score, "new_score": new_score})

    return {
        "scan_1": scan_id_1,
        "scan_2": scan_id_2,
        "new_vulnerabilities": new_vulns,
        "fixed_vulnerabilities": fixed_vulns,
        "worsened": worsened,
        "improved": improved,
        "summary": {
            "new": len(new_vulns),
            "fixed": len(fixed_vulns),
            "worsened": len(worsened),
            "improved": len(improved),
        },
    }


# --- PROBLEM 15 FIX: Incremental Live Reports ---


@router.get("/live/{scan_id}")
async def get_live_report(scan_id: str):
    """
    Get the current live report state for an active or completed scan.
    Allows viewing findings mid-scan without waiting for completion.
    """
    # Try sharded state first
    data = await stats_db_manager.read_scan_state(scan_id)

    # Fallback to stats.json
    if not data:
        scan = next((s for s in stats_db_manager.get_stats().get("scans", []) if s["id"] == scan_id), None)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")
        data = scan

    events = data.get("events", [])
    vuln_events = [e for e in events if e.get("type") in ["VULN_CONFIRMED", "VULN_CANDIDATE"]]

    return {
        "scan_id": scan_id,
        "status": data.get("status", "unknown"),
        "vulnerability_count": len(vuln_events),
        "vulnerabilities": vuln_events[:100],  # Cap for performance
        "total_events": len(events),
        "started_at": data.get("timestamp", data.get("started_at")),
        "last_updated": data.get("last_updated", data.get("timestamp")),
        "results": data.get("results", []),
    }
