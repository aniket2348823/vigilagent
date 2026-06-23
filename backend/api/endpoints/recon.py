import asyncio
from fastapi import APIRouter, HTTPException, Request
from backend.schemas.payloads import ReconPayload
from backend.api.socket_manager import manager, publish_request_event
from typing import Dict, Any
import os
import json
from datetime import datetime
import random
import logging

logger = logging.getLogger(__name__)

KEYRING_FILE = "keyring.json"

router = APIRouter()

def summarize_result(packet_data: Dict[str, Any]) -> str:
    """Returns a concise summary for the 'RESULT' column."""
    url = packet_data.get("url", "").lower()
    headers = packet_data.get("headers", {})
    
    if "passwd" in url or "shadow" in url:
        return "âš ï¸ DATA LEAK"
    if "admin" in url and "config" in url:
        return "ðŸ”‘ AUTH BYPASS"
    if "sql" in url or "select" in url:
        return "ðŸ’‰ INJECTION"
    
    # Check for scanner engine results
    if headers.get("x-scanner") == "v12-engine":
        return "ðŸ” SCANNER FINDING"
        
    return "OK"

@router.post("/ingest")
async def ingest_recon_data(payload: ReconPayload):
    # Mark spy alive and count for RPS
    await manager.mark_spy_alive()
    
    packet_data = payload.model_dump()
    result_summary = summarize_result(packet_data)
    
    # Determine severity/anomaly
    is_anomaly = "âš ï¸" in result_summary or "ðŸ”‘" in result_summary or "ðŸ’‰" in result_summary
    severity = "high" if is_anomaly else "low"

    # [NEW] Broadcast to UI via Adaptive Sampling
    try:
        await publish_request_event({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "method": packet_data.get("method", "GET"),
            "endpoint": packet_data.get("url", "Unknown")[-60:],
            "url": packet_data.get("url", "Unknown"),
            "payload": str(packet_data.get("body", ""))[:30] or "NONE",
            "status": 200, 
            "latency": random.randint(10, 80),
            "result": result_summary,
            "anomaly": is_anomaly,
            "severity": severity
        })
    except Exception as e:
        logger.debug(f"Broadcast Error: {e}")

    # Legacy RECON_PACKET for components that haven't migrated
    await manager.broadcast({
        "type": "RECON_PACKET",
        "payload": packet_data
    })

    # --- BRAIN INGESTION (Existing Logic) ---
    # FIX-059: Wrap sync file I/O in asyncio.to_thread to avoid blocking
    # the event loop (Architecture §29.13).
    headers = packet_data.get("headers", {})
    if headers.get("x-scanner") == "v12-engine":
        try:
            scan_payload = packet_data.get("payload", {})
            if "findings" in scan_payload:
                memory_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "brain", "memory.json")
                def _ingest_brain():
                    brain_data = []
                    if os.path.exists(memory_file):
                        with open(memory_file, "r") as f:
                            brain_data = json.load(f)
                    for finding in scan_payload["findings"]:
                        brain_data.append({
                            "type": "VULN_CANDIDATE",
                            "description": finding.get("description"),
                            "payload": finding,
                            "source": "ScannerEngine V12",
                            "timestamp": packet_data.get("timestamp"),
                            "verified": False
                        })
                    with open(memory_file, "w") as f:
                        json.dump(brain_data, f, indent=2)
                await asyncio.to_thread(_ingest_brain)
        except Exception as e:
            logger.debug(f"Brain Ingest Error: {e}")
    # -----------------------------------
    return {"status": "ingested"}

@router.get("/keyring")
async def get_keyring():
    if not os.path.exists(KEYRING_FILE):
        return []
    try:
        # FIX-059: Wrap sync file I/O in asyncio.to_thread
        def _read_keyring():
            with open(KEYRING_FILE, "r") as f:
                return json.load(f)
        return await asyncio.to_thread(_read_keyring)
    except Exception as e:
        logger.debug("Keyring load failed: %s", e)
        return []

@router.post("/keys")
async def ingest_keys(request: Request):
    """Ingest extension-captured auth keys.

    This is a passive observation endpoint — the extension reports what it
    sees from ALL browser tabs.  We accept raw JSON and normalize the
    payload so that every realistic extension request is properly ingested.
    Only dangerous payloads (SSRF to cloud metadata) are rejected.
    """
    try:
        body = await request.json()
    except Exception:
        # Even unparseable bodies get a minimal record so the extension
        # doesn't backoff and retry endlessly.
        body = {}

    if not isinstance(body, dict):
        body = {}

    # Normalize fields — accept whatever the extension sends and coerce
    # to the shape we need.  Never reject for missing/malformed data;
    # instead provide sensible defaults.
    #
    # NOTE: We use ``is not None`` instead of truthiness (``or``) because
    # empty dicts/strings are valid values the caller may send intentionally.
    # An empty ``keys`` dict means "no sensitive headers found" — we should
    # ingest it as-is, not skip to the next field.
    url = str(body.get("url") or body.get("target_url") or body.get("endpoint") or "").strip()

    keys_raw = body.get("keys")
    if keys_raw is None:
        keys_raw = body.get("headers")
    if keys_raw is None:
        keys_raw = body.get("captured_keys")
    if keys_raw is None:
        keys_raw = {}
    if not isinstance(keys_raw, dict):
        try:
            keys_raw = {"raw": str(keys_raw)}
        except Exception:
            keys_raw = {}

    # Coerce timestamp from any format (int, float, string, epoch millis)
    timestamp = body.get("timestamp")
    if timestamp is None:
        timestamp = body.get("ts", 0.0)
    try:
        timestamp = float(timestamp)
        # Extension sometimes sends epoch milliseconds; normalize to seconds
        if timestamp > 1e12:
            timestamp = timestamp / 1000.0
    except (TypeError, ValueError):
        timestamp = 0.0

    # SSRF guard: block cloud metadata endpoints only
    if url:
        from urllib.parse import urlparse as _urlparse
        _parsed = _urlparse(url)
        _blocked_metadata = {"169.254.169.254", "metadata.google.internal", "metadata.azure.com"}
        if (_parsed.hostname or "").lower() in _blocked_metadata:
            raise HTTPException(status_code=400, detail="Cloud metadata endpoint blocked")

    data = {"url": url, "keys": keys_raw, "timestamp": timestamp}

    # FIX-059: Wrap sync file I/O in asyncio.to_thread
    def _write_keyring():
        keyring = []
        if os.path.exists(KEYRING_FILE):
            try:
                with open(KEYRING_FILE, "r") as f:
                    keyring = json.load(f)
            except Exception as e:
                logger.debug(f"Recon error: {e}")
        keyring.append(data)
        if len(keyring) > 100: keyring = keyring[-100:]
        try:
            with open(KEYRING_FILE, "w") as f:
                json.dump(keyring, f, indent=4)
        except Exception as e:
            logger.debug(f"Recon error: {e}")
    await asyncio.to_thread(_write_keyring)
    await manager.broadcast({"type": "KEY_CAPTURE", "payload": data})
    return {"status": "archived"}
