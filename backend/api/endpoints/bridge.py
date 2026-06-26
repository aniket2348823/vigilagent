"""
Browser Extension Bridge API (Architecture §4.2, §19, §29.8)
================================================================================
The extension is an optional, passive-first session and telemetry bridge. It
captures only in-scope data and never independently exploits targets. The
backend enforces scope + the extension capture allowlist before INGESTING any
observation (Architecture §19 design rules, §29.8 requirements).

Endpoints (Architecture §19):
  POST /bridge/session   - session metadata
  POST /bridge/token     - auth headers/tokens (masked in storage)
  POST /bridge/traffic   - XHR/fetch metadata
  POST /bridge/dom       - DOM snapshots
  POST /bridge/storage   - storage observations
  POST /bridge/ws        - WebSocket metadata
  GET  /bridge/commands  - approved instructions for the extension
  WS   /bridge/live      - live operator-visible status stream

All ingest is additive and governed; out-of-scope or disallowed captures are
rejected with a clear reason (never silently stored).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from backend.core.scope import ScopeViolation, scope_guard

logger = logging.getLogger("api.bridge")
router = APIRouter()

# Map endpoint -> the capture class it ingests (must be in the scope allowlist).
_CAPTURE_CLASS = {
    "session": "cookies",
    "token": "auth_headers",
    "traffic": "xhr_metadata",
    "dom": "dom_snapshot",
    "storage": "cookies",
    "ws": "websocket_metadata",
}

# Keys whose values must be masked before storage (Architecture §19).
_SENSITIVE_KEYS = {"token", "authorization", "cookie", "password", "secret", "api_key", "jwt"}


def _mask(payload: dict[str, Any]) -> dict[str, Any]:
    """Mask sensitive values so secrets are never stored verbatim (Architecture §19)."""
    masked: dict[str, Any] = {}
    for k, v in (payload or {}).items():
        if k.lower() in _SENSITIVE_KEYS and isinstance(v, str) and v:
            masked[k] = v[:4] + "***" + (f"({len(v)})")
        else:
            masked[k] = v
    return masked


def _scope_url(payload: dict[str, Any]) -> str | None:
    return payload.get("url") or payload.get("origin") or payload.get("target")


async def _ingest(capture_class: str, request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception as exc:
        logger.debug(f"[Bridge] Invalid JSON from extension: {exc}")
        return JSONResponse(status_code=400, content={"accepted": False, "reason": "invalid_json"})

    # 1. The capture class must be allowed by the engagement scope (Architecture §19).
    if not scope_guard.allows_extension_capture(capture_class):
        return JSONResponse(
            status_code=403, content={"accepted": False, "reason": f"capture_class_not_allowed:{capture_class}"}
        )

    # 2. The observed URL/origin must be in scope (Architecture §9).
    url = _scope_url(payload)
    if url:
        try:
            scope_guard.assert_allowed(url, action="request")
        except ScopeViolation as exc:
            return JSONResponse(status_code=403, content={"accepted": False, "reason": f"out_of_scope:{exc}"})

    masked = _mask(payload)
    logger.info("[Bridge] ingested %s capture (scope-checked)", capture_class)
    # Persist into durable scan state when a scan_id is present.
    scan_id = payload.get("scan_id", "GLOBAL")
    try:
        from backend.core.scan_state_db import scan_state_db

        scan_state_db.add_event(scan_id, f"bridge_{capture_class}", "extension", masked)
    except Exception as e:
        logger.debug("[Bridge] scan_state_db persist failed: %s", e)
    return JSONResponse(content={"accepted": True, "capture_class": capture_class})


@router.post("/session")
async def bridge_session(request: Request):
    return await _ingest(_CAPTURE_CLASS["session"], request)


@router.post("/token")
async def bridge_token(request: Request):
    return await _ingest(_CAPTURE_CLASS["token"], request)


@router.post("/traffic")
async def bridge_traffic(request: Request):
    return await _ingest(_CAPTURE_CLASS["traffic"], request)


@router.post("/dom")
async def bridge_dom(request: Request):
    return await _ingest(_CAPTURE_CLASS["dom"], request)


@router.post("/storage")
async def bridge_storage(request: Request):
    return await _ingest(_CAPTURE_CLASS["storage"], request)


@router.post("/ws")
async def bridge_ws(request: Request):
    return await _ingest(_CAPTURE_CLASS["ws"], request)


@router.get("/commands")
async def bridge_commands():
    """Approved instructions for the extension. The extension is passive by
    default; commands here are operator-approved, scope-bounded directives only
    (Architecture §19 — the extension does not independently attack)."""
    return JSONResponse(
        content={
            "commands": [],
            "capture_paused": False,
            "scope": {
                "authorized": scope_guard.is_authorized(),
                "allowed_captures": sorted(scope_guard.extension_capture_allowlist),
            },
        }
    )


@router.websocket("/live")
async def bridge_live(websocket: WebSocket):
    """Live operator-visible status stream for the extension (Architecture §19
    'WS /bridge/live'). Passive bridge channel: the extension receives scope and
    capture-pause status and may push scope-checked heartbeats. It is never an
    autonomous-exploitation channel — only governed status is exchanged."""
    from backend.api.socket_manager import manager

    await manager.connect(websocket, client_type="ui")
    try:
        # Send the initial scope/status snapshot so the extension can render
        # operator-visible state and honor the capture-paused flag.
        await websocket.send_json(
            {
                "type": "BRIDGE_STATUS",
                "payload": {
                    "authorized": scope_guard.is_authorized(),
                    "capture_paused": False,
                    "allowed_captures": sorted(scope_guard.extension_capture_allowlist),
                },
            }
        )
        while True:
            # Inbound frames are treated as untrusted heartbeats/acks only.
            await websocket.receive_text()
            await manager.mark_spy_alive()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:  # pragma: no cover - defensive cleanup
        logger.debug("[Bridge] live WS cleanup: %s", e)
        manager.disconnect(websocket)
