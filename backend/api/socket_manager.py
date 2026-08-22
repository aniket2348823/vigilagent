import asyncio
import collections
import json
import logging
import time
from typing import Any

from fastapi import WebSocket

from backend.core.task_manager import TaskManager

# Message schema validation (security hardening)
# Every event type that any part of the backend may broadcast through
# broadcast_immediate() (which validates) must appear here.
_ALLOWED_EVENT_TYPES = {
    # Live feed & threats
    "LIVE_ATTACK_FEED",
    "LIVE_THREAT_LOG",
    # Vulnerability updates
    "VULN_UPDATE",
    "RECON_PACKET",
    "COVERAGE_UPDATE",
    # Spy / extension
    "SPY_STATUS",
    # Batch envelope
    "BATCH",
    # Lifecycle / scan state
    "SCAN_UPDATE",
    "REPORT_READY",
    "PHASE_STARTED",
    "PHASE_COMPLETED",
    "LIFECYCLE_EVENT",
    # Agent heartbeat & progress
    "AGENT_HEARTBEAT",
    "RECON_PROGRESS",
    "EXPLOIT_PROGRESS",
    # Job dispatch & cluster telemetry
    "JOB_ASSIGNED",
    "CLUSTER_TELEMETRY",
    # Key capture (extension bridge)
    "KEY_CAPTURE",
    # Zombie sweep & governance
    "ZOMBIE_SWEEP_RESULT",
    # GI5 system log
    "GI5_LOG",
    # Endpoint discovery
    "ENDPOINT_DISCOVERED",
    "ENDPOINT_TESTED",
}
_MAX_MESSAGE_SIZE = 65536  # 64KB max message size


# --- Adaptive 300 Monitoring Logic ---
def get_display_limit(rps):
    if rps <= 200:
        return rps
    elif rps <= 600:
        return int(rps * 0.6)
    else:
        return 400


def should_emit(event: dict[str, Any], rps: float) -> bool:
    # V7: User requested ALL requests be shown without limits.
    # Disabling sampling entirely.
    return True


# Global scan target URL for filtering (set by orchestrator)
_active_scan_target = ""


def set_active_scan_target(url: str):
    global _active_scan_target
    _active_scan_target = url


def get_active_scan_target() -> str:
    return _active_scan_target


async def publish_request_event(data: dict[str, Any], scan_id: str = None):
    """Publish a real-time request event and record metrics in StateManager."""
    from backend.core.state import stats_db_manager

    try:
        if manager is None:
            return

        # [V7] Increment real global counter
        await stats_db_manager.increment_request_count()

        # Track for real-time RPS gauge
        manager.packet_count += 1

        # Approximate current RPS for log metadata
        current_rps = manager.recent_rps

        if should_emit(data, current_rps):
            # Determine severity from event data
            raw_severity = str(data.get("severity", "")).upper()
            if not raw_severity or raw_severity == "NONE":
                # Derive severity from result/anomaly
                result_str = str(data.get("result", "")).upper()
                if data.get("anomaly") or any(kw in result_str for kw in ["INJECTION", "BYPASS", "LEAK", "ERROR"]):
                    raw_severity = "HIGH"
                elif "BLOCKED" in result_str or "API" in result_str or "SENSITIVE" in result_str:
                    raw_severity = "MEDIUM"
                else:
                    raw_severity = "INFO"

            # Determine risk score from severity if not provided
            risk_score = data.get("risk_score")
            if risk_score is None or risk_score == 0:
                risk_map = {"CRITICAL": 95, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 10}
                risk_score = risk_map.get(raw_severity, 15)

            # Format for Dashboard.jsx
            url_raw = str(data.get("url", data.get("endpoint", "Unknown")))
            formatted_event = {
                "type": "LIVE_ATTACK_FEED",
                "scan_id": scan_id,  # V7: Explicit Scan ID for isolation
                "payload": {
                    "timestamp": data.get("timestamp", time.strftime("%H:%M:%S")),
                    "agent": data.get("agent", "alpha_recon"),
                    "threat_type": data.get("result", "TRAFFIC"),
                    "method": data.get("method", "GET"),
                    "endpoint": url_raw[-40:] if len(url_raw) > 40 else url_raw,
                    "url": url_raw,
                    "severity": raw_severity,
                    "risk_score": risk_score,
                    "status": data.get("status", 0),
                    "anomaly": data.get("anomaly", False),
                    "result": data.get("result", "OK"),
                    "arsenal": data.get("result", "Standard Interaction"),
                    "action": f"{data.get('method', 'GET')} request triggered",
                },
            }
            await manager.broadcast(formatted_event)

            # Periodic Performance Update (Every 5 requests to avoid spam but
            # remain reactive). PERF: the gate reads the live counter via
            # get_total_requests() — a lock-protected int — instead of
            # get_stats(), whose full deepcopy of every scan record used to
            # run on EVERY intercepted request (increment_request_count no
            # longer invalidates the stats cache either, so the dashboard's
            # /stats + /runtime/health polls stop re-deepcopying per request
            # during a scan).
            total_requests = await stats_db_manager.get_total_requests()
            if total_requests % 5 == 0:
                stats = stats_db_manager.get_stats()
                await manager.broadcast(
                    {
                        "type": "VULN_UPDATE",
                        "payload": {
                            "metrics": {
                                "vulnerabilities": stats["vulnerabilities"],
                                "critical": stats["critical"],
                                "active_scans": stats["active_scans"],
                                "total_scans": stats["total_scans"],
                                "total_requests": total_requests,
                                "rps": manager.recent_rps,
                            }
                        },
                    }
                )
    except Exception as e:
        logging.getLogger("Vigilagent.SocketManager").error(f"publish_request_event error: {e}")


# ------------------------------------------


class SocketManager:
    # Replay ring buffer cap. A late-connecting Live Monitor will receive
    # the most recent N broadcasts so it doesn't show a blank screen when it
    # joins after a scan has already started broadcasting events.
    REPLAY_BUFFER_SIZE = 50
    MAX_UI_CONNECTIONS = 100  # FIX-047: Prevent resource exhaustion from unbounded connections
    MAX_SPY_CONNECTIONS = 10
    # Per-IP rate limiting: max connections within the sliding window
    _RATE_LIMIT_WINDOW = 60.0  # seconds
    _RATE_LIMIT_MAX = 10  # max connections per IP within window

    def __init__(self):
        self.ui_connections: list[WebSocket] = []
        self.spy_connections: list[WebSocket] = []
        self.logger = logging.getLogger("Vigilagent.SocketManager")

        self.last_spy_activity = 0.0
        self.message_queue = collections.deque(maxlen=10000)  # Memory Guard: Capped for reasonable memory usage
        self._batch_task = None
        # Per-IP rate limiting: {ip: [timestamp, ...]}
        self._connect_timestamps: dict[str, list[float]] = {}

        # Replay buffer: every successful broadcast is appended here, so a
        # newly-connected ui client can be primed with recent activity. We
        # keep this in-memory only — no disk, no Redis — because it's purely
        # a UX nicety, and a process restart drops it cleanly.
        self._replay_buffer: collections.deque = collections.deque(maxlen=self.REPLAY_BUFFER_SIZE)

        # [NEW] RPS Tracking for Adaptive Sampling
        self.packet_count = 0
        self.recent_rps = 0
        self._rps_task = None
        self._running = False
        self._task_manager = TaskManager("SocketManager")

    def _start_tasks(self):
        if self._running:
            return
        self._running = True
        if self._batch_task is None:
            self._batch_task = self._task_manager.create_task(self._process_batch_queue(), name="batch_processor")
        if self._rps_task is None:
            self._rps_task = self._task_manager.create_task(self._track_rps(), name="rps_tracker")

    async def stop_tasks(self):
        """Cleanup Lifecycle: Stop background monitoring tasks."""
        self._running = False
        await self._task_manager.cancel_all()
        self._batch_task = None
        self._rps_task = None

    async def _track_rps(self):
        """Calculates RPS every second for adaptive sampling.
        Also prunes stale per-IP rate-limit entries every 60s."""
        _prune_counter = 0
        while self._running:
            await asyncio.sleep(1.0)
            self.recent_rps = self.packet_count
            self.packet_count = 0
            _prune_counter += 1
            if _prune_counter >= 60:
                _prune_counter = 0
                now = time.time()
                stale_ips = [
                    ip for ip, ts_list in self._connect_timestamps.items()
                    if not ts_list or all(now - t >= self._RATE_LIMIT_WINDOW for t in ts_list)
                ]
                for ip in stale_ips:
                    del self._connect_timestamps[ip]

    @staticmethod
    def _sanitize_bytes(obj):
        """Serialize bytes to hex for JSON compatibility."""
        if isinstance(obj, bytes):
            return obj.hex()
        return str(obj)

    @staticmethod
    async def _send_with_timeout(connection, msg):
        """Send message to a WebSocket with a 1s timeout. Returns connection on failure."""
        try:
            await asyncio.wait_for(connection.send_text(msg), timeout=1.0)
            return None
        except Exception as exc:
            logging.getLogger("Vigilagent.SocketManager").debug("WS send timeout/failure: %s", exc)
            return connection

    async def _process_batch_queue(self):
        """Batches messages and sends to UI at ~50 FPS. JSON serialized once per event."""
        while self._running:
            try:
                await asyncio.sleep(0.02)
                if self.message_queue:
                    batch = []
                    while self.message_queue:
                        try:
                            batch.append(self.message_queue.popleft())
                        except IndexError:
                            break

                    if not batch:
                        continue

                    # PERF: Serialize once, send same string to all connections
                    if len(batch) == 1:
                        message = json.dumps(batch[0], default=self._sanitize_bytes)
                    else:
                        # Wrap multiple events in a BATCH envelope — single frame
                        message = json.dumps({"type": "BATCH", "payload": batch}, default=self._sanitize_bytes)

                    if self.ui_connections:
                        results = await asyncio.gather(
                            *(self._send_with_timeout(conn, message) for conn in self.ui_connections),
                            return_exceptions=True,
                        )
                        try:
                            from backend.core.metrics import metrics as _m

                            n = len(self.ui_connections)
                            errors = sum(1 for r in results if r is not None)
                            _m.ws_messages_sent_total.inc(n * len(batch))
                            if errors:
                                _m.ws_send_errors_total.inc(errors)
                        except Exception:
                            pass
                        for dead in results:
                            if isinstance(dead, WebSocket) and dead in self.ui_connections:
                                self.ui_connections.remove(dead)
            except Exception as e:
                self.logger.error(f"Batch Error: {e}")
                await asyncio.sleep(1.0)

    def is_spy_online(self) -> bool:
        if len(self.spy_connections) > 0:
            return True
        return (time.time() - self.last_spy_activity) < 60.0

    async def mark_spy_alive(self):
        self.last_spy_activity = time.time()
        self.packet_count += 1  # Count for RPS

    async def connect(self, websocket: WebSocket, client_type: str = "ui"):
        # H-9/H-10: Validate WebSocket origin to prevent cross-site hijacking
        origin = websocket.headers.get("origin", "")
        if origin:
            try:
                from urllib.parse import urlparse

                _op = urlparse(origin)
                origin_host = _op.hostname or ""
                origin_scheme = (_op.scheme or "").lower()
                # The local Chrome extension (Vigilagent Spy) connects from a
                # chrome-extension://<id> origin — its hostname is the extension
                # ID, not an HTTP host. Locally-installed component, same trust
                # domain as localhost.
                if origin_scheme == "chrome-extension":
                    origin_host = ""
                # Reject if origin doesn't match expected hosts
                allowed_origins = {"localhost", "127.0.0.1", ""}
                if origin_host and origin_host not in allowed_origins:
                    self.logger.warning(f"WebSocket rejected: suspicious origin {origin_host}")
                    await websocket.close(code=4003, reason="Invalid origin")
                    return
            except Exception:
                pass  # If origin parsing fails, allow (backward compat)

        # FIX-047: Enforce connection limits to prevent resource exhaustion
        if client_type == "spy" and len(self.spy_connections) >= self.MAX_SPY_CONNECTIONS:
            self.logger.warning("Spy connection limit reached, rejecting")
            await websocket.close(code=1013, reason="Too many connections")
            return
        if client_type != "spy" and len(self.ui_connections) >= self.MAX_UI_CONNECTIONS:
            self.logger.warning("UI connection limit reached, rejecting")
            await websocket.close(code=1013, reason="Too many connections")
            return

        # Per-IP rate limiting: reject IPs exceeding connection rate
        client_ip = websocket.client.host if websocket.client else "unknown"
        now = time.time()
        timestamps = self._connect_timestamps.setdefault(client_ip, [])
        # Prune old timestamps outside the sliding window
        self._connect_timestamps[client_ip] = [
            t for t in timestamps if now - t < self._RATE_LIMIT_WINDOW
        ]
        if len(self._connect_timestamps[client_ip]) >= self._RATE_LIMIT_MAX:
            self.logger.warning(
                "WebSocket rate limit exceeded for %s (%d connects in %ds)",
                client_ip, len(self._connect_timestamps[client_ip]), self._RATE_LIMIT_WINDOW,
            )
            await websocket.close(code=1013, reason="Rate limit exceeded")
            return
        self._connect_timestamps[client_ip].append(now)
        self._start_tasks()
        await websocket.accept()
        if client_type == "spy":
            self.spy_connections.append(websocket)
            await self.mark_spy_alive()
            await self.broadcast_to_ui({"type": "SPY_STATUS", "payload": {"connected": True}})
        else:
            self.ui_connections.append(websocket)
            spy_is_online = self.is_spy_online()
            await websocket.send_text(json.dumps({"type": "SPY_STATUS", "payload": {"connected": spy_is_online}}))
            # Replay the recent ring buffer so a late-joining Live Monitor
            # sees recent activity instead of a blank screen. Send each event
            # as its own frame to match the format the dashboard expects when
            # not batched.
            if self._replay_buffer:
                try:
                    snapshot = list(self._replay_buffer)
                    for event in snapshot:
                        try:
                            await websocket.send_text(json.dumps(event, default=self._sanitize_bytes))
                        except Exception as exc:
                            # Client gone mid-replay; bail out, the disconnect
                            # path will clean it up on the next batch tick.
                            self.logger.debug("replay-on-connect send failed: %s", exc)
                            break
                except Exception as e:
                    self.logger.debug(f"replay-on-connect failed: {e}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.spy_connections:
            self.spy_connections.remove(websocket)
        elif websocket in self.ui_connections:
            self.ui_connections.remove(websocket)

    @staticmethod
    def _validate_message(data: dict) -> bool:
        """Validate message structure before broadcasting.

        Prevents malformed or excessively large messages from being
        broadcast to connected clients (security hardening).
        """
        if not isinstance(data, dict):
            return False
        # Check message size
        try:
            msg_size = len(json.dumps(data, default=str).encode("utf-8"))
            if msg_size > _MAX_MESSAGE_SIZE:
                logging.getLogger("Vigilagent.SocketManager").warning(
                    "Message too large (%d bytes), dropping", msg_size
                )
                return False
        except Exception:
            return False
        # Validate event type if present
        evt_type = data.get("type")
        if evt_type and evt_type not in _ALLOWED_EVENT_TYPES:
            logging.getLogger("Vigilagent.SocketManager").debug("Unknown event type: %s", evt_type)
        return True

    async def broadcast(self, data: dict):
        if not self._validate_message(data):
            return
        await self.broadcast_to_ui(data)

    async def broadcast_immediate(self, data: dict):
        """Bypass batching for critical TC010 control events.

        SECURITY FIX (M-1): Apply the same validation that broadcast() uses
        so oversized or malformed messages cannot be pushed via this path.

        FREEZE FIX: the scan-monitor loop awaits this every ~2s. A stale or
        closed UI WebSocket previously blocked ``send_text`` indefinitely,
        freezing the whole scan (observed live: global event silence at
        15:19:22). Each send now uses the same 1s ``_send_with_timeout`` as
        the batched path, and dead connections are removed — a dead dashboard
        tab can never stall a scan again.
        """
        if not self._validate_message(data):
            return
        message = json.dumps(data, default=self._sanitize_bytes)
        if self.ui_connections:
            results = await asyncio.gather(
                *(self._send_with_timeout(conn, message) for conn in self.ui_connections),
                return_exceptions=True,
            )
            for dead in results:
                if isinstance(dead, WebSocket) and dead in self.ui_connections:
                    self.ui_connections.remove(dead)

    async def broadcast_to_ui(self, data: dict):
        # Cache for late-joiners. Validation already done in broadcast(). We only retain "live" event types — system
        # heartbeats and SPY_STATUS pings would just clutter the replay. The
        # buffer is bounded by REPLAY_BUFFER_SIZE so memory stays flat under
        # high RPS.
        try:
            evt_type = data.get("type") if isinstance(data, dict) else None
            if evt_type and evt_type not in ("SPY_STATUS",):
                self._replay_buffer.append(data)
        except Exception as exc:
            # Never let buffer caching kill a broadcast.
            self.logger.debug("replay buffer caching error: %s", exc)
        self.message_queue.append(data)


manager = SocketManager()
