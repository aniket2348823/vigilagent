"""
Alpha V6 Interactsh Client Adapter — Scan-wide OOB callback detection.

Manages an Interactsh client per-scan for out-of-band vulnerability validation.
Polls for interactions and correlates them back to source payloads.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import time
from typing import TYPE_CHECKING

from backend.agents.alpha_recon.models import stable_id
from backend.core.database import db_manager
from backend.core.queue import command_lane

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("alpha.interactsh")


class InteractshAdapter:
    """Manages Interactsh client lifecycle for a scan."""

    def __init__(self, scan_id: str, artifacts_root: Path):
        self.scan_id = scan_id
        self.artifacts_root = artifacts_root
        self.interaction_log = artifacts_root / "raw" / "interactsh_interactions.jsonl"
        self.interaction_log.parent.mkdir(parents=True, exist_ok=True)
        self._correlation_id: str = ""
        self._interactsh_url: str = ""
        self._poll_task: asyncio.Task | None = None
        self._interactions: list[dict] = []
        self._running = False

    @property
    def oob_url(self) -> str:
        """Get the OOB callback URL for embedding in payloads."""
        return self._interactsh_url

    @property
    def correlation_id(self) -> str:
        return self._correlation_id

    def _fallback_url(self) -> str:
        """Placeholder OOB URL so payload injection still works when the
        real interactsh client cannot start (offline network, missing client)."""
        self._interactsh_url = f"INTERACT_{self._correlation_id}.oast.live"
        return self._interactsh_url

    @staticmethod
    async def _terminate(proc) -> None:
        """Best-effort cleanup of the client subprocess."""
        if proc is None:
            return
        try:
            proc.terminate()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(proc.wait(), timeout=3)
        except Exception:
            pass
        with contextlib.suppress(Exception):
            proc.kill()

    @staticmethod
    async def _drain_stderr(proc, seconds: float = 1.0) -> str:
        """Read a short sample of stderr for diagnostics (best-effort)."""
        try:
            data = await asyncio.wait_for(proc.stderr.read(4000), timeout=seconds)
            return data.decode("utf-8", errors="replace").strip()[:2000]
        except Exception:
            return ""

    async def start(self) -> str:
        """Start the Interactsh client and return the OOB URL."""
        # Generate a correlation ID for this scan
        self._correlation_id = hashlib.sha256(
            f"{self.scan_id}_{time.time()}".encode()).hexdigest()[:12]

        # Check if interactsh-client is available
        import shutil
        client_path = shutil.which("interactsh-client")
        if not client_path:
            logger.warning("[INTERACTSH] Client not found, using placeholder URL")
            return self._fallback_url()

        proc = None
        # Start the client process
        try:
            async with command_lane.slot():
                proc = await asyncio.create_subprocess_exec(
                    client_path, "-json", "-poll-interval", "5",
                    "-o", str(self.interaction_log),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

            # Read the first line to get the URL. A timeout / empty line /
            # non-JSON line means the client cannot reach the interactsh
            # server (no network) — fall back instead of logging an empty
            # "Failed to start:" and leaking the process.
            try:
                first_line = await asyncio.wait_for(proc.stdout.readline(), timeout=12)
            except asyncio.TimeoutError:
                _err = await self._drain_stderr(proc)
                logger.warning(
                    "[INTERACTSH] Client produced no URL within 12s (network blocked? stderr: %.200s); using placeholder",
                    _err,
                )
                await self._terminate(proc)
                return self._fallback_url()

            if not first_line:
                _err = await self._drain_stderr(proc)
                logger.warning(
                    "[INTERACTSH] Client exited without output (stderr: %.200s); using placeholder",
                    _err,
                )
                await self._terminate(proc)
                return self._fallback_url()

            try:
                url_data = json.loads(first_line.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as exc:
                logger.warning(
                    "[INTERACTSH] Unexpected client output (%s: %.120r); using placeholder",
                    exc,
                    first_line[:120],
                )
                await self._terminate(proc)
                return self._fallback_url()

            self._interactsh_url = url_data.get("url", "")
            if not self._interactsh_url:
                logger.warning("[INTERACTSH] Client returned no URL; using placeholder")
                await self._terminate(proc)
                return self._fallback_url()

            self._running = True
            self._poll_task = asyncio.create_task(
                self._poll_interactions(proc))
            logger.info(f"[INTERACTSH] Started with URL: {self._interactsh_url}")
            return self._interactsh_url
        except Exception as exc:
            logger.warning(
                "[INTERACTSH] Failed to start (%s: %s); using placeholder",
                type(exc).__name__,
                exc,
            )
            await self._terminate(proc)
            return self._fallback_url()

    async def stop(self) -> list[dict]:
        """Stop the client and return all interactions."""
        self._running = False
        if self._poll_task:
            self._poll_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._poll_task
        return self._interactions

    async def _poll_interactions(self, proc):
        """Background task to read interactions from the client."""
        try:
            while self._running:
                line = await asyncio.wait_for(
                    proc.stdout.readline(), timeout=10)
                if not line:
                    await asyncio.sleep(1)
                    continue
                try:
                    interaction = json.loads(line.decode("utf-8", errors="replace"))
                    await self._process_interaction(interaction)
                except json.JSONDecodeError:
                    continue
        except (TimeoutError, asyncio.CancelledError):
            pass
        except Exception as exc:
            logger.warning(f"[INTERACTSH] Poll error: {exc}")
        finally:
            try:
                proc.terminate()
            except Exception as term_exc:
                logger.debug("[INTERACTSH] process terminate failed: %s", term_exc)

    async def _process_interaction(self, interaction: dict):
        """Process a single OOB interaction."""
        int_type = interaction.get("protocol", "unknown")
        raw_request = interaction.get("raw-request", "")
        remote_addr = interaction.get("remote-address", "")
        timestamp = interaction.get("timestamp", "")

        record = {
            "id": stable_id(self.scan_id, "oob", str(time.time())),
            "scan_id": self.scan_id,
            "provider": "interactsh",
            "interaction_type": int_type,
            "correlation_id": self._correlation_id,
            "source_endpoint": "",
            "raw": {
                "remote_address": remote_addr,
                "raw_request": raw_request[:2000],
                "timestamp": timestamp,
                "full_response": interaction.get("raw-response", "")[:2000],
            },
            "severity": self._classify_severity(int_type),
        }

        self._interactions.append(record)

        # Persist to database
        try:
            await db_manager.create_recon_oob_interaction(**record)
        except Exception as exc:
            logger.warning(f"[INTERACTSH] DB persist failed: {exc}")

        # Log to file
        with self.interaction_log.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

        logger.info(f"[INTERACTSH] OOB {int_type} from {remote_addr}")

    @staticmethod
    def _classify_severity(protocol: str) -> str:
        high_protos = {"dns", "http", "https", "smtp", "ftp", "ldap"}
        return "critical" if protocol in high_protos else "high"

    def get_payload_markers(self) -> dict[str, str]:
        """Get payload markers for use in Nuclei templates and custom payloads."""
        url = self._interactsh_url
        return {
            "oob_url": url,
            "oob_http": f"http://{url}",
            "oob_https": f"https://{url}",
            "oob_dns": url,
            "correlation_id": self._correlation_id,
        }
